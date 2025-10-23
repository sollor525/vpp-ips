/*
 * ips_flow.c - VPP IPS Plugin Flow Management
 *
 * Copyright (c) 2024 VPP IPS Project
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/pool.h>

#include "ips.h"

/**
 * @brief Create a new flow session
 */
ips_flow_t *
ips_flow_create (ips_per_thread_data_t * ptd, ips_flow_key_t * key)
{
    ips_flow_t *flow;
    u32 hash;

    /* Allocate new flow */
    pool_get_zero (ptd->flows, flow);

    /* Initialize flow */
    flow->key = *key;
    flow->flow_start_time = vlib_time_now (vlib_get_main ());
    flow->last_packet_time = flow->flow_start_time;
    flow->session_index = flow - ptd->flows;
    flow->thread_index = vlib_get_thread_index ();

    /* Initialize TCP reordering */
    ips_tcp_reorder_init_flow (flow);

    /* Calculate hash */
    hash = ips_flow_key_hash (key);
    flow->flow_hash = hash;

    /* Add to hash table */
    hash_set (ptd->flow_hash, hash, flow->session_index);

    return flow;
}

/**
 * @brief Delete a flow session
 */
void
ips_flow_delete (ips_per_thread_data_t * ptd, ips_flow_t * flow)
{
    if (PREDICT_FALSE (!flow))
        return;

    /* Close Hyperscan stream if open */
    /* Hyperscan temporarily disabled */
    /*
    if (flow->hs_stream)
    {
        hs_error_t hs_err = hs_close_stream (flow->hs_stream, NULL, NULL, NULL);
        if (hs_err != HS_SUCCESS)
        {
            clib_warning ("Failed to close Hyperscan stream: %d", hs_err);
        }
        flow->hs_stream = NULL;
    }
    */

    /* Clean up TCP reordering state */
    ips_tcp_reorder_cleanup_flow (flow);

    /* Remove from hash table */
    hash_unset (ptd->flow_hash, flow->flow_hash);

    /* Return to pool */
    pool_put (ptd->flows, flow);
}

/**
 * @brief Lookup flow by key
 */
ips_flow_t *
ips_flow_lookup (ips_per_thread_data_t * ptd, ips_flow_key_t * key)
{
    uword *p;
    u32 hash;
    ips_flow_t *flow;

    hash = ips_flow_key_hash (key);
    p = hash_get (ptd->flow_hash, hash);

    if (!p)
        return NULL;

    flow = pool_elt_at_index (ptd->flows, p[0]);

    /* Verify key match */
    if (!ips_flow_key_equal (&flow->key, key))
        return NULL;

    return flow;
}

/**
 * @brief Update TCP state machine
 */
void
ips_flow_update_tcp_state (ips_flow_t * flow, tcp_header_t * tcp, u8 is_to_server)
{
    u8 tcp_flags = tcp->flags;
    ips_tcp_state_t *state;
    u32 *seq, *ack;

    if (is_to_server)
    {
        state = &flow->tcp_state_src;
        seq = &flow->tcp_seq_src;
        ack = &flow->tcp_ack_src;
    }
    else
    {
        state = &flow->tcp_state_dst;
        seq = &flow->tcp_seq_dst;
        ack = &flow->tcp_ack_dst;
    }

    /* Update sequence numbers */
    *seq = clib_net_to_host_u32 (tcp->seq_number);
    *ack = clib_net_to_host_u32 (tcp->ack_number);

    /* State machine transitions */
    switch (*state)
    {
    case IPS_TCP_NONE:
        if (tcp_flags & TCP_FLAG_SYN)
        {
            *state = IPS_TCP_SYN_SENT;
        }
        break;

    case IPS_TCP_SYN_SENT:
        if (tcp_flags & (TCP_FLAG_SYN | TCP_FLAG_ACK))
        {
            *state = IPS_TCP_SYN_RECV;
        }
        break;

    case IPS_TCP_SYN_RECV:
        if (tcp_flags & TCP_FLAG_ACK)
        {
            *state = IPS_TCP_ESTABLISHED;
        }
        break;

    case IPS_TCP_ESTABLISHED:
        if (tcp_flags & TCP_FLAG_FIN)
        {
            *state = IPS_TCP_FIN_WAIT1;
        }
        else if (tcp_flags & TCP_FLAG_RST)
        {
            *state = IPS_TCP_CLOSED;
        }
        break;

    case IPS_TCP_FIN_WAIT1:
        if (tcp_flags & TCP_FLAG_ACK)
        {
            *state = IPS_TCP_FIN_WAIT2;
        }
        break;

    case IPS_TCP_FIN_WAIT2:
        if (tcp_flags & TCP_FLAG_FIN)
        {
            *state = IPS_TCP_TIME_WAIT;
        }
        break;

    default:
        break;
    }
}

/**
 * @brief Check if flow is expired
 */
int
ips_flow_is_expired (ips_flow_t * flow, f64 timeout)
{
    ips_main_t *im = &ips_main;
    f64 now = vlib_time_now (im->vlib_main);

    return ((now - flow->last_packet_time) > timeout);
}

/**
 * @brief Update flow statistics
 */
void
ips_flow_update_stats (ips_flow_t * flow, vlib_buffer_t * b, u8 is_to_server)
{
    u32 pkt_len = vlib_buffer_length_in_chain (vlib_get_main (), b);

    if (is_to_server)
    {
        flow->packet_count_src++;
        flow->byte_count_src += pkt_len;
    }
    else
    {
        flow->packet_count_dst++;
        flow->byte_count_dst += pkt_len;
    }

    flow->last_packet_time = vlib_time_now (vlib_get_main ());
}

/**
 * @brief Cleanup expired flows
 */
void
ips_flow_cleanup_expired (ips_per_thread_data_t * ptd, f64 timeout)
{
    ips_flow_t *flow;
    u32 *expired_flows = 0;
    u32 i;

    /* Collect expired flows */
    pool_foreach (flow, ptd->flows)
    {
        if (ips_flow_is_expired (flow, timeout))
        {
            vec_add1 (expired_flows, flow->session_index);
        }
    }

    /* Delete expired flows */
    for (i = 0; i < vec_len (expired_flows); i++)
    {
        flow = pool_elt_at_index (ptd->flows, expired_flows[i]);
        ips_flow_delete (ptd, flow);
    }

    vec_free (expired_flows);
}
