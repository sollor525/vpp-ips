/*
 * ips_tcp_reorder_node.c - VPP IPS TCP Reordering Node
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
#include <vnet/feature/feature.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/tcp/tcp_packet.h>

#include "ips.h"
#include "session/ips_session.h"
#include "session/ips_tcp_reorder.h"

typedef struct
{
    u32 next_index;
    u32 sw_if_index;
    u32 session_index;
    u32 reorder_result;
    u32 buffered_bytes;
} ips_tcp_reorder_trace_t;

/* Packet processing next nodes */
typedef enum
{
    IPS_TCP_REORDER_NEXT_DROP,
    IPS_TCP_REORDER_NEXT_INSPECT_DETECT,  /* Final step: intrusion detection */
    IPS_TCP_REORDER_N_NEXT,
} ips_tcp_reorder_next_t;

typedef enum
{
    IPS_TCP_REORDER_ERROR_NONE = 0,
    IPS_TCP_REORDER_ERROR_SESSION_NOT_FOUND,
    IPS_TCP_REORDER_ERROR_REORDER_FAILED,
    IPS_TCP_REORDER_ERROR_BUFFER_FULL,
    IPS_TCP_REORDER_ERROR_INVALID_PACKET,
    IPS_TCP_REORDER_N_ERROR,
} ips_tcp_reorder_error_t;

static char *ips_tcp_reorder_error_strings[] = {
    [IPS_TCP_REORDER_ERROR_NONE] = "No error",
    [IPS_TCP_REORDER_ERROR_SESSION_NOT_FOUND] = "Session not found",
    [IPS_TCP_REORDER_ERROR_REORDER_FAILED] = "Reorder failed",
    [IPS_TCP_REORDER_ERROR_BUFFER_FULL] = "Reorder buffer full",
    [IPS_TCP_REORDER_ERROR_INVALID_PACKET] = "Invalid packet",
};

/**
 * @brief Format trace output for TCP reorder node
 */
static u8 *
format_ips_tcp_reorder_trace (u8 * s, va_list * args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    ips_tcp_reorder_trace_t *t = va_arg (*args, ips_tcp_reorder_trace_t *);

    s = format (s, "IPS-TCP-REORDER: sw_if_index %d, next %d, session %d, result %d, buffered %d",
               t->sw_if_index, t->next_index, t->session_index, t->reorder_result, t->buffered_bytes);

    return s;
}

/**
 * @brief Main TCP reordering function
 */
static_always_inline uword
ips_tcp_reorder_node_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
                           vlib_frame_t * frame, int is_ip6)
{
    u32 n_left_from, *from, *to_next;
    ips_tcp_reorder_next_t next_index;
    u32 pkts_processed = 0;
    u32 pkts_reordered = 0;
    u32 pkts_buffered = 0;
    u32 thread_index = vm->thread_index;

    from = vlib_frame_vector_args (frame);
    n_left_from = frame->n_vectors;
    next_index = node->cached_next_index;

    while (n_left_from > 0)
    {
        u32 n_left_to_next;

        vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

        while (n_left_from > 0 && n_left_to_next > 0)
        {
            u32 bi0;
            vlib_buffer_t *b0;
            u32 next0 = IPS_TCP_REORDER_NEXT_DROP;  /* Default: drop for mirror traffic */
            u32 sw_if_index0;
            u32 session_index;
            u16 src_port, dst_port;
            ips_session_t *session = NULL;
            int reorder_result = 0;
            u32 buffered_bytes = 0;

            /* Get packet */
            bi0 = from[0];
            to_next[0] = bi0;
            from += 1;
            to_next += 1;
            n_left_from -= 1;
            n_left_to_next -= 1;

            b0 = vlib_get_buffer (vm, bi0);
            sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

            /* Increment basic packet counters */
            vlib_increment_simple_counter(&ips_main.counters, thread_index, IPS_COUNTER_REORDER_PACKETS_IN, 1);
            vlib_increment_simple_counter(&ips_main.counters, thread_index, IPS_COUNTER_REORDER_PROCESSED, 1);

            /* Get session information from previous node */
            session_index = vnet_buffer (b0)->unused[0];
            src_port = vnet_buffer (b0)->unused[1];
            dst_port = vnet_buffer (b0)->unused[2];

            /* Get session manager data for direct pool access */
            ips_session_manager_t *sm = &ips_session_manager;
            ips_session_per_thread_data_t *ptd = &sm->per_thread_data[thread_index];

            /* Look up session using IP and port information */
            if (!is_ip6)
            {
                ip4_header_t *ip4h = vlib_buffer_get_current (b0);
                if (PREDICT_TRUE (ip4h->protocol == IP_PROTOCOL_TCP))
                {
                    /* Try direct pool access first (performance optimization) */
                    session = NULL;
                    if (PREDICT_TRUE(session_index < pool_len(ptd->session_pool) &&
                                     !pool_is_free_index(ptd->session_pool, session_index)))
                    {
                        session = pool_elt_at_index(ptd->session_pool, session_index);

                        /* Validate session matches */
                        if (PREDICT_FALSE(session->session_index != session_index ||
                                           session->thread_index != thread_index))
                        {
                            session = NULL; /* Session reused or invalid - fallback to hash lookup */
                        }
                    }

                    /* Fallback to hash lookup if direct access failed */
                    if (PREDICT_FALSE(session == NULL))
                    {
                        /* Create session key for hash lookup */
                        ips_session_key4_t key = {
                            .src_ip = ip4h->src_address,
                            .dst_ip = ip4h->dst_address,
                            .src_port = src_port,
                            .dst_port = dst_port,
                            .protocol = IP_PROTOCOL_TCP
                        };

                        session = ips_session_lookup_ipv4(thread_index, &key);
                    }

                    if (PREDICT_TRUE (session != NULL))
                    {
                        /* Step 1: For now, bypass TCP reordering and forward directly */
                        /* TCP reordering will be reimplemented using session structures */
                        next0 = IPS_TCP_REORDER_NEXT_INSPECT_DETECT;
                        pkts_reordered++;  /* Count as processed for stats */

                        /* Increment reorder bypass counter */
                        vlib_increment_simple_counter(&ips_main.counters, thread_index, IPS_COUNTER_REORDER_BYPASSED, 1);

                        IPS_LOG(IPS_LOG_LEVEL_DEBUG,
                               "TCP reordering bypassed for session %u, forwarding directly",
                               session_index);
                    }
                    else
                    {
                        /* Session not found - drop packet */
                        next0 = IPS_TCP_REORDER_NEXT_DROP;
                        b0->error = IPS_TCP_REORDER_ERROR_SESSION_NOT_FOUND;

                        /* Increment session not found counter */
                        vlib_increment_simple_counter(&ips_main.counters, thread_index, IPS_COUNTER_SESSION_NOT_FOUND, 1);
                    }
                }
                else
                {
                    /* Non-TCP packet - drop (mirror traffic) */
                    next0 = IPS_TCP_REORDER_NEXT_DROP;

                    /* Note: Non-TCP drops are counted in input node */
                }
            }
            else
            {
                ip6_header_t *ip6h = vlib_buffer_get_current (b0);
                if (PREDICT_TRUE (ip6h->protocol == IP_PROTOCOL_TCP))
                {
                    /* Try direct pool access first (performance optimization) */
                    session = NULL;
                    if (PREDICT_TRUE(session_index < pool_len(ptd->session_pool) &&
                                     !pool_is_free_index(ptd->session_pool, session_index)))
                    {
                        session = pool_elt_at_index(ptd->session_pool, session_index);

                        /* Validate session matches */
                        if (PREDICT_FALSE(session->session_index != session_index ||
                                           session->thread_index != thread_index))
                        {
                            session = NULL; /* Session reused or invalid - fallback to hash lookup */
                        }
                    }

                    /* Fallback to hash lookup if direct access failed */
                    if (PREDICT_FALSE(session == NULL))
                    {
                        /* Create session key for hash lookup */
                        ips_session_key6_t key = {
                            .src_ip = ip6h->src_address,
                            .dst_ip = ip6h->dst_address,
                            .src_port = src_port,
                            .dst_port = dst_port,
                            .protocol = IP_PROTOCOL_TCP
                        };

                        session = ips_session_lookup_ipv6(thread_index, &key);
                    }

                    if (PREDICT_TRUE (session != NULL))
                    {
                        /* Step 1: For now, bypass TCP reordering and forward directly */
                        /* TCP reordering will be reimplemented using session structures */
                        next0 = IPS_TCP_REORDER_NEXT_INSPECT_DETECT;
                        pkts_reordered++;  /* Count as processed for stats */

                        /* Increment reorder bypass counter */
                        vlib_increment_simple_counter(&ips_main.counters, thread_index, IPS_COUNTER_REORDER_BYPASSED, 1);

                        IPS_LOG(IPS_LOG_LEVEL_DEBUG,
                               "TCP reordering bypassed for session %u, forwarding directly",
                               session_index);
                    }
                    else
                    {
                        /* Session not found - drop packet */
                        next0 = IPS_TCP_REORDER_NEXT_DROP;
                        b0->error = IPS_TCP_REORDER_ERROR_SESSION_NOT_FOUND;

                        /* Increment session not found counter */
                        vlib_increment_simple_counter(&ips_main.counters, thread_index, IPS_COUNTER_SESSION_NOT_FOUND, 1);
                    }
                }
                else
                {
                    /* Non-TCP packet - drop (mirror traffic) */
                    next0 = IPS_TCP_REORDER_NEXT_DROP;

                    /* Note: Non-TCP drops are counted in input node */
                }
            }

            /* Add trace if enabled */
            if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
            {
                ips_tcp_reorder_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
                t->next_index = next0;
                t->sw_if_index = sw_if_index0;
                t->session_index = session_index;
                t->reorder_result = reorder_result;
                t->buffered_bytes = buffered_bytes;
            }

            /* Verify speculative enqueue */
            vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next, n_left_to_next, bi0, next0);
        }

        vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

    /* TCP reordering statistics are tracked internally */
    /* Log the statistics for debugging */
    IPS_LOG(IPS_LOG_LEVEL_DEBUG,
           "TCP reorder node stats: processed=%u, reordered=%u, buffered=%u",
           pkts_processed, pkts_reordered, pkts_buffered);

    return frame->n_vectors;
}

/**
 * @brief IPv4 TCP reordering node function
 */
static uword
ips_tcp_reorder_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                        vlib_frame_t * frame)
{
    return ips_tcp_reorder_node_inline (vm, node, frame, 0 /* is_ip6 */);
}

/**
 * @brief IPv6 TCP reordering node function
 */
static uword
ips_tcp_reorder_ip6_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                             vlib_frame_t * frame)
{
    return ips_tcp_reorder_node_inline (vm, node, frame, 1 /* is_ip6 */);
}

/* Node registration for IPv4 */
VLIB_REGISTER_NODE (ips_tcp_reorder_node) = {
    .name = "ips-tcp-reorder",
    .function = ips_tcp_reorder_node_fn,
    .vector_size = sizeof (u32),
    .format_trace = format_ips_tcp_reorder_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,
    .n_errors = IPS_TCP_REORDER_N_ERROR,
    .error_strings = ips_tcp_reorder_error_strings,
    .n_next_nodes = IPS_TCP_REORDER_N_NEXT,
    .next_nodes = {
        [IPS_TCP_REORDER_NEXT_DROP] = "error-drop",
        [IPS_TCP_REORDER_NEXT_INSPECT_DETECT] = "ips-inspect",
    },
    
};

/* Node registration for IPv6 */
VLIB_REGISTER_NODE (ips_tcp_reorder_ip6_node) = {
    .name = "ips-tcp-reorder-ip6",
    .function = ips_tcp_reorder_ip6_node_fn,
    .vector_size = sizeof (u32),
    .format_trace = format_ips_tcp_reorder_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,
    .n_errors = IPS_TCP_REORDER_N_ERROR,
    .error_strings = ips_tcp_reorder_error_strings,
    .n_next_nodes = IPS_TCP_REORDER_N_NEXT,
    .next_nodes = {
        [IPS_TCP_REORDER_NEXT_DROP] = "error-drop",
        [IPS_TCP_REORDER_NEXT_INSPECT_DETECT] = "ips-inspect",
    },
    
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */