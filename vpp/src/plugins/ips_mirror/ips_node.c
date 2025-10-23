/*
 * ips_node.c - VPP IPS Plugin Node Implementation
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

#include "ips.h"
#include "detection/ips_detection.h" /* for foreach_ips_error */
#include "session/ips_session.h"
#include "vlib/buffer.h"
#include "vnet/ip/ip4_packet.h"
#include "vnet/tcp/tcp_packet.h"




typedef struct
{
    u32 next_index;
    u32 sw_if_index;
    u32 session_index;
    u32 rule_matches;
} ips_trace_t;

/* Packet processing next nodes */
typedef enum
{
    IPS_INPUT_NEXT_DROP,
    IPS_INPUT_NEXT_IP4_LOOKUP,
    IPS_INPUT_NEXT_IP6_LOOKUP,
    IPS_INPUT_NEXT_ETHERNET_INPUT,
    IPS_INPUT_N_NEXT,
} ips_input_next_t;

static char *ips_error_strings[] =
{
#define _(sym,string) string,
    foreach_ips_error
#undef _
};

typedef enum
{
#define _(sym,str) IPS_ERROR_##sym,
    foreach_ips_error
#undef _
    IPS_N_ERROR,
} ips_error_t;

/**
 * @brief Format trace output
 */
static u8 *
format_ips_trace (u8 * s, va_list * args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    ips_trace_t *t = va_arg (*args, ips_trace_t *);

    s = format (s, "IPS: sw_if_index %d, next index %d, session %d, matches %d",
               t->sw_if_index, t->next_index, t->session_index, t->rule_matches);

    return s;
}

/* Removed legacy flow session helper; session handling is now centralized */

/**
 * @brief Main IPS packet processing function
 */
static_always_inline uword
ips_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
                 vlib_frame_t * frame, int is_ip6)
{
    ips_main_t *im = &ips_main;
    u32 n_left_from, *from, *to_next;
    ips_input_next_t next_index;
    u32 pkts_processed = 0;
    u32 pkts_dropped = 0;
    u32 thread_index = vm->thread_index;
    ips_per_thread_data_t *ptd = &im->per_thread_data[thread_index];

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
            u32 next0 = IPS_INPUT_NEXT_IP4_LOOKUP;
            u32 sw_if_index0;

            /* Get packet */
            bi0 = from[0];
            to_next[0] = bi0;
            from += 1;
            to_next += 1;
            n_left_from -= 1;
            n_left_to_next -= 1;

            b0 = vlib_get_buffer (vm, bi0);
            sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

            /* Direct session handling without flow parsing */
            if (!is_ip6)
            {
                ip4_header_t *ip4h = vlib_buffer_get_current (b0);
                if (PREDICT_TRUE (ip4h->protocol == IP_PROTOCOL_TCP))
                {
                    tcp_header_t *tcph = ip4_next_header (ip4h);
                    (void) ips_session_lookup_or_create_ipv4 (thread_index, ip4h, tcph);
                }
                next0 = IPS_INPUT_NEXT_IP4_LOOKUP;
            }
            else
            {
                ip6_header_t *ip6h = vlib_buffer_get_current (b0);
                if (PREDICT_TRUE (ip6h->protocol == IP_PROTOCOL_TCP))
                {
                    tcp_header_t *tcph = ip6_next_header (ip6h);
                    (void) ips_session_lookup_or_create_ipv6 (thread_index, ip6h, tcph);
                }
                next0 = IPS_INPUT_NEXT_IP6_LOOKUP;
            }

            pkts_processed++;

            if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
                              (b0->flags & VLIB_BUFFER_IS_TRACED)))
            {
                ips_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
                t->sw_if_index = sw_if_index0;
                t->next_index = next0;
                t->session_index = ~0;
                t->rule_matches = 0;
            }

            /* Validate speculative enqueue */
            vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                                           to_next, n_left_to_next,
                                           bi0, next0);
        }

        vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

    /* Update per-thread statistics */
    ptd->total_packets += pkts_processed;
    ptd->dropped_packets += pkts_dropped;

    return frame->n_vectors;
}

/**
 * @brief IPv4 input node function
 */
VLIB_NODE_FN (ips_input_ip4_node) (vlib_main_t * vm,
                                   vlib_node_runtime_t * node,
                                   vlib_frame_t * frame)
{
    return ips_input_inline (vm, node, frame, 0);
}

/**
 * @brief IPv6 input node function
 */
VLIB_NODE_FN (ips_input_ip6_node) (vlib_main_t * vm,
                                   vlib_node_runtime_t * node,
                                   vlib_frame_t * frame)
{
    return ips_input_inline (vm, node, frame, 1);
}

/* IPv4 input node registration */
VLIB_REGISTER_NODE (ips_input_ip4_node) =
{
    .name = "ips-input-ip4",
    .vector_size = sizeof (u32),
    .format_trace = format_ips_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,
    .n_errors = ARRAY_LEN (ips_error_strings),
    .error_strings = ips_error_strings,
    .n_next_nodes = IPS_INPUT_N_NEXT,
    .next_nodes =
    {
        [IPS_INPUT_NEXT_DROP] = "error-drop",
        [IPS_INPUT_NEXT_IP4_LOOKUP] = "ip4-lookup",
        [IPS_INPUT_NEXT_IP6_LOOKUP] = "ip6-lookup",
        [IPS_INPUT_NEXT_ETHERNET_INPUT] = "ethernet-input",
    },
};

/* IPv6 input node registration */
VLIB_REGISTER_NODE (ips_input_ip6_node) =
{
    .name = "ips-input-ip6",
    .vector_size = sizeof (u32),
    .format_trace = format_ips_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,
    .n_errors = ARRAY_LEN (ips_error_strings),
    .error_strings = ips_error_strings,
    .n_next_nodes = IPS_INPUT_N_NEXT,
    .next_nodes =
    {
        [IPS_INPUT_NEXT_DROP] = "error-drop",
        [IPS_INPUT_NEXT_IP4_LOOKUP] = "ip4-lookup",
        [IPS_INPUT_NEXT_IP6_LOOKUP] = "ip6-lookup",
        [IPS_INPUT_NEXT_ETHERNET_INPUT] = "ethernet-input",
    },
};

/* Feature arc registration for IPv4 */
VNET_FEATURE_INIT (ips_ip4_input, static) =
{
    .arc_name = "ip4-unicast",
    .node_name = "ips-input-ip4",
    .runs_before = VNET_FEATURES ("ip4-lookup"),
};

/* Feature arc registration for IPv6 */
VNET_FEATURE_INIT (ips_ip6_input, static) =
{
    .arc_name = "ip6-unicast",
    .node_name = "ips-input-ip6",
    .runs_before = VNET_FEATURES ("ip6-lookup"),
};
