/*
 * ips_tcp_acl_node.c - VPP IPS TCP ACL Node
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
#include "acl/ips_acl.h"

typedef struct
{
    u32 next_index;
    u32 sw_if_index;
    u32 session_index;
    u32 acl_result;
    u32 acl_action;
} ips_tcp_acl_trace_t;

/* Packet processing next nodes */
typedef enum
{
    IPS_TCP_ACL_NEXT_DROP,
    IPS_TCP_ACL_NEXT_BLOCK,
    IPS_TCP_ACL_NEXT_PROTOCOL_DETECT,
    IPS_TCP_ACL_NEXT_IP4_LOOKUP,
    IPS_TCP_ACL_NEXT_IP6_LOOKUP,
    IPS_TCP_ACL_N_NEXT,
} ips_tcp_acl_next_t;

typedef enum
{
    IPS_TCP_ACL_ERROR_NONE = 0,
    IPS_TCP_ACL_ERROR_SESSION_NOT_FOUND,
    IPS_TCP_ACL_ERROR_ACL_CHECK_FAILED,
    IPS_TCP_ACL_ERROR_INVALID_PACKET,
    IPS_TCP_ACL_ERROR_BLOCK_FAILED,
    IPS_TCP_ACL_N_ERROR,
} ips_tcp_acl_error_t;

static char *ips_tcp_acl_error_strings[] = {
    [IPS_TCP_ACL_ERROR_NONE] = "No error",
    [IPS_TCP_ACL_ERROR_SESSION_NOT_FOUND] = "Session not found",
    [IPS_TCP_ACL_ERROR_ACL_CHECK_FAILED] = "ACL check failed",
    [IPS_TCP_ACL_ERROR_INVALID_PACKET] = "Invalid packet",
    [IPS_TCP_ACL_ERROR_BLOCK_FAILED] = "Block action failed",
};

/**
 * @brief Format trace output for TCP ACL node
 */
static u8 *
format_ips_tcp_acl_trace (u8 * s, va_list * args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    ips_tcp_acl_trace_t *t = va_arg (*args, ips_tcp_acl_trace_t *);

    s = format (s, "IPS-TCP-ACL: sw_if_index %d, next %d, session %d, acl_result %d, action %d",
               t->sw_if_index, t->next_index, t->session_index, t->acl_result, t->acl_action);

    return s;
}

/**
 * @brief Main TCP ACL function
 */
static_always_inline uword
ips_tcp_acl_node_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
                       vlib_frame_t * frame, int is_ip6)
{
    u32 n_left_from, *from, *to_next;
    ips_tcp_acl_next_t next_index;
    u32 pkts_processed = 0;
    u32 pkts_blocked = 0;
    u32 pkts_permitted = 0;
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
            u32 next0 = IPS_TCP_ACL_NEXT_IP4_LOOKUP;
            u32 sw_if_index0;
            u32 session_index;
            u16 src_port, dst_port;
            ips_session_t *session = NULL;
            int acl_result = 0;
            ips_acl_action_t acl_action = IPS_ACL_ACTION_PERMIT;

            /* Get packet */
            bi0 = from[0];
            to_next[0] = bi0;
            from += 1;
            to_next += 1;
            n_left_from -= 1;
            n_left_to_next -= 1;

            b0 = vlib_get_buffer (vm, bi0);
            sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

            /* Get session information from previous node */
            session_index = vnet_buffer (b0)->unused[0];
            src_port = vnet_buffer (b0)->unused[1];
            dst_port = vnet_buffer (b0)->unused[2];

            /* Look up session using IP and port information */
            if (!is_ip6)
            {
                ip4_header_t *ip4h = vlib_buffer_get_current (b0);
                if (PREDICT_TRUE (ip4h->protocol == IP_PROTOCOL_TCP))
                {
                    tcp_header_t *tcph = ip4_next_header (ip4h);

                    /* Create session key for lookup */
                    ips_session_key4_t key = {
                        .src_ip = ip4h->src_address,
                        .dst_ip = ip4h->dst_address,
                        .src_port = src_port,
                        .dst_port = dst_port,
                        .protocol = IP_PROTOCOL_TCP
                    };

                    /* Find session by key */
                    session = ips_session_lookup_ipv4(thread_index, &key);

                    if (PREDICT_TRUE (session != NULL))
                    {
                        /* Step 1: Check if session is already blocked */
                        if (session->flags & IPS_SESSION_FLAG_BLOCKED)
                        {
                            /* Session already blocked - send to block node */
                            next0 = IPS_TCP_ACL_NEXT_BLOCK;
                            pkts_blocked++;

                            IPS_LOG(IPS_LOG_LEVEL_DEBUG,
                                   "Session %u already blocked, sending to block node",
                                   session_index);
                        }
                        else
                        {
                            /* Step 2: Check ACL with session context */
                            acl_result = ips_acl_check_packet(thread_index, session, ip4h, NULL, tcph, &acl_action);

                            /* Step 3: Apply ACL decision */
                            if (acl_result != 0 || acl_action == IPS_ACL_ACTION_DENY ||
                                acl_action == IPS_ACL_ACTION_RESET)
                            {
                                /* ACL denies - mark session as blocked and send to block node */
                                session->flags |= IPS_SESSION_FLAG_BLOCKED;
                                next0 = IPS_TCP_ACL_NEXT_BLOCK;
                                pkts_blocked++;

                                IPS_LOG(IPS_LOG_LEVEL_INFO,
                                       "ACL blocked session %u (action: %d)",
                                       session_index, acl_action);

                                /* Set timeout for blocked session cleanup */
                                /* TODO: Implement proper session timeout setting */
                            }
                            else if (acl_action == IPS_ACL_ACTION_PERMIT)
                            {
                                /* ACL permits - send to protocol detection for IPS inspection */
                                next0 = IPS_TCP_ACL_NEXT_PROTOCOL_DETECT;
                                pkts_permitted++;

                                IPS_LOG(IPS_LOG_LEVEL_DEBUG,
                                       "ACL permitted session %u",
                                       session_index);
                            }
                            else
                            {
                                /* Unknown action - permit by default */
                                next0 = IPS_TCP_ACL_NEXT_PROTOCOL_DETECT;
                                pkts_permitted++;

                                IPS_LOG(IPS_LOG_LEVEL_WARNING,
                                       "Unknown ACL action %d for session %u, permitting",
                                       acl_action, session_index);
                            }
                        }

                        /* Step 4: Update session ACL statistics */
                        /* TODO: Add ACL statistics tracking to session structure */
                    }
                    else
                    {
                        /* Session not found - forward normally */
                        next0 = IPS_TCP_ACL_NEXT_IP4_LOOKUP;
                    }
                }
                else
                {
                    /* Non-TCP packet - forward normally */
                    next0 = IPS_TCP_ACL_NEXT_IP4_LOOKUP;
                }
            }
            else
            {
                ip6_header_t *ip6h = vlib_buffer_get_current (b0);
                if (PREDICT_TRUE (ip6h->protocol == IP_PROTOCOL_TCP))
                {
                    tcp_header_t *tcph = ip6_next_header (ip6h);

                    /* Create session key for lookup */
                    ips_session_key6_t key = {
                        .src_ip = ip6h->src_address,
                        .dst_ip = ip6h->dst_address,
                        .src_port = src_port,
                        .dst_port = dst_port,
                        .protocol = IP_PROTOCOL_TCP
                    };

                    /* Find session by key */
                    session = ips_session_lookup_ipv6(thread_index, &key);

                    if (PREDICT_TRUE (session != NULL))
                    {
                        /* Step 1: Check if session is already blocked */
                        if (session->flags & IPS_SESSION_FLAG_BLOCKED)
                        {
                            /* Session already blocked - send to block node */
                            next0 = IPS_TCP_ACL_NEXT_BLOCK;
                            pkts_blocked++;

                            IPS_LOG(IPS_LOG_LEVEL_DEBUG,
                                   "Session %u already blocked, sending to block node",
                                   session_index);
                        }
                        else
                        {
                            /* Step 2: Check ACL with session context */
                            acl_result = ips_acl_check_packet(thread_index, session, NULL, ip6h, tcph, &acl_action);

                            /* Step 3: Apply ACL decision */
                            if (acl_result != 0 || acl_action == IPS_ACL_ACTION_DENY ||
                                acl_action == IPS_ACL_ACTION_RESET)
                            {
                                /* ACL denies - mark session as blocked and send to block node */
                                session->flags |= IPS_SESSION_FLAG_BLOCKED;
                                next0 = IPS_TCP_ACL_NEXT_BLOCK;
                                pkts_blocked++;

                                IPS_LOG(IPS_LOG_LEVEL_INFO,
                                       "ACL blocked session %u (action: %d)",
                                       session_index, acl_action);

                                /* Set timeout for blocked session cleanup */
                                /* TODO: Implement proper session timeout setting */
                            }
                            else if (acl_action == IPS_ACL_ACTION_PERMIT)
                            {
                                /* ACL permits - send to protocol detection for IPS inspection */
                                next0 = IPS_TCP_ACL_NEXT_PROTOCOL_DETECT;
                                pkts_permitted++;

                                IPS_LOG(IPS_LOG_LEVEL_DEBUG,
                                       "ACL permitted session %u",
                                       session_index);
                            }
                            else
                            {
                                /* Unknown action - permit by default */
                                next0 = IPS_TCP_ACL_NEXT_PROTOCOL_DETECT;
                                pkts_permitted++;

                                IPS_LOG(IPS_LOG_LEVEL_WARNING,
                                       "Unknown ACL action %d for session %u, permitting",
                                       acl_action, session_index);
                            }
                        }

                        /* Step 4: Update session ACL statistics */
                        /* TODO: Add ACL statistics tracking to session structure */
                    }
                    else
                    {
                        /* Session not found - forward normally */
                        next0 = IPS_TCP_ACL_NEXT_IP6_LOOKUP;
                    }
                }
                else
                {
                    /* Non-TCP packet - forward normally */
                    next0 = IPS_TCP_ACL_NEXT_IP6_LOOKUP;
                }
            }

            /* Add trace if enabled */
            if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
            {
                ips_tcp_acl_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
                t->next_index = next0;
                t->sw_if_index = sw_if_index0;
                t->session_index = session_index;
                t->acl_result = acl_result;
                t->acl_action = acl_action;
            }

            /* Verify speculative enqueue */
            vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next, n_left_to_next, bi0, next0);
        }

        vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

    /* TCP ACL statistics are tracked internally */
    /* Log the statistics for debugging */
    IPS_LOG(IPS_LOG_LEVEL_DEBUG,
           "TCP ACL node stats: processed=%u, blocked=%u, permitted=%u",
           pkts_processed, pkts_blocked, pkts_permitted);

    return frame->n_vectors;
}

/**
 * @brief IPv4 TCP ACL node function
 */
static uword
ips_tcp_acl_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                    vlib_frame_t * frame)
{
    return ips_tcp_acl_node_inline (vm, node, frame, 0 /* is_ip6 */);
}

/**
 * @brief IPv6 TCP ACL node function
 */
static uword
ips_tcp_acl_ip6_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                          vlib_frame_t * frame)
{
    return ips_tcp_acl_node_inline (vm, node, frame, 1 /* is_ip6 */);
}

/* Node registration for IPv4 */
VLIB_REGISTER_NODE (ips_tcp_acl_node) = {
    .name = "ips-tcp-acl",
    .function = ips_tcp_acl_node_fn,
    .vector_size = sizeof (u32),
    .format_trace = format_ips_tcp_acl_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,
    .n_errors = IPS_TCP_ACL_N_ERROR,
    .error_strings = ips_tcp_acl_error_strings,
    .n_next_nodes = IPS_TCP_ACL_N_NEXT,
    .next_nodes = {
        [IPS_TCP_ACL_NEXT_DROP] = "error-drop",
        [IPS_TCP_ACL_NEXT_BLOCK] = "ips-block",
        [IPS_TCP_ACL_NEXT_PROTOCOL_DETECT] = "ips-protocol-detect",
        [IPS_TCP_ACL_NEXT_IP4_LOOKUP] = "ip4-lookup",
        [IPS_TCP_ACL_NEXT_IP6_LOOKUP] = "ip6-lookup",
    },
};

/* Node registration for IPv6 */
VLIB_REGISTER_NODE (ips_tcp_acl_ip6_node) = {
    .name = "ips-tcp-acl-ip6",
    .function = ips_tcp_acl_ip6_node_fn,
    .vector_size = sizeof (u32),
    .format_trace = format_ips_tcp_acl_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,
    .n_errors = IPS_TCP_ACL_N_ERROR,
    .error_strings = ips_tcp_acl_error_strings,
    .n_next_nodes = IPS_TCP_ACL_N_NEXT,
    .next_nodes = {
        [IPS_TCP_ACL_NEXT_DROP] = "error-drop",
        [IPS_TCP_ACL_NEXT_BLOCK] = "ips-block",
        [IPS_TCP_ACL_NEXT_PROTOCOL_DETECT] = "ips-protocol-detect",
        [IPS_TCP_ACL_NEXT_IP4_LOOKUP] = "ip4-lookup",
        [IPS_TCP_ACL_NEXT_IP6_LOOKUP] = "ip6-lookup",
    },
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */