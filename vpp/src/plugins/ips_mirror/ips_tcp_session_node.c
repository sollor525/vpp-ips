/*
 * ips_tcp_session_node.c - VPP IPS TCP Session Management Node
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
#include "session/ips_session_timer.h"

typedef struct
{
    u32 next_index;
    u32 sw_if_index;
    u32 session_index;
    u32 tcp_state;
} ips_tcp_session_trace_t;

/* Packet processing next nodes */
typedef enum
{
    IPS_TCP_SESSION_NEXT_DROP,
    IPS_TCP_SESSION_NEXT_TCP_ACL,      /* Direct to ACL after session management */
    IPS_TCP_SESSION_N_NEXT,
} ips_tcp_session_next_t;

typedef enum
{
    IPS_TCP_SESSION_ERROR_NONE = 0,
    IPS_TCP_SESSION_ERROR_SESSION_CREATE_FAILED,
    IPS_TCP_SESSION_ERROR_INVALID_PACKET,
    IPS_TCP_SESSION_ERROR_TIMEOUT,
    IPS_TCP_SESSION_N_ERROR,
} ips_tcp_session_error_t;

static char *ips_tcp_session_error_strings[] = {
    [IPS_TCP_SESSION_ERROR_NONE] = "No error",
    [IPS_TCP_SESSION_ERROR_SESSION_CREATE_FAILED] = "Session creation failed",
    [IPS_TCP_SESSION_ERROR_INVALID_PACKET] = "Invalid packet",
    [IPS_TCP_SESSION_ERROR_TIMEOUT] = "Session timeout",
};

/**
 * @brief Format trace output for TCP session node
 */
static u8 *
format_ips_tcp_session_trace (u8 * s, va_list * args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    ips_tcp_session_trace_t *t = va_arg (*args, ips_tcp_session_trace_t *);

    s = format (s, "IPS-TCP-SESSION: sw_if_index %d, next %d, session %d, tcp_state %d",
               t->sw_if_index, t->next_index, t->session_index, t->tcp_state);

    return s;
}

/**
 * @brief Main TCP session management function
 */
static_always_inline uword
ips_tcp_session_node_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
                           vlib_frame_t * frame, int is_ip6)
{
    u32 n_left_from, *from, *to_next;
    ips_tcp_session_next_t next_index;
    CLIB_UNUSED (u32 pkts_dropped) = 0;
    u32 thread_index = vm->thread_index;

    from = vlib_frame_vector_args (frame);
    n_left_from = frame->n_vectors;
    next_index = node->cached_next_index;

    /* 定期检查定时器（每 10 秒），确保低流量时也能老化会话
     * Thread-safe 因为每个线程只处理自己的定时器和会话池 */
    ips_session_per_thread_data_t *ptd = &ips_session_manager.per_thread_data[thread_index];
    f64 now = vlib_time_now (vm);

    if (now - ptd->last_timer_check > 10.0)
    {
        ips_session_timer_expire_timers (thread_index);
        ptd->last_timer_check = now;
    }

    while (n_left_from > 0)
    {
        u32 n_left_to_next;

        vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

        while (n_left_from > 0 && n_left_to_next > 0)
        {
            u32 bi0;
            vlib_buffer_t *b0;
            u32 next0 = IPS_TCP_SESSION_NEXT_DROP;  /* Default: drop for mirror traffic */
            u32 sw_if_index0;
            ips_session_t *session = NULL;

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
            vlib_increment_simple_counter(&ips_main.counters, thread_index, IPS_COUNTER_SESSION_PACKETS_SEEN, 1);
            vlib_increment_simple_counter(&ips_main.counters, thread_index, IPS_COUNTER_SESSION_BYTES_SEEN, b0->current_length);

            /* Process based on IP version */
            if (!is_ip6)
            {
                ip4_header_t *ip4h = vlib_buffer_get_current (b0);
                if (PREDICT_TRUE (ip4h->protocol == IP_PROTOCOL_TCP))
                {
                    tcp_header_t *tcph = ip4_next_header (ip4h);

                    /* Step 1: Lookup or create session */
                    session = ips_session_lookup_or_create_ipv4 (thread_index, ip4h, tcph);

                    if (PREDICT_TRUE (session != NULL))
                    {
                        /* Step 2: Session management - session already created/updated by lookup function */
                        /* TCP state is managed by session lookup function */
                        /* Statistics are tracked implicitly by session management */
                        /* Timeout is managed by session timer system */

                        /* Step 5: Send all TCP sessions to ACL for processing */
                        /* This ensures ACL filtering happens before expensive operations */
                        next0 = IPS_TCP_SESSION_NEXT_TCP_ACL;

                        /* Store session information in buffer for next nodes */
                        vnet_buffer (b0)->unused[0] = session->session_index;
                        vnet_buffer (b0)->unused[1] = session->src_port;
                        vnet_buffer (b0)->unused[2] = session->dst_port;
                    }
                    else
                    {
                        /* Session creation failed - drop packet */
                        next0 = IPS_TCP_SESSION_NEXT_DROP;
                        pkts_dropped++;
                    }
                }
                else
                {
                    /* Non-TCP packet - drop (mirror traffic) */
                    next0 = IPS_TCP_SESSION_NEXT_DROP;
                }
            }
            else
            {
                ip6_header_t *ip6h = vlib_buffer_get_current (b0);
                if (PREDICT_TRUE (ip6h->protocol == IP_PROTOCOL_TCP))
                {
                    tcp_header_t *tcph = ip6_next_header (ip6h);

                    /* Step 1: Lookup or create session */
                    session = ips_session_lookup_or_create_ipv6 (thread_index, ip6h, tcph);

                    if (PREDICT_TRUE (session != NULL))
                    {
                        /* Step 2: Session management - session already created/updated by lookup function */
                        /* TCP state is managed by session lookup function */
                        /* Statistics are tracked implicitly by session management */
                        /* Timeout is managed by session timer system */

                        /* Step 5: Send all TCP sessions to ACL for processing */
                        /* This ensures ACL filtering happens before expensive operations */
                        next0 = IPS_TCP_SESSION_NEXT_TCP_ACL;

                        /* Store session information in buffer for next nodes */
                        vnet_buffer (b0)->unused[0] = session->session_index;
                        vnet_buffer (b0)->unused[1] = session->src_port;
                        vnet_buffer (b0)->unused[2] = session->dst_port;
                    }
                    else
                    {
                        /* Session creation failed - drop packet */
                        next0 = IPS_TCP_SESSION_NEXT_DROP;
                        pkts_dropped++;
                    }
                }
                else
                {
                    /* Non-TCP packet - drop (mirror traffic) */
                    next0 = IPS_TCP_SESSION_NEXT_DROP;
                }
            }

            /* Add trace if enabled */
            if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
            {
                ips_tcp_session_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
                t->next_index = next0;
                t->sw_if_index = sw_if_index0;
                t->session_index = session ? session->session_index : ~0;
                t->tcp_state = session ? session->tcp_state_src : 0;
            }

            /* Verify speculative enqueue */
            vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next, n_left_to_next, bi0, next0);
        }

        vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

    return frame->n_vectors;
}

/**
 * @brief IPv4 TCP session node function
 */
static uword
ips_tcp_session_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                        vlib_frame_t * frame)
{
    return ips_tcp_session_node_inline (vm, node, frame, 0 /* is_ip6 */);
}

/**
 * @brief IPv6 TCP session node function
 */
static uword
ips_tcp_session_ip6_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                             vlib_frame_t * frame)
{
    return ips_tcp_session_node_inline (vm, node, frame, 1 /* is_ip6 */);
}

/* Node registration for IPv4 */
VLIB_REGISTER_NODE (ips_tcp_session_node) = {
    .name = "ips-tcp-session",
    .function = ips_tcp_session_node_fn,
    .vector_size = sizeof (u32),
    .format_trace = format_ips_tcp_session_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,
    .n_errors = IPS_TCP_SESSION_N_ERROR,
    .error_strings = ips_tcp_session_error_strings,
    .n_next_nodes = IPS_TCP_SESSION_N_NEXT,
    .next_nodes = {
        [IPS_TCP_SESSION_NEXT_DROP] = "error-drop",
        [IPS_TCP_SESSION_NEXT_TCP_ACL] = "ips-tcp-acl",
    },
};

/* Node registration for IPv6 */
VLIB_REGISTER_NODE (ips_tcp_session_ip6_node) = {
    .name = "ips-tcp-session-ip6",
    .function = ips_tcp_session_ip6_node_fn,
    .vector_size = sizeof (u32),
    .format_trace = format_ips_tcp_session_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,
    .n_errors = IPS_TCP_SESSION_N_ERROR,
    .error_strings = ips_tcp_session_error_strings,
    .n_next_nodes = IPS_TCP_SESSION_N_NEXT,
    .next_nodes = {
        [IPS_TCP_SESSION_NEXT_DROP] = "error-drop",
        [IPS_TCP_SESSION_NEXT_TCP_ACL] = "ips-tcp-acl",
    },
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */