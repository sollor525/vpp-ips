/*
 * ips_block_node.c - VPP IPS Plugin Blocking Node Implementation
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
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>
#include <vnet/tcp/tcp_packet.h>
#include <vppinfra/pool.h>
#include <vppinfra/clib.h>
#include <vppinfra/error.h>

#include "ips_block.h"

/* Blocking packet processing next nodes */
typedef enum
{
    IPS_BLOCK_NEXT_DROP,
    IPS_BLOCK_NEXT_IP4_LOOKUP,
    IPS_BLOCK_NEXT_IP6_LOOKUP,
    IPS_BLOCK_N_NEXT,
} ips_block_next_t;



/* Per-thread blocking node statistics */
static ips_block_node_stats_t *block_node_stats;

/**
 * @brief Create TCP reset packet using public API
 */
static int
create_tcp_reset_packet (vlib_main_t * vm, vlib_buffer_t * __clib_unused b,
                        ip4_header_t *ip4, ip6_header_t *ip6,
                        tcp_header_t *tcp)
{
    /* Use public blocking module API */
    if (ip4)
    {
        return ips_block_send_tcp_reset (vm->thread_index, NULL, ip4, NULL, tcp, 1, IPS_BLOCK_REASON_ACL);
    }
    else if (ip6)
    {
        return ips_block_send_tcp_reset (vm->thread_index, NULL, NULL, ip6, tcp, 1, IPS_BLOCK_REASON_ACL);
    }

    return -1;
}

/**
 * @brief Main blocking node function - simplified version
 */
static uword
ips_block_node_fn (vlib_main_t * vm,
                  vlib_node_runtime_t * __clib_unused node,
                  vlib_frame_t * frame)
{
    u32 n_left_from, *from;

    from = vlib_frame_vector_args (frame);
    n_left_from = frame->n_vectors;

    while (n_left_from > 0)
    {
        u32 bi0 = from[0];
        vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);

        /* Get packet headers */
        ip4_header_t *ip4h = NULL;
        ip6_header_t *ip6h = NULL;
        tcp_header_t *tcph = NULL;

        /* Determine packet type and get headers */
        if (b0->current_length >= sizeof (ip4_header_t))
        {
            ip4h = vlib_buffer_get_current (b0);
            if (ip4h->ip_version_and_header_length == 0x45) /* IPv4 */
            {
                if (b0->current_length >= sizeof (ip4_header_t) + sizeof (tcp_header_t) &&
                    ip4h->protocol == IP_PROTOCOL_TCP)
                {
                    tcph = (tcp_header_t *) ((u8 *) ip4h + sizeof (ip4_header_t));
                }
            }
            else if ((ip4h->ip_version_and_header_length & 0xf0) == 0x60) /* IPv6 */
            {
                ip6h = (ip6_header_t *) ip4h;
                if (b0->current_length >= sizeof (ip6_header_t) + sizeof (tcp_header_t) &&
                    ip6h->protocol == IP_PROTOCOL_TCP)
                {
                    tcph = (tcp_header_t *) ((u8 *) ip6h + sizeof (ip6_header_t));
                }
            }
        }

        /* Process blocking action - create TCP reset */
        if (tcph && (ip4h || ip6h))
        {
            if (create_tcp_reset_packet (vm, b0, ip4h, ip6h, tcph) == 0)
            {
                block_node_stats[vm->thread_index].tcp_resets_sent++;
            }
            else
            {
                block_node_stats[vm->thread_index].failed_blocks++;
            }
        }
        else
        {
            /* Not a TCP packet, just drop */
            block_node_stats[vm->thread_index].silent_drops++;
        }

        block_node_stats[vm->thread_index].packets_processed++;

        /* Always drop the original packet after processing */
        vlib_buffer_free (vm, &bi0, 1);

        from += 1;
        n_left_from -= 1;
    }

    return frame->n_vectors;
}

/**
 * @brief Initialize blocking node
 */
static clib_error_t *
ips_block_node_init (vlib_main_t * vm)
{
    /* Initialize per-thread statistics */
    u32 num_threads = vlib_num_workers () + 1;
    vec_validate (block_node_stats, num_threads - 1);
    clib_memset (block_node_stats, 0, sizeof (ips_block_node_stats_t) * num_threads);

    return 0;
}

VLIB_REGISTER_NODE (ips_block_node) = {
    .function = ips_block_node_fn,
    .name = "ips-block-node",
    .vector_size = sizeof (u32),
    .type = VLIB_NODE_TYPE_INTERNAL,
    .n_next_nodes = IPS_BLOCK_N_NEXT,
    .next_nodes = {
        [IPS_BLOCK_NEXT_DROP] = "error-drop",
        [IPS_BLOCK_NEXT_IP4_LOOKUP] = "ip4-lookup",
        [IPS_BLOCK_NEXT_IP6_LOOKUP] = "ip6-lookup",
    },
};

VLIB_INIT_FUNCTION (ips_block_node_init);

/**
 * @brief Get blocking node statistics
 */
void
ips_block_node_get_stats (u32 thread_index, ips_block_node_stats_t *stats)
{
    if (thread_index >= vec_len (block_node_stats) || !stats)
        return;

    *stats = block_node_stats[thread_index];
}

/**
 * @brief Reset blocking node statistics
 */
void
ips_block_node_reset_stats (u32 thread_index)
{
    if (thread_index >= vec_len (block_node_stats))
        return;

    clib_memset (&block_node_stats[thread_index], 0, sizeof (ips_block_node_stats_t));
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */