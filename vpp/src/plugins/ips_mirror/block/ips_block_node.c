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
#include <vlib/vlib_node_funcs.h>
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>
#include <vnet/tcp/tcp_packet.h>
#include <vppinfra/pool.h>
#include <vppinfra/clib.h>
#include <vppinfra/error.h>

#include "ips_block.h"
#include "session/ips_session.h"

/* Blocking packet processing next nodes */
typedef enum
{
    IPS_BLOCK_NEXT_DROP,
    IPS_BLOCK_NEXT_IP4_LOOKUP,
    IPS_BLOCK_NEXT_IP6_LOOKUP,
    IPS_BLOCK_N_NEXT,
} ips_block_next_t;

/* Blocking node statistics */
typedef struct
{
    u64 packets_processed;
    u64 tcp_resets_sent;
    u64 icmp_unreach_sent;
    u64 silent_drops;
    u64 failed_blocks;
} ips_block_node_stats_t;

/* Per-thread blocking node statistics */
static ips_block_node_stats_t *block_node_stats;

/**
 * @brief Create TCP reset packet directly in buffer
 */
static int
create_tcp_reset_packet (vlib_main_t * vm, vlib_buffer_t * b,
                        ip4_header_t *ip4, ip6_header_t *ip6,
                        tcp_header_t *tcp)
{
    u32 tcp_header_len = sizeof (tcp_header_t);
    u32 ip_header_len;
    u32 packet_len;

    if (ip6)
    {
        ip_header_len = sizeof (ip6_header_t);
        packet_len = ip_header_len + tcp_header_len;

        /* Make sure buffer has enough space */
        if (vlib_buffer_length_in_chain (vm, b) < packet_len)
            return -1;

        /* Copy IPv6 header */
        ip6_header_t *new_ip6 = (ip6_header_t *) vlib_buffer_get_current (b);
        *new_ip6 = *ip6;
        new_ip6->payload_length = clib_host_to_net_u16 (tcp_header_len);
        new_ip6->hop_limit = 255;

        /* Create TCP header */
        tcp_header_t *new_tcp = (tcp_header_t *) ((u8 *) new_ip6 + ip_header_len);
        *new_tcp = *tcp;
        new_tcp->data_offset_and_reserved = (tcp_header_len / 4) << 4;
        new_tcp->flags = TCP_FLAG_RST;
        if (tcp->flags & TCP_FLAG_ACK)
            new_tcp->flags |= TCP_FLAG_ACK;
        new_tcp->window = clib_host_to_net_u16 (0);
        new_tcp->urgent_pointer = 0;
        new_tcp->checksum = 0;
        new_tcp->checksum = ip6_tcp_udp_checksum (vm, new_ip6);
    }
    else
    {
        ip_header_len = sizeof (ip4_header_t);
        packet_len = ip_header_len + tcp_header_len;

        /* Make sure buffer has enough space */
        if (vlib_buffer_length_in_chain (vm, b) < packet_len)
            return -1;

        /* Copy IPv4 header */
        ip4_header_t *new_ip4 = (ip4_header_t *) vlib_buffer_get_current (b);
        *new_ip4 = *ip4;
        new_ip4->total_length = clib_host_to_net_u16 (packet_len);
        new_ip4->ttl = 255;
        new_ip4->checksum = 0;
        new_ip4->checksum = ip4_header_checksum (new_ip4);

        /* Create TCP header */
        tcp_header_t *new_tcp = (tcp_header_t *) ((u8 *) new_ip4 + ip_header_len);
        *new_tcp = *tcp;
        new_tcp->data_offset_and_reserved = (tcp_header_len / 4) << 4;
        new_tcp->flags = TCP_FLAG_RST;
        if (tcp->flags & TCP_FLAG_ACK)
            new_tcp->flags |= TCP_FLAG_ACK;
        new_tcp->window = clib_host_to_net_u16 (0);
        new_tcp->urgent_pointer = 0;
        new_tcp->checksum = 0;
        new_tcp->checksum = ip4_tcp_udp_checksum (vm, new_ip4);
    }

    /* Set buffer length */
    b->current_length = packet_len;

    return 0;
}

/**
 * @brief Main blocking node function
 */
static uword
ips_block_node_fn (vlib_main_t * vm,
                  vlib_node_runtime_t * node,
                  vlib_frame_t * frame)
{
    u32 n_left_from, *from, *to_next;
    ips_block_next_t next_index;
    u32 pkts_processed = 0;

    from = vlib_frame_vector_args (frame);
    n_left_from = frame->n_vectors;
    next_index = node->cached_next_index;

    while (n_left_from > 0)
    {
        vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

        while (n_left_from > 0 && n_left_to_next > 0)
        {
            u32 bi0 = from[0];
            vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
            u32 next0 = IPS_BLOCK_NEXT_DROP;

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
                    next0 = ip6h ? IPS_BLOCK_NEXT_IP6_LOOKUP : IPS_BLOCK_NEXT_IP4_LOOKUP;
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

            /* Enqueue to next node */
            to_next[0] = bi0;
            from += 1;
            to_next += 1;
            n_left_from -= 1;
            n_left_to_next -= 1;

            vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                                           to_next, n_left_to_next,
                                           bi0, next0);
        }

        vlib_put_next_frame (vm, node, next_index, n_left_to_next);
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
    .name = "ips-block-process",
    .vector_size = sizeof (u32),
    .type = VLIB_NODE_TYPE_INTERNAL,
    .n_next_nodes = IPS_BLOCK_N_NEXT,
    .next_nodes = {
        [IPS_BLOCK_NEXT_DROP] = "error-drop",
        [IPS_BLOCK_NEXT_IP4_LOOKUP] = "ip4-lookup",
        [IPS_BLOCK_NEXT_IP6_LOOKUP] = "ip6-lookup",
    },
    .init_function = ips_block_node_init,
};

VLIB_NODE_FUNCTION_MULTIARCH (ips_block_node_fn, ips_block_node_fn)

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