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
#include "../ips.h"

/* Blocking packet processing next nodes - simplified for mirror traffic */
typedef enum
{
    IPS_BLOCK_NEXT_DROP,
    IPS_BLOCK_N_NEXT,
} ips_block_next_t;



/* Note: Statistics now use VPP's unified counter system via ips_main.counters */

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
        u32 sw_if_index = vnet_buffer(b0)->sw_if_index[VLIB_RX];
        u32 thread_index = vm->thread_index;

        /* Increment basic packet counters */
        vlib_increment_simple_counter(&ips_main.counters, thread_index, IPS_COUNTER_BLOCK_PACKETS_IN, 1);
        /* Note: Bytes counted in input node */
        vlib_increment_simple_counter(&ips_main.counters, thread_index, IPS_COUNTER_BLOCK_SENT, 1);

        /* Get packet headers - buffer current pointer is at IP header (not Ethernet) */
        ip4_header_t *ip4h = NULL;
        ip6_header_t *ip6h = NULL;
        tcp_header_t *tcph = NULL;
        u8 *dst_mac = NULL;  /* Will get from Ethernet header if available */
        
        /* Current pointer should be at IP header */
        u8 *ip_start = vlib_buffer_get_current (b0);

        /* Determine packet type and get headers */
        if (b0->current_length >= sizeof(ip4_header_t))
        {
            ip4h = (ip4_header_t *)ip_start;
            if (ip4h->ip_version_and_header_length == 0x45) /* IPv4 */
            {
                if (b0->current_length >= sizeof(ip4_header_t) + sizeof(tcp_header_t) &&
                    ip4h->protocol == IP_PROTOCOL_TCP)
                {
                    u32 ip_header_len = (ip4h->ip_version_and_header_length & 0x0f) * 4;
                    tcph = (tcp_header_t *) ((u8 *) ip4h + ip_header_len);
                }
            }
            else if ((ip4h->ip_version_and_header_length & 0xf0) == 0x60) /* IPv6 */
            {
                ip6h = (ip6_header_t *) ip4h;
                ip4h = NULL;  /* Clear ip4h */
                if (b0->current_length >= sizeof(ip6_header_t) + sizeof(tcp_header_t) &&
                    ip6h->protocol == IP_PROTOCOL_TCP)
                {
                    tcph = (tcp_header_t *) ((u8 *) ip6h + sizeof (ip6_header_t));
                }
            }
        }
        
        /* Try to get destination MAC from Ethernet header if present
         * Ethernet header is at data start (before current pointer) */
        if (b0->current_data >= sizeof(ethernet_header_t))
        {
            ethernet_header_t *eth = (ethernet_header_t *)(((u8 *)b0->data) + b0->current_data - sizeof(ethernet_header_t));
            dst_mac = eth->src_address;
        }
        else
        {
            /* No Ethernet header available, use broadcast */
            static u8 broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
            dst_mac = broadcast_mac;
        }

        /* Process blocking action - send TCP reset directly out the interface */
        if (tcph && (ip4h || ip6h))
        {
            /* Get configured TX interface (or use RX if not configured) */
            extern ips_block_manager_t ips_block_manager;
            u32 tx_sw_if_index = ips_block_manager.use_rx_interface ? 
                                sw_if_index : ips_block_manager.block_tx_sw_if_index;
            
            /* Send reset packet:
             * - TX interface: configured or RX interface
             * - Source MAC: will be automatically set to TX interface's MAC
             * - Dest MAC: original packet's source MAC
             */
            if (ips_block_send_tcp_reset(thread_index, tx_sw_if_index,
                                        NULL, dst_mac,  /* src_mac is ignored, dst_mac from original */
                                        NULL, ip4h, ip6h, tcph,
                                        0, /* is_reply */
                                        IPS_BLOCK_REASON_ACL) == 0)
            {
                vlib_increment_simple_counter(&ips_main.counters, thread_index, IPS_COUNTER_BLOCK_TCP_RESETS_SENT, 1);
            }
            else
            {
                vlib_increment_simple_counter(&ips_main.counters, thread_index, IPS_COUNTER_BLOCK_ERRORS, 1);
            }
        }
        else
        {
            /* Not a TCP packet, just drop */
            vlib_increment_simple_counter(&ips_main.counters, thread_index, IPS_COUNTER_BLOCK_NON_TCP_DROPPED, 1);
        }

        /* Always drop the original packet after processing */
        vlib_buffer_free (vm, &bi0, 1);

        from += 1;
        n_left_from -= 1;
    }

    return frame->n_vectors;
}

VLIB_REGISTER_NODE (ips_block_node) = {
    .function = ips_block_node_fn,
    .name = "ips-block-node",
    .vector_size = sizeof (u32),
    .type = VLIB_NODE_TYPE_INTERNAL,
    .n_next_nodes = IPS_BLOCK_N_NEXT,
    .next_nodes = {
        [IPS_BLOCK_NEXT_DROP] = "error-drop",
    },
    
};

/*
 * Note: Statistics functions removed - now using VPP's unified counter system
 * Use vlib_get_simple_counter(&ips_main.counters[thread_index], counter_index)
 * to access specific counter values
 */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */