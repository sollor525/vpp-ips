/*
 * ips_response.c - VPP IPS Plugin Response Actions
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
#include <vnet/ip/ip.h>
#include <vnet/tcp/tcp.h>
#include <vnet/udp/udp.h>
#include <vnet/ethernet/ethernet.h>

#include "ips.h"
#include "common/ips_response.h"

/**
 * @brief Drop packet
 */
u32
ips_drop_packet (vlib_main_t *vm, vlib_buffer_t *b)
{
    /* Mark buffer for drop */
    b->error = VLIB_BUFFER_IS_TRACED;

    /* Return drop disposition */
    return VNET_DEVICE_INPUT_NEXT_DROP;
}

/**
 * @brief Send TCP RST packet
 */
int
ips_send_tcp_rst (vlib_main_t *vm, vlib_buffer_t *b, ips_flow_t *flow)
{
    vlib_buffer_t *rst_b;
    ethernet_header_t *eth, *rst_eth;
    ip4_header_t *ip4, *rst_ip4;
    tcp_header_t *tcp, *rst_tcp;
    u32 bi;

    if (PREDICT_FALSE (flow->key.protocol != IPS_PROTO_TCP))
        return -1;

    /* Allocate new buffer for RST packet */
    if (vlib_buffer_alloc (vm, &bi, 1) != 1)
        return -1;

    rst_b = vlib_get_buffer (vm, bi);

    /* Copy original headers */
    eth = (ethernet_header_t *) flow->l2_header;
    ip4 = (ip4_header_t *) flow->l3_header;
    tcp = (tcp_header_t *) flow->l4_header;

    /* Build RST packet */
    rst_eth = vlib_buffer_get_current (rst_b);
    clib_memcpy (rst_eth, eth, sizeof (ethernet_header_t));

    /* Swap MAC addresses */
    clib_memcpy (rst_eth->dst_address, eth->src_address, 6);
    clib_memcpy (rst_eth->src_address, eth->dst_address, 6);

    /* Build IP header */
    rst_ip4 = (ip4_header_t *) (rst_eth + 1);
    clib_memcpy (rst_ip4, ip4, sizeof (ip4_header_t));

    /* Swap IP addresses */
    rst_ip4->src_address = ip4->dst_address;
    rst_ip4->dst_address = ip4->src_address;
    rst_ip4->length = clib_host_to_net_u16 (sizeof (ip4_header_t) + sizeof (tcp_header_t));

    /* Build TCP header */
    rst_tcp = (tcp_header_t *) (rst_ip4 + 1);
    clib_memset (rst_tcp, 0, sizeof (tcp_header_t));

    /* Swap ports */
    rst_tcp->src_port = tcp->dst_port;
    rst_tcp->dst_port = tcp->src_port;

    /* Set RST flag */
    rst_tcp->flags = TCP_FLAG_RST;
    rst_tcp->data_offset_and_reserved = 5 << 4; /* 20 bytes header */

    /* Set sequence number */
    rst_tcp->seq_number = tcp->ack_number;
    rst_tcp->ack_number = clib_host_to_net_u32 (clib_net_to_host_u32 (tcp->seq_number) + 1);

    /* Set buffer length */
    rst_b->current_length = sizeof (ethernet_header_t) + sizeof (ip4_header_t) + sizeof (tcp_header_t);

    return 0;
}

/**
 * @brief Send ICMP unreachable packet
 */
int
ips_send_icmp_unreachable (vlib_main_t *vm, vlib_buffer_t *b, ips_flow_t *flow)
{
    vlib_buffer_t *icmp_b;
    ethernet_header_t *eth, *icmp_eth;
    ip4_header_t *ip4, *icmp_ip4;
    icmp46_header_t *icmp;
    u32 bi;
    u32 payload_len;

    if (PREDICT_FALSE (flow->key.is_ip6))
        return -1; /* IPv6 not implemented */

    /* Allocate new buffer for ICMP packet */
    if (vlib_buffer_alloc (vm, &bi, 1) != 1)
        return -1;

    icmp_b = vlib_get_buffer (vm, bi);

    /* Copy original headers */
    eth = (ethernet_header_t *) flow->l2_header;
    ip4 = (ip4_header_t *) flow->l3_header;

    /* Build ICMP packet */
    icmp_eth = vlib_buffer_get_current (icmp_b);
    clib_memcpy (icmp_eth, eth, sizeof (ethernet_header_t));

    /* Swap MAC addresses */
    clib_memcpy (icmp_eth->dst_address, eth->src_address, 6);
    clib_memcpy (icmp_eth->src_address, eth->dst_address, 6);

    /* Build IP header */
    icmp_ip4 = (ip4_header_t *) (icmp_eth + 1);
    clib_memset (icmp_ip4, 0, sizeof (ip4_header_t));

    icmp_ip4->ip_version_and_header_length = 0x45;
    icmp_ip4->tos = 0;
    icmp_ip4->ttl = 64;
    icmp_ip4->protocol = IP_PROTOCOL_ICMP;
    icmp_ip4->src_address = ip4->dst_address;
    icmp_ip4->dst_address = ip4->src_address;

    /* Build ICMP header */
    icmp = (icmp46_header_t *) (icmp_ip4 + 1);
    icmp->type = ICMP4_destination_unreachable;
    icmp->code = ICMP4_destination_unreachable_port_unreachable;
    icmp->checksum = 0;

    /* Copy original IP header + 8 bytes of data */
    payload_len = clib_min (flow->l3_len, 28);
    clib_memcpy (icmp + 1, ip4, payload_len);

    /* Set lengths */
    icmp_ip4->length = clib_host_to_net_u16 (sizeof (ip4_header_t) +
                                           sizeof (icmp46_header_t) + payload_len);
    icmp_b->current_length = sizeof (ethernet_header_t) +
                            sizeof (ip4_header_t) +
                            sizeof (icmp46_header_t) + payload_len;

    /* Calculate checksums */
    icmp_ip4->checksum = ip4_header_checksum (icmp_ip4);

    return 0;
}

/**
 * @brief Execute response action
 */
u32
ips_execute_response (vlib_main_t *vm, vlib_buffer_t *b, ips_flow_t *flow, ips_action_t action)
{
    switch (action)
    {
    case IPS_ACTION_DROP:
        return ips_drop_packet (vm, b);

    case IPS_ACTION_REJECT:
        if (flow->key.protocol == IPS_PROTO_TCP)
        {
            ips_send_tcp_rst (vm, b, flow);
        }
        else
        {
            ips_send_icmp_unreachable (vm, b, flow);
        }
        return ips_drop_packet (vm, b);

    case IPS_ACTION_ALERT:
        /* Alert already generated in detection engine */
        return VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;

    case IPS_ACTION_LOG:
        /* Log action - detailed logging will be handled in detection engine */
        /* The actual detailed log is generated when the rule matches in ips_generate_log_entry */
        return VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;

    case IPS_ACTION_PASS:
    default:
        return VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
    }
}

/**
 * @brief Send TCP RST response to reject connection
 */
int
ips_send_reject_response (ips_flow_t *flow, vlib_buffer_t *b)
{
    ips_main_t *im = &ips_main;
    vlib_main_t *vm = im->vlib_main;

    /* Only handle TCP for now */
    if (flow->key.protocol != IP_PROTOCOL_TCP)
    {
        return -1;
    }

    /* Get original packet headers */
    ethernet_header_t *eth0;
    ip4_header_t *ip0 = 0;
    ip6_header_t *ip6_0 = 0;
    tcp_header_t *tcp0;
    u32 tcp_offset = 0;

    eth0 = vlib_buffer_get_current (b);

    if (flow->key.is_ip6)
    {
        ip6_0 = (ip6_header_t *) (eth0 + 1);
        tcp_offset = sizeof (ethernet_header_t) + sizeof (ip6_header_t);
    }
    else
    {
        ip0 = (ip4_header_t *) (eth0 + 1);
        tcp_offset = sizeof (ethernet_header_t) + sizeof (ip4_header_t);
    }

    tcp0 = (tcp_header_t *) ((u8 *) eth0 + tcp_offset);

    /* Mark as intentionally unused - may be used for future features */
    (void)ip0;
    (void)ip6_0;

    /* Allocate new buffer for RST response */
    u32 bi;
    vlib_buffer_t *rst_b;

    if (vlib_buffer_alloc (vm, &bi, 1) != 1)
    {
        return -1;
    }

    rst_b = vlib_get_buffer (vm, bi);

    /* Copy original ethernet header and swap addresses */
    ethernet_header_t *eth_rst = vlib_buffer_get_current (rst_b);
    clib_memcpy (eth_rst, eth0, sizeof (ethernet_header_t));

    /* Swap MAC addresses */
    mac_address_t temp_mac;
    clib_memcpy (&temp_mac, eth_rst->src_address, 6);
    clib_memcpy (eth_rst->src_address, eth_rst->dst_address, 6);
    clib_memcpy (eth_rst->dst_address, &temp_mac, 6);

    if (flow->key.is_ip6)
    {
        /* IPv6 RST response */
        ip6_header_t *ip6_rst = (ip6_header_t *) (eth_rst + 1);
        tcp_header_t *tcp_rst = (tcp_header_t *) (ip6_rst + 1);

        /* Fill IPv6 header */
        clib_memset (ip6_rst, 0, sizeof (ip6_header_t));
        ip6_rst->ip_version_traffic_class_and_flow_label =
            clib_host_to_net_u32 (0x60000000);
        ip6_rst->payload_length = clib_host_to_net_u16 (sizeof (tcp_header_t));
        ip6_rst->protocol = IP_PROTOCOL_TCP;
        ip6_rst->hop_limit = 64;

        /* Swap addresses */
        clib_memcpy (&ip6_rst->src_address, &flow->key.dst_ip6,
                     sizeof (ip6_address_t));
        clib_memcpy (&ip6_rst->dst_address, &flow->key.src_ip6,
                     sizeof (ip6_address_t));

        /* Fill TCP header */
        clib_memset (tcp_rst, 0, sizeof (tcp_header_t));
        tcp_rst->src_port = clib_host_to_net_u16 (flow->key.dst_port);
        tcp_rst->dst_port = clib_host_to_net_u16 (flow->key.src_port);
        tcp_rst->flags = TCP_FLAG_RST;
        tcp_rst->window = 0;
        tcp_rst->data_offset_and_reserved =
            (sizeof (tcp_header_t) / 4) << 4;

        /* Set sequence number */
        if (tcp0->flags & TCP_FLAG_ACK)
        {
            tcp_rst->seq_number = tcp0->ack_number;
        }
        else
        {
            tcp_rst->ack_number =
                clib_host_to_net_u32 (clib_net_to_host_u32 (tcp0->seq_number) + 1);
            tcp_rst->flags |= TCP_FLAG_ACK;
        }

        /* Calculate checksum */
        tcp_rst->checksum = 0;
        tcp_rst->checksum = ip6_tcp_udp_icmp_compute_checksum (vm, rst_b,
                                                               ip6_rst, 0);

        rst_b->current_length = sizeof (ethernet_header_t) +
                               sizeof (ip6_header_t) + sizeof (tcp_header_t);
    }
    else
    {
        /* IPv4 RST response */
        ip4_header_t *ip_rst = (ip4_header_t *) (eth_rst + 1);
        tcp_header_t *tcp_rst = (tcp_header_t *) (ip_rst + 1);

        /* Fill IPv4 header */
        clib_memset (ip_rst, 0, sizeof (ip4_header_t));
        ip_rst->ip_version_and_header_length = 0x45;
        ip_rst->ttl = 64;
        ip_rst->protocol = IP_PROTOCOL_TCP;
        ip_rst->length = clib_host_to_net_u16 (sizeof (ip4_header_t) +
                                              sizeof (tcp_header_t));

        /* Swap addresses */
        ip_rst->src_address.as_u32 = flow->key.dst_ip4.as_u32;
        ip_rst->dst_address.as_u32 = flow->key.src_ip4.as_u32;

        /* Calculate IP checksum */
        ip_rst->checksum = ip4_header_checksum (ip_rst);

        /* Fill TCP header */
        clib_memset (tcp_rst, 0, sizeof (tcp_header_t));
        tcp_rst->src_port = clib_host_to_net_u16 (flow->key.dst_port);
        tcp_rst->dst_port = clib_host_to_net_u16 (flow->key.src_port);
        tcp_rst->flags = TCP_FLAG_RST;
        tcp_rst->window = 0;
        tcp_rst->data_offset_and_reserved =
            (sizeof (tcp_header_t) / 4) << 4;

        /* Set sequence number */
        if (tcp0->flags & TCP_FLAG_ACK)
        {
            tcp_rst->seq_number = tcp0->ack_number;
        }
        else
        {
            tcp_rst->ack_number =
                clib_host_to_net_u32 (clib_net_to_host_u32 (tcp0->seq_number) + 1);
            tcp_rst->flags |= TCP_FLAG_ACK;
        }

        /* Calculate TCP checksum */
        tcp_rst->checksum = 0;
        tcp_rst->checksum = ip4_tcp_udp_compute_checksum (vm, rst_b, ip_rst);

        rst_b->current_length = sizeof (ethernet_header_t) +
                               sizeof (ip4_header_t) + sizeof (tcp_header_t);
    }

    /* Set up buffer for transmission */
    vnet_buffer (rst_b)->sw_if_index[VLIB_RX] =
        vnet_buffer (b)->sw_if_index[VLIB_RX];
    vnet_buffer (rst_b)->sw_if_index[VLIB_TX] = ~0;

    /* Send the RST packet */
    vlib_frame_t *f = vlib_get_frame_to_node (vm, ethernet_input_node.index);
    u32 *to_next = vlib_frame_vector_args (f);
    to_next[0] = bi;
    f->n_vectors = 1;
    vlib_put_frame_to_node (vm, ethernet_input_node.index, f);

    return 0;
}
