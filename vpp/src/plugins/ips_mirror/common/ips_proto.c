/*
 * ips_proto.c - VPP IPS Plugin Protocol Parsing
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
#include <vnet/ip/ip.h>
#include <vnet/tcp/tcp.h>
#include <vnet/udp/udp.h>

#include "ips.h"
#include "common/ips_proto.h"

/**
 * @brief Parse Ethernet header
 */
int
ips_parse_ethernet (vlib_buffer_t * b, ips_flow_t * flow)
{
    ethernet_header_t *eth;
    u16 ethertype;

    if (PREDICT_FALSE (!b || !flow))
        return -1;

    eth = vlib_buffer_get_current (b);
    flow->l2_header = (u8 *) eth;
    flow->l2_len = sizeof (ethernet_header_t);

    ethertype = clib_net_to_host_u16 (eth->type);
    flow->l3_header = (u8 *) (eth + 1);

    /* Parse L3 protocol */
    switch (ethertype)
    {
    case ETHERNET_TYPE_IP4:
        return ips_parse_ip4 (b, flow);
    case ETHERNET_TYPE_IP6:
        return ips_parse_ip6 (b, flow);
    default:
        return -1;
    }
}

/**
 * @brief Parse IPv4 header
 */
int
ips_parse_ip4 (vlib_buffer_t * b, ips_flow_t * flow)
{
    ip4_header_t *ip4;
    u8 protocol;
    u16 ip_len;

    if (PREDICT_FALSE (!flow->l3_header))
        return -1;

    ip4 = (ip4_header_t *) flow->l3_header;

    /* Validate IPv4 header */
    if (ip4->ip_version_and_header_length >> 4 != 4)
        return -1;

    ip_len = ip4_header_bytes (ip4);
    flow->l3_len = clib_net_to_host_u16 (ip4->length);
    protocol = ip4->protocol;

    /* Update flow key */
    flow->key.src_ip4 = ip4->src_address;
    flow->key.dst_ip4 = ip4->dst_address;
    flow->key.protocol = protocol;
    flow->key.is_ip6 = 0;

    /* Set L4 header pointer */
    flow->l4_header = flow->l3_header + ip_len;

    /* Parse L4 protocol */
    switch (protocol)
    {
    case IP_PROTOCOL_TCP:
        return ips_parse_tcp (b, flow);
    case IP_PROTOCOL_UDP:
        return ips_parse_udp (b, flow);
    case IP_PROTOCOL_ICMP:
        return ips_parse_icmp (b, flow);
    default:
        flow->l4_len = flow->l3_len - ip_len;
        return 0;
    }
}

/**
 * @brief Parse IPv6 header
 */
int
ips_parse_ip6 (vlib_buffer_t * b, ips_flow_t * flow)
{
    ip6_header_t *ip6;
    u8 protocol;
    u16 payload_len;

    if (PREDICT_FALSE (!flow->l3_header))
        return -1;

    ip6 = (ip6_header_t *) flow->l3_header;

    /* Validate IPv6 header */
    if ((ip6->ip_version_traffic_class_and_flow_label >> 28) != 6)
        return -1;

    payload_len = clib_net_to_host_u16 (ip6->payload_length);
    flow->l3_len = sizeof (ip6_header_t) + payload_len;
    protocol = ip6->protocol;

    /* Update flow key */
    flow->key.src_ip6 = ip6->src_address;
    flow->key.dst_ip6 = ip6->dst_address;
    flow->key.protocol = protocol;
    flow->key.is_ip6 = 1;

    /* Set L4 header pointer */
    flow->l4_header = (u8 *) (ip6 + 1);

    /* Parse L4 protocol */
    switch (protocol)
    {
    case IP_PROTOCOL_TCP:
        return ips_parse_tcp (b, flow);
    case IP_PROTOCOL_UDP:
        return ips_parse_udp (b, flow);
    case IP_PROTOCOL_ICMP6:
        return ips_parse_icmpv6 (b, flow);
    default:
        flow->l4_len = payload_len;
        return 0;
    }
}

/**
 * @brief Parse TCP header
 */
int
ips_parse_tcp (vlib_buffer_t * b, ips_flow_t * flow)
{
    tcp_header_t *tcp;
    u16 tcp_len;

    if (PREDICT_FALSE (!flow->l4_header))
        return -1;

    tcp = (tcp_header_t *) flow->l4_header;
    tcp_len = tcp_doff (tcp) * 4;
    flow->l4_len = tcp_len;

    /* Update flow key with port information */
    flow->key.src_port = clib_net_to_host_u16 (tcp->src_port);
    flow->key.dst_port = clib_net_to_host_u16 (tcp->dst_port);

    /* Set application header pointer */
    flow->app_header = flow->l4_header + tcp_len;
    flow->app_len = (flow->l3_len - (flow->l4_header - flow->l3_header)) - tcp_len;

    /* Detect application protocol */
    ips_detect_app_protocol (flow);

    return 0;
}

/**
 * @brief Parse UDP header
 */
int
ips_parse_udp (vlib_buffer_t * b, ips_flow_t * flow)
{
    udp_header_t *udp;
    u16 udp_len;

    if (PREDICT_FALSE (!flow->l4_header))
        return -1;

    udp = (udp_header_t *) flow->l4_header;
    udp_len = clib_net_to_host_u16 (udp->length);
    flow->l4_len = udp_len;

    /* Update flow key with port information */
    flow->key.src_port = clib_net_to_host_u16 (udp->src_port);
    flow->key.dst_port = clib_net_to_host_u16 (udp->dst_port);

    /* Set application header pointer */
    flow->app_header = flow->l4_header + sizeof (udp_header_t);
    flow->app_len = udp_len - sizeof (udp_header_t);

    /* Detect application protocol */
    ips_detect_app_protocol (flow);

    return 0;
}

/**
 * @brief Parse ICMP header
 */
int
ips_parse_icmp (vlib_buffer_t * b, ips_flow_t * flow)
{
    icmp46_header_t *icmp;

    if (PREDICT_FALSE (!flow->l4_header))
        return -1;

    icmp = (icmp46_header_t *) flow->l4_header;
    flow->l4_len = sizeof (icmp46_header_t);

    /* ICMP doesn't have ports, use type/code */
    flow->key.src_port = icmp->type;
    flow->key.dst_port = icmp->code;

    /* Set application header pointer */
    flow->app_header = flow->l4_header + sizeof (icmp46_header_t);
    flow->app_len = flow->l3_len - (flow->l4_header - flow->l3_header) - sizeof (icmp46_header_t);

    return 0;
}

/**
 * @brief Parse ICMPv6 header
 */
int
ips_parse_icmpv6 (vlib_buffer_t * b, ips_flow_t * flow)
{
    icmp46_header_t *icmp6;

    if (PREDICT_FALSE (!flow->l4_header))
        return -1;

    icmp6 = (icmp46_header_t *) flow->l4_header;
    flow->l4_len = sizeof (icmp46_header_t);

    /* ICMPv6 doesn't have ports, use type/code */
    flow->key.src_port = icmp6->type;
    flow->key.dst_port = icmp6->code;

    /* Set application header pointer */
    flow->app_header = flow->l4_header + sizeof (icmp46_header_t);
    flow->app_len = flow->l3_len - (flow->l4_header - flow->l3_header) - sizeof (icmp46_header_t);

    return 0;
}

/**
 * @brief Detect application protocol
 */
void
ips_detect_app_protocol (ips_flow_t * flow)
{
    u16 src_port = flow->key.src_port;
    u16 dst_port = flow->key.dst_port;

    /* Simple port-based detection */
    if (src_port == 80 || dst_port == 80)
    {
        flow->app_proto = IPS_APP_PROTO_HTTP;
    }
    else if (src_port == 443 || dst_port == 443)
    {
        flow->app_proto = IPS_APP_PROTO_HTTPS;
    }
    else if (src_port == 22 || dst_port == 22)
    {
        flow->app_proto = IPS_APP_PROTO_SSH;
    }
    else if (src_port == 21 || dst_port == 21)
    {
        flow->app_proto = IPS_APP_PROTO_FTP;
    }
    else if (src_port == 25 || dst_port == 25)
    {
        flow->app_proto = IPS_APP_PROTO_SMTP;
    }
    else if (src_port == 53 || dst_port == 53)
    {
        flow->app_proto = IPS_APP_PROTO_DNS;
    }
    else if (src_port == 23 || dst_port == 23)
    {
        flow->app_proto = IPS_APP_PROTO_TELNET;
    }
    else
    {
        flow->app_proto = IPS_APP_PROTO_UNKNOWN;
    }
}

/**
 * @brief Parse packet from IP layer (for feature arc processing)
 * This function is used when IPS is registered on ip4-unicast/ip6-unicast
 */
int
ips_parse_from_ip_layer (vlib_buffer_t * b, ips_flow_t * flow, int is_ip6)
{
    if (PREDICT_FALSE (!b || !flow))
        return -1;

    /* Set L3 header to current buffer position (IP header) */
    flow->l3_header = vlib_buffer_get_current (b);

    /* Parse based on IP version */
    if (is_ip6)
    {
        return ips_parse_ip6 (b, flow);
    }
    else
    {
        return ips_parse_ip4 (b, flow);
    }
}

/**
 * @brief Parse encapsulation headers (VLAN, MPLS, etc.)
 * This function is used when IPS is registered on ethernet-input
 */
int
ips_parse_encapsulation (vlib_buffer_t * b, ips_flow_t * flow)
{
    ethernet_header_t *eth;
    u16 ethertype;
    u8 *current_header;

    if (PREDICT_FALSE (!b || !flow))
        return -1;

    eth = vlib_buffer_get_current (b);
    ethertype = clib_net_to_host_u16 (eth->type);
    current_header = (u8 *) (eth + 1);

    /* Set L2 header information */
    flow->l2_header = (u8 *) eth;
    flow->l2_len = sizeof (ethernet_header_t);
    flow->encap_type = IPS_ENCAP_NONE;

    /* Handle VLAN tags */
    while (ethertype == ETHERNET_TYPE_VLAN)
    {
        ethernet_vlan_header_t *vlan = (ethernet_vlan_header_t *) current_header;

        /* Extract VLAN ID */
        if (flow->encap_type == IPS_ENCAP_NONE)
        {
            flow->encap_type = IPS_ENCAP_VLAN;
            flow->vlan_id[0] = clib_net_to_host_u16 (vlan->priority_cfi_and_id) & 0xfff;
        }
        else if (flow->encap_type == IPS_ENCAP_VLAN)
        {
            flow->encap_type = IPS_ENCAP_DOUBLE_VLAN;
            flow->vlan_id[1] = clib_net_to_host_u16 (vlan->priority_cfi_and_id) & 0xfff;
        }

        ethertype = clib_net_to_host_u16 (vlan->type);
        current_header += sizeof (ethernet_vlan_header_t);
        flow->l2_len += sizeof (ethernet_vlan_header_t);
    }

    /* Update L3 header pointer after stripping encapsulation */
    flow->l3_header = current_header;

    /* Continue with L3 parsing */
    switch (ethertype)
    {
    case ETHERNET_TYPE_IP4:
        return ips_parse_ip4 (b, flow);
    case ETHERNET_TYPE_IP6:
        return ips_parse_ip6 (b, flow);
    case ETHERNET_TYPE_MPLS:
        /* MPLS parsing would go here */
        flow->encap_type = IPS_ENCAP_MPLS;
        return -1; /* Not implemented yet */
    default:
        return -1;
    }
}
