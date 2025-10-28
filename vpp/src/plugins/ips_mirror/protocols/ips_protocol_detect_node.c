/*
 * ips_protocol_detect_node.c - IPS Protocol Detection Node
 *
 * Copyright (c) 2024 VPP IPS Project
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/tcp/tcp_packet.h>

#include "../ips.h"
#include "../session/ips_session.h"
#include "ips_protocol_detection.h"

typedef struct
{
    u32 next_index;
    u32 session_index;
    ips_alproto_t detected_protocol;
    u8 confidence;
} ips_proto_detect_trace_t;

/* Next node indices */
typedef enum
{
    IPS_PROTO_NEXT_DROP,
    IPS_PROTO_NEXT_IPS_INSPECT,  /* Send to IPS rule matching node */
    IPS_PROTO_NEXT_BLOCK,
    IPS_PROTO_NEXT_IP4_LOOKUP,
    IPS_PROTO_NEXT_IP6_LOOKUP,
    IPS_PROTO_N_NEXT,
} ips_proto_detect_next_t;

static u8 *
format_ips_proto_detect_trace (u8 *s, va_list *args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    ips_proto_detect_trace_t *t = va_arg (*args, ips_proto_detect_trace_t *);

    s = format (s, "IPS-PROTO-DETECT: session=%u protocol=%s confidence=%u next=%u",
                t->session_index,
                ips_alproto_to_string(t->detected_protocol),
                t->confidence,
                t->next_index);
    return s;
}

/**
 * @brief Build IPv4 session key
 */
static_always_inline void
build_session_key4(ips_session_key4_t *key, ip4_header_t *ip4h, tcp_header_t *tcph)
{
    clib_memset(key, 0, sizeof(*key));
    key->src_ip = ip4h->src_address;
    key->dst_ip = ip4h->dst_address;
    key->src_port = tcph->src_port;
    key->dst_port = tcph->dst_port;
    key->protocol = ip4h->protocol;
}

/**
 * @brief Build IPv6 session key
 */
static_always_inline void
build_session_key6(ips_session_key6_t *key, ip6_header_t *ip6h, tcp_header_t *tcph)
{
    clib_memset(key, 0, sizeof(*key));
    key->src_ip = ip6h->src_address;
    key->dst_ip = ip6h->dst_address;
    key->src_port = tcph->src_port;
    key->dst_port = tcph->dst_port;
    key->protocol = ip6h->protocol;
}

/**
 * @brief Extract TCP payload from buffer
 */
static_always_inline u8 *
get_tcp_payload (vlib_buffer_t *b, ip4_header_t *ip4h, ip6_header_t *ip6h,
                 tcp_header_t *tcph, u32 *payload_len)
{
    u8 *ip_end;
    u8 *tcp_data;
    u32 tcp_header_len;
    u32 ip_len;
    
    if (ip4h)
    {
        ip_len = clib_net_to_host_u16(ip4h->length);
        ip_end = (u8 *)ip4h + ip_len;
        tcp_header_len = tcp_doff(tcph) * 4;
        tcp_data = (u8 *)tcph + tcp_header_len;
        
        if (tcp_data < ip_end)
            *payload_len = ip_end - tcp_data;
        else
            *payload_len = 0;
    }
    else if (ip6h)
    {
        ip_len = clib_net_to_host_u16(ip6h->payload_length);
        tcp_header_len = tcp_doff(tcph) * 4;
        tcp_data = (u8 *)tcph + tcp_header_len;
        
        *payload_len = ip_len > tcp_header_len ? ip_len - tcp_header_len : 0;
    }
    else
    {
        *payload_len = 0;
        return NULL;
    }
    
    return tcp_data;
}

/**
 * @brief Protocol detection node function
 */
static uword
ips_protocol_detect_node_fn (vlib_main_t *vm,
                             vlib_node_runtime_t *node,
                             vlib_frame_t *frame)
{
    u32 n_left_from, *from;
    u32 thread_index = vm->thread_index;

    from = vlib_frame_vector_args (frame);
    n_left_from = frame->n_vectors;

    while (n_left_from > 0)
    {
        u32 bi0;
        vlib_buffer_t *b0;
        u32 next0 = IPS_PROTO_NEXT_IP4_LOOKUP;  /* Default: forward */
        
        bi0 = from[0];
        b0 = vlib_get_buffer (vm, bi0);
        
        /* Get packet headers - buffer is at IP header */
        u8 *ip_start = vlib_buffer_get_current (b0);
        ip4_header_t *ip4h = NULL;
        ip6_header_t *ip6h = NULL;
        tcp_header_t *tcph = NULL;
        u8 *payload = NULL;
        u32 payload_len = 0;
        u8 is_ip6 = 0;
        
        /* Determine IP version and get headers */
        if (b0->current_length >= sizeof(ip4_header_t))
        {
            ip4h = (ip4_header_t *)ip_start;
            
            if ((ip4h->ip_version_and_header_length & 0xF0) == 0x40)  /* IPv4 */
            {
                is_ip6 = 0;
                if (ip4h->protocol == IP_PROTOCOL_TCP &&
                    b0->current_length >= sizeof(ip4_header_t) + sizeof(tcp_header_t))
                {
                    u32 ip_header_len = (ip4h->ip_version_and_header_length & 0x0f) * 4;
                    tcph = (tcp_header_t *)((u8 *)ip4h + ip_header_len);
                    payload = get_tcp_payload(b0, ip4h, NULL, tcph, &payload_len);
                }
            }
            else if ((ip4h->ip_version_and_header_length & 0xF0) == 0x60)  /* IPv6 */
            {
                ip6h = (ip6_header_t *)ip4h;
                ip4h = NULL;
                is_ip6 = 1;
                
                if (ip6h->protocol == IP_PROTOCOL_TCP &&
                    b0->current_length >= sizeof(ip6_header_t) + sizeof(tcp_header_t))
                {
                    tcph = (tcp_header_t *)((u8 *)ip6h + sizeof(ip6_header_t));
                    payload = get_tcp_payload(b0, NULL, ip6h, tcph, &payload_len);
                }
            }
        }
        
        /* Get session by looking up IP/TCP headers */
        ips_session_t *session = NULL;
        if (tcph)
        {
            if (ip4h)
            {
                ips_session_key4_t key4;
                build_session_key4(&key4, ip4h, tcph);
                session = ips_session_lookup_ipv4(thread_index, &key4);
            }
            else if (ip6h)
            {
                ips_session_key6_t key6;
                build_session_key6(&key6, ip6h, tcph);
                session = ips_session_lookup_ipv6(thread_index, &key6);
            }
        }
        
        if (session && tcph && payload && payload_len > 0)
        {
            /* Detect application protocol */
            u8 direction = (tcph->flags & TCP_FLAG_SYN) ? 0 : 1;  /* Rough estimate */
            ips_alproto_t proto = ips_detect_protocol(session, b0, IP_PROTOCOL_TCP,
                                                     payload, payload_len, direction);
            
            /* If protocol detected or has enough data, send to IPS inspect node */
            if (proto != IPS_ALPROTO_UNKNOWN || payload_len >= 100)
            {
                /* Send to IPS rule matching node */
                next0 = IPS_PROTO_NEXT_IPS_INSPECT;
            }
            else
            {
                /* Protocol not yet detected, forward for now */
                /* Continue detection on next packets */
                next0 = is_ip6 ? IPS_PROTO_NEXT_IP6_LOOKUP : IPS_PROTO_NEXT_IP4_LOOKUP;
            }
            
            /* Add trace if enabled */
            if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
            {
                ips_proto_detect_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
                t->next_index = next0;
                t->session_index = session->session_index;
                ips_proto_detect_ctx_t *ctx = ips_get_proto_detect_ctx(session);
                t->detected_protocol = ctx ? ctx->detected_protocol : IPS_ALPROTO_UNKNOWN;
                t->confidence = ctx ? ctx->confidence : 0;
            }
        }
        else
        {
            /* No session or no payload - forward normally */
            next0 = is_ip6 ? IPS_PROTO_NEXT_IP6_LOOKUP : IPS_PROTO_NEXT_IP4_LOOKUP;
        }
        
        /* Enqueue packet to next node */
        vlib_set_next_frame_buffer (vm, node, next0, bi0);
        
        from += 1;
        n_left_from -= 1;
    }

    return frame->n_vectors;
}

VLIB_REGISTER_NODE (ips_protocol_detect_node) = {
    .function = ips_protocol_detect_node_fn,
    .name = "ips-protocol-detect",
    .vector_size = sizeof (u32),
    .format_trace = format_ips_proto_detect_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,
    
    .n_next_nodes = IPS_PROTO_N_NEXT,
    .next_nodes = {
        [IPS_PROTO_NEXT_DROP] = "error-drop",
        [IPS_PROTO_NEXT_IPS_INSPECT] = "ips-inspect",
        [IPS_PROTO_NEXT_BLOCK] = "ips-block-node",
        [IPS_PROTO_NEXT_IP4_LOOKUP] = "ip4-lookup",
        [IPS_PROTO_NEXT_IP6_LOOKUP] = "ip6-lookup",
    },
};

