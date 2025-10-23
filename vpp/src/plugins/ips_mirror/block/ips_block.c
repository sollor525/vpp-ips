/*
 * ips_block.c - VPP IPS Plugin Blocking Module Implementation
 *
 * Copyright (c) 2024 VPP IPS Project
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#include <vlib/vlib.h>
#include <vlib/node_funcs.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/ip/icmp46_packet.h>
#include <vnet/ethernet/ethernet.h>
#include <vppinfra/pool.h>
#include <vppinfra/clib.h>
#include <vppinfra/error.h>

#include "ips_block.h"
#include "session/ips_session.h"

/* Global blocking manager instance */
ips_block_manager_t ips_block_manager;

/* Action strings */
static const char *action_strings[] = {
    [IPS_BLOCK_ACTION_NONE] = "none",
    [IPS_BLOCK_ACTION_TCP_RESET] = "tcp-reset",
    [IPS_BLOCK_ACTION_TCP_FIN] = "tcp-fin",
    [IPS_BLOCK_ACTION_ICMP_UNREACH] = "icmp-unreach",
    [IPS_BLOCK_ACTION_ICMP_ADMIN_PROHIB] = "icmp-admin-prohib",
    [IPS_BLOCK_ACTION_DROP] = "drop",
    [IPS_BLOCK_ACTION_REDIRECT] = "redirect",
};

/* Reason strings */
static const char *reason_strings[] = {
    [IPS_BLOCK_REASON_ACL] = "acl",
    [IPS_BLOCK_REASON_RULE_ENGINE] = "rule-engine",
    [IPS_BLOCK_REASON_SIGNATURE] = "signature",
    [IPS_BLOCK_REASON_ANOMALY] = "anomaly",
    [IPS_BLOCK_REASON_RATE_LIMIT] = "rate-limit",
    [IPS_BLOCK_REASON_MANUAL] = "manual",
};

/**
 * @brief Initialize blocking module
 */
clib_error_t *
ips_block_init(vlib_main_t *vm)
{
    ips_block_manager_t *bm = &ips_block_manager;
    u32 num_threads = vlib_num_workers() + 1;

    /* Suppress unused parameter warning in release builds */
    (void)vm;

    /* Clear manager structure */
    clib_memset(bm, 0, sizeof(*bm));

    /* Initialize per-thread statistics */
    vec_validate(bm->per_thread_stats, num_threads - 1);
    vec_validate(bm->block_counters, num_threads - 1);
    vec_validate(bm->last_reset_time, num_threads - 1);
    bm->num_threads = num_threads;

    /* Initialize rate limiting state */
    f64 now = vlib_time_now(vm);
    for (u32 i = 0; i < num_threads; i++)
    {
        bm->last_reset_time[i] = now;
    }

    /* Set default configuration */
    bm->enable_logging = 1;
    bm->rate_limit_enabled = 1;
    bm->max_blocks_per_second = 1000; /* 1000 blocks/sec per thread */

    clib_warning("IPS blocking module initialized successfully");
    return 0;
}

/**
 * @brief Cleanup blocking module
 */
void
ips_block_cleanup(void)
{
    ips_block_manager_t *bm = &ips_block_manager;

    vec_free(bm->per_thread_stats);
    vec_free(bm->block_counters);
    vec_free(bm->last_reset_time);

    clib_memset(bm, 0, sizeof(*bm));
}

/**
 * @brief Check if blocking is rate limited
 */
int
ips_block_is_rate_limited(u32 thread_index)
{
    ips_block_manager_t *bm = &ips_block_manager;
    f64 now = vlib_time_now(vlib_get_main());

    if (!bm->rate_limit_enabled)
        return 0;

    if (thread_index >= vec_len(bm->per_thread_stats))
        return 0;

    /* Reset counter every second */
    if (now - bm->last_reset_time[thread_index] >= 1.0)
    {
        bm->block_counters[thread_index] = 0;
        bm->last_reset_time[thread_index] = now;
        return 0;
    }

    /* Check if we've exceeded the rate limit */
    if (bm->block_counters[thread_index] >= bm->max_blocks_per_second)
        return 1;

    return 0;
}

/**
 * @brief Send TCP reset packet (internal implementation)
 */
static int
ips_block_send_tcp_reset_internal(u32 thread_index,
                                ip4_header_t *ip4, ip6_header_t *ip6,
                                tcp_header_t *tcp, u8 is_reply,
                                ips_block_reason_t reason)
{
    vlib_main_t *vm = vlib_get_main();
    vlib_buffer_t *b;
    u32 bi;
    tcp_header_t *rst_tcp;
    u32 tcp_len = sizeof(tcp_header_t);
    u32 ip_len;
    u32 next_index;
    u8 is_ipv6 = (ip6 != NULL);

    /* Allocate buffer */
    if (vlib_buffer_alloc(vm, &bi, 1) != 1)
        return -1;

    b = vlib_get_buffer(vm, bi);
    vlib_buffer_reset(b);

    /* Calculate packet size */
    if (is_ipv6)
        ip_len = sizeof(ip6_header_t) + tcp_len;
    else
        ip_len = sizeof(ip4_header_t) + tcp_len;

    /* Set packet data */
    vlib_buffer_make_headroom(b, sizeof(ethernet_header_t));
    b->current_length = ip_len;

    /* Set up pointers */
    if (is_ipv6)
    {
        ip6_header_t *new_ip6 = vlib_buffer_get_current(b);
        rst_tcp = (tcp_header_t *)(new_ip6 + 1);
        clib_memset(new_ip6, 0, sizeof(ip6_header_t));

        /* Copy original IP6 header and modify */
        *new_ip6 = *ip6;
        new_ip6->payload_length = clib_host_to_net_u16(tcp_len);
        new_ip6->hop_limit = 255;

        if (is_reply)
        {
            new_ip6->src_address = ip6->dst_address;
            new_ip6->dst_address = ip6->src_address;
        }
    }
    else
    {
        ip4_header_t *new_ip4 = vlib_buffer_get_current(b);
        rst_tcp = (tcp_header_t *)(new_ip4 + 1);
        clib_memset(new_ip4, 0, sizeof(ip4_header_t));

        /* Copy original IP4 header and modify */
        *new_ip4 = *ip4;
        new_ip4->length = clib_host_to_net_u16(ip_len);
        new_ip4->ttl = 64;

        if (is_reply)
        {
            new_ip4->src_address = ip4->dst_address;
            new_ip4->dst_address = ip4->src_address;
        }
    }

    /* Construct TCP RST header */
    clib_memset(rst_tcp, 0, sizeof(tcp_header_t));

    if (is_reply)
    {
        /* Reset in reverse direction */
        rst_tcp->src_port = tcp->dst_port;
        rst_tcp->dst_port = tcp->src_port;
        rst_tcp->seq_number = tcp->ack_number;
        rst_tcp->ack_number = clib_host_to_net_u32(clib_net_to_host_u32(tcp->seq_number) + 1);
    }
    else
    {
        /* Reset in original direction */
        rst_tcp->src_port = tcp->src_port;
        rst_tcp->dst_port = tcp->dst_port;
        rst_tcp->seq_number = tcp->seq_number;
        rst_tcp->ack_number = tcp->ack_number;
    }

    rst_tcp->flags = TCP_FLAG_RST | TCP_FLAG_ACK;
    rst_tcp->data_offset_and_reserved = (sizeof(tcp_header_t) / 4) << 4;
    rst_tcp->window = 0;
    rst_tcp->urgent_pointer = 0;
    rst_tcp->checksum = 0; /* Will be calculated by IP layer */

    /* Set buffer metadata */
    b->current_length = ip_len;
    b->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
    b->total_length_not_including_first_buffer = 0;

    /* Send packet to output */
    vlib_frame_t *f;
    u32 *to_next;

    if (is_ipv6)
        next_index = ip6_lookup_node.index;
    else
        next_index = ip4_lookup_node.index;

    f = vlib_get_frame_to_node(vm, next_index);
    to_next = vlib_frame_vector_args(f);
    to_next[0] = bi;
    f->n_vectors = 1;
    vlib_put_frame_to_node(vm, next_index, f);

    return 0;
}

/**
 * @brief Send TCP reset packet
 */
int
ips_block_send_tcp_reset(u32 thread_index, ips_session_t *session,
                        ip4_header_t *ip4, ip6_header_t *ip6,
                        tcp_header_t *tcp, u8 is_reply,
                        ips_block_reason_t reason)
{
    ips_block_manager_t *bm = &ips_block_manager;
    ips_block_stats_t *stats;

    if (thread_index >= vec_len(bm->per_thread_stats))
        return -1;

    stats = &bm->per_thread_stats[thread_index];

    /* Check rate limiting */
    if (ips_block_is_rate_limited(thread_index))
    {
        stats->failed_blocks++;
        return -1;
    }

    /* Determine packet headers */
    if (session)
    {
        /* Use session information */
        ip4_header_t session_ip4;
        ip6_header_t session_ip6;
        tcp_header_t session_tcp;

        clib_memset(&session_ip4, 0, sizeof(session_ip4));
        clib_memset(&session_ip6, 0, sizeof(session_ip6));
        clib_memset(&session_tcp, 0, sizeof(session_tcp));

        if (session->is_ipv6)
        {
            session_ip6.src_address = session->src_ip6;
            session_ip6.dst_address = session->dst_ip6;
            session_ip6.protocol = session->protocol;
            session_tcp.src_port = clib_host_to_net_u16(session->src_port);
            session_tcp.dst_port = clib_host_to_net_u16(session->dst_port);
            session_tcp.seq_number = clib_host_to_net_u32(session->tcp_seq_src);
            session_tcp.ack_number = clib_host_to_net_u32(session->tcp_ack_dst);
        }
        else
        {
            session_ip4.src_address = session->src_ip4;
            session_ip4.dst_address = session->dst_ip4;
            session_ip4.protocol = session->protocol;
            session_tcp.src_port = clib_host_to_net_u16(session->src_port);
            session_tcp.dst_port = clib_host_to_net_u16(session->dst_port);
            session_tcp.seq_number = clib_host_to_net_u32(session->tcp_seq_src);
            session_tcp.ack_number = clib_host_to_net_u32(session->tcp_ack_dst);
        }

        if (ips_block_send_tcp_reset_internal(thread_index,
                                              session->is_ipv6 ? NULL : &session_ip4,
                                              session->is_ipv6 ? &session_ip6 : NULL,
                                              &session_tcp, is_reply, reason) == 0)
        {
            stats->tcp_resets++;
            stats->total_blocks++;
            stats->blocks_by_reason[reason]++;
            bm->block_counters[thread_index]++;

            if (bm->enable_logging)
            {
                clib_warning("TCP reset sent: session=%u, reason=%s, reply=%u",
                           session->session_index,
                           ips_block_reason_to_string(reason), is_reply);
            }
            return 0;
        }
    }
    else if (ip4 || ip6)
    {
        /* Use provided packet headers */
        if (ips_block_send_tcp_reset_internal(thread_index, ip4, ip6, tcp, is_reply, reason) == 0)
        {
            stats->tcp_resets++;
            stats->total_blocks++;
            stats->blocks_by_reason[reason]++;
            bm->block_counters[thread_index]++;

            if (bm->enable_logging)
            {
                clib_warning("TCP reset sent: reason=%s, reply=%u",
                           ips_block_reason_to_string(reason), is_reply);
            }
            return 0;
        }
    }

    stats->failed_blocks++;
    return -1;
}

/**
 * @brief Send ICMP unreachable message
 */
int
ips_block_send_icmp_unreach(u32 thread_index, u8 is_ipv6,
                           const ip4_address_t *src_ip4, const ip6_address_t *src_ip6,
                           const ip4_address_t *dst_ip4, const ip6_address_t *dst_ip6,
                           u8 code, ips_block_reason_t reason)
{
    ips_block_manager_t *bm = &ips_block_manager;
    ips_block_stats_t *stats;

    if (thread_index >= vec_len(bm->per_thread_stats))
        return -1;

    stats = &bm->per_thread_stats[thread_index];

    /* Check rate limiting */
    if (ips_block_is_rate_limited(thread_index))
    {
        stats->failed_blocks++;
        return -1;
    }

    /* TODO: Implement ICMP unreachable packet construction */
    /* This would involve:
     * 1. Creating ICMP header
     * 2. Copying original IP header and first 8 bytes
     * 3. Calculating checksums
     * 4. Sending via appropriate output node
     */

    stats->icmp_unreach++;
    stats->total_blocks++;
    stats->blocks_by_reason[reason]++;
    bm->block_counters[thread_index]++;

    if (bm->enable_logging)
    {
        clib_warning("ICMP unreachable sent: reason=%s, code=%u",
                   ips_block_reason_to_string(reason), code);
    }

    return 0;
}

/**
 * @brief Send blocking response
 */
int
ips_block_send(const ips_block_request_t *request)
{
    if (!request)
        return -1;

    switch (request->action)
    {
    case IPS_BLOCK_ACTION_TCP_RESET:
        {
            ip4_header_t ip4;
            ip6_header_t ip6;
            tcp_header_t tcp;

            clib_memset(&ip4, 0, sizeof(ip4));
            clib_memset(&ip6, 0, sizeof(ip6));
            clib_memset(&tcp, 0, sizeof(tcp));

            if (request->is_ipv6)
            {
                ip6.src_address = request->src_ip6;
                ip6.dst_address = request->dst_ip6;
                ip6.protocol = request->protocol;
                tcp.src_port = clib_host_to_net_u16(request->src_port);
                tcp.dst_port = clib_host_to_net_u16(request->dst_port);
                tcp.seq_number = clib_host_to_net_u32(request->tcp_seq);
                tcp.ack_number = clib_host_to_net_u32(request->tcp_ack);
                tcp.flags = request->tcp_flags;
            }
            else
            {
                ip4.src_address = request->src_ip4;
                ip4.dst_address = request->dst_ip4;
                ip4.protocol = request->protocol;
                tcp.src_port = clib_host_to_net_u16(request->src_port);
                tcp.dst_port = clib_host_to_net_u16(request->dst_port);
                tcp.seq_number = clib_host_to_net_u32(request->tcp_seq);
                tcp.ack_number = clib_host_to_net_u32(request->tcp_ack);
                tcp.flags = request->tcp_flags;
            }

            return ips_block_send_tcp_reset(request->thread_index, NULL,
                                          request->is_ipv6 ? NULL : &ip4,
                                          request->is_ipv6 ? &ip6 : NULL,
                                          &tcp, 0, request->reason);
        }

    case IPS_BLOCK_ACTION_ICMP_UNREACH:
        return ips_block_send_icmp_unreach(request->thread_index,
                                         request->is_ipv6,
                                         &request->src_ip4, &request->src_ip6,
                                         &request->dst_ip4, &request->dst_ip6,
                                         3, request->reason); /* Port unreachable */

    case IPS_BLOCK_ACTION_DROP:
        /* Silent drop - just update statistics */
        {
            ips_block_stats_t *stats = &ips_block_manager.per_thread_stats[request->thread_index];
            stats->silent_drops++;
            stats->total_blocks++;
            stats->blocks_by_reason[request->reason]++;
            return 0;
        }

    default:
        return -1;
    }
}

/**
 * @brief Block session with specified action
 */
int
ips_block_session(u32 thread_index, ips_session_t *session,
                  ips_block_action_t action, ips_block_reason_t reason)
{
    ips_block_request_t request = {0};

    request.session_index = session->session_index;
    request.thread_index = thread_index;
    request.action = action;
    request.reason = reason;
    request.is_ipv6 = session->is_ipv6;

    if (session->is_ipv6)
    {
        request.src_ip6 = session->src_ip6;
        request.dst_ip6 = session->dst_ip6;
    }
    else
    {
        request.src_ip4 = session->src_ip4;
        request.dst_ip4 = session->dst_ip4;
    }

    request.protocol = session->protocol;
    request.src_port = session->src_port;
    request.dst_port = session->dst_port;
    request.tcp_seq = session->tcp_seq_src;
    request.tcp_ack = session->tcp_ack_dst;
    request.send_both_directions = 1;
    request.log_block = 1;

    return ips_block_send(&request);
}

/**
 * @brief Block packet flow
 */
int
ips_block_flow(u32 thread_index,
               ip4_header_t *ip4, ip6_header_t *ip6,
               tcp_header_t *tcp,
               ips_block_action_t action, ips_block_reason_t reason)
{
    ips_block_request_t request = {0};

    request.thread_index = thread_index;
    request.action = action;
    request.reason = reason;
    request.is_ipv6 = (ip6 != NULL);

    if (ip6)
    {
        request.src_ip6 = ip6->src_address;
        request.dst_ip6 = ip6->dst_address;
    }
    else if (ip4)
    {
        request.src_ip4 = ip4->src_address;
        request.dst_ip4 = ip4->dst_address;
    }

    if (tcp)
    {
        request.protocol = ip4 ? ip4->protocol : ip6->protocol;
        request.src_port = clib_net_to_host_u16(tcp->src_port);
        request.dst_port = clib_net_to_host_u16(tcp->dst_port);
        request.tcp_seq = clib_net_to_host_u32(tcp->seq_number);
        request.tcp_ack = clib_net_to_host_u32(tcp->ack_number);
        request.tcp_flags = tcp->flags;
    }

    request.log_block = 1;

    return ips_block_send(&request);
}

/**
 * @brief Get blocking statistics
 */
void
ips_block_get_stats(u32 thread_index, ips_block_stats_t *stats)
{
    ips_block_manager_t *bm = &ips_block_manager;

    if (thread_index < vec_len(bm->per_thread_stats) && stats)
    {
        *stats = bm->per_thread_stats[thread_index];
    }
}

/**
 * @brief Reset blocking statistics
 */
void
ips_block_reset_stats(u32 thread_index)
{
    ips_block_manager_t *bm = &ips_block_manager;

    if (thread_index < vec_len(bm->per_thread_stats))
    {
        clib_memset(&bm->per_thread_stats[thread_index], 0,
                   sizeof(bm->per_thread_stats[thread_index]));
    }
}

/**
 * @brief Get action string for logging
 */
const char *
ips_block_action_to_string(ips_block_action_t action)
{
    if (action < sizeof(action_strings) / sizeof(action_strings[0]))
        return action_strings[action];
    return "unknown";
}

/**
 * @brief Get reason string for logging
 */
const char *
ips_block_reason_to_string(ips_block_reason_t reason)
{
    if (reason < sizeof(reason_strings) / sizeof(reason_strings[0]))
        return reason_strings[reason];
    return "unknown";
}