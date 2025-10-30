/*
 * ips_tcp_reorder.c - VPP IPS Plugin TCP Out-of-Order Reassembly
 *
 * Complete TCP reordering implementation using VPP buffer chains
 * Based on VPP IP reassembly mechanism (ip4_full_reass_inline)
 *
 * Copyright (c) 2024 VPP IPS Project
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/tcp/tcp_packet.h>
#include <vppinfra/string.h>
#include <vppinfra/vec.h>

#include "ips.h"
#include "detection/ips_detection.h"
/* Hyperscan support */
#include <hs/hs.h>

/**
 * @brief TCP reorder return codes
 */
typedef enum
{
    IPS_TCP_REORDER_RC_OK,              /* Packet processed successfully */
    IPS_TCP_REORDER_RC_BUFFERED,        /* Packet buffered for reordering */
    IPS_TCP_REORDER_RC_ERROR,           /* Error occurred */
    IPS_TCP_REORDER_RC_NO_PAYLOAD,      /* No payload data */
    IPS_TCP_REORDER_RC_DUPLICATE,       /* Duplicate packet */
    IPS_TCP_REORDER_RC_WINDOW_FULL,     /* Reorder window full */
    IPS_TCP_REORDER_RC_COMPLETED        /* Reordering completed, ordered data available */
} ips_tcp_reorder_rc_t;

/**
 * @brief Initialize TCP reordering for a flow
 */
void
ips_tcp_reorder_init_flow (ips_flow_t *flow)
{
    if (!flow)
        return;

    flow->tcp_reorder_first_bi_src = ~0;
    flow->tcp_reorder_first_bi_dst = ~0;
    flow->tcp_next_seq_src = 0;
    flow->tcp_next_seq_dst = 0;
    flow->tcp_reorder_window_src = IPS_TCP_REORDER_WINDOW;
    flow->tcp_reorder_window_dst = IPS_TCP_REORDER_WINDOW;
    flow->tcp_reorder_data_len_src = 0;
    flow->tcp_reorder_data_len_dst = 0;
    flow->tcp_reorder_buffer_count_src = 0;
    flow->tcp_reorder_buffer_count_dst = 0;
    flow->tcp_stream_established = 0;
    flow->tcp_reorder_enabled = 1; /* Enable reordering by default */
}

/**
 * @brief Free all buffers in a TCP reorder chain
 */
static void
tcp_reorder_free_buffers (vlib_main_t *vm, u32 first_bi)
{
    u32 current_bi = first_bi;

    while (~0 != current_bi)
    {
        vlib_buffer_t *b = vlib_get_buffer (vm, current_bi);
        vnet_buffer_opaque_t *vnb = vnet_buffer (b);
        u32 next_bi = vnb->ip.reass.next_range_bi;

        vlib_buffer_free_one (vm, current_bi);
        current_bi = next_bi;
    }
}

/**
 * @brief Clean up TCP reordering state for a flow
 */
void
ips_tcp_reorder_cleanup_flow (ips_flow_t *flow)
{
    vlib_main_t *vm = vlib_get_main ();

    if (!flow)
        return;

    /* Free buffered packets for both directions */
    if (~0 != flow->tcp_reorder_first_bi_src)
    {
        tcp_reorder_free_buffers (vm, flow->tcp_reorder_first_bi_src);
        flow->tcp_reorder_first_bi_src = ~0;
    }

    if (~0 != flow->tcp_reorder_first_bi_dst)
    {
        tcp_reorder_free_buffers (vm, flow->tcp_reorder_first_bi_dst);
        flow->tcp_reorder_first_bi_dst = ~0;
    }

    flow->tcp_reorder_data_len_src = 0;
    flow->tcp_reorder_data_len_dst = 0;
    flow->tcp_reorder_buffer_count_src = 0;
    flow->tcp_reorder_buffer_count_dst = 0;
}

/**
 * @brief Compare TCP sequence numbers with wrap-around handling
 */
static inline int
tcp_seq_compare (u32 seq1, u32 seq2)
{
    return (int)(seq1 - seq2);
}

/**
 * @brief Check if sequence number is within reorder window
 */
static inline int
tcp_seq_in_window (u32 seq, u32 expected_seq, u32 window_size)
{
    return tcp_seq_compare (seq, expected_seq) >= 0 &&
           tcp_seq_compare (seq, expected_seq + window_size) < 0;
}

/**
 * @brief Get TCP payload data length in buffer
 */
static inline u16
tcp_reorder_buffer_get_data_len (vlib_buffer_t *b)
{
    vnet_buffer_opaque_t *vnb = vnet_buffer (b);
    return vnb->ip.reass.range_last - vnb->ip.reass.range_first + 1;
}

/**
 * @brief Insert TCP buffer into reorder chain (similar to IP reassembly)
 */
static ips_tcp_reorder_rc_t
tcp_reorder_insert_range_in_chain (vlib_main_t *vm, ips_flow_t *flow,
                                  u32 prev_range_bi, u32 new_bi, u8 is_src_direction)
{
    vlib_buffer_t *new_b = vlib_get_buffer (vm, new_bi);
    vnet_buffer_opaque_t *new_vnb = vnet_buffer (new_b);
    u32 *first_bi = is_src_direction ? &flow->tcp_reorder_first_bi_src :
                                      &flow->tcp_reorder_first_bi_dst;
    u32 *data_len = is_src_direction ? &flow->tcp_reorder_data_len_src :
                                      &flow->tcp_reorder_data_len_dst;
    u16 *buffer_count = is_src_direction ? &flow->tcp_reorder_buffer_count_src :
                                          &flow->tcp_reorder_buffer_count_dst;

    if (~0 == prev_range_bi)
    {
        /* Insert as first buffer */
        new_vnb->ip.reass.next_range_bi = *first_bi;
        *first_bi = new_bi;
    }
    else
    {
        /* Insert after prev_range_bi */
        vlib_buffer_t *prev_b = vlib_get_buffer (vm, prev_range_bi);
        vnet_buffer_opaque_t *prev_vnb = vnet_buffer (prev_b);

        new_vnb->ip.reass.next_range_bi = prev_vnb->ip.reass.next_range_bi;
        prev_vnb->ip.reass.next_range_bi = new_bi;
    }

    *data_len += tcp_reorder_buffer_get_data_len (new_b);
    (*buffer_count)++;

    return IPS_TCP_REORDER_RC_OK;
}



/**
 * @brief Check if TCP reordering is complete and ready to finalize
 */
static int
tcp_reorder_is_complete (ips_flow_t *flow, u8 is_src_direction)
{
    u32 *first_bi = is_src_direction ? &flow->tcp_reorder_first_bi_src :
                                      &flow->tcp_reorder_first_bi_dst;
    u32 *expected_seq = is_src_direction ? &flow->tcp_next_seq_src :
                                          &flow->tcp_next_seq_dst;

    if (~0 == *first_bi)
        return 0; /* No buffered data */

    vlib_main_t *vm = vlib_get_main ();
    vlib_buffer_t *first_b = vlib_get_buffer (vm, *first_bi);
    vnet_buffer_opaque_t *first_vnb = vnet_buffer (first_b);

    /* Check if first buffered segment starts at expected sequence */
    return (first_vnb->ip.reass.range_first == *expected_seq);
}

/**
 * @brief Finalize TCP reordering and create ordered buffer chain
 * Similar to ip4_full_reass_finalize
 */
static ips_tcp_reorder_rc_t
tcp_reorder_finalize (vlib_main_t *vm, ips_flow_t *flow, u32 *ordered_bi,
                     u32 *ordered_len, u8 is_src_direction)
{
    u32 *first_bi = is_src_direction ? &flow->tcp_reorder_first_bi_src :
                                      &flow->tcp_reorder_first_bi_dst;
    u32 *expected_seq = is_src_direction ? &flow->tcp_next_seq_src :
                                          &flow->tcp_next_seq_dst;

    if (~0 == *first_bi)
        return IPS_TCP_REORDER_RC_ERROR;

    vlib_buffer_t *first_b = vlib_get_buffer (vm, *first_bi);
    vlib_buffer_t *last_b = NULL;
    u32 sub_chain_bi = *first_bi;
    u32 total_length = 0;
    u32 consumed_ranges = 0;

    /* Build the ordered chain similar to IP reassembly */
    do
    {
        u32 tmp_bi = sub_chain_bi;
        vlib_buffer_t *tmp = vlib_get_buffer (vm, tmp_bi);
        vnet_buffer_opaque_t *vnb = vnet_buffer (tmp);

        /* Check if this range is contiguous with previous */
        if (vnb->ip.reass.range_first != *expected_seq)
            break; /* Gap found, stop here */

        u32 data_len = tcp_reorder_buffer_get_data_len (tmp);

        /* Link buffers in chain */
        if (last_b)
        {
            last_b->flags |= VLIB_BUFFER_NEXT_PRESENT;
            last_b->next_buffer = tmp_bi;
        }
        last_b = tmp;
        total_length += data_len;
        consumed_ranges++;

        /* Update expected sequence */
        *expected_seq = vnb->ip.reass.range_last + 1;

        /* Move to next range */
        sub_chain_bi = vnb->ip.reass.next_range_bi;

        /* Clear next_range_bi to avoid confusion */
        vnb->ip.reass.next_range_bi = ~0;

    } while (~0 != sub_chain_bi);

    if (!last_b || total_length == 0)
        return IPS_TCP_REORDER_RC_ERROR;

    /* Terminate the chain */
    last_b->flags &= ~VLIB_BUFFER_NEXT_PRESENT;

    /* Set up buffer chain metadata */
    first_b->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
    first_b->total_length_not_including_first_buffer =
        total_length - first_b->current_length;

    /* Update flow state - remove consumed ranges from reorder chain */
    *first_bi = sub_chain_bi; /* Remaining ranges */

    if (is_src_direction)
    {
        flow->tcp_reorder_data_len_src -= total_length;
        flow->tcp_reorder_buffer_count_src -= consumed_ranges;
    }
    else
    {
        flow->tcp_reorder_data_len_dst -= total_length;
        flow->tcp_reorder_buffer_count_dst -= consumed_ranges;
    }

    /* Use linearize to create a contiguous buffer */
    if (!vlib_buffer_chain_linearize (vm, first_b))
    {
        return IPS_TCP_REORDER_RC_ERROR;
    }

    *ordered_bi = vlib_get_buffer_index (vm, first_b);
    *ordered_len = total_length;

    return IPS_TCP_REORDER_RC_COMPLETED;
}

/**
 * @brief Handle TCP handshake state transitions
 */
static void
tcp_handle_handshake (ips_flow_t *flow, tcp_header_t *tcp, u8 is_to_server)
{
    u8 tcp_flags = tcp->flags;
    u32 seq = clib_net_to_host_u32 (tcp->seq_number);

    if (!flow->tcp_stream_established)
    {
        if (is_to_server && (tcp_flags & TCP_FLAG_SYN) && !(tcp_flags & TCP_FLAG_ACK))
        {
            /* SYN from client - initialize src sequence */
            flow->tcp_next_seq_src = seq + 1;
        }
        else if (!is_to_server && (tcp_flags & TCP_FLAG_SYN) && (tcp_flags & TCP_FLAG_ACK))
        {
            /* SYN-ACK from server - initialize dst sequence */
            flow->tcp_next_seq_dst = seq + 1;
        }
        else if (is_to_server && (tcp_flags & TCP_FLAG_ACK) && !(tcp_flags & TCP_FLAG_SYN))
        {
            /* ACK from client - handshake complete */
            flow->tcp_stream_established = 1;
        }
    }
}

/**
 * @brief Update TCP reorder state with new packet
 */
static ips_tcp_reorder_rc_t
tcp_reorder_update (vlib_main_t *vm, ips_flow_t *flow, u32 *bi,
                   u8 is_src_direction)
{
    vlib_buffer_t *b = vlib_get_buffer (vm, *bi);
    tcp_header_t *tcp = (tcp_header_t *) flow->l4_header;

    if (!tcp)
        return IPS_TCP_REORDER_RC_ERROR;

    u32 seq_number = clib_net_to_host_u32 (tcp->seq_number);
    u32 payload_len = flow->app_len;

    if (payload_len == 0)
        return IPS_TCP_REORDER_RC_NO_PAYLOAD;

    u32 fragment_first = seq_number;
    u32 fragment_last = seq_number + payload_len - 1;
    u32 *expected_seq = is_src_direction ? &flow->tcp_next_seq_src :
                                          &flow->tcp_next_seq_dst;
    u32 *first_bi = is_src_direction ? &flow->tcp_reorder_first_bi_src :
                                      &flow->tcp_reorder_first_bi_dst;
    u16 *buffer_count = is_src_direction ? &flow->tcp_reorder_buffer_count_src :
                                          &flow->tcp_reorder_buffer_count_dst;

    /* Set up buffer metadata similar to IP reassembly */
    vnet_buffer_opaque_t *vnb = vnet_buffer (b);
    vnb->ip.reass.fragment_first = fragment_first;
    vnb->ip.reass.fragment_last = fragment_last;
    vnb->ip.reass.range_first = fragment_first;
    vnb->ip.reass.range_last = fragment_last;
    vnb->ip.reass.next_range_bi = ~0;

    /* Store timestamp for expiration */
    f64 timestamp = vlib_time_now (vm);
    clib_memcpy (&vnb->ip.reass.estimated_mtu, &timestamp, sizeof(f64));

    /* Check if this is an in-order packet */
    if (seq_number == *expected_seq)
    {
        /* In-order packet - update expected sequence */
        *expected_seq += payload_len;

        /* Check if we can extract buffered consecutive packets */
        if (~0 != *first_bi && tcp_reorder_is_complete (flow, is_src_direction))
        {
            /* We have buffered consecutive data - return buffered data */
            return IPS_TCP_REORDER_RC_COMPLETED;
        }

        /* Just this packet is in order */
        return IPS_TCP_REORDER_RC_OK;
    }

    /* Out-of-order packet - check if within window */
    u32 window_size = is_src_direction ? flow->tcp_reorder_window_src :
                                        flow->tcp_reorder_window_dst;

    if (!tcp_seq_in_window (seq_number, *expected_seq, window_size))
    {
        /* Outside window - drop it */
        return IPS_TCP_REORDER_RC_ERROR;
    }

    /* Check if buffer limit reached */
    if (*buffer_count >= IPS_TCP_REORDER_MAX_BUFFERS)
    {
        return IPS_TCP_REORDER_RC_WINDOW_FULL;
    }

    /* Buffer this packet for reordering */
    if (~0 == *first_bi)
    {
        /* First buffered packet */
        tcp_reorder_insert_range_in_chain (vm, flow, ~0, *bi, is_src_direction);
    }
    else
    {
        /* Find insertion point based on sequence number */
        u32 candidate_bi = *first_bi;
        u32 prev_bi = ~0;

        while (~0 != candidate_bi)
        {
            vlib_buffer_t *candidate_b = vlib_get_buffer (vm, candidate_bi);
            vnet_buffer_opaque_t *candidate_vnb = vnet_buffer (candidate_b);

            if (fragment_first > candidate_vnb->ip.reass.range_last)
            {
                /* This fragment starts after candidate range */
                prev_bi = candidate_bi;
                candidate_bi = candidate_vnb->ip.reass.next_range_bi;
                continue;
            }

            if (fragment_last < candidate_vnb->ip.reass.range_first)
            {
                /* This fragment ends before candidate range */
                tcp_reorder_insert_range_in_chain (vm, flow, prev_bi, *bi, is_src_direction);
                break;
            }

            /* Check for overlap or duplicate */
            if (fragment_first >= candidate_vnb->ip.reass.range_first &&
                fragment_last <= candidate_vnb->ip.reass.range_last)
            {
                /* Duplicate or subset - drop it */
                return IPS_TCP_REORDER_RC_DUPLICATE;
            }

            /* Partial overlap - for simplicity, drop it */
            return IPS_TCP_REORDER_RC_DUPLICATE;
        }

        if (~0 == candidate_bi)
        {
            /* Insert at end */
            tcp_reorder_insert_range_in_chain (vm, flow, prev_bi, *bi, is_src_direction);
        }
    }

    *bi = ~0;  /* Buffer consumed */

    /* Check if reordering is now complete */
    if (tcp_reorder_is_complete (flow, is_src_direction))
    {
        return IPS_TCP_REORDER_RC_COMPLETED;
    }

    return IPS_TCP_REORDER_RC_BUFFERED;
}

/**
 * @brief Process TCP packet and handle reordering
 */
int
ips_tcp_reorder_process_packet (ips_flow_t *flow, vlib_buffer_t *b,
                               u8 **ordered_data, u32 *ordered_len)
{
    vlib_main_t *vm = vlib_get_main ();
    tcp_header_t *tcp;
    u8 tcp_flags;
    u8 is_to_server;
    f64 current_time;
    u32 bi = vlib_get_buffer_index (vm, b);

    *ordered_data = NULL;
    *ordered_len = 0;

    if (!flow || !b || !flow->tcp_reorder_enabled)
        return -1;

    if (flow->key.protocol != IP_PROTOCOL_TCP)
        return -1;

    tcp = (tcp_header_t *) flow->l4_header;
    if (!tcp)
        return -1;

    tcp_flags = tcp->flags;
    current_time = vlib_time_now (vm);

    /* Determine direction */
    is_to_server = (flow->key.src_port < flow->key.dst_port) ? 1 : 0;

    /* Handle TCP handshake */
    tcp_handle_handshake (flow, tcp, is_to_server);

    /* Handle control packets (SYN, FIN, RST) */
    if (tcp_flags & (TCP_FLAG_SYN | TCP_FLAG_FIN | TCP_FLAG_RST))
    {
        u32 seq = clib_net_to_host_u32 (tcp->seq_number);
        if (tcp_flags & TCP_FLAG_SYN)
        {
            if (is_to_server)
                flow->tcp_next_seq_src = seq + 1;
            else
                flow->tcp_next_seq_dst = seq + 1;
        }
        else if (tcp_flags & TCP_FLAG_FIN)
        {
            if (is_to_server)
                flow->tcp_next_seq_src = seq + 1;
            else
                flow->tcp_next_seq_dst = seq + 1;
        }
        return 0;  /* Control packets don't need reordering */
    }

    /* Skip packets without payload */
    if (flow->app_len == 0)
        return 0;

    /* Process the packet for reordering */
    u32 tmp_bi = bi;
    ips_tcp_reorder_rc_t rc = tcp_reorder_update (vm, flow, &tmp_bi, is_to_server);

    switch (rc)
    {
    case IPS_TCP_REORDER_RC_OK:
        /* In-order packet - can process immediately */
        *ordered_data = flow->app_header;
        *ordered_len = flow->app_len;
        return 1;

    case IPS_TCP_REORDER_RC_COMPLETED:
        /* Reordering completed - extract ordered data */
        {
            u32 ordered_bi;
            u32 total_len;
            if (tcp_reorder_finalize (vm, flow, &ordered_bi, &total_len, is_to_server)
                == IPS_TCP_REORDER_RC_COMPLETED)
            {
                vlib_buffer_t *ordered_b = vlib_get_buffer (vm, ordered_bi);
                *ordered_data = vlib_buffer_get_current (ordered_b);
                *ordered_len = total_len;

                /* Note: ordered_b will be freed by the caller or detection engine */
                return 1;
            }
            else
            {
                return -1;
            }
        }

    case IPS_TCP_REORDER_RC_BUFFERED:
        /* Packet buffered - no data to process now */
        return 0;

    case IPS_TCP_REORDER_RC_NO_PAYLOAD:
        /* No payload - nothing to do */
        return 0;

    case IPS_TCP_REORDER_RC_DUPLICATE:
    case IPS_TCP_REORDER_RC_WINDOW_FULL:
    case IPS_TCP_REORDER_RC_ERROR:
    default:
        /* Error occurred */
        return -1;
    }
}

/**
 * @brief Enhanced pattern detection with TCP reordering
 */
int
ips_detect_patterns_with_reorder (ips_flow_t *flow, vlib_buffer_t *b)
{
    u8 *ordered_data = NULL;
    u32 ordered_len = 0;
    int reorder_result;

    /* Process TCP reordering if enabled and applicable */
    if (flow->key.protocol == IP_PROTOCOL_TCP && flow->tcp_reorder_enabled)
    {
        reorder_result = ips_tcp_reorder_process_packet (flow, b, &ordered_data, &ordered_len);

        clib_warning ("DEBUG: TCP reorder result=%d, ordered_data=%p, ordered_len=%u",
                     reorder_result, ordered_data, ordered_len);

        if (reorder_result > 0 && ordered_data && ordered_len > 0)
        {
            /* We have ordered data - use it for detection (ONLY PATH) */
            clib_warning ("DEBUG: Using TCP reordered data detection path");
            return ips_detect_patterns_on_data (flow, ordered_data, ordered_len);
        }
        else if (reorder_result == 0)
        {
            /* Packet buffered or no payload - no detection needed */
            clib_warning ("DEBUG: Packet buffered or no payload, no detection");
            return 0;
        }
        else
        {
            /* Reordering failed - fall back to original detection (ONLY PATH) */
            clib_warning ("DEBUG: TCP reorder failed, using fallback detection");
            return ips_detect_patterns (flow, b);
        }
    }
    else
    {
        /* Non-TCP or reordering disabled - use original detection */
        clib_warning ("DEBUG: Non-TCP or reordering disabled, using normal detection");
        return ips_detect_patterns (flow, b);
    }
}

/**
 * @brief Local Hyperscan match callback for TCP reorder detection
 */
static int
tcp_reorder_hs_match_callback (unsigned int id, unsigned long long from,
                               unsigned long long to, unsigned int flags, void *ctx)
{
    ips_detection_context_t *det_ctx = (ips_detection_context_t *) ctx;
    ips_rule_t *rule;
    ips_main_t *im = &ips_main;

    if (PREDICT_FALSE (id >= vec_len (im->rules)))
        return 0;

    rule = &im->rules[id];
    if (PREDICT_FALSE (!rule || !(rule->flags & IPS_RULE_FLAG_ENABLED)))
        return 0;

    /* Store match information */
    det_ctx->matched_rules[det_ctx->match_count] = rule;
    det_ctx->match_offsets[det_ctx->match_count] = from;
    det_ctx->match_lengths[det_ctx->match_count] = to - from;
    det_ctx->match_count++;

    /* Check if we've reached maximum matches */
    if (det_ctx->match_count >= IPS_MAX_MATCHES_PER_PACKET)
        return 1; /* Stop scanning */

    return 0; /* Continue scanning */
}

/**
 * @brief Detect patterns on provided ordered data buffer
 */
int
ips_detect_patterns_on_data (ips_flow_t *flow, const u8 *data, u32 data_len)
{
    ips_main_t *im = &ips_main;
    ips_detection_context_t det_ctx;
    int ret = 0;

  hs_scratch_t *scratch = NULL;
    hs_error_t hs_err;

    if (PREDICT_FALSE (!im->rules_compiled))
        return 0;

    if (PREDICT_FALSE (!data || data_len == 0))
        return 0;

    /* Initialize detection context */
    clib_memset (&det_ctx, 0, sizeof (det_ctx));
    det_ctx.flow = flow;
    det_ctx.buffer = NULL; /* No specific buffer for ordered data detection */

  if (PREDICT_FALSE (!im->hs_database))
        return 0;

    /* Allocate scratch space */
    hs_err = hs_alloc_scratch (im->hs_database, &scratch);
    if (hs_err != HS_SUCCESS)
    {
        clib_warning ("Failed to allocate Hyperscan scratch space");
        return -1;
    }

    /* Open stream if not already open */
    if (!flow->hs_stream)
    {
        hs_err = hs_open_stream (im->hs_database, 0, &flow->hs_stream);
        if (hs_err != HS_SUCCESS)
        {
            clib_warning ("Failed to open Hyperscan stream: %d", hs_err);
            hs_free_scratch (scratch);
            return -1;
        }
        /* Initialize stream state */
        flow->stream_bytes_processed = 0;
        flow->stream_packet_count = 0;
    }

    /* Scan ordered data using stream mode */
    hs_err = hs_scan_stream (flow->hs_stream, (const char *) data, data_len,
                           0, scratch, tcp_reorder_hs_match_callback, &det_ctx);

    /* Update stream state */
    flow->stream_bytes_processed += data_len;
    flow->stream_packet_count++;

    if (hs_err != HS_SUCCESS && hs_err != HS_SCAN_TERMINATED)
    {
        clib_warning ("Hyperscan stream scan failed: %d", hs_err);
        ret = -1;
    }
    else
    {
        ret = det_ctx.match_count;
    }

    /* Process matches */
    for (u32 i = 0; i < det_ctx.match_count; i++)
    {
        ips_rule_t *rule = det_ctx.matched_rules[i];

        /* Basic rule matching (IP/port) - still needed */
        if (!ips_rule_match (rule, flow, NULL))
            continue;

        /* Advanced rule matching - only non-content features */
        if (!ips_match_rule_advanced_minimal (NULL, flow, rule, vlib_get_thread_index ()))
            continue;

        /* Generate alert or log based on rule action */
        if (rule->action == IPS_ACTION_LOG)
        {
            /* For LOG action, use detailed log function */
            ips_generate_log_entry (rule, flow, NULL);
        }
        else
        {
            /* For other actions, use alert function */
            ips_generate_alert (rule, flow, NULL);
        }

        /* Take action based on rule */
        switch (rule->action)
        {
        case IPS_ACTION_DROP:
            flow->detection_flags |= IPS_DETECTION_FLAG_DROP;
            break;
        case IPS_ACTION_REJECT:
            flow->detection_flags |= IPS_DETECTION_FLAG_REJECT;
            break;
        case IPS_ACTION_ALERT:
            flow->detection_flags |= IPS_DETECTION_FLAG_ALERT;
            break;
        case IPS_ACTION_LOG:
            flow->detection_flags |= IPS_DETECTION_FLAG_LOG;
            break;
        case IPS_ACTION_PASS:
        default:
            break;
        }
    }

    /* Free scratch space */
    hs_free_scratch (scratch);

    return ret;
}

/**
 * @brief Get reordering statistics for a flow
 */
void
ips_tcp_reorder_get_stats (ips_flow_t *flow, u32 *buffered_src, u32 *buffered_dst)
{
    if (!flow)
    {
        if (buffered_src) *buffered_src = 0;
        if (buffered_dst) *buffered_dst = 0;
        return;
    }

    if (buffered_src) *buffered_src = flow->tcp_reorder_buffer_count_src;
    if (buffered_dst) *buffered_dst = flow->tcp_reorder_buffer_count_dst;
}
