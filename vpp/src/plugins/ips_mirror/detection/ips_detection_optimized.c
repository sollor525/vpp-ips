/*
 * ips_detection_optimized.c - VPP IPS Plugin Optimized Detection Engine
 *
 * Copyright (c) 2024 VPP IPS Project
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/string.h>
#include <vppinfra/vec.h>

#include "ips.h"
#include "detection/ips_detection.h"
/* Hyperscan temporarily disabled */
/* #include <hs/hs.h> */

/**
 * @brief Enhanced Hyperscan compilation with extended parameters
 * Integrates offset, depth, and other content-related features into compilation
 */
int
ips_rules_compile_optimized (void)
{
    ips_main_t *im = &ips_main;
    int ret = 0;
    char **patterns = NULL;
    unsigned int *flags = NULL;
    unsigned int *ids = NULL;
    hs_expr_ext_t **ext_params = NULL;
    u32 pattern_count = 0;
    u32 i;
    hs_compile_error_t *compile_err;
    hs_database_t *database;

    /* Count enabled rules with content */
    for (i = 0; i < vec_len (im->rules); i++)
    {
        ips_rule_t *rule = &im->rules[i];
        if ((rule->flags & IPS_RULE_FLAG_ENABLED) && rule->content)
            pattern_count++;
    }

    if (pattern_count == 0)
    {
        im->rules_compiled = 1;
        im->rules_dirty = 0;
        return 0;
    }

    /* Allocate arrays for Hyperscan compilation */
    vec_validate (patterns, pattern_count - 1);
    vec_validate (flags, pattern_count - 1);
    vec_validate (ids, pattern_count - 1);
    vec_validate (ext_params, pattern_count - 1);

    /* Build pattern arrays with extended parameters */
    u32 pattern_idx = 0;
    for (i = 0; i < vec_len (im->rules); i++)
    {
        ips_rule_t *rule = &im->rules[i];
        if (!(rule->flags & IPS_RULE_FLAG_ENABLED) || !rule->content)
            continue;

        patterns[pattern_idx] = (char *) rule->content;
        flags[pattern_idx] = HS_FLAG_DOTALL | HS_FLAG_SINGLEMATCH | HS_FLAG_ALLOWEMPTY;

        if (rule->flags & IPS_RULE_FLAG_NOCASE || rule->options.nocase)
            flags[pattern_idx] |= HS_FLAG_CASELESS;

        ids[pattern_idx] = i; /* Use rule index as pattern ID */

        /* Create extended parameters for advanced features */
        hs_expr_ext_t *ext = clib_mem_alloc (sizeof (hs_expr_ext_t));
        clib_memset (ext, 0, sizeof (hs_expr_ext_t));

        /* Set extended parameters based on rule options */
        /* u64 ext_flags = 0; // Unused variable */

        /* Min offset (start position) */
        if (rule->options.offset > 0)
        {
            ext->flags |= HS_EXT_FLAG_MIN_OFFSET;
            ext->min_offset = rule->options.offset;
        }

        /* Max offset (end position for depth) */
        if (rule->options.depth > 0)
        {
            ext->flags |= HS_EXT_FLAG_MAX_OFFSET;
            ext->max_offset = rule->options.offset + rule->options.depth;
        }

        /* Min length (for content length validation) */
        if (rule->content_len > 0)
        {
            ext->flags |= HS_EXT_FLAG_MIN_LENGTH;
            ext->min_length = rule->content_len;
        }

        ext_params[pattern_idx] = ext;
        pattern_idx++;
    }

    /* Compile patterns with extended parameters for streaming mode */
    hs_error_t hs_err = hs_compile_ext_multi ((const char **) patterns,
                                             flags, ids,
                                             (const hs_expr_ext_t * const *) ext_params,
                                             pattern_count,
                                             HS_MODE_STREAM, NULL,
                                             &database, &compile_err);

    if (hs_err != HS_SUCCESS)
    {
        clib_warning ("Hyperscan optimized compilation failed: %s",
                     compile_err ? compile_err->message : "Unknown error");
        if (compile_err)
            hs_free_compile_error (compile_err);
        ret = -1;
        goto cleanup;
    }

    /* Replace old database */
    if (im->hs_database)
        hs_free_database (im->hs_database);

    im->hs_database = database;
    im->rules_compiled = 1;
    im->rules_dirty = 0;

    clib_warning ("Compiled %u patterns into optimized Hyperscan database with extended parameters",
                 pattern_count);

cleanup:
    /* Free extended parameters */
    for (i = 0; i < pattern_count; i++)
    {
        if (ext_params && ext_params[i])
            clib_mem_free (ext_params[i]);
    }

    vec_free (patterns);
    vec_free (flags);
    vec_free (ids);
    vec_free (ext_params);

    return ret;
}

/**
 * @brief Stream-aware offset/depth matching callback
 * Handles cumulative stream positioning correctly
 */
static int
ips_hs_stream_match_callback (unsigned int id, unsigned long long from,
                             unsigned long long to, unsigned int flags, void *ctx)
{
    ips_detection_context_t *det_ctx = (ips_detection_context_t *) ctx;
    ips_rule_t *rule;
    ips_main_t *im = &ips_main;
    ips_flow_t *flow = det_ctx->flow;

    if (PREDICT_FALSE (id >= vec_len (im->rules)))
        return 0;

    rule = &im->rules[id];
    if (PREDICT_FALSE (!rule || !(rule->flags & IPS_RULE_FLAG_ENABLED)))
        return 0;

    /* Adjust match positions for stream accumulation */
    u64 stream_from = flow->stream_bytes_processed + from;
    u64 stream_to = flow->stream_bytes_processed + to;

    /* Validate stream-aware offset and depth */
    if (rule->options.offset > 0 && stream_from < rule->options.offset)
        return 0;

    if (rule->options.depth > 0 &&
        stream_to > (rule->options.offset + rule->options.depth))
        return 0;

    /* Distance and within validation for multi-content rules */
    if (rule->options.distance > 0 || rule->options.within > 0)
    {
        /* Check against previous matches in this flow */
        /* This requires maintaining match history in flow state */
        if (flow->last_match_position > 0)
        {
            u64 distance = stream_from - flow->last_match_position;

            if (rule->options.distance > 0 && distance < rule->options.distance)
                return 0;

            if (rule->options.within > 0 && distance > rule->options.within)
                return 0;
        }
    }

    /* Store match information */
    det_ctx->matched_rules[det_ctx->match_count] = rule;
    det_ctx->match_offsets[det_ctx->match_count] = stream_from;
    det_ctx->match_lengths[det_ctx->match_count] = stream_to - stream_from;
    det_ctx->match_count++;

    /* Update flow match state for distance/within calculations */
    flow->last_match_position = stream_to;

    /* Check if we've reached maximum matches */
    if (det_ctx->match_count >= IPS_MAX_MATCHES_PER_PACKET)
        return 1; /* Stop scanning */

    return 0; /* Continue scanning */
}

/**
 * @brief Optimized pattern detection with reduced second-phase checks
 */
int
ips_detect_patterns_optimized (ips_flow_t * flow, vlib_buffer_t * b)
{
    ips_main_t *im = &ips_main;
    ips_detection_context_t det_ctx;
    u8 *payload;
    u32 payload_len;
    int ret = 0;
    hs_scratch_t *scratch = NULL;
    hs_error_t hs_err;

    if (PREDICT_FALSE (!im->rules_compiled))
        return 0;

    if (PREDICT_FALSE (!im->hs_database))
        return 0;

    /* Initialize detection context */
    clib_memset (&det_ctx, 0, sizeof (det_ctx));
    det_ctx.flow = flow;
    det_ctx.buffer = b;

    /* Extract payload from packet */
    payload = (u8 *) vlib_buffer_get_current (b);
    payload_len = vlib_buffer_length_in_chain (vlib_get_main (), b);

    if (PREDICT_FALSE (!payload || payload_len == 0))
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

    /* Scan payload using optimized stream mode callback */
    hs_err = hs_scan_stream (flow->hs_stream, (const char *) payload, payload_len,
                           0, scratch, ips_hs_stream_match_callback, &det_ctx);

    /* Update stream state */
    flow->stream_bytes_processed += payload_len;
    flow->stream_packet_count++;

    if (hs_err != HS_SUCCESS && hs_err != HS_SCAN_TERMINATED)
    {
        clib_warning ("Hyperscan optimized stream scan failed: %d", hs_err);
        ret = -1;
    }
    else
    {
        ret = det_ctx.match_count;
    }

    /* Process matches with reduced second-phase checks */
    for (u32 i = 0; i < det_ctx.match_count; i++)
    {
        ips_rule_t *rule = det_ctx.matched_rules[i];

        /* Basic rule matching (IP/port) - still needed */
        if (!ips_rule_match (rule, flow, b))
            continue;

        /* Advanced rule matching - only non-content features */
        if (!ips_match_rule_advanced_minimal (b, flow, rule, vlib_get_thread_index ()))
            continue;

        /* Generate alert or log based on rule action */
        if (rule->action == IPS_ACTION_LOG)
        {
            /* For LOG action, use detailed log function */
            ips_generate_log_entry (rule, flow, b);
        }
        else
        {
            /* For other actions, use alert function */
            ips_generate_alert (rule, flow, b);
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
 * @brief Minimal advanced rule matching - only non-content features
 * Content-related features (offset, depth, distance, within) are handled by Hyperscan
 */

/* Function ips_match_rule_advanced_minimal is defined in ips_detection.c */
