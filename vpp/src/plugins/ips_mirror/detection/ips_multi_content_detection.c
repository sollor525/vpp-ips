/*
 * Copyright (c) 2023 VPP IPS Multi-Content Detection Engine
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <ctype.h>
#include "ips.h"

/**
 * @brief Check if single content pattern matches in data
 */
static int
check_single_content_match (ips_content_t *content, const u8 *data, u32 data_len,
                           u32 *match_pos)
{
    if (!content || !content->pattern || !data || data_len == 0)
        return 0;

    u32 pattern_len = content->pattern_len;
    if (pattern_len > data_len)
        return 0;

    /* Apply offset and depth constraints */
    u32 search_start = content->offset;
    u32 search_end = data_len;

    if (content->depth > 0 && content->depth < data_len)
        search_end = content->depth;

    if (search_start >= search_end)
        return 0;

    /* Search for pattern */
    for (u32 i = search_start; i <= search_end - pattern_len; i++)
    {
        int match = 1;

        /* Compare pattern */
        for (u32 j = 0; j < pattern_len; j++)
        {
            u8 data_byte = data[i + j];
            u8 pattern_byte = content->pattern[j];

            /* Handle case insensitive matching */
            if (content->nocase)
            {
                if (isalpha (data_byte))
                    data_byte = tolower (data_byte);
                if (isalpha (pattern_byte))
                    pattern_byte = tolower (pattern_byte);
            }

            if (data_byte != pattern_byte)
            {
                match = 0;
                break;
            }
        }

        if (match)
        {
            if (match_pos)
                *match_pos = i;
            return 1;
        }
    }

    return 0;
}

/**
 * @brief Check if content pattern matches with distance/within constraints
 */
static int
check_content_match_with_constraints (ips_content_t *content, const u8 *data,
                                     u32 data_len, u32 prev_match_pos, u32 *match_pos)
{
    if (!content || !content->pattern || !data || data_len == 0)
        return 0;

    u32 pattern_len = content->pattern_len;
    if (pattern_len > data_len)
        return 0;

    /* Calculate search boundaries based on distance/within */
    u32 search_start = 0;
    u32 search_end = data_len - pattern_len;

    if (content->distance > 0)
    {
        search_start = prev_match_pos + content->distance;
        if (search_start >= data_len)
            return 0;
    }

    if (content->within > 0)
    {
        u32 within_end = prev_match_pos + content->within;
        if (within_end < search_end)
            search_end = within_end;
    }

    /* Apply offset (relative to search start) */
    search_start += content->offset;

    /* Apply depth */
    if (content->depth > 0)
    {
        u32 depth_end = search_start + content->depth;
        if (depth_end < search_end)
            search_end = depth_end;
    }

    if (search_start > search_end)
        return 0;

    /* Search for pattern in constrained area */
    for (u32 i = search_start; i <= search_end; i++)
    {
        int match = 1;

        /* Compare pattern */
        for (u32 j = 0; j < pattern_len; j++)
        {
            if (i + j >= data_len)
            {
                match = 0;
                break;
            }

            u8 data_byte = data[i + j];
            u8 pattern_byte = content->pattern[j];

            /* Handle case insensitive matching */
            if (content->nocase)
            {
                if (isalpha (data_byte))
                    data_byte = tolower (data_byte);
                if (isalpha (pattern_byte))
                    pattern_byte = tolower (pattern_byte);
            }

            if (data_byte != pattern_byte)
            {
                match = 0;
                break;
            }
        }

        if (match)
        {
            if (match_pos)
                *match_pos = i + pattern_len; /* Position after this match */
            return 1;
        }
    }

    return 0;
}

/**
 * @brief Match all content patterns in rule (multi-content support)
 */
int
ips_match_multi_content_rule (ips_rule_t *rule, const u8 *data, u32 data_len)
{
    if (!rule || !data || data_len == 0)
        return 0;

    /* If no content patterns, this is a non-content rule */
    if (rule->content_count == 0)
        return 1; /* Non-content rules match if they reach here */

    u32 last_match_pos = 0;
    u8 first_match = 1;

    /* All content patterns must match in order */
    for (u32 i = 0; i < rule->content_count; i++)
    {
        ips_content_t *content = &rule->contents[i];
        u32 match_pos = 0;
        int matched = 0;

        if (first_match)
        {
            /* First content - no distance/within constraints */
            matched = check_single_content_match (content, data, data_len, &match_pos);
            first_match = 0;
        }
        else
        {
            /* Subsequent content - apply distance/within constraints */
            matched = check_content_match_with_constraints (content, data, data_len,
                                                          last_match_pos, &match_pos);
        }

        if (!matched)
        {
            clib_warning ("DEBUG: Content #%u failed to match in rule SID:%u",
                         i + 1, rule->sid);
            return 0; /* All content must match */
        }

        last_match_pos = match_pos;
        clib_warning ("DEBUG: Content #%u matched at position %u in rule SID:%u",
                     i + 1, match_pos, rule->sid);
    }

    clib_warning ("DEBUG: All %u content patterns matched in rule SID:%u",
                 rule->content_count, rule->sid);
    return 1; /* All content patterns matched */
}

/**
 * @brief Enhanced rule matching with multi-content support
 */
int
ips_match_enhanced_rule (ips_rule_t *rule, ips_flow_t *flow, vlib_buffer_t *b)
{
    if (!rule || !flow || !b)
        return 0;

    /* Get packet data */
    u8 *data = vlib_buffer_get_current (b);
    u32 data_len = vlib_buffer_length_in_chain (vlib_get_main (), b);

    if (!data || data_len == 0)
        return 0;

    /* Basic protocol/port matching (existing logic) */
    /* ... add existing matching logic here ... */

    /* Enhanced multi-content matching */
    if (!ips_match_multi_content_rule (rule, data, data_len))
    {
        return 0; /* Content patterns didn't match */
    }

    /* If we reach here, rule matched */
    clib_warning ("Multi-content rule SID:%u MATCHED successfully with %u content patterns",
                 rule->sid, rule->content_count);

    return 1;
}

/**
 * @brief Main detection function with multi-content support
 */
int
ips_detect_multi_content_patterns (ips_flow_t *flow, vlib_buffer_t *b)
{
    ips_main_t *im = &ips_main;
    int matched_rules = 0;

    if (!flow || !b)
        return 0;

    /* Get packet data */
    u8 *data = vlib_buffer_get_current (b);
    u32 data_len = vlib_buffer_length_in_chain (vlib_get_main (), b);

    if (!data || data_len == 0)
        return 0;

    clib_warning ("DEBUG: Processing packet with %u bytes for multi-content detection", data_len);

    /* Check each rule */
    for (u32 i = 0; i < vec_len (im->rules); i++)
    {
        ips_rule_t *rule = &im->rules[i];

        if (!(rule->flags & IPS_RULE_FLAG_ENABLED))
            continue;

        /* Enhanced rule matching with multi-content support */
        if (ips_match_enhanced_rule (rule, flow, b))
        {
            matched_rules++;

            /* Generate alert */
            ips_generate_alert (rule, flow, b);

            /* Update counters */
            rule->match_count++;
            rule->alert_count++;
            rule->last_match_time = vlib_time_now (vlib_get_main ());

            clib_warning ("Multi-content rule SID:%u triggered alert (total: %llu matches, %llu alerts)",
                         rule->sid, rule->match_count, rule->alert_count);
        }
    }

    clib_warning ("DEBUG: Multi-content detection completed, %d rules matched", matched_rules);
    return matched_rules;
}

/**
 * @brief Initialize multi-content detection engine
 */
void
ips_multi_content_detection_init (void)
{
    clib_warning ("Multi-content detection engine initialized");
}
