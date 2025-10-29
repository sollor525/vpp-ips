/*
 * ips_detection.c - VPP IPS Plugin Detection Engine
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
#include <vppinfra/string.h>
#include <vppinfra/vec.h>
#include <vppinfra/hash.h>
#include <vppinfra/xxhash.h>
#include <arpa/inet.h>
#include <time.h>

#include "ips.h"
#include "ips_logging.h"
#include "ips_detection.h"
#include <hs/hs.h>

/* Forward declarations */
static int ips_check_non_content_rules (ips_flow_t * flow, vlib_buffer_t * b);

/**
 * @brief Hyperscan match callback function
 */
static int
ips_hs_match_callback (unsigned int id, unsigned long long from,
                       unsigned long long to, unsigned int flags, void *ctx)
{
    ips_detection_context_t *det_ctx = (ips_detection_context_t *) ctx;
    ips_rule_t *rule;
    ips_main_t *im = &ips_main;

    /* Decode rule index and content index from ID - UPDATED FOR MULTI-CONTENT AND PCRE */
    u32 rule_index = (id >> 16) & 0xFFFF;  /* High 16 bits */
    u32 content_index = id & 0xFFFF;       /* Low 16 bits */
    u8 is_pcre = (content_index & 0x8000) ? 1 : 0;  /* Bit 15 indicates PCRE pattern */

    if (PREDICT_FALSE (rule_index >= vec_len (im->rules)))
        return 0;

    rule = &im->rules[rule_index];
    if (PREDICT_FALSE (!rule || !(rule->flags & IPS_RULE_FLAG_ENABLED)))
        return 0;

    /* Handle PCRE pattern matches */
    if (is_pcre)
    {
        clib_warning ("DEBUG: PCRE pattern match: rule SID:%u matched at %llu-%llu: %s",
                     rule->sid, from, to, rule->options.pcre_pattern);
    }
    /* For multi-content rules, we need sequential matching logic */
    else if (rule->content_count > 0 && rule->contents)
    {
        clib_warning ("DEBUG: Multi-content match: rule SID:%u, content #%u matched at %llu-%llu: %s",
                     rule->sid, content_index + 1, from, to, rule->contents[content_index].pattern);

        /* TODO: Implement sequential multi-content matching logic here */
        /* For now, treat each content match independently */
    }
    else
    {
        clib_warning ("DEBUG: Legacy content match: rule SID:%u matched at %llu-%llu: %s",
                     rule->sid, from, to, rule->content);
    }

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
 * @brief Initialize detection engine
 */
clib_error_t *
ips_detection_init (ips_main_t *im)
{
    clib_error_t *error = 0;

    /* Initialize Hyperscan database */
    im->hs_database = NULL;
    im->hs_compile_error = NULL;

    /* Initialize rule compilation state */
    im->rules_compiled = 0;
    im->rules_dirty = 0;

    return error;
}

/**
 * @brief Validate individual pattern for Hyperscan compatibility
 */
static int
validate_pattern_for_hyperscan (const char *pattern)
{
    hs_database_t *test_db;
    hs_compile_error_t *compile_err;
    unsigned int flags = HS_FLAG_DOTALL | HS_FLAG_SINGLEMATCH | HS_FLAG_ALLOWEMPTY;

    /* Check for empty pattern */
    if (!pattern || strlen(pattern) == 0)
    {
        clib_warning ("Empty pattern provided, skipping");
        return -1;
    }

    /* Check for extremely long patterns (Hyperscan has limits) */
    if (strlen(pattern) > 8192)
    {
        clib_warning ("Pattern too long (%zu chars), skipping: %.50s...", strlen(pattern), pattern);
        return -1;
    }

    /* Check for patterns that are likely to cause issues */
    if (strstr(pattern, "\x00") != NULL)
    {
        clib_warning ("Pattern contains null bytes, may cause issues: %s", pattern);
        /* Don't skip, but warn - Hyperscan might handle it */
    }

    /* Test compile the pattern to check if it's supported */
    hs_error_t hs_err = hs_compile (pattern, flags, HS_MODE_STREAM, NULL,
                                   &test_db, &compile_err);

    if (hs_err != HS_SUCCESS)
    {
        if (compile_err)
        {
            /* Provide more specific error information */
            if (strstr(compile_err->message, "start anchor"))
            {
                clib_warning ("Pattern validation failed: %s - Start anchors not supported in streaming mode", pattern);
            }
            else if (strstr(compile_err->message, "end anchor"))
            {
                clib_warning ("Pattern validation failed: %s - End anchors not supported in streaming mode", pattern);
            }
            else if (strstr(compile_err->message, "lookahead") || strstr(compile_err->message, "lookbehind"))
            {
                clib_warning ("Pattern validation failed: %s - Lookahead/lookbehind not supported", pattern);
            }
            else if (strstr(compile_err->message, "backreference"))
            {
                clib_warning ("Pattern validation failed: %s - Backreferences not supported", pattern);
            }
            else
            {
                clib_warning ("Pattern validation failed: %s - %s", pattern, compile_err->message);
            }
            hs_free_compile_error (compile_err);
        }
        else
        {
            clib_warning ("Pattern validation failed: %s - Unknown Hyperscan error", pattern);
        }
        return -1;
    }

    hs_free_database (test_db);
    clib_warning ("Pattern validated successfully: %s", pattern);
    return 0;
}

/**
 * @brief Compile rules into Hyperscan database
 */
int
ips_rules_compile (void)
{
    ips_main_t *im = &ips_main;
    int ret = 0;
    char **patterns = NULL;
    unsigned int *flags = NULL;
    unsigned int *ids = NULL;
    u32 pattern_count = 0;
    u32 valid_pattern_count = 0;
    u32 i;
    hs_compile_error_t *compile_err;
    hs_database_t *database;

    /* Count enabled rules with content - UPDATED FOR MULTI-CONTENT */
    u32 total_rules = 0;
    u32 non_content_rules = 0;
    for (i = 0; i < vec_len (im->rules); i++)
    {
        ips_rule_t *rule = &im->rules[i];
        if (rule->flags & IPS_RULE_FLAG_ENABLED)
        {
            total_rules++;
            /* Count PCRE patterns */
            if (rule->options.pcre_pattern)
            {
                pattern_count++;
            }

            /* Multi-content support: count all content patterns */
            if (rule->content_count > 0 && rule->contents)
            {
                pattern_count += rule->content_count;
            }
            /* Legacy single content support */
            else if (rule->content)
            {
                pattern_count++;
            }
            else
            {
                non_content_rules++;
            }
        }
    }

    clib_warning ("Rule compilation: %u total rules (%u with content, %u without content)",
                 total_rules, pattern_count, non_content_rules);

    if (pattern_count == 0)
    {
        /* No content-based rules, but we might have non-content rules */
        if (non_content_rules > 0)
        {
            clib_warning ("No content patterns to compile, but %u non-content rules available",
                         non_content_rules);
        }
        else
        {
            clib_warning ("No rules to process");
        }
        im->rules_compiled = 1;
        im->rules_dirty = 0;
        return 0;
    }

    clib_warning ("Compiling %u patterns for Hyperscan database", pattern_count);

    /* Allocate arrays for Hyperscan compilation */
    vec_validate (patterns, pattern_count - 1);
    vec_validate (flags, pattern_count - 1);
    vec_validate (ids, pattern_count - 1);

    /* Build pattern arrays with validation - UPDATED FOR MULTI-CONTENT */
    u32 pattern_idx = 0;
    for (i = 0; i < vec_len (im->rules); i++)
    {
        ips_rule_t *rule = &im->rules[i];
        if (!(rule->flags & IPS_RULE_FLAG_ENABLED))
            continue;

        /* Process PCRE patterns first */
        if (rule->options.pcre_pattern)
        {
            u8 *hs_pattern = NULL;
            unsigned int pcre_flags = 0;
            u8 *error_msg = NULL;

            /* Convert PCRE to Hyperscan pattern */
            if (ips_convert_pcre_to_hyperscan ((char *) rule->options.pcre_pattern,
                                             &hs_pattern, &pcre_flags, &error_msg) == 0)
            {
                /* Validate converted pattern */
                if (validate_pattern_for_hyperscan ((char*)hs_pattern) == 0)
                {
                    patterns[pattern_idx] = (char*)hs_pattern;
                    flags[pattern_idx] = HS_FLAG_DOTALL | HS_FLAG_SINGLEMATCH | HS_FLAG_ALLOWEMPTY | pcre_flags;

                    /* Encode rule index with special PCRE marker */
                    ids[pattern_idx] = (i << 16) | 0x8000; /* High 16 bits: rule index, bit 15: PCRE marker */
                    pattern_idx++;
                    valid_pattern_count++;

                    clib_warning ("DEBUG: Added PCRE pattern from rule SID:%u: %s -> %s",
                                 rule->sid, rule->options.pcre_pattern, hs_pattern);
                }
                else
                {
                    clib_warning ("Converted PCRE pattern validation failed for rule SID:%u: %s",
                                 rule->sid, hs_pattern);
                    ips_free_converted_pattern ((char*)hs_pattern);
                }
            }
            else
            {
                clib_warning ("PCRE to Hyperscan conversion failed for rule SID:%u: %s (%s)",
                             rule->sid, rule->options.pcre_pattern, error_msg ? (char*)error_msg : "Unknown error");
                if (error_msg)
                    vec_free (error_msg);
            }
        }

        /* Process multi-content patterns */
        if (rule->content_count > 0 && rule->contents)
        {
            for (u32 content_idx = 0; content_idx < rule->content_count; content_idx++)
            {
                ips_content_t *content = &rule->contents[content_idx];

                /* Validate pattern before adding */
                if (validate_pattern_for_hyperscan ((char *) content->pattern) < 0)
                {
                    clib_warning ("Skipping incompatible multi-content pattern from rule SID:%u content #%u: %s",
                                 rule->sid, content_idx + 1, content->pattern);
                    continue;
                }

                patterns[pattern_idx] = (char *) content->pattern;
                flags[pattern_idx] = HS_FLAG_DOTALL | HS_FLAG_SINGLEMATCH | HS_FLAG_ALLOWEMPTY;

                if (content->nocase || rule->flags & IPS_RULE_FLAG_NOCASE)
                    flags[pattern_idx] |= HS_FLAG_CASELESS;

                /* Encode rule index and content index in ID */
                ids[pattern_idx] = (i << 16) | content_idx; /* High 16 bits: rule index, Low 16 bits: content index */
                pattern_idx++;
                valid_pattern_count++;

                clib_warning ("DEBUG: Added multi-content pattern #%u from rule SID:%u: %s",
                             content_idx + 1, rule->sid, content->pattern);
            }
        }
        /* Legacy single content support */
        else if (rule->content)
        {
            /* Validate pattern before adding */
            if (validate_pattern_for_hyperscan ((char *) rule->content) < 0)
            {
                clib_warning ("Skipping incompatible pattern from rule SID:%u: %s",
                             rule->sid, rule->content);
                continue;
            }

            patterns[pattern_idx] = (char *) rule->content;
            flags[pattern_idx] = HS_FLAG_DOTALL | HS_FLAG_SINGLEMATCH | HS_FLAG_ALLOWEMPTY;

            if (rule->flags & IPS_RULE_FLAG_NOCASE)
                flags[pattern_idx] |= HS_FLAG_CASELESS;

            /* Legacy ID encoding: rule index only */
            ids[pattern_idx] = (i << 16) | 0; /* High 16 bits: rule index, Low 16 bits: 0 for legacy */
            pattern_idx++;
            valid_pattern_count++;

            clib_warning ("DEBUG: Added legacy content pattern from rule SID:%u: %s",
                         rule->sid, rule->content);
        }
    }

    if (valid_pattern_count == 0)
    {
        clib_warning ("No valid patterns after validation, marking as compiled");
        im->rules_compiled = 1;
        im->rules_dirty = 0;
        ret = 0;
        goto cleanup;
    }

    clib_warning ("Validated %u/%u patterns for compilation",
                 valid_pattern_count, pattern_count);

    /* Compile patterns for streaming mode */
    /* TODO: Add Hyperscan extended parameters optimization for offset/depth */
    hs_error_t hs_err = hs_compile_multi ((const char **) patterns,
                                         flags, ids, valid_pattern_count,
                                         HS_MODE_STREAM, NULL,
                                         &database, &compile_err);

    if (hs_err != HS_SUCCESS)
    {
        clib_warning ("Hyperscan compilation failed: %s",
                     compile_err ? compile_err->message : "Unknown error");

        /* Print detailed error information */
        if (compile_err)
        {
            clib_warning ("Compilation error at expression: %d",
                         compile_err->expression);
            hs_free_compile_error (compile_err);
        }

        /* Try to compile individual patterns to identify problematic ones */
        clib_warning ("Attempting individual pattern compilation for debugging:");
        for (u32 j = 0; j < valid_pattern_count; j++)
        {
            hs_database_t *test_db;
            hs_compile_error_t *test_err;
            hs_error_t test_result = hs_compile (patterns[j], flags[j],
                                               HS_MODE_STREAM, NULL,
                                               &test_db, &test_err);
            if (test_result != HS_SUCCESS)
            {
                clib_warning ("Problem pattern [%u]: %s - %s",
                             j, patterns[j],
                             test_err ? test_err->message : "Unknown");
                if (test_err)
                    hs_free_compile_error (test_err);
            }
            else
            {
                hs_free_database (test_db);
            }
        }

        ret = -1;
        goto cleanup;
    }

    /* Replace old database */
    if (im->hs_database)
        hs_free_database (im->hs_database);

    im->hs_database = database;
    im->rules_compiled = 1;
    im->rules_dirty = 0;

    clib_warning ("Successfully compiled %u patterns into Hyperscan database",
                 valid_pattern_count);

cleanup:
    vec_free (patterns);
    vec_free (flags);
    vec_free (ids);

    return ret;
}

/**
 * @brief Detect patterns in packet payload using streaming mode
 */
int
ips_detect_patterns (ips_flow_t * flow, vlib_buffer_t * b)
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

    /* We can proceed even without Hyperscan database if we have non-content rules */

    /* Initialize detection context */
    clib_memset (&det_ctx, 0, sizeof (det_ctx));
    det_ctx.flow = flow;
    det_ctx.buffer = b;

    /* Process content-based rules using Hyperscan (if available) */
    if (im->hs_database)
    {
        /* Extract payload from packet */
        payload = (u8 *) vlib_buffer_get_current (b);
        payload_len = vlib_buffer_length_in_chain (vlib_get_main (), b);

        if (PREDICT_TRUE (payload && payload_len > 0))
        {
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
            }

            /* Scan payload using stream mode - lower latency */
            hs_err = hs_scan_stream (flow->hs_stream, (const char *) payload, payload_len,
                                   0, scratch, ips_hs_match_callback, &det_ctx);

            if (hs_err != HS_SUCCESS && hs_err != HS_SCAN_TERMINATED)
            {
                clib_warning ("Hyperscan stream scan failed: %d", hs_err);
                ret = -1;
            }
            else
            {
                ret = det_ctx.match_count;
            }

            /* Process Hyperscan matches */
            for (u32 i = 0; i < det_ctx.match_count; i++)
            {
                ips_rule_t *rule = det_ctx.matched_rules[i];

                /* Basic rule matching logic */
                if (!ips_rule_match (rule, flow, b))
                    continue;

                /* Advanced rule matching with enhanced features */
                if (!ips_match_rule_advanced (b, flow, rule, vlib_get_thread_index ()))
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
                    /* In mirror mode, DROP means whitelist (allow to pass) */
                    flow->detection_flags |= IPS_DETECTION_FLAG_DROP;
                    break;
                case IPS_ACTION_REJECT:
                    /* REJECT means actual blocking with RST/ICMP response */
                    flow->detection_flags |= IPS_DETECTION_FLAG_REJECT;
                    break;
                case IPS_ACTION_ALERT:
                    /* Alert only, continue processing */
                    flow->detection_flags |= IPS_DETECTION_FLAG_ALERT;
                    break;
                case IPS_ACTION_LOG:
                    /* Log only, continue processing */
                    flow->detection_flags |= IPS_DETECTION_FLAG_LOG;
                    break;
                case IPS_ACTION_PASS:
                default:
                    /* No action needed, continue processing */
                    break;
                }
            }

            /* Free scratch space */
            hs_free_scratch (scratch);
        }
    }
    else
    {
        clib_warning ("DEBUG: No Hyperscan database available, skipping content-based rules");
    }

    /* IMPORTANT: Also check non-content rules (Suricata compatibility)
     * These rules don't have content patterns and therefore are not
     * processed by Hyperscan, but should still be evaluated */
    int non_content_matches = ips_check_non_content_rules (flow, b);
    ret += non_content_matches;

    return ret;
}

/**
 * @brief Additional rule matching beyond pattern matching
 */
int
ips_rule_match (ips_rule_t * rule, ips_flow_t * flow, vlib_buffer_t * b)
{
    /* DEBUG: Log protocol comparison for debugging */
    clib_warning ("DEBUG: Rule %u protocol check: rule_proto=%u, flow_proto=%u, src_port=%u, dst_port=%u",
                 rule->sid, rule->protocol, flow->key.protocol,
                 flow->key.src_port, flow->key.dst_port);

    /* Check protocol */
    if (rule->protocol != 0 && rule->protocol != flow->key.protocol)
    {
        clib_warning ("DEBUG: Rule %u PROTOCOL MISMATCH: rule wants %u, flow has %u",
                     rule->sid, rule->protocol, flow->key.protocol);
        return 0;
    }

    /* Check source address */
    if (rule->src_addr_mask > 0)
    {
        if (flow->key.is_ip6)
        {
            ip6_address_t mask;
            ip6_preflen_to_mask (rule->src_addr_mask, &mask);
            if (!ip6_address_is_equal_masked (&flow->key.src_ip6, &rule->src_addr.ip6, &mask))
                return 0;
        }
        else
        {
            u32 mask = ~((1 << (32 - rule->src_addr_mask)) - 1);
            if ((flow->key.src_ip4.as_u32 & mask) !=
                (rule->src_addr.ip4.as_u32 & mask))
                return 0;
        }
    }

    /* Check destination address */
    if (rule->dst_addr_mask > 0)
    {
        if (flow->key.is_ip6)
        {
            ip6_address_t mask;
            ip6_preflen_to_mask (rule->dst_addr_mask, &mask);
            if (!ip6_address_is_equal_masked (&flow->key.dst_ip6, &rule->dst_addr.ip6, &mask))
                return 0;
        }
        else
        {
            u32 mask = ~((1 << (32 - rule->dst_addr_mask)) - 1);
            if ((flow->key.dst_ip4.as_u32 & mask) !=
                (rule->dst_addr.ip4.as_u32 & mask))
                return 0;
        }
    }

    /* Check source port range */
    if (rule->src_port_min > 0 || rule->src_port_max > 0)
    {
        if (flow->key.src_port < rule->src_port_min ||
            flow->key.src_port > rule->src_port_max)
            return 0;
    }

    /* Check destination port range */
    if (rule->dst_port_min > 0 || rule->dst_port_max > 0)
    {
        if (flow->key.dst_port < rule->dst_port_min ||
            flow->key.dst_port > rule->dst_port_max)
            return 0;
    }

    clib_warning ("DEBUG: Rule %u MATCHED SUCCESSFULLY: proto=%u, src=%u->%u dst=%u->%u",
                 rule->sid, rule->protocol, flow->key.src_port, rule->src_port_min,
                 flow->key.dst_port, rule->dst_port_min);
    return 1; /* Rule matches */
}

/**
 * @brief Generate detailed log entry in Suricata format
 */
static void
ips_generate_detailed_log (ips_rule_t *rule, ips_flow_t *flow, vlib_buffer_t *b,
                          const char *action_str, u8 is_alert)
{
    /* Use real system time instead of VPP relative time */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    f64 timestamp = (f64)ts.tv_sec + (f64)ts.tv_nsec / 1000000000.0;
    u32 packet_len = b ? vlib_buffer_length_in_chain (vlib_get_main (), b) : 0;

    /* Protocol name mapping */
    const char *proto_str = "Unknown";
    switch (flow->key.protocol)
    {
    case IPS_PROTO_TCP:
        proto_str = "TCP";
        break;
    case IPS_PROTO_UDP:
        proto_str = "UDP";
        break;
    case IPS_PROTO_ICMP:
        proto_str = "ICMP";
        break;
    case IPS_PROTO_ICMPV6:
        proto_str = "ICMPv6";
        break;
    default:
        proto_str = "IP";
        break;
    }

    /* Classification and priority */
    const char *classification = rule->classtype ? (char *)rule->classtype : "Unknown";
    u32 priority = rule->priority ? rule->priority : 3;

    /* Format flow information string */
    char flow_info[256];
    char src_ip_str[INET6_ADDRSTRLEN];
    char dst_ip_str[INET6_ADDRSTRLEN];

    if (flow->key.is_ip6)
    {
        /* IPv6 format */
        inet_ntop (AF_INET6, &flow->key.src_ip6, src_ip_str, sizeof(src_ip_str));
        inet_ntop (AF_INET6, &flow->key.dst_ip6, dst_ip_str, sizeof(dst_ip_str));
        snprintf (flow_info, sizeof(flow_info), "[%s]:%u -> [%s]:%u",
                 src_ip_str, flow->key.src_port, dst_ip_str, flow->key.dst_port);
    }
    else
    {
        /* IPv4 format */
        inet_ntop (AF_INET, &flow->key.src_ip4, src_ip_str, sizeof(src_ip_str));
        inet_ntop (AF_INET, &flow->key.dst_ip4, dst_ip_str, sizeof(dst_ip_str));
        snprintf (flow_info, sizeof(flow_info), "%s:%u -> %s:%u",
                 src_ip_str, flow->key.src_port, dst_ip_str, flow->key.dst_port);
    }

    /* Log rule match using async logging system (FAST PATH SAFE) */
    ips_log_rule_match_async (action_str, rule->sid,
                             rule->msg ? (char *)rule->msg : "No message",
                             classification, priority, proto_str, flow_info,
                             packet_len, timestamp, vlib_get_thread_index ());

    /* Additional packet information for detailed logging */
    if (b && is_alert)
    {
        /* Extract more packet details for alerts */
        ethernet_header_t *eth = vlib_buffer_get_current (b);

        if (flow->key.protocol == IPS_PROTO_TCP && packet_len > 54)
        {
            tcp_header_t *tcp;
            if (flow->key.is_ip6)
            {
                tcp = (tcp_header_t *)((u8 *)eth + sizeof(ethernet_header_t) + sizeof(ip6_header_t));
            }
            else
            {
                ip4_header_t *ip4 = (ip4_header_t *)((u8 *)eth + sizeof(ethernet_header_t));
                tcp = (tcp_header_t *)((u8 *)ip4 + sizeof(ip4_header_t));
            }

            char tcp_flags[16];
            snprintf (tcp_flags, sizeof(tcp_flags), "%s%s%s%s%s%s%s%s",
                     tcp->flags & TCP_FLAG_FIN ? "F" : "",
                     tcp->flags & TCP_FLAG_SYN ? "S" : "",
                     tcp->flags & TCP_FLAG_RST ? "R" : "",
                     tcp->flags & TCP_FLAG_PSH ? "P" : "",
                     tcp->flags & TCP_FLAG_ACK ? "A" : "",
                     tcp->flags & TCP_FLAG_URG ? "U" : "",
                     tcp->flags & TCP_FLAG_ECE ? "E" : "",
                     tcp->flags & TCP_FLAG_CWR ? "C" : "");

            /* Log TCP details using async logging system (FAST PATH SAFE) */
            ips_log_tcp_details_async (tcp_flags,
                                     clib_net_to_host_u32 (tcp->seq_number),
                                     clib_net_to_host_u32 (tcp->ack_number),
                                     clib_net_to_host_u16 (tcp->window),
                                     timestamp, vlib_get_thread_index ());
        }
    }

    /* Update rule statistics - PREVENT DOUBLE COUNTING */
    /* Generate a simple hash of the packet to detect duplicates */
    u32 packet_hash = 0;
    if (b)
    {
        /* Create a hash from buffer content, timestamp, and flow info */
        u64 hash_input = ((u64)(timestamp * 1000000) << 32) |
                        (u64)vlib_buffer_length_in_chain(vlib_get_main(), b);
        packet_hash = (u32)clib_xxhash(hash_input ^ flow->flow_hash);
    }
    else
    {
        /* For reordered data detection without buffer, use timestamp and flow only */
        u64 hash_input = ((u64)(timestamp * 1000000) << 32) | (u64)rule->sid;
        packet_hash = (u32)clib_xxhash(hash_input ^ flow->flow_hash);
    }

    /* Check if this is the same packet we just processed */
    if (packet_hash != flow->last_processed_packet_hash)
    {
        /* This is a new/different packet, update counters */
        if (is_alert)
        {
            rule->alert_count++;
        }
        rule->match_count++;
        rule->last_match_time = (u64)(timestamp * 1000000); /* Convert to microseconds */
        flow->last_processed_packet_hash = packet_hash;

        clib_warning ("DEBUG: Rule %u match counted (match_count=%u, alert_count=%u, hash=0x%x)",
                     rule->sid, rule->match_count, rule->alert_count, packet_hash);
    }
    else
    {
        clib_warning ("DEBUG: Rule %u duplicate match ignored (same packet hash=0x%x)",
                     rule->sid, packet_hash);
    }
}

/**
 * @brief Generate alert for matched rule
 */
void
ips_generate_alert (ips_rule_t * rule, ips_flow_t * flow, vlib_buffer_t * b)
{
    ips_main_t *im = &ips_main;
    ips_per_thread_data_t *ptd;
    const char *action_str;

    ptd = &im->per_thread_data[vlib_get_thread_index ()];
    ptd->alerted_packets++;

    /* Determine action string */
    switch (rule->action)
    {
    case IPS_ACTION_DROP:
        action_str = "DROP";
        break;
    case IPS_ACTION_REJECT:
        action_str = "REJECT";
        break;
    case IPS_ACTION_ALERT:
        action_str = "ALERT";
        break;
    case IPS_ACTION_LOG:
        action_str = "LOG";
        break;
    case IPS_ACTION_PASS:
        action_str = "PASS";
        break;
    default:
        action_str = "UNKNOWN";
        break;
    }

    /* Generate detailed log in Suricata format */
    ips_generate_detailed_log (rule, flow, b, action_str, 1);
}

/**
 * @brief Generate log entry for LOG action
 */
void
ips_generate_log_entry (ips_rule_t *rule, ips_flow_t *flow, vlib_buffer_t *b)
{
    /* Generate detailed log entry using the same format */
    ips_generate_detailed_log (rule, flow, b, "LOG", 0);
}

/**
 * @brief Add rule to detection engine
 */
int
ips_rule_add (ips_rule_t * rule)
{
    ips_main_t *im = &ips_main;
    ips_rule_t *new_rule;

    if (PREDICT_FALSE (!rule))
        return -1;

    /* Check if rule already exists */
    if (ips_rule_lookup (rule->rule_id))
        return -2; /* Rule already exists */

    /* Skip rules marked as unsupported */
    if (rule->flags & IPS_RULE_FLAG_UNSUPPORTED)
    {
        clib_warning ("Skipping unsupported rule SID:%u - %s",
                     rule->sid, rule->msg ? (char *)rule->msg : "No message");
        return -3; /* Rule unsupported */
    }

    /* Add rule to vector */
    vec_add2 (im->rules, new_rule, 1);
    *new_rule = *rule;

    /* Copy dynamic fields */
    if (rule->msg)
        new_rule->msg = vec_dup (rule->msg);
    if (rule->reference)
        new_rule->reference = vec_dup (rule->reference);
    if (rule->classtype)
        new_rule->classtype = vec_dup (rule->classtype);
    if (rule->content)
        new_rule->content = vec_dup (rule->content);

    /* Enable rule by default */
    new_rule->flags |= IPS_RULE_FLAG_ENABLED;

    /* Mark rules as dirty for recompilation */
    im->rules_dirty = 1;
    im->rules_compiled = 0;
    im->rule_count++;

    return 0;
}

/**
 * @brief Delete rule from detection engine
 */
int
ips_rule_delete (u32 rule_id)
{
    ips_main_t *im = &ips_main;
    ips_rule_t *rule;
    u32 i;

    /* Find rule by ID */
    for (i = 0; i < vec_len (im->rules); i++)
    {
        rule = &im->rules[i];
        if (rule->rule_id == rule_id)
        {
            /* Free dynamic fields */
            vec_free (rule->msg);
            vec_free (rule->reference);
            vec_free (rule->classtype);
            vec_free (rule->content);

            /* Remove from vector */
            vec_delete (im->rules, 1, i);

            /* Mark rules as dirty */
            im->rules_dirty = 1;
            im->rules_compiled = 0;
            im->rule_count--;

            return 0;
        }
    }

    return -1; /* Rule not found */
}

/**
 * @brief Lookup rule by ID
 */
ips_rule_t *
ips_rule_lookup (u32 rule_id)
{
    ips_main_t *im = &ips_main;
    ips_rule_t *rule;
    u32 i;

    for (i = 0; i < vec_len (im->rules); i++)
    {
        rule = &im->rules[i];
        if (rule->rule_id == rule_id)
            return rule;
    }

    return NULL;
}

/**
 * @brief Minimal advanced rule matching - only non-content features
 * Content-related features (offset, depth, distance, within) are handled by Hyperscan
 * Note: This is a simplified version that calls the full advanced detection when needed
 */
int
ips_match_rule_advanced_minimal (vlib_buffer_t *b, ips_flow_t *flow, ips_rule_t *rule, u32 thread_index)
{
    if (!b || !flow || !rule)
        return 0;

    /* For now, use the existing full advanced detection function */
    /* In a production implementation, this would be optimized to only check
     * features that cannot be handled by Hyperscan:
     * - TCP flags, TTL, TOS, fragment bits
     * - Sequence/acknowledgment numbers, ICMP type/code
     * - Byte tests, flow bits, thresholds
     *
     * Content-related features (offset, depth, distance, within, nocase)
     * should be handled by Hyperscan extended parameters
     */
    return ips_match_rule_advanced (b, flow, rule, thread_index);
}

/**
 * @brief Check non-content rules for matches
 * This function processes rules that don't have content patterns and therefore
 * are not handled by Hyperscan. It implements the Suricata-compatible behavior
 * of supporting pure network/metadata rules.
 */
static int
ips_check_non_content_rules (ips_flow_t * flow, vlib_buffer_t * b)
{
    ips_main_t *im = &ips_main;
    int match_count = 0;
    u32 i;

    if (PREDICT_FALSE (!im->rules_compiled))
        return 0;

    /* Iterate through all rules to find non-content ones */
    for (i = 0; i < vec_len (im->rules); i++)
    {
        ips_rule_t *rule = &im->rules[i];

        /* Skip disabled rules */
        if (!(rule->flags & IPS_RULE_FLAG_ENABLED))
            continue;

        /* Skip rules with content patterns (handled by Hyperscan) */
        if (rule->content || rule->content_hex)
            continue;

        clib_warning ("DEBUG: Checking non-content rule %u", rule->sid);

        /* Check basic rule matching (protocol, IP, port) */
        if (!ips_rule_match (rule, flow, b))
            continue;

        /* Check advanced rule features */
        if (!ips_match_rule_advanced (b, flow, rule, vlib_get_thread_index ()))
            continue;

        clib_warning ("DEBUG: Non-content rule %u MATCHED!", rule->sid);

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
            /* In mirror mode, DROP means whitelist (allow to pass) */
            flow->detection_flags |= IPS_DETECTION_FLAG_DROP;
            break;
        case IPS_ACTION_REJECT:
            /* REJECT means actual blocking with RST/ICMP response */
            flow->detection_flags |= IPS_DETECTION_FLAG_REJECT;
            break;
        case IPS_ACTION_ALERT:
            /* Alert only, continue processing */
            flow->detection_flags |= IPS_DETECTION_FLAG_ALERT;
            break;
        case IPS_ACTION_LOG:
            /* Log only, continue processing */
            flow->detection_flags |= IPS_DETECTION_FLAG_LOG;
            break;
        case IPS_ACTION_PASS:
        default:
            /* No action needed, continue processing */
            break;
        }

        match_count++;
    }

    if (match_count > 0)
    {
        clib_warning ("DEBUG: Non-content rules matched: %d", match_count);
    }

    return match_count;
}
