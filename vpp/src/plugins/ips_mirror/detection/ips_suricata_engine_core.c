/*
 * ips_suricata_engine_core.c - VPP IPS Suricata Detection Engine Core Implementation
 *
 * Copyright (c) 2024 VPP IPS Project
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#include <vlib/vlib.h>
#include <vnet/ip/ip.h>
#include <vppinfra/string.h>
#include <vppinfra/hash.h>
#include <ctype.h>

#include "ips_suricata_engine.h"
#include "ips_suricata_rule_types.h"
#include "ips_suricata_parser.h"
#include "../session/ips_session.h"
#include "../protocols/ips_protocol_detection.h"
#include "../ips_logging.h"

/* Global engine state */
static ips_detection_engine_t engine = {0};

/* Per-thread rule cache */
typedef struct {
    ips_suricata_rule_t **recent_rules;
    u32 *rule_hashes;
    u32 capacity;
    u32 head;
    u32 count;
    u64 hits;
    u64 misses;
} ips_thread_rule_cache_t;

/* Per-thread flowbit storage */
typedef struct {
    hash_t *flowbit_hash;  // key: session_id+flowbit_name_hash, value: flowbit_state
    u32 cleanup_counter;
    f64 last_cleanup_time;
} ips_thread_flowbits_t;

/* Per-thread engine state */
typedef struct {
    ips_thread_rule_cache_t rule_cache;
    ips_thread_flowbits_t flowbits;
    ips_detection_stats_t stats;
    u8 initialized;
} ips_thread_engine_t;

/* Get per-thread engine state */
static ips_thread_engine_t *
ips_get_thread_engine(void)
{
    static ips_thread_engine_t *thread_engines = NULL;
    static u32 num_threads = 0;

    u32 thread_index = vlib_get_thread_index();

    if (thread_engines == NULL) {
        num_threads = vlib_get_n_threads();
        vec_validate(thread_engines, num_threads - 1);
    }

    if (!thread_engines[thread_index].initialized) {
        /* Initialize rule cache */
        thread_engines[thread_index].rule_cache.capacity = 1024;
        vec_validate(thread_engines[thread_index].rule_cache.recent_rules,
                    thread_engines[thread_index].rule_cache.capacity - 1);
        vec_validate(thread_engines[thread_index].rule_cache.rule_hashes,
                    thread_engines[thread_index].rule_cache.capacity - 1);

        /* Initialize flowbits */
        thread_engines[thread_index].flowbits.flowbit_hash =
            hash_create(0, sizeof(uword));
        thread_engines[thread_index].flowbits.last_cleanup_time =
            vlib_time_now(vlib_get_main());

        thread_engines[thread_index].initialized = 1;
    }

    return &thread_engines[thread_index];
}

/**
 * @brief Initialize detection engine
 */
clib_error_t *
ips_suricata_engine_init(const ips_detection_config_t *config)
{
    if (engine.initialized)
        return 0;  /* Already initialized */

    /* Use provided config or defaults */
    if (config)
        engine.config = *config;
    else
    {
        /* Default configuration */
        engine.config.enable_fast_path = 1;
        engine.config.enable_content_caching = 1;
        engine.config.enable_rule_groups = 1;
        engine.config.enable_flowbits = 1;
        engine.config.max_stages_per_packet = 6;
        engine.config.max_rules_per_packet = 64;
        engine.config.enable_rule_prefetch = 1;
        engine.config.cache_size = 1024;
    }

    /* Initialize rule indexes */
    engine.rule_hash_by_sid = hash_create(0, sizeof(uword));
    engine.rule_hash_by_content = hash_create(0, sizeof(uword));
    engine.rule_hash_by_protocol = hash_create(0, sizeof(uword));

    /* Initialize rule groups */
    vec_validate(engine.rule_groups, 255);  /* One group per protocol */

    engine.initialized = 1;

    ips_log_system_async(IPS_LOG_LEVEL_INFO,
                        "Suricata detection engine initialized");

    return NULL;
}

/**
 * @brief Boyer-Moore-Horspool string search implementation
 */
static inline const u8 *
bmh_search(const u8 *pattern, u32 pattern_len,
           const u8 *text, u32 text_len, u8 nocase)
{
    if (pattern_len == 0 || text_len < pattern_len)
        return NULL;

    /* Preprocess bad character table */
    u8 bad_char[256];
    for (int i = 0; i < 256; i++)
        bad_char[i] = pattern_len;

    for (int i = 0; i < pattern_len - 1; i++) {
        u8 c = pattern[i];
        if (nocase) c = tolower(c);
        bad_char[c] = pattern_len - 1 - i;
    }

    /* Search */
    u32 skip = 0;
    while (text_len - skip >= pattern_len) {
        const u8 *haystack = text + skip;
        int i = pattern_len - 1;

        while (i >= 0) {
            u8 h = haystack[i];
            u8 p = pattern[i];
            if (nocase) {
                h = tolower(h);
                p = tolower(p);
            }
            if (h != p) break;
            i--;
        }

        if (i < 0) {
            return haystack;  /* Match found */
        }

        u8 c = haystack[pattern_len - 1];
        if (nocase) c = tolower(c);
        skip += bad_char[c];
    }

    return NULL;
}

/**
 * @brief Fast content pattern matching
 */
const u8 *
ips_find_content_pattern(const u8 *pattern, u32 pattern_len,
                        const u8 *data, u32 data_len, u8 nocase)
{
    /* For very short patterns, use simple search */
    if (pattern_len <= 3) {
        for (u32 i = 0; i <= data_len - pattern_len; i++) {
            u32 j;
            for (j = 0; j < pattern_len; j++) {
                u8 d = data[i + j];
                u8 p = pattern[j];
                if (nocase) {
                    d = tolower(d);
                    p = tolower(p);
                }
                if (d != p) break;
            }
            if (j == pattern_len) return &data[i];
        }
        return NULL;
    }

    /* Use BMH for longer patterns */
    return bmh_search(pattern, pattern_len, data, data_len, nocase);
}

/**
 * @brief Match content with modifiers
 */
int
ips_match_content_with_modifiers(const ips_content_match_t *content,
                                const u8 *data, u32 data_len,
                                u32 *relative_offset)
{
    u32 search_start = *relative_offset;
    u32 search_end = data_len;

    /* Apply offset modifier */
    if (content->modifiers & IPS_CONTENT_MOD_OFFSET) {
        search_start = content->offset;
    }

    /* Apply depth modifier */
    if (content->modifiers & IPS_CONTENT_MOD_DEPTH) {
        search_end = clib_min(search_start + content->depth, data_len);
    }

    /* Apply distance modifier */
    if (content->modifiers & IPS_CONTENT_MOD_DISTANCE &&
        *relative_offset > 0) {
        search_start = *relative_offset + content->distance;
    }

    /* Apply within modifier */
    if (content->modifiers & IPS_CONTENT_MOD_WITHIN) {
        search_end = clib_min(search_start + content->within, data_len);
    }

    /* Validate search range */
    if (search_start >= search_end || search_end > data_len)
        return 0;

    /* Search for pattern */
    const u8 *match = ips_find_content_pattern(
        content->pattern, content->pattern_len,
        data + search_start, search_end - search_start,
        content->modifiers & IPS_CONTENT_MOD_NOCASE);

    if (match) {
        *relative_offset = (match - data) + content->pattern_len;
        return 1;
    }

    return 0;
}

clib_error_t *
ips_suricata_engine_init_vpp(vlib_main_t *vm)
{
    (void)vm;  /* Unused parameter */
    return ips_suricata_engine_init(NULL);
}


/**
 * @brief Match byte_test option
 */
int
ips_match_byte_test(const ips_byte_test_t *byte_test,
                   const u8 *data, u32 data_len,
                   u32 *relative_offset)
{
    u32 offset = byte_test->offset;
    if (byte_test->relative) {
        offset += *relative_offset;
    }

    if (offset + byte_test->bytes > data_len)
        return 0;  /* Out of bounds */

    u32 value = 0;
    for (int i = 0; i < byte_test->bytes; i++) {
        value = (value << 8) | data[offset + i];
    }

    if (byte_test->mask) {
        value &= byte_test->mask;
    }

    switch (byte_test->op) {
    case IPS_BYTE_TEST_EQ: return value == byte_test->value;
    case IPS_BYTE_TEST_NE: return value != byte_test->value;
    case IPS_BYTE_TEST_LT: return value < byte_test->value;
    case IPS_BYTE_TEST_GT: return value > byte_test->value;
    case IPS_BYTE_TEST_LE: return value <= byte_test->value;
    case IPS_BYTE_TEST_GE: return value >= byte_test->value;
    case IPS_BYTE_TEST_AND: return (value & byte_test->value) != 0;
    case IPS_BYTE_TEST_OR:  return (value | byte_test->value) != 0;
    case IPS_BYTE_TEST_XOR: return (value ^ byte_test->value) != 0;
    default: return 0;
    }
}

/**
 * @brief Match protocol stage
 */
ips_match_result_t
ips_match_protocol(ips_suricata_rule_t *rule, ips_packet_context_t *ctx)
{
    /* Check protocol match */
    if (rule->protocol != IPS_PROTO_ANY && rule->protocol != ctx->protocol)
        return IPS_MATCH_NO_MATCH;

    return IPS_MATCH_PARTIAL;
}

/**
 * @brief Match IP header stage
 */
ips_match_result_t
ips_match_ip_header(ips_suricata_rule_t *rule, ips_packet_context_t *ctx)
{
    /* Check source IP */
    if (!rule->src_ip.is_any) {
        if (rule->src_ip.is_ipv6) {
            /* TODO: IPv6 matching */
            return IPS_MATCH_NO_MATCH;
        } else {
            u32 src_ip = ctx->src_ip.ip4.as_u32;
            u32 rule_ip = rule->src_ip.addr.ip4.as_u32;
            u32 rule_mask = rule->src_ip.mask.ip4.as_u32;

            if ((src_ip & rule_mask) != (rule_ip & rule_mask))
                return IPS_MATCH_NO_MATCH;
        }
    }

    /* Check destination IP */
    if (!rule->dst_ip.is_any) {
        if (rule->dst_ip.is_ipv6) {
            /* TODO: IPv6 matching */
            return IPS_MATCH_NO_MATCH;
        } else {
            u32 dst_ip = ctx->dst_ip.ip4.as_u32;
            u32 rule_ip = rule->dst_ip.addr.ip4.as_u32;
            u32 rule_mask = rule->dst_ip.mask.ip4.as_u32;

            if ((dst_ip & rule_mask) != (rule_ip & rule_mask))
                return IPS_MATCH_NO_MATCH;
        }
    }

    return IPS_MATCH_PARTIAL;
}

/**
 * @brief Match transport stage
 */
ips_match_result_t
ips_match_transport(ips_suricata_rule_t *rule, ips_packet_context_t *ctx)
{
    /* Check source port */
    if (!rule->src_port.is_any) {
        if (ctx->src_port < rule->src_port.start ||
            ctx->src_port > rule->src_port.end)
            return IPS_MATCH_NO_MATCH;
    }

    /* Check destination port */
    if (!rule->dst_port.is_any) {
        if (ctx->dst_port < rule->dst_port.start ||
            ctx->dst_port > rule->dst_port.end)
            return IPS_MATCH_NO_MATCH;
    }

    /* Check TCP flags if TCP protocol */
    if (ctx->protocol == IPS_PROTO_TCP && rule->tcp_flags_mask) {
        if ((ctx->tcp_flags & rule->tcp_flags_mask) != rule->tcp_flags_value)
            return IPS_MATCH_NO_MATCH;
    }

    return IPS_MATCH_PARTIAL;
}

/**
 * @brief Match application stage
 */
ips_match_result_t
ips_match_application(ips_suricata_rule_t *rule, ips_packet_context_t *ctx)
{
    /* Check if rule has HTTP content modifiers */
    if (rule->has_http_content) {
        if (ctx->app_proto != IPS_ALPROTO_HTTP)
            return IPS_MATCH_NO_MATCH;
    }

    return IPS_MATCH_PARTIAL;
}

/**
 * @brief Match content stage
 */
ips_match_result_t
ips_match_content(ips_suricata_rule_t *rule, ips_packet_context_t *ctx)
{
    if (rule->content_count == 0)
        return IPS_MATCH_PARTIAL;

    /* Get application layer payload */
    u8 *payload = ctx->packet_data;
    u32 payload_len = ctx->packet_len;

    /* TODO: Extract actual application payload based on protocol */
    /* For now, use entire packet */

    u32 relative_offset = 0;

    /* Match all content patterns */
    for (u32 i = 0; i < rule->content_count; i++) {
        ips_content_match_t *content = &rule->contents[i];

        if (ips_match_content_with_modifiers(content, payload, payload_len,
                                             &relative_offset)) {
            /* Content matched, continue with next content */
            continue;
        } else {
            /* Content not matched, rule fails */
            return IPS_MATCH_NO_MATCH;
        }
    }

    return IPS_MATCH_PARTIAL;
}

/**
 * @brief Match options stage
 */
ips_match_result_t
ips_match_options(ips_suricata_rule_t *rule, ips_packet_context_t *ctx)
{
    u8 *payload = ctx->packet_data;
    u32 payload_len = ctx->packet_len;
    u32 relative_offset = 0;

    /* Match byte_test options */
    for (u32 i = 0; i < rule->byte_test_count; i++) {
        if (!ips_match_byte_test(&rule->byte_tests[i], payload, payload_len,
                                &relative_offset)) {
            return IPS_MATCH_NO_MATCH;
        }
    }

    /* TODO: Implement other options (byte_jump, pcre, flowbits, etc.) */

    return IPS_MATCH_COMPLETE;
}

/**
 * @brief Extract packet information into context
 */
static int
ips_extract_packet_context(ips_session_t *session, vlib_buffer_t *b,
                          ips_packet_context_t *ctx)
{
    clib_memset(ctx, 0, sizeof(*ctx));

    ctx->thread_index = vlib_get_thread_index();
    ctx->buffer = b;
    ctx->packet_data = vlib_buffer_get_current(b);
    ctx->packet_len = b->current_length;

    /* Get IP information from session */
    if (session->is_ipv6) {
        ctx->src_ip.ip6 = session->src_ip6;
        ctx->dst_ip.ip6 = session->dst_ip6;
    } else {
        ctx->src_ip.ip4 = session->src_ip4;
        ctx->dst_ip.ip4 = session->dst_ip4;
    }
    ctx->src_port = session->src_port;
    ctx->dst_port = session->dst_port;

    /* Determine protocol */
    ctx->protocol = session->protocol;  // TODO: Map to ips_protocol_t

    /* Extract TCP header if available */
    if (ctx->protocol == IPS_PROTO_TCP) {
        /* TODO: Extract TCP header from buffer */
        ctx->tcp_flags = 0;  /* TODO: Get actual flags */
    }

    /* Get application protocol */
    ips_proto_detect_ctx_t *proto_ctx = ips_get_proto_detect_ctx(session);
    if (proto_ctx) {
        ctx->app_proto = proto_ctx->detected_protocol;
        ctx->proto_detect_ctx = proto_ctx;
    }

    return 0;
}



/**
 * @brief Add rule to engine
 */
int
ips_suricata_engine_add_rule(ips_suricata_rule_t *rule)
{
    if (!rule || !engine.initialized)
        return -1;

    /* Add to SID hash */
    hash_set(engine.rule_hash_by_sid, rule->sid, (uword)rule);

    /* Add to protocol hash */
    hash_set(engine.rule_hash_by_protocol, rule->protocol, (uword)rule);

    /* TODO: Add to content hash */

    engine.total_rules++;
    if (rule->enabled)
        engine.enabled_rules++;

    return 0;
}

/**
 * @brief VPP-compatible initialization function
 */
ips_match_result_t
ips_suricata_engine_match_rule(ips_suricata_rule_t *rule,
                               ips_packet_context_t *ctx)
{
    if (!rule->enabled)
        return IPS_MATCH_NO_MATCH;

    /* Multi-stage matching with early exit */
    ips_match_result_t result;

    result = ips_match_protocol(rule, ctx);
    if (result != IPS_MATCH_PARTIAL) return result;

    result = ips_match_ip_header(rule, ctx);
    if (result != IPS_MATCH_PARTIAL) return result;

    result = ips_match_transport(rule, ctx);
    if (result != IPS_MATCH_PARTIAL) return result;

    result = ips_match_application(rule, ctx);
    if (result != IPS_MATCH_PARTIAL) return result;

    result = ips_match_content(rule, ctx);
    if (result != IPS_MATCH_PARTIAL) return result;

    result = ips_match_options(rule, ctx);
    return result;
}

/**
 * @brief Match packet against all rules
 */
int
ips_suricata_engine_match_packet(ips_session_t *session,
                                vlib_buffer_t *b,
                                ips_packet_context_t *packet_context)
{
    if (!session || !b || !packet_context || !engine.initialized)
        return -1;

    /* Extract packet context */
    if (ips_extract_packet_context(session, b, packet_context) < 0)
        return -1;

    ips_thread_engine_t *thread_engine = ips_get_thread_engine();
    f64 start_time = vlib_time_now(vlib_get_main());

    packet_context->start_time = start_time;
    packet_context->matches_found = 0;

    /* Get candidate rules based on protocol */
    uword *rule_hash = hash_get(engine.rule_hash_by_protocol, packet_context->protocol);
    if (!rule_hash) {
        /* Try 'any' protocol */
        rule_hash = hash_get(engine.rule_hash_by_protocol, IPS_PROTO_ANY);
    }

    if (!rule_hash)
        return 0;  /* No rules for this protocol */

    ips_suricata_rule_t *rule = (ips_suricata_rule_t *)rule_hash[0];

    /* For now, just process single rule */
    /* TODO: Implement rule chain/hash bucket processing */

    ips_match_result_t result = ips_suricata_engine_match_rule(rule, packet_context);

    if (result == IPS_MATCH_COMPLETE) {
        packet_context->matched_rules[packet_context->matches_found] = rule;
        packet_context->matches_found++;
        thread_engine->stats.rules_matched++;
    }

    /* Update statistics */
    f64 processing_time = vlib_time_now(vlib_get_main()) - start_time;
    thread_engine->stats.packets_processed++;
    thread_engine->stats.avg_processing_time +=
        (processing_time - thread_engine->stats.avg_processing_time) /
        thread_engine->stats.packets_processed;

    return packet_context->matches_found;
}

/**
 * @brief Execute rule action
 */
int
ips_suricata_engine_execute_action(ips_suricata_rule_t *rule,
                                   ips_packet_context_t *packet_context)
{
    if (!rule || !packet_context)
        return -1;

    ips_thread_engine_t *thread_engine = ips_get_thread_engine();

    switch (rule->action) {
    case IPS_ACTION_ALERT:
        thread_engine->stats.alerts_generated++;
        ips_log_system_async(IPS_LOG_LEVEL_INFO,
                            "ALERT: SID:%u %s", rule->sid, rule->msg);
        return 0;  /* Allow packet */

    case IPS_ACTION_DROP:
        thread_engine->stats.drops_generated++;
        ips_log_system_async(IPS_LOG_LEVEL_INFO,
                            "DROP: SID:%u %s", rule->sid, rule->msg);
        return 1;  /* Block packet */

    case IPS_ACTION_REJECT:
        thread_engine->stats.rejections_generated++;
        ips_log_system_async(IPS_LOG_LEVEL_INFO,
                            "REJECT: SID:%u %s", rule->sid, rule->msg);
        return 1;  /* Block packet */

    case IPS_ACTION_LOG:
        ips_log_system_async(IPS_LOG_LEVEL_INFO,
                            "LOG: SID:%u %s", rule->sid, rule->msg);
        return 0;  /* Allow packet */

    case IPS_ACTION_PASS:
        return 0;  /* Allow packet */

    default:
        return 0;  /* Default to allow */
    }
}

/**
 * @brief Get engine statistics
 */
void
ips_suricata_engine_get_stats(ips_detection_stats_t *stats)
{
    if (!stats)
        return;

    ips_thread_engine_t *thread_engine = ips_get_thread_engine();
    *stats = thread_engine->stats;

    /* Add global stats */
    /* TODO: Add total_rules and enabled_rules fields to ips_detection_stats_t */
    // stats->total_rules = engine.total_rules;
    // stats->enabled_rules = engine.enabled_rules;
}

/**
 * @brief Cleanup engine
 */
void
ips_suricata_engine_cleanup(void)
{
    if (!engine.initialized)
        return;

    /* TODO: Free all allocated memory */

    clib_memset(&engine, 0, sizeof(engine));
}

/**
 * @brief Remove rule from detection engine
 */
int
ips_suricata_engine_remove_rule(u32 sid)
{
    if (!engine.initialized)
        return -1;

    /* Find rule in hash table */
    uword *p = hash_get(engine.rule_hash_by_sid, sid);
    if (!p)
        return -1;

    ips_suricata_rule_t *rule = (ips_suricata_rule_t *)(uintptr_t)p[0];

    /* Remove from hash tables */
    hash_unset(engine.rule_hash_by_sid, sid);

    /* TODO: Remove from other indexes and groups */

    /* Free rule memory */
    ips_suricata_rule_free(rule);

    /* Update statistics */
    engine.total_rules--;
    if (rule->enabled)
        engine.enabled_rules--;

    return 0;
}

/**
 * @brief Enable/disable rule
 */
int
ips_suricata_engine_set_rule_state(u32 sid, u8 enabled)
{
    if (!engine.initialized)
        return -1;

    /* Find rule in hash table */
    uword *p = hash_get(engine.rule_hash_by_sid, sid);
    if (!p)
        return -1;

    ips_suricata_rule_t *rule = (ips_suricata_rule_t *)(uintptr_t)p[0];

    /* Update rule state */
    u8 old_state = rule->enabled;
    rule->enabled = enabled;

    /* Update statistics */
    if (old_state && !enabled) {
        engine.enabled_rules--;
    } else if (!old_state && enabled) {
        engine.enabled_rules++;
    }

    return 0;
}

