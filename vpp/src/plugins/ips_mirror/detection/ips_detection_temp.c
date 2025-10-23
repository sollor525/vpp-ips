/*
 * ips_detection_temp.c - Temporary VPP IPS Plugin Detection Engine Stub
 * Temporarily replaces Hyperscan-dependent detection with basic functionality
 *
 * Copyright (c) 2024 VPP IPS Project
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/error.h>
#include <vppinfra/string.h>

#include "ips.h"
#include "detection/ips_detection.h"

/* Forward declaration */
static int ips_check_non_content_rules_stub(ips_flow_t *flow, vlib_buffer_t *b);

/**
 * @brief Initialize detection engine (temporary stub)
 */
clib_error_t *
ips_detection_init (ips_main_t *im)
{
    clib_error_t *error = 0;

    /* Initialize rule compilation state */
    im->rules_compiled = 0;
    im->rules_dirty = 0;

    return error;
}

/**
 * @brief Cleanup detection engine (temporary stub)
 */
void
ips_detection_cleanup (ips_main_t *im)
{
    /* Basic cleanup - no Hyperscan resources to clean */
    im->rules_compiled = 0;
}

/**
 * @brief Compile rules into detection database (temporary stub)
 */
int
ips_compile_rules (ips_main_t *im)
{
    if (!im)
        return -1;

    if (vec_len (im->rules) == 0)
    {
        clib_warning ("No rules to process");
        im->rules_compiled = 1;
        im->rules_dirty = 0;
        return 0;
    }

    clib_warning ("Rule compilation temporarily disabled - %u rules loaded but not compiled",
                  vec_len (im->rules));

    im->rules_compiled = 1;
    im->rules_dirty = 0;
    return 0;
}

/**
 * @brief Detect patterns in packet payload (temporary stub)
 */
int
ips_detect_patterns (ips_flow_t *flow, vlib_buffer_t *b)
{
    if (!flow || !b)
        return 0;

    ips_main_t *im = &ips_main;

    if (PREDICT_FALSE (!im->rules_compiled))
        return 0;

    /* Temporarily disabled - will only check non-content rules */
    return ips_check_non_content_rules_stub (flow, b);
}

/**
 * @brief Stub function for non-content rule checking
 */
static int
ips_check_non_content_rules_stub (ips_flow_t *flow, vlib_buffer_t *b)
{
    /* Basic placeholder for non-content rule matching */
    return 0;
}

/**
 * @brief Advanced rule matching (temporary stub)
 */
int
ips_match_rule_advanced (vlib_buffer_t *b, ips_flow_t *flow, ips_rule_t *rule, u32 thread_index)
{
    if (!b || !flow || !rule)
        return 0;

    /* Basic protocol and port matching without content patterns */
    if (rule->protocol != 0 && rule->protocol != flow->key.protocol)
        return 0;

    if (rule->src_port_min > 0 || rule->src_port_max > 0)
    {
        if (flow->key.src_port < rule->src_port_min ||
            flow->key.src_port > rule->src_port_max)
            return 0;
    }

    if (rule->dst_port_min > 0 || rule->dst_port_max > 0)
    {
        if (flow->key.dst_port < rule->dst_port_min ||
            flow->key.dst_port > rule->dst_port_max)
            return 0;
    }

    return 1; /* Basic match */
}

/**
 * @brief Generate alert (temporary stub)
 */
void
ips_generate_alert (ips_rule_t *rule, ips_flow_t *flow, vlib_buffer_t *b)
{
    if (!rule || !flow || !b)
        return;

    clib_warning ("IPS Alert: Rule %u - %s", rule->sid,
                  rule->msg ? (char *)rule->msg : "No message");
}

/**
 * @brief Generate log entry (temporary stub)
 */
void
ips_generate_log_entry (ips_rule_t *rule, ips_flow_t *flow, vlib_buffer_t *b)
{
    if (!rule || !flow || !b)
        return;

    /* Basic logging - can be expanded later */
}

/**
 * @brief Add rule to detection engine (basic implementation)
 */
int
ips_detection_add_rule (ips_rule_t *rule)
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
    new_rule->rule_id = rule->rule_id;
    new_rule->sid = rule->sid;

    /* Add to rule index */
    hash_set (im->rule_index_by_id, new_rule->rule_id, new_rule - im->rules);

    /* Mark rules as dirty for recompilation */
    im->rules_dirty = 1;
    im->rules_compiled = 0;
    im->rule_count++;

    return 0;
}

/**
 * @brief Delete rule from detection engine (basic implementation)
 */
int
ips_detection_delete_rule (u32 rule_id)
{
    ips_main_t *im = &ips_main;
    uword *p;
    u32 i;

    p = hash_get (im->rule_index_by_id, rule_id);
    if (PREDICT_FALSE (!p))
        return -1; /* Rule not found */

    i = p[0];
    if (PREDICT_FALSE (i >= vec_len (im->rules)))
        return -1; /* Invalid index */

    /* Mark rules as dirty */
    im->rules_dirty = 1;
    im->rules_compiled = 0;
    im->rule_count--;

    /* Remove from hash table */
    hash_unset (im->rule_index_by_id, rule_id);

    /* Remove from vector (this is inefficient - should use pool) */
    vec_delete (im->rules, 1, i);

    return 0;
}

/**
 * @brief Lookup rule by ID
 */
ips_rule_t *
ips_rule_lookup (u32 rule_id)
{
    ips_main_t *im = &ips_main;
    uword *p;
    u32 i;
    ips_rule_t *rule;

    p = hash_get (im->rule_index_by_id, rule_id);
    if (PREDICT_FALSE (!p))
        return NULL;

    i = p[0];
    if (PREDICT_FALSE (i >= vec_len (im->rules)))
        return NULL;

    rule = &im->rules[i];
    return rule;
}

/**
 * @brief Compile rules for efficient matching (stub implementation)
 */
int
ips_rules_compile (void)
{
    ips_main_t *im = &ips_main;

    /* Mark rules as compiled */
    im->rules_compiled = 1;
    im->rules_dirty = 0;

    clib_warning("IPS: Rules compilation completed (stub implementation)");
    return 0;
}