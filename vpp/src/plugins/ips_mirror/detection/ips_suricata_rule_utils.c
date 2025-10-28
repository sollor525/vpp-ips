/*
 * ips_suricata_rule_utils.c - VPP IPS Suricata Rule Utility Functions
 *
 * Copyright (c) 2024 VPP IPS Project
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#include <vlib/vlib.h>
#include <vppinfra/string.h>
#include <vppinfra/mem.h>

#include "ips_suricata_rule_types.h"
#include "../ips_logging.h"

/**
 * @brief Create a new Suricata rule
 */

/**
 * @brief Free a Suricata rule
 */

/**
 * @brief Clone a Suricata rule
 */

/**
 * @brief Validate a Suricata rule
 */
int
ips_suricata_rule_validate(ips_suricata_rule_t *rule)
{
    if (!rule)
        return -1;

    /* Check required fields */
    if (rule->sid == 0) {
        snprintf(rule->error_msg, sizeof(rule->error_msg), "SID cannot be 0");
        rule->has_error = 1;
        return -1;
    }

    if (rule->action >= IPS_ACTION_MAX) {
        snprintf(rule->error_msg, sizeof(rule->error_msg), "Invalid action");
        rule->has_error = 1;
        return -1;
    }

    if (rule->protocol > IPS_PROTO_IP && rule->protocol != IPS_PROTO_ANY) {
        snprintf(rule->error_msg, sizeof(rule->error_msg), "Invalid protocol");
        rule->has_error = 1;
        return -1;
    }

    /* Validate rule has meaningful content */
    if (rule->content_count == 0 && rule->pcre_count == 0) {
        /* Rules without content or pcre are usually metadata-only */
        ips_log_system_async(IPS_LOG_LEVEL_DEBUG,
                            "Rule SID %u has no content or PCRE patterns", rule->sid);
    }

    return 0;
}

/**
 * @brief Print a Suricata rule for debugging
 */
void
ips_suricata_rule_print(ips_suricata_rule_t *rule)
{
    if (!rule)
        return;

    ips_log_system_async(IPS_LOG_LEVEL_INFO,
                        "Rule: SID:%u GID:%u Rev:%u Action:%s Proto:%s",
                        rule->sid, rule->gid, rule->rev,
                        ips_action_to_string(rule->action),
                        ips_protocol_to_string(rule->protocol));

    if (rule->msg[0] != '\0') {
        ips_log_system_async(IPS_LOG_LEVEL_INFO, "  Message: %s", rule->msg);
    }

    if (rule->content_count > 0) {
        ips_log_system_async(IPS_LOG_LEVEL_INFO, "  Contents: %u", rule->content_count);
        for (u32 i = 0; i < rule->content_count; i++) {
            ips_content_match_t *content = &rule->contents[i];
            if (content->pattern && content->pattern_len > 0) {
                ips_log_system_async(IPS_LOG_LEVEL_INFO,
                                    "    [%u] %.*s", i, content->pattern_len, content->pattern);
            }
        }
    }

    if (rule->pcre_count > 0) {
        ips_log_system_async(IPS_LOG_LEVEL_INFO, "  PCREs: %u", rule->pcre_count);
        for (u32 i = 0; i < rule->pcre_count; i++) {
            ips_pcre_match_t *pcre = &rule->pcre_patterns[i];
            if (pcre->pattern) {
                ips_log_system_async(IPS_LOG_LEVEL_INFO, "    [%u] %s", i, pcre->pattern);
            }
        }
    }
}

/* Content match functions are defined in ips_suricata_enhanced_parser.c */

/**
 * @brief Create a PCRE match structure
 */
ips_pcre_match_t *
ips_pcre_match_create(void)
{
    ips_pcre_match_t *pcre = clib_mem_alloc(sizeof(ips_pcre_match_t));
    if (!pcre)
        return NULL;

    clib_memset(pcre, 0, sizeof(*pcre));
    return pcre;
}

/**
 * @brief Free a PCRE match structure
 */
void
ips_pcre_match_free(ips_pcre_match_t *pcre)
{
    if (!pcre)
        return;

    if (pcre->pattern)
        clib_mem_free(pcre->pattern);
    if (pcre->compiled_regex)
        clib_mem_free(pcre->compiled_regex);
    if (pcre->study_data)
        clib_mem_free(pcre->study_data);

    /* Note: This is typically called on array elements, not individual allocations */
}

/**
 * @brief Set PCRE pattern
 */
int
ips_pcre_match_set_pattern(ips_pcre_match_t *pcre, const char *pattern)
{
    if (!pcre || !pattern)
        return -1;

    u32 len = strlen(pattern);
    if (len > IPS_MAX_PCRE_PATTERN_LENGTH)
        return -1;

    pcre->pattern = clib_mem_alloc(len + 1);
    if (!pcre->pattern)
        return -1;

    clib_memcpy(pcre->pattern, pattern, len + 1);
    pcre->pattern_len = len;

    return 0;
}

/**
 * @brief Create a flowbit structure
 */
ips_flowbit_t *
ips_flowbit_create(void)
{
    ips_flowbit_t *flowbit = clib_mem_alloc(sizeof(ips_flowbit_t));
    if (!flowbit)
        return NULL;

    clib_memset(flowbit, 0, sizeof(*flowbit));
    return flowbit;
}

/**
 * @brief Free a flowbit structure
 */
void
ips_flowbit_free(ips_flowbit_t *flowbit)
{
    if (!flowbit)
        return;

    /* Note: This is typically called on array elements, not individual allocations */
}

/**
 * @brief Set flowbit name
 */
int
ips_flowbit_set_name(ips_flowbit_t *flowbit, const char *name)
{
    if (!flowbit || !name)
        return -1;

    u32 len = strlen(name);
    if (len >= IPS_MAX_FLOWBIT_NAME)
        return -1;

    clib_strncpy(flowbit->name, name, sizeof(flowbit->name) - 1);
    flowbit->name[sizeof(flowbit->name) - 1] = '\0';

    return 0;
}

/**
 * @brief Convert byte test operator to string
 */
const char *
ips_byte_test_op_to_string(ips_byte_test_op_t op)
{
    switch (op) {
    case IPS_BYTE_TEST_EQ: return "=";
    case IPS_BYTE_TEST_NE: return "!=";
    case IPS_BYTE_TEST_LT: return "<";
    case IPS_BYTE_TEST_GT: return ">";
    case IPS_BYTE_TEST_LE: return "<=";
    case IPS_BYTE_TEST_GE: return ">=";
    case IPS_BYTE_TEST_AND: return "&";
    case IPS_BYTE_TEST_OR: return "|";
    case IPS_BYTE_TEST_XOR: return "^";
    default: return "unknown";
    }
}

/**
 * @brief Convert flowbit operation to string
 */
const char *
ips_flowbit_op_to_string(ips_flowbit_op_t op)
{
    switch (op) {
    case IPS_FLOWBIT_SET: return "set";
    case IPS_FLOWBIT_UNSET: return "unset";
    case IPS_FLOWBIT_ISSET: return "isset";
    case IPS_FLOWBIT_ISNOTSET: return "isnotset";
    case IPS_FLOWBIT_NOALERT: return "noalert";
    default: return "unknown";
    }
}

/**
 * @brief Convert threshold type to string
 */
const char *
ips_threshold_type_to_string(ips_threshold_type_t type)
{
    switch (type) {
    case IPS_THRESHOLD_LIMIT: return "limit";
    case IPS_THRESHOLD_THRESHOLD: return "threshold";
    case IPS_THRESHOLD_BOTH: return "both";
    default: return "unknown";
    }
}

/* Rule hash function is defined in ips_suricata_enhanced_parser.c */

/**
 * @brief Check if two rules are equal
 */
int
ips_suricata_rule_equals(ips_suricata_rule_t *rule1, ips_suricata_rule_t *rule2)
{
    if (!rule1 || !rule2)
        return 0;

    /* Compare key identifiers */
    if (rule1->sid != rule2->sid || rule1->gid != rule2->gid || rule1->rev != rule2->rev)
        return 0;

    /* Compare content */
    if (rule1->content_count != rule2->content_count)
        return 0;

    for (u32 i = 0; i < rule1->content_count; i++) {
        if (rule1->contents[i].pattern_len != rule2->contents[i].pattern_len)
            return 0;
        if (clib_memcmp(rule1->contents[i].pattern, rule2->contents[i].pattern,
                       rule1->contents[i].pattern_len) != 0)
            return 0;
    }

    return 1;
}

/**
 * @brief Check if rule matches packet basic criteria
 */
int
ips_suricata_rule_matches_packet(ips_suricata_rule_t *rule,
                                 ips_protocol_t proto,
                                 ip46_address_t *src_ip, u16 src_port,
                                 ip46_address_t *dst_ip, u16 dst_port)
{
    if (!rule || !src_ip || !dst_ip)
        return 0;

    /* Check protocol */
    if (rule->protocol != IPS_PROTO_ANY && rule->protocol != proto)
        return 0;

    /* Check IP addresses - simplified check */
    if (!rule->src_ip.is_any && !ip46_address_is_equal(&rule->src_ip.addr, src_ip))
        return 0;
    if (!rule->dst_ip.is_any && !ip46_address_is_equal(&rule->dst_ip.addr, dst_ip))
        return 0;

    /* Check ports */
    if (!rule->src_port.is_any) {
        if (src_port < rule->src_port.start || src_port > rule->src_port.end)
            return 0;
    }
    if (!rule->dst_port.is_any) {
        if (dst_port < rule->dst_port.start || dst_port > rule->dst_port.end)
            return 0;
    }

    return 1;
}