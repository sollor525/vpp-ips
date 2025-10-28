/*
 * ips_suricata_integration.c - Integration layer for Suricata Engine
 *
 * Copyright (c) 2024 VPP IPS Project
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#include <vlib/vlib.h>
#include <vppinfra/string.h>

#include "ips_suricata_enhanced_engine.h"
#include "ips_suricata_rule_types.h"
#include "ips_suricata_enhanced_parser.h"
#include "ips_flowbits.h"
#include "ips_byte_operations.h"
#include "ips_rule_index.h"
#include "ips_suricata_integration.h"
#include "../ips_logging.h"

/* Forward declarations */
void ips_suricata_inspect_reset_stats(u32 thread_index);

/* Integration state */
typedef struct {
    u8 initialized;
    u32 rules_loaded;
    u32 rules_enabled;
    u32 rules_disabled;
    u32 rules_with_errors;
    f64 init_time;
    char last_loaded_file[256];
} ips_suricata_integration_t;

static ips_suricata_integration_t integration = {0};

/**
 * @brief Initialize Suricata integration
 */
clib_error_t *
ips_suricata_integration_init(vlib_main_t *vm)
{
    if (integration.initialized) {
        return 0;  /* Already initialized */
    }

    /* Initialize detection engine */
    ips_detection_config_t config = {
        .enable_fast_path = 1,
        .enable_content_caching = 1,
        .enable_rule_groups = 1,
        .enable_flowbits = 1,
        .max_stages_per_packet = 6,
        .max_rules_per_packet = 64,
        .enable_rule_prefetch = 1,
        .cache_size = 1024,
    };

    clib_error_t *error = ips_suricata_engine_init(&config);
    if (error) {
        return error;
    }

    /* Initialize supporting modules */
    ips_rule_index_init();
    ips_flowbits_init();

    integration.initialized = 1;
    integration.init_time = vlib_time_now(vm);

    ips_log_system_async(IPS_LOG_LEVEL_INFO,
                        "Suricata integration initialized");

    return 0;
}

/**
 * @brief Cleanup Suricata integration
 */
void
ips_suricata_integration_cleanup(void)
{
    if (!integration.initialized)
        return;

    /* Cleanup modules */
    ips_rule_index_cleanup();
    ips_flowbits_cleanup();
    ips_suricata_engine_cleanup();

    clib_memset(&integration, 0, sizeof(integration));
}

/**
 * @brief Load default rules
 */
int
ips_suricata_load_default_rules(void)
{
    if (!integration.initialized) {
        return -1;
    }

    const char *default_rules_file = "rules/default.rules";
    return ips_suricata_load_rules_file(default_rules_file);
}

/**
 * @brief Load rules from file
 */
int
ips_suricata_load_rules_file(const char *filename)
{
    if (!integration.initialized || !filename) {
        return -1;
    }

    ips_log_system_async(IPS_LOG_LEVEL_INFO,
                        "Loading Suricata rules from: %s", filename);

    /* Create rule table */
    ips_suricata_rule_table_t rule_table = {0};

    /* Parse rules file */
    int rules_loaded = ips_suricata_parse_rules_file(filename, &rule_table);
    if (rules_loaded < 0) {
        ips_log_system_async(IPS_LOG_LEVEL_ERROR,
                            "Failed to parse rules file: %s", filename);
        return -1;
    }

    /* Add rules to engine */
    int rules_added = 0;
    /* TODO: Iterate through rule_table and add to engine */
    /* For now, just update statistics */

    integration.rules_loaded += rules_loaded;
    integration.rules_enabled += rules_added;
    clib_strncpy(integration.last_loaded_file, filename,
                sizeof(integration.last_loaded_file) - 1);

    ips_log_system_async(IPS_LOG_LEVEL_INFO,
                        "Loaded %u Suricata rules from %s (%u added)",
                        rules_loaded, filename, rules_added);

    return rules_loaded;
}

/**
 * @brief Add rule programmatically
 */
int
ips_suricata_add_rule(const char *rule_text)
{
    if (!integration.initialized || !rule_text) {
        return -1;
    }

    /* Parse rule */
    ips_suricata_rule_t *rule = ips_suricata_parse_rule(rule_text, "<programmatic>", 0);
    if (!rule) {
        return -1;
    }

    /* Validate and optimize rule */
    if (ips_suricata_validate_and_optimize_rule(rule) < 0) {
        ips_suricata_rule_free(rule);
        return -1;
    }

    /* Add to engine */
    if (ips_suricata_engine_add_rule(rule) < 0) {
        ips_suricata_rule_free(rule);
        return -1;
    }

    /* Add to index */
    if (ips_rule_index_add_rule(rule) < 0) {
        ips_log_system_async(IPS_LOG_LEVEL_WARNING,
                            "Failed to add rule to index: SID %u", rule->sid);
    }

    integration.rules_loaded++;
    if (rule->enabled) {
        integration.rules_enabled++;
    } else {
        integration.rules_disabled++;
    }

    ips_log_system_async(IPS_LOG_LEVEL_DEBUG,
                        "Added rule: SID %u GID %u Rev %u Action %s",
                        rule->sid, rule->gid, rule->rev,
                        ips_action_to_string(rule->action));

    return 0;
}

/**
 * @brief Remove rule by SID
 */
int
ips_suricata_remove_rule(u32 sid)
{
    if (!integration.initialized) {
        return -1;
    }

    /* Remove from index */
    if (ips_rule_index_remove_rule(sid) < 0) {
        return -1;
    }

    /* Remove from engine */
    if (ips_suricata_engine_remove_rule(sid) < 0) {
        return -1;
    }

    integration.rules_loaded--;

    ips_log_system_async(IPS_LOG_LEVEL_INFO,
                        "Removed rule: SID %u", sid);

    return 0;
}

/**
 * @brief Enable/disable rule
 */
int
ips_suricata_set_rule_state(u32 sid, u8 enabled)
{
    if (!integration.initialized) {
        return -1;
    }

    if (ips_suricata_engine_set_rule_state(sid, enabled) < 0) {
        return -1;
    }

    if (enabled) {
        integration.rules_enabled++;
        integration.rules_disabled--;
    } else {
        integration.rules_enabled--;
        integration.rules_disabled++;
    }

    ips_log_system_async(IPS_LOG_LEVEL_INFO,
                        "%s rule: SID %u", enabled ? "Enabled" : "Disabled", sid);

    return 0;
}

/**
 * @brief Get rule statistics
 */
void
ips_suricata_get_rule_stats(u32 *total_rules, u32 *enabled_rules,
                            u32 *disabled_rules, u32 *rules_with_errors)
{
    if (!integration.initialized) {
        if (total_rules) *total_rules = 0;
        if (enabled_rules) *enabled_rules = 0;
        if (disabled_rules) *disabled_rules = 0;
        if (rules_with_errors) *rules_with_errors = 0;
        return;
    }

    if (total_rules) *total_rules = integration.rules_loaded;
    if (enabled_rules) *enabled_rules = integration.rules_enabled;
    if (disabled_rules) *disabled_rules = integration.rules_disabled;
    if (rules_with_errors) *rules_with_errors = integration.rules_with_errors;

    /* Get engine statistics */
    ips_detection_stats_t engine_stats;
    ips_suricata_engine_get_stats(&engine_stats);
}

/**
 * @brief Get detailed statistics
 */
void
ips_suricata_get_detailed_stats(ips_detection_stats_t *engine_stats,
                                u64 *rule_index_hits,
                                u64 *flowbit_operations)
{
    if (!integration.initialized) {
        if (engine_stats) clib_memset(engine_stats, 0, sizeof(*engine_stats));
        if (rule_index_hits) *rule_index_hits = 0;
        if (flowbit_operations) *flowbit_operations = 0;
        return;
    }

    if (engine_stats) {
        ips_suricata_engine_get_stats(engine_stats);
    }

    if (rule_index_hits) {
        u64 total_lookups, protocol_hits, port_hits, content_hits, sid_hits, index_misses;
        ips_rule_index_get_stats(&total_lookups, &protocol_hits, &port_hits, &content_hits, &sid_hits, &index_misses);
        *rule_index_hits = protocol_hits + port_hits + content_hits;
    }

    if (flowbit_operations) {
        u64 total_ops, cache_hits, cache_misses;
        ips_flowbit_get_stats(vlib_get_thread_index(), &total_ops,
                               &cache_hits, &cache_misses);
        *flowbit_operations = total_ops;
    }
}

/**
 * @brief Reset statistics
 */
void
ips_suricata_reset_stats(void)
{
    if (!integration.initialized)
        return;

    /* Reset engine statistics */
    ips_detection_stats_t engine_stats;
    ips_suricata_engine_get_stats(&engine_stats);
    clib_memset(&engine_stats, 0, sizeof(engine_stats));

    /* Reset index statistics */
    ips_rule_index_reset_stats();

    /* Reset thread statistics */
    u32 thread_index = vlib_get_thread_index();
    ips_suricata_inspect_reset_stats(thread_index);
}

/**
 * @brief Check if integration is initialized
 */
u8
ips_suricata_is_initialized(void)
{
    return integration.initialized;
}

/**
 * @brief Get initialization time
 */
f64
ips_suricata_get_init_time(void)
{
    return integration.init_time;
}

/**
 * @brief Get last loaded file
 */
const char *
ips_suricata_get_last_loaded_file(void)
{
    if (!integration.initialized || integration.last_loaded_file[0] == '\0') {
        return NULL;
    }
    return integration.last_loaded_file;
}

/**
 * @brief Validate rule configuration
 */
int
ips_suricata_validate_config(void)
{
    if (!integration.initialized) {
        return -1;
    }

    /* Check if any rules are loaded */
    if (integration.rules_loaded == 0) {
        ips_log_system_async(IPS_LOG_LEVEL_WARNING,
                            "No Suricata rules loaded");
        return 1;  /* Warning, not error */
    }

    /* Check if any rules are enabled */
    if (integration.rules_enabled == 0) {
        ips_log_system_async(IPS_LOG_LEVEL_ERROR,
                            "No Suricata rules are enabled");
        return -1;
    }

    /* Check error rate */
    if (integration.rules_loaded > 0) {
        u32 error_rate = (integration.rules_with_errors * 100) / integration.rules_loaded;
        if (error_rate > 50) {
            ips_log_system_async(IPS_LOG_LEVEL_ERROR,
                                "High rule error rate: %u%%", error_rate);
            return -1;
        }
    }

    ips_log_system_async(IPS_LOG_LEVEL_INFO,
                        "Suricata configuration validation passed: %u total, %u enabled, %u errors",
                        integration.rules_loaded, integration.rules_enabled,
                        integration.rules_with_errors);

    return 0;
}

/**
 * @brief Create test rule
 */
int
ips_suricata_create_test_rule(void)
{
    const char *test_rule =
        "alert tcp any any -> any any ("
        "msg:\"Test Suricata Rule\"; "
        "content:\"GET\"; "
        "http_method; "
        "sid:1000001; "
        "rev:1; "
        "priority:1; "
        "classtype:web-application-attack; "
        ")";

    return ips_suricata_add_rule(test_rule);
}

/**
 * @brief Load basic rule set for testing
 */
int
ips_suricata_load_basic_rules(void)
{
    if (!ips_suricata_is_initialized()) {
        return -1;
    }

    /* Create a few basic test rules */
    const char *basic_rules[] = {
        /* HTTP GET test */
        "alert tcp any any -> any any (msg:\"HTTP GET Detected\"; content:\"GET \"; http_method; sid:1000001; rev:1;)",

        /* SSH test */
        "alert tcp any any -> any 22 (msg:\"SSH Connection\"; content:\"SSH-\"; sid:1000002; rev:1;)",

        /* DNS test */
        "alert udp any any -> any 53 (msg:\"DNS Query\"; content:\"\\x00\\x01\\x00\\x01\"; sid:1000003; rev:1;)",

        /* TLS test */
        "alert tcp any any -> any 443 (msg:\"TLS Handshake\"; content:\"\\x16\\x03\"; sid:1000004; rev:1;)",

        /* Generic test */
        "alert ip any any -> any any (msg:\"Generic Test Rule\"; content:\"TEST\"; sid:1000005; rev:1;)"
    };

    int rules_added = 0;
    for (u32 i = 0; i < ARRAY_LEN(basic_rules); i++) {
        if (ips_suricata_add_rule(basic_rules[i]) == 0) {
            rules_added++;
        }
    }

    ips_log_system_async(IPS_LOG_LEVEL_INFO,
                        "Loaded %u basic Suricata rules for testing", rules_added);

    return rules_added;
}

/**
 * @brief Initialize default rules (legacy function for CLI compatibility)
 */
int
ips_suricata_init_default_rules(void)
{
    return ips_suricata_load_basic_rules();
}