/*
 * ips_suricata_integration.h - VPP IPS Plugin Suricata Integration Header
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

#ifndef __IPS_SURICATA_INTEGRATION_H__
#define __IPS_SURICATA_INTEGRATION_H__

#include <vlib/vlib.h>
#include "ips_suricata_engine.h"

/**
 * @brief Initialize Suricata integration
 */
clib_error_t *ips_suricata_integration_init(vlib_main_t *vm);

/**
 * @brief Cleanup Suricata integration
 */
void ips_suricata_integration_cleanup(void);

/**
 * @brief Load default rules
 */
int ips_suricata_load_default_rules(void);

/**
 * @brief Load rules from file
 */
int ips_suricata_load_rules_file(const char *filename);

/**
 * @brief Add rule programmatically
 */
int ips_suricata_add_rule(const char *rule_text);

/**
 * @brief Remove rule by SID
 */
int ips_suricata_remove_rule(u32 sid);

/**
 * @brief Enable/disable rule
 */
int ips_suricata_set_rule_state(u32 sid, u8 enabled);

/**
 * @brief Get rule statistics
 */
void ips_suricata_get_rule_stats(u32 *total_rules, u32 *enabled_rules,
                                u32 *disabled_rules, u32 *rules_with_errors);

/**
 * @brief Get detailed statistics
 */
void ips_suricata_get_detailed_stats(ips_detection_stats_t *engine_stats,
                                    u64 *rule_index_hits,
                                    u64 *flowbit_operations);

/**
 * @brief Reset statistics
 */
void ips_suricata_reset_stats(void);

/**
 * @brief Check if integration is initialized
 */
u8 ips_suricata_is_initialized(void);

/**
 * @brief Get initialization time
 */
f64 ips_suricata_get_init_time(void);

/**
 * @brief Get last loaded file
 */
const char *ips_suricata_get_last_loaded_file(void);

/**
 * @brief Validate rule configuration
 */
int ips_suricata_validate_config(void);

/**
 * @brief Create test rule
 */
int ips_suricata_create_test_rule(void);

/**
 * @brief Load basic rule set for testing
 */
int ips_suricata_load_basic_rules(void);

/**
 * @brief Initialize default rules (legacy function for CLI compatibility)
 */
int ips_suricata_init_default_rules(void);

#endif /* __IPS_SURICATA_INTEGRATION_H__ */