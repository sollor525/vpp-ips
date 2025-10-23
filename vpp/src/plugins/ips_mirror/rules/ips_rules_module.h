/*
 * ips_rules_module.h - VPP IPS Plugin Rules Module Main Header
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

#ifndef __IPS_RULES_MODULE_H__
#define __IPS_RULES_MODULE_H__

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/vec.h>
#include <vppinfra/hash.h>

#include "ips.h"

/* Rules module public API */

/**
 * @brief Initialize rules module
 */
clib_error_t *ips_rules_module_init(void);

/**
 * @brief Cleanup rules module
 */
void ips_rules_module_cleanup(void);

/**
 * @brief Load rules from file (basic)
 */
int ips_load_rules_from_file(const char *filename);

/**
 * @brief Load rules from file (enhanced)
 */
int ips_load_rules_from_file_enhanced(const char *filename);

/**
 * @brief Load rules from file (enhanced Suricata)
 */
int ips_load_rules_from_file_suricata(const char *filename);

/**
 * @brief Load rules from file (multi-content)
 */
int ips_load_rules_from_file_multi_content(const char *filename);

/**
 * @brief Compile loaded rules
 */
int ips_rules_compile(void);

/**
 * @brief Add individual rule
 */
int ips_add_rule(const ips_rule_t *rule);

/**
 * @brief Delete rule by ID
 */
int ips_delete_rule(u32 rule_id);

/**
 * @brief Find rule by ID
 */
ips_rule_t *ips_find_rule(u32 rule_id);

/**
 * @brief Rules statistics structure
 */
typedef struct {
    u32 total_rules;
    u32 active_rules;
    u32 compiled_rules;
    u64 total_matches;
    u64 total_bytes_processed;
} ips_rules_stats_t;

/**
 * @brief Rules configuration structure
 */
typedef struct {
    u32 max_rules;
    u32 enable_optimization;
    u32 enable_compilation;
    u32 log_level;
} ips_rules_config_t;

/**
 * @brief Get rules statistics
 */
void ips_rules_get_stats(ips_rules_stats_t *stats);

/**
 * @brief Clear all rules
 */
void ips_rules_clear(void);

/**
 * @brief Set rules configuration
 */
void ips_rules_set_config(const ips_rules_config_t *config);

/* Include all rules module headers */
#include "ips_rule_parser.h"

#endif /* __IPS_RULES_MODULE_H__ */