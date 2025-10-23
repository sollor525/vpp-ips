/*
 * ips_detection_module.h - VPP IPS Plugin Detection Engine Module Main Header
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

#ifndef __IPS_DETECTION_MODULE_H__
#define __IPS_DETECTION_MODULE_H__

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/hash.h>
#include <vppinfra/vec.h>

#include "ips.h"
#include "common/ips_proto.h"

/* Detection engine public API */

/**
 * @brief Initialize detection engine
 */
clib_error_t *ips_detection_module_init(ips_main_t *im);

/**
 * @brief Cleanup detection engine
 */
void ips_detection_module_cleanup(void);

/**
 * @brief Initialize advanced detection engine
 */
void ips_detection_advanced_init(void);

/**
 * @brief Run pattern detection with reordering
 */
int ips_detect_patterns_with_reorder(ips_flow_t *flow, vlib_buffer_t *b);

/**
 * @brief Check non-content rules
 */
int ips_check_non_content_rules(ips_flow_t *flow, vlib_buffer_t *b);

/**
 * @brief Process detection results
 */
void ips_process_detection_results(ips_flow_t *flow, u32 rule_matches);

/**
 * @brief Detection statistics structure
 */
typedef struct {
    u64 total_packets_processed;
    u64 total_bytes_processed;
    u64 total_matches;
    u64 total_rules_checked;
    u64 total_detections;
    f64 total_processing_time;
} ips_detection_stats_t;

/**
 * @brief Detection configuration structure
 */
typedef struct {
    u32 enable_advanced_detection;
    u32 enable_optimized_detection;
    u32 max_rules_per_packet;
    u32 log_level;
    u32 timeout_ms;
} ips_detection_config_t;

/**
 * @brief Get detection statistics
 */
void ips_detection_get_stats(ips_detection_stats_t *stats);

/**
 * @brief Reset detection statistics
 */
void ips_detection_reset_stats(void);

/**
 * @brief Set detection configuration
 */
void ips_detection_set_config(const ips_detection_config_t *config);

/* Include all detection module headers */
#include "ips_detection.h"

#endif /* __IPS_DETECTION_MODULE_H__ */