/*
 * ips_detection.h - VPP IPS Plugin Detection Engine Header
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

#ifndef __included_ips_detection_h__
#define __included_ips_detection_h__

#include "ips.h"

/* Detection context for pattern matching */
typedef struct
{
    ips_flow_t *flow;
    vlib_buffer_t *buffer;
    ips_rule_t *matched_rules[IPS_MAX_MATCHES_PER_PACKET];
    u64 match_offsets[IPS_MAX_MATCHES_PER_PACKET];   /* Stream-aware match positions (64-bit for large streams) */
    u32 match_lengths[IPS_MAX_MATCHES_PER_PACKET];   /* Match lengths for analysis */
    u32 match_count;
} ips_detection_context_t;

/* Error definitions */
#define foreach_ips_error                               \
    _(PROCESSED, "Packets processed")                   \
    _(DROPPED, "Packets dropped")                       \
    _(ALERTS, "Alerts generated")                       \
    _(SESSION_CREATE_FAILED, "Session creation failed") \
    _(RULE_MATCH_FAILED, "Rule matching failed")       \
    _(PARSE_ERROR, "Packet parsing error")              \
    _(HYPERSCAN_ERROR, "Hyperscan error")               \
    _(MEMORY_ERROR, "Memory allocation error")

/* Function prototypes */
clib_error_t *ips_detection_init (ips_main_t * im);
int ips_rules_compile (void);
int ips_detect_patterns (ips_flow_t * flow, vlib_buffer_t * b);
int ips_rule_match (ips_rule_t * rule, ips_flow_t * flow, vlib_buffer_t * b);
void ips_generate_alert (ips_rule_t * rule, ips_flow_t * flow, vlib_buffer_t * b);
int ips_rule_add (ips_rule_t * rule);
int ips_rule_delete (u32 rule_id);
ips_rule_t *ips_rule_lookup (u32 rule_id);

/* Optimized detection functions */
int ips_rules_compile_optimized (void);
int ips_detect_patterns_optimized (ips_flow_t * flow, vlib_buffer_t * b);
int ips_match_rule_advanced_minimal (vlib_buffer_t *b, ips_flow_t *flow, ips_rule_t *rule, u32 thread_index);

#endif /* __included_ips_detection_h__ */
