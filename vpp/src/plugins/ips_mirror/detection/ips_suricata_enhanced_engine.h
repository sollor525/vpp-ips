/*
 * ips_suricata_enhanced_engine.h - VPP IPS Enhanced Suricata Detection Engine
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

#ifndef __IPS_SURICATA_ENHANCED_ENGINE_H__
#define __IPS_SURICATA_ENHANCED_ENGINE_H__

#include <vlib/vlib.h>
#include <vnet/ip/ip.h>
#include <vppinfra/hash.h>
#include "ips_suricata_rule_types.h"
#include "../session/ips_session.h"
#include "../protocols/ips_protocol_detection.h"

/* Maximum number of rules that can match a single packet */

/* Maximum number of content matches per rule */
#define IPS_MAX_CONTENTS_PER_RULE 32

/* Matching stages */
typedef enum
{
    IPS_MATCH_STAGE_PROTOCOL = 0,
    IPS_MATCH_STAGE_IP_HEADER,
    IPS_MATCH_STAGE_TRANSPORT,
    IPS_MATCH_STAGE_APPLICATION,
    IPS_MATCH_STAGE_CONTENT,
    IPS_MATCH_STAGE_OPTIONS,
    IPS_MATCH_STAGE_COMPLETE
} ips_match_stage_t;

/* Matching result */
typedef enum
{
    IPS_MATCH_NO_MATCH = 0,
    IPS_MATCH_PARTIAL,
    IPS_MATCH_COMPLETE,
    IPS_MATCH_ERROR
} ips_match_result_t;

/* Packet context for matching */
typedef struct
{
    /* Packet information */
    u32 thread_index;
    u32 packet_index;
    vlib_buffer_t *buffer;
    u8 *packet_data;
    u32 packet_len;

    /* Protocol information */
    ips_protocol_t protocol;
    ip46_address_t src_ip;
    ip46_address_t dst_ip;
    u16 src_port;
    u16 dst_port;
    u8 direction;  /* 0=client->server, 1=server->client */

    /* Transport layer information */
    tcp_header_t *tcp_header;
    udp_header_t *udp_header;
    u8 tcp_flags;
    u32 seq;
    u32 ack;
    u16 window;

    /* Application layer information */
    ips_alproto_t app_proto;
    ips_proto_detect_ctx_t *proto_detect_ctx;

    /* Matching state */
    u32 current_stage;
    u32 rules_examined;
    u32 matches_found;
    ips_suricata_rule_t *matched_rules[IPS_MAX_MATCHES_PER_PACKET];
    u8 match_reasons[IPS_MAX_MATCHES_PER_PACKET];

    /* Performance tracking */
    f64 start_time;
    f64 stage_times[IPS_MATCH_STAGE_COMPLETE];

} ips_packet_context_t;

/* Rule group for optimization */
typedef struct
{
    u32 group_id;
    char name[64];
    ips_suricata_rule_t **rules;
    u32 rule_count;
    u32 hash;
    u8 protocol_filter;
    u8 port_filter_active;
    u16 port_start, port_end;
} ips_rule_group_t;

/* Content match context */
typedef struct
{
    const u8 *data;
    u32 data_len;
    u32 start_offset;
    u32 end_offset;
    u32 relative_offset;
    u8 within_distance_active;
    u32 distance_offset;
} ips_content_match_context_t;

/* Flowbit state */
typedef struct
{
    char name[IPS_MAX_FLOWBIT_NAME];
    u8 is_set;
    u8 is_persistent;
    f64 set_time;
    u32 set_packet_count;
    u32 access_count;
} ips_flowbit_state_t;

/* Session flowbit state */
typedef struct
{
    ips_flowbit_state_t *flowbits;
    u32 flowbit_count;
    u64 last_access_time;
    u32 access_count;
} ips_session_flowbits_t;

/* Detection engine configuration */
typedef struct
{
    /* Performance settings */
    u8 enable_fast_path;
    u8 enable_content_caching;
    u8 enable_rule_groups;
    u8 enable_flowbits;
    u8 enable_stream_reassembly;
    u8 max_stages_per_packet;
    u32 max_rules_per_packet;

    /* Optimization settings */
    u8 enable_rule_prefetch;
    u8 enable_parallel_matching;
    u8 enable_match_caching;
    u32 cache_size;
    u32 prefetch_distance;

    /* Debug settings */
    u8 enable_debug_logging;
    u8 enable_performance_tracking;
    u32 max_debug_rules;
} ips_detection_config_t;

/* Detection engine statistics */
typedef struct
{
    /* Overall statistics */
    u64 packets_processed;
    u64 rules_matched;
    u64 alerts_generated;
    u64 drops_generated;
    u64 rejections_generated;

    /* Performance statistics */
    f64 avg_processing_time;
    f64 max_processing_time;
    f64 avg_content_match_time;
    u64 cache_hits;
    u64 cache_misses;

    /* Stage statistics */
    u64 stage_attempts[IPS_MATCH_STAGE_COMPLETE];
    u64 stage_failures[IPS_MATCH_STAGE_COMPLETE];
    f64 avg_stage_times[IPS_MATCH_STAGE_COMPLETE];

    /* Rule statistics */
    u64 rule_match_counts[IPS_MAX_CONTENTS_PER_RULE];
    u32 most_matched_rules[16];
    u64 most_matched_counts[16];

    /* Error statistics */
    u64 parse_errors;
    u64 match_errors;
    u64 memory_errors;
    u64 timeout_errors;

} ips_detection_stats_t;

/* Global detection engine state */
typedef struct
{
    ips_detection_config_t config;
    ips_detection_stats_t stats;
    ips_rule_group_t *rule_groups;
    u32 rule_group_count;
    hash_t *rule_hash_by_sid;
    hash_t *rule_hash_by_content;
    hash_t *rule_hash_by_protocol;
    u32 total_rules;
    u32 enabled_rules;
    u8 initialized;
} ips_detection_engine_t;

/* Function prototypes */

/**
 * @brief Check if detection engine is initialized
 * @return 1 if initialized, 0 otherwise
 */
u8 ips_suricata_engine_is_initialized(void);

/**
 * @brief Initialize the enhanced detection engine
 * @param config Engine configuration (can be NULL for defaults)
 * @return clib_error_t * on success, NULL on error
 */
clib_error_t *ips_suricata_engine_init(const ips_detection_config_t *config);

/**
 * @brief VPP-compatible initialization function
 * @param vm VPP main structure
 * @return clib_error_t * on success, NULL on error
 */
clib_error_t *ips_suricata_engine_init_vpp(vlib_main_t *vm);

/**
 * @brief Cleanup detection engine
 */
void ips_suricata_engine_cleanup(void);

/**
 * @brief Add rule to detection engine
 * @param rule Rule to add
 * @return 0 on success, -1 on error
 */
int ips_suricata_engine_add_rule(ips_suricata_rule_t *rule);

/**
 * @brief Remove rule from detection engine
 * @param sid Security ID of rule to remove
 * @return 0 on success, -1 on error
 */
int ips_suricata_engine_remove_rule(u32 sid);

/**
 * @brief Enable/disable rule
 * @param sid Security ID of rule
 * @param enabled 1 to enable, 0 to disable
 * @return 0 on success, -1 on error
 */
int ips_suricata_engine_set_rule_state(u32 sid, u8 enabled);

/**
 * @brief Match packet against all rules
 * @param session Session context
 * @param b Packet buffer
 * @param packet_context Output packet context
 * @return Number of matches, or -1 on error
 */
int ips_suricata_engine_match_packet(ips_session_t *session,
                                    vlib_buffer_t *b,
                                    ips_packet_context_t *packet_context);

/**
 * @brief Match packet against specific rule
 * @param rule Rule to match against
 * @param packet_context Packet context
 * @return Match result
 */
ips_match_result_t ips_suricata_engine_match_rule(ips_suricata_rule_t *rule,
                                                  ips_packet_context_t *packet_context);

/**
 * @brief Execute rule action
 * @param rule Rule that matched
 * @param packet_context Packet context
 * @return Action result (0=pass, 1=block)
 */
int ips_suricata_engine_execute_action(ips_suricata_rule_t *rule,
                                      ips_packet_context_t *packet_context);

/* Stage-specific matching functions */

/**
 * @brief Match protocol stage
 */
ips_match_result_t ips_match_protocol(ips_suricata_rule_t *rule,
                                     ips_packet_context_t *ctx);

/**
 * @brief Match IP header stage
 */
ips_match_result_t ips_match_ip_header(ips_suricata_rule_t *rule,
                                      ips_packet_context_t *ctx);

/**
 * @brief Match transport layer stage
 */
ips_match_result_t ips_match_transport(ips_suricata_rule_t *rule,
                                      ips_packet_context_t *ctx);

/**
 * @brief Match application layer stage
 */
ips_match_result_t ips_match_application(ips_suricata_rule_t *rule,
                                       ips_packet_context_t *ctx);

/**
 * @brief Match content stage
 */
ips_match_result_t ips_match_content(ips_suricata_rule_t *rule,
                                    ips_packet_context_t *ctx);

/**
 * @brief Match rule options stage
 */
ips_match_result_t ips_match_options(ips_suricata_rule_t *rule,
                                    ips_packet_context_t *ctx);

/* Content matching functions */

/**
 * @brief Match single content pattern
 */
int ips_match_content_pattern(const ips_content_match_t *content,
                             const u8 *data, u32 data_len,
                             ips_content_match_context_t *match_ctx);

/**
 * @brief Match content with modifiers
 */
int ips_match_content_with_modifiers(const ips_content_match_t *content,
                                    const u8 *data, u32 data_len,
                                    u32 *relative_offset);

/**
 * @boyie Find content pattern in data
 */
const u8 *ips_find_content_pattern(const u8 *pattern, u32 pattern_len,
                                  const u8 *data, u32 data_len,
                                  u8 nocase);

/* Option matching functions */

/**
 * @brief Match byte_test option
 */
int ips_match_byte_test(const ips_byte_test_t *byte_test,
                       const u8 *data, u32 data_len,
                       u32 *relative_offset);

/**
 * @brief Match byte_jump option
 */
int ips_match_byte_jump(const ips_byte_jump_t *byte_jump,
                       const u8 *data, u32 data_len,
                       ips_content_match_context_t *match_ctx);

/**
 * @brief Match PCRE pattern
 */
int ips_match_pcre(const ips_pcre_match_t *pcre,
                  const u8 *data, u32 data_len,
                  ips_content_match_context_t *match_ctx);

/**
 * @brief Match flow condition
 */
int ips_match_flow(const ips_suricata_rule_t *rule,
                  ips_session_t *session,
                  ips_packet_context_t *ctx);

/* Flowbit management */

/**
 * @brief Set flowbit for session
 */
int ips_flowbit_set(ips_session_t *session,
                    const char *name,
                    u32 thread_index);

/**
 * @brief Unset flowbit for session
 */
int ips_flowbit_unset(ips_session_t *session,
                      const char *name,
                      u32 thread_index);

/**
 * @brief Check if flowbit is set
 */
int ips_flowbit_is_set(ips_session_t *session,
                       const char *name,
                       u32 thread_index);

/**
 * @brief Get session flowbits
 */
ips_session_flowbits_t *ips_get_session_flowbits(ips_session_t *session,
                                                 u32 thread_index);

/**
 * @brief Cleanup expired flowbits
 */
void ips_flowbit_cleanup_expired(u32 thread_index, f64 current_time);

/* Performance optimization functions */

/**
 * @brief Build rule indexes
 */
int ips_build_rule_indexes(void);

/**
 * @brief Create rule groups
 */
int ips_create_rule_groups(void);

/**
 * @brief Optimize rule ordering
 */
int ips_optimize_rule_ordering(void);

/**
 * @brief Prefetch rules for packet
 */
void ips_prefetch_rules(ips_packet_context_t *ctx);

/* Statistics and debugging */

/**
 * @brief Get engine statistics
 */
void ips_suricata_engine_get_stats(ips_detection_stats_t *stats);

/**
 * @brief Reset engine statistics
 */
void ips_suricata_engine_reset_stats(void);

/**
 * @brief Get packet processing trace
 */
int ips_get_packet_trace(ips_packet_context_t *ctx,
                        char *buffer, u32 buffer_len);

/**
 * @brief Enable debug logging for specific rule
 */
void ips_enable_rule_debug(u32 sid);

/**
 * @brief Disable debug logging for specific rule
 */
void ips_disable_rule_debug(u32 sid);

#endif /* __IPS_SURICATA_ENHANCED_ENGINE_H__ */