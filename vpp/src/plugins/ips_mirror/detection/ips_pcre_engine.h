/*
 * ips_pcre_engine.h - VPP IPS PCRE/Regex Engine Header
 *
 * Copyright (c) 2024 VPP IPS Project
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#ifndef __IPS_PCRE_ENGINE_H__
#define __IPS_PCRE_ENGINE_H__

#include <vlib/vlib.h>
#include "ips_suricata_rule_types.h"

/* Maximum number of PCRE captures */
#define IPS_PCRE_MAX_CAPTURES 128

/* PCRE engine return codes */
#define IPS_PCRE_SUCCESS           0
#define IPS_PCRE_ERROR            -1
#define IPS_PCRE_NO_MATCH         -2
#define IPS_PCRE_COMPILE_ERROR    -3

/**
 * @brief Initialize the PCRE engine
 * @return 0 on success, -1 on error
 */
int ips_pcre_engine_init(void);

/**
 * @brief Cleanup the PCRE engine
 */
void ips_pcre_engine_cleanup(void);

/**
 * @brief Add PCRE pattern from Suricata rule
 * @param suricata_pcre PCRE match structure from rule
 * @param rule_id Rule ID for tracking
 * @return 0 on success, -1 on error
 */
int ips_pcre_engine_add_pattern(ips_pcre_match_t *suricata_pcre, u32 rule_id);

/**
 * @brief Match data against compiled PCRE pattern
 * @param rule_id Rule ID to match against
 * @param data Data to match
 * @param data_len Length of data
 * @param offset Offset in data to start matching
 * @param matches_found Output for number of matches found
 * @return 0 on success, -1 on error
 */
int ips_pcre_engine_match_pattern(u32 rule_id, const u8 *data, u32 data_len,
                                 u32 offset, u32 *matches_found);

/**
 * @brief Get PCRE engine statistics
 * @param total_matches Output for total matches
 * @param total_compilations Output for total compilations
 * @param compilation_errors Output for compilation errors
 * @param avg_match_time Output for average match time
 */
void ips_pcre_engine_get_stats(u64 *total_matches, u64 *total_compilations,
                              u64 *compilation_errors, f64 *avg_match_time);

/**
 * @brief Reset PCRE engine statistics
 */
void ips_pcre_engine_reset_stats(void);

/**
 * @brief Check if PCRE engine is initialized
 * @return 1 if initialized, 0 otherwise
 */
static inline int
ips_pcre_engine_is_initialized(void)
{
    extern int _ips_pcre_initialized;
    return _ips_pcre_initialized;
}

/**
 * @brief Check if a PCRE pattern is compatible with our engine
 * @param pattern PCRE pattern string
 * @param pattern_len Pattern length
 * @return 1 if compatible, 0 otherwise
 */
int ips_pcre_is_compatible_pattern(const char *pattern, u32 pattern_len);

/**
 * @brief Validate PCRE pattern syntax
 * @param pattern Pattern string to validate
 * @param pattern_len Pattern length
 * @param options PCRE options
 * @param error_msg Output for error message
 * @return 0 if valid, -1 if invalid
 */
int ips_pcre_validate_pattern(const char *pattern, u32 pattern_len,
                             u32 options, char **error_msg);

/**
 * @brief Get pattern match information
 * @param rule_id Rule ID
 * @param match_index Match index (0-based)
 * @param start_offset Output for match start offset
 * @param end_offset Output for match end offset
 * @param capture_groups Output for capture groups count
 * @return 0 on success, -1 on error
 */
int ips_pcre_get_match_info(u32 rule_id, u32 match_index,
                           u32 *start_offset, u32 *end_offset,
                           u32 *capture_groups);

/**
 * @brief Get capture group content
 * @param rule_id Rule ID
 * @param match_index Match index
 * @param capture_index Capture group index
 * @param capture_data Output for capture data
 * @param capture_len Output for capture length
 * @return 0 on success, -1 on error
 */
int ips_pcre_get_capture_group(u32 rule_id, u32 match_index, u32 capture_index,
                              const char **capture_data, u32 *capture_len);

#endif /* __IPS_PCRE_ENGINE_H__ */