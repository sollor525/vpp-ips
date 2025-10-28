/*
 * ips_hyperscan_engine.h - VPP IPS Hyperscan Integration Engine Header
 *
 * Copyright (c) 2024 VPP IPS Project
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#ifndef __IPS_HYPERSCAN_ENGINE_H__
#define __IPS_HYPERSCAN_ENGINE_H__

#include <vlib/vlib.h>
#include "ips_suricata_rule_types.h"
#include "ips_suricata_enhanced_engine.h"

/* Maximum number of patterns per database */
#define IPS_HS_MAX_PATTERNS 1024

/* Default Hyperscan flags */
#define IPS_HS_DEFAULT_FLAGS (HS_FLAG_CASELESS | HS_FLAG_SOM_LEFTMOST)

/* Forward declarations */
typedef struct ips_hs_database_t ips_hs_database_t;

/**
 * @brief Initialize the Hyperscan engine
 * @return 0 on success, -1 on error
 */
int ips_hyperscan_engine_init(void);

/**
 * @brief Cleanup the Hyperscan engine
 */
void ips_hyperscan_engine_cleanup(void);

/**
 * @brief Add rules to the Hyperscan engine
 * @param rules Array of rules to add
 * @param rule_count Number of rules
 * @return 0 on success, -1 on error
 */
int ips_hyperscan_engine_add_rules(ips_suricata_rule_t **rules, u32 rule_count);

/**
 * @brief Scan packet data with Hyperscan
 * @param packet_ctx Packet context for match results
 * @param data Packet data to scan
 * @param data_len Length of packet data
 * @return Number of matches found, or -1 on error
 */
int ips_hyperscan_engine_scan_packet(ips_packet_context_t *packet_ctx,
                                    const u8 *data, u32 data_len);

/**
 * @brief Get Hyperscan engine statistics
 * @param total_scans Output for total scans performed
 * @param total_matches Output for total matches found
 * @param avg_scan_time Output for average scan time
 */
void ips_hyperscan_engine_get_stats(u64 *total_scans, u64 *total_matches,
                                   f64 *avg_scan_time);

/**
 * @brief Reset Hyperscan engine statistics
 */
void ips_hyperscan_engine_reset_stats(void);

/**
 * @brief Check if Hyperscan engine is initialized
 * @return 1 if initialized, 0 otherwise
 */
static inline int
ips_hyperscan_engine_is_initialized(void)
{
    extern int _ips_hs_initialized;
    return _ips_hs_initialized;
}

/**
 * @brief Convert Suricata content modifiers to Hyperscan flags
 * @param content Content match structure
 * @return Hyperscan flags
 */
unsigned int ips_content_to_hs_flags(const ips_content_match_t *content);

/**
 * @brief Check if a rule is suitable for Hyperscan matching
 * @param rule Suricata rule to check
 * @return 1 if suitable, 0 otherwise
 */
int ips_rule_is_hyperscan_compatible(const ips_suricata_rule_t *rule);

/**
 * @brief Extract content patterns from a rule for Hyperscan compilation
 * @param rule Source rule
 * @param patterns Output array for pattern strings
 * @param flags Output array for pattern flags
 * @param ids Output array for pattern IDs
 * @param max_patterns Maximum number of patterns to extract
 * @return Number of patterns extracted, or -1 on error
 */
int ips_rule_extract_hyperscan_patterns(const ips_suricata_rule_t *rule,
                                       char **patterns, unsigned int *flags,
                                       unsigned int *ids, u32 max_patterns);

#endif /* __IPS_HYPERSCAN_ENGINE_H__ */