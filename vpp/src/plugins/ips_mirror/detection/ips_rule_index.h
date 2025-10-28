/*
 * ips_rule_index.h - VPP IPS Rule Index Header
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

#ifndef __included_ips_rule_index_h__
#define __included_ips_rule_index_h__

#include "ips_suricata_rule_types.h"
#include "ips_suricata_enhanced_engine.h"

/* Rule index entry */
typedef struct {
    ips_suricata_rule_t *rule;
    u32 rule_hash;
    u8 priority;          /* Rule priority for ordering */
    u8 content_min_len;   /* Shortest content length */
    u16 fast_pattern_idx; /* Index of fast pattern content */
} ips_rule_index_entry_t;

/* Function prototypes */
int ips_rule_index_add_rule(ips_suricata_rule_t *rule);
int ips_rule_index_remove_rule(u32 sid);
ips_rule_index_entry_t *ips_find_candidate_rules(ips_packet_context_t *ctx, u32 *count);
int ips_rule_index_init(void);
void ips_rule_index_cleanup(void);
void ips_rule_index_reset_stats(void);
void ips_rule_index_get_stats(u64 *total_lookups, u64 *protocol_hits, u64 *port_hits, u64 *content_hits, u64 *sid_hits, u64 *index_misses);

#endif /* __included_ips_rule_index_h__ */
