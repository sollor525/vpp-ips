/*
 * ips_flowbits.h - VPP IPS Flowbits Header
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

#ifndef __included_ips_flowbits_h__
#define __included_ips_flowbits_h__

#include "../session/ips_session.h"
#include "ips_suricata_rule_types.h"

/* Flowbit operations - defined in ips_suricata_rule_types.h */

/* Function prototypes */
int ips_flowbit_set(ips_session_t *session, const char *flowbit_name, u32 thread_index);
int ips_flowbit_unset(ips_session_t *session, const char *flowbit_name, u32 thread_index);
int ips_flowbit_is_set(ips_session_t *session, const char *flowbit_name, u32 thread_index);
int ips_flowbit_is_not_set(ips_session_t *session, const char *flowbit_name, u32 thread_index);
int ips_flowbit_execute_operation(ips_session_t *session, const char *flowbit_name,
                                 ips_flowbit_op_t operation, u32 thread_index);
int ips_flowbits_check_rule(ips_suricata_rule_t *rule, ips_session_t *session, u32 thread_index);
void ips_flowbit_cleanup_expired(u32 thread_index, f64 current_time);
void ips_flowbit_get_stats(u32 thread_index, u64 *total_operations, u64 *cache_hits, u64 *cache_misses);
void ips_flowbit_cleanup_thread(u32 thread_index);
int ips_flowbits_init(void);
void ips_flowbits_cleanup(void);

#endif /* __included_ips_flowbits_h__ */
