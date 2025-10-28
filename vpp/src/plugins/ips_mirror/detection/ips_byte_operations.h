/*
 * ips_byte_operations.h - VPP IPS Byte Operations Header
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

#ifndef __included_ips_byte_operations_h__
#define __included_ips_byte_operations_h__

#include "ips_suricata_rule_types.h"

/* Function prototypes */
int ips_parse_byte_test(const char *params, ips_byte_test_t *byte_test);
int ips_parse_byte_jump(const char *params, ips_byte_jump_t *byte_jump);
int ips_byte_test_execute(const ips_byte_test_t *byte_test,
                         const u8 *data, u32 data_len, u32 *result);
int ips_byte_jump_execute(const ips_byte_jump_t *byte_jump,
                         const u8 *data, u32 data_len, u32 *offset);
int ips_byte_test_check_rule(ips_suricata_rule_t *rule,
                           ips_packet_context_t *ctx);
int ips_byte_jump_execute_rule(ips_suricata_rule_t *rule,
                             ips_packet_context_t *ctx);
ips_byte_test_t *ips_byte_test_clone(const ips_byte_test_t *src);
ips_byte_jump_t *ips_byte_jump_clone(const ips_byte_jump_t *src);
void ips_byte_test_free(ips_byte_test_t *byte_test);
void ips_byte_jump_free(ips_byte_jump_t *byte_jump);

#endif /* __included_ips_byte_operations_h__ */
