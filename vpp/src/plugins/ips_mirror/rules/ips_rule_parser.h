/*
 * ips_rule_parser.h - VPP IPS Plugin Rule Parser Header
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

#ifndef __included_ips_rule_parser_h__
#define __included_ips_rule_parser_h__

#include "ips.h"

/* Function prototypes */
int ips_load_rules_from_file (const char *filename);
int ips_load_rules_from_file_enhanced (const char *filename);
int ips_load_advanced_rules_from_file (const char *filename);
int parse_advanced_rule_line (char *line, ips_rule_t *rule);

#endif /* __included_ips_rule_parser_h__ */
