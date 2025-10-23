/*
 * ips_proto.h - VPP IPS Plugin Protocol Parsing Header
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

#ifndef __included_ips_proto_h__
#define __included_ips_proto_h__

#include "ips.h"

/* Function prototypes */
int ips_parse_ethernet (vlib_buffer_t * b, ips_flow_t * flow);
int ips_parse_ip4 (vlib_buffer_t * b, ips_flow_t * flow);
int ips_parse_ip6 (vlib_buffer_t * b, ips_flow_t * flow);
int ips_parse_tcp (vlib_buffer_t * b, ips_flow_t * flow);
int ips_parse_udp (vlib_buffer_t * b, ips_flow_t * flow);
int ips_parse_icmp (vlib_buffer_t * b, ips_flow_t * flow);
int ips_parse_icmpv6 (vlib_buffer_t * b, ips_flow_t * flow);
void ips_detect_app_protocol (ips_flow_t * flow);
int ips_parse_encapsulation (vlib_buffer_t * b, ips_flow_t * flow);

#endif /* __included_ips_proto_h__ */ 