/*
 * ips_response.h - VPP IPS Plugin Response Actions Header
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

#ifndef __included_ips_response_h__
#define __included_ips_response_h__

#include "ips.h"

/* Function prototypes */
u32 ips_drop_packet (vlib_main_t * vm, vlib_buffer_t * b);
int ips_send_tcp_rst (vlib_main_t * vm, vlib_buffer_t * b, ips_flow_t * flow);
int ips_send_icmp_unreachable (vlib_main_t * vm, vlib_buffer_t * b, ips_flow_t * flow);
u32 ips_execute_response (vlib_main_t * vm, vlib_buffer_t * b, ips_flow_t * flow, ips_action_t action);

#endif /* __included_ips_response_h__ */ 