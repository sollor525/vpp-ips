/*
 * ips_tcp_reorder.h - TCP Reordering Header
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

#ifndef __IPS_TCP_REORDER_H__
#define __IPS_TCP_REORDER_H__

#include <vlib/vlib.h>
#include <vlib/buffer.h>
#include "ips.h"

/**
 * @brief Initialize TCP reordering for a flow
 * @param flow Flow structure to initialize
 */
void ips_tcp_reorder_init_flow(ips_flow_t *flow);

/**
 * @brief Cleanup TCP reordering for a flow
 * @param flow Flow structure to cleanup
 */
void ips_tcp_reorder_cleanup_flow(ips_flow_t *flow);

/**
 * @brief Process a TCP packet with reordering
 * @param flow Flow structure
 * @param b Buffer containing the packet
 * @param ordered_data Output pointer to ordered data
 * @param ordered_len Output pointer to ordered data length
 * @return 0 on success, 1 if packet buffered, <0 on error
 */
int ips_tcp_reorder_process_packet(ips_flow_t *flow, vlib_buffer_t *b,
                                  u8 **ordered_data, u32 *ordered_len);

/**
 * @brief Get TCP reordering statistics
 * @param flow Flow structure
 * @param buffered_src Output pointer to buffered src bytes
 * @param buffered_dst Output pointer to buffered dst bytes
 */
void ips_tcp_reorder_get_stats(ips_flow_t *flow, u32 *buffered_src, u32 *buffered_dst);

#endif /* __IPS_TCP_REORDER_H__ */