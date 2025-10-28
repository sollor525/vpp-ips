/*
 * ips_flow.h - VPP IPS Plugin Flow Management Header
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

#ifndef __included_ips_flow_h__
#define __included_ips_flow_h__

#include "ips.h"

/**
 * @brief Create a new flow session
 * @param ptd Per-thread data
 * @param key Flow key
 * @return Pointer to new flow, or NULL on failure
 */
ips_flow_t *ips_flow_create(ips_per_thread_data_t *ptd, ips_flow_key_t *key);

/**
 * @brief Delete a flow session
 * @param ptd Per-thread data
 * @param flow Flow to delete
 */
void ips_flow_delete(ips_per_thread_data_t *ptd, ips_flow_t *flow);

/**
 * @brief Lookup flow by key
 * @param ptd Per-thread data
 * @param key Flow key
 * @return Pointer to flow, or NULL if not found
 */
ips_flow_t *ips_flow_lookup(ips_per_thread_data_t *ptd, ips_flow_key_t *key);

/**
 * @brief Update TCP state machine
 * @param flow Flow to update
 * @param tcp TCP header
 * @param is_to_server Direction flag
 */
void ips_flow_update_tcp_state(ips_flow_t *flow, tcp_header_t *tcp, u8 is_to_server);

/**
 * @brief Check if flow is expired
 * @param flow Flow to check
 * @param timeout Timeout value
 * @return 1 if expired, 0 otherwise
 */
int ips_flow_is_expired(ips_flow_t *flow, f64 timeout);

/**
 * @brief Update flow statistics
 * @param flow Flow to update
 * @param b VPP buffer
 * @param is_to_server Direction flag
 */
void ips_flow_update_stats(ips_flow_t *flow, vlib_buffer_t *b, u8 is_to_server);

/**
 * @brief Cleanup expired flows
 * @param ptd Per-thread data
 * @param timeout Timeout value
 */
void ips_flow_cleanup_expired(ips_per_thread_data_t *ptd, f64 timeout);

#endif /* __included_ips_flow_h__ */