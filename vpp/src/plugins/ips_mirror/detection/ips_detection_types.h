/*
 * ips_detection_types.h - VPP IPS Plugin Detection-Specific Type Definitions
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

#ifndef __included_ips_detection_types_h__
#define __included_ips_detection_types_h__

/* Detection types primary definition guard */
#ifndef IPS_DETECTION_TYPES_DEFINED
#define IPS_DETECTION_TYPES_DEFINED

#include <vlib/vlib.h>
#include <vnet/ip/ip.h>
#include <vppinfra/hash.h>

#include "../ips.h"


/**
 * @brief Rule flags for detection engine
 */
#define IPS_RULE_FLAG_ENABLED     (1 << 0)  /**< Rule is enabled */
#define IPS_RULE_FLAG_NOALERT     (1 << 1)  /**< No alert generation */
#define IPS_RULE_FLAG_FAST_PATTERN (1 << 2) /**< Fast pattern rule */

/**
 * @brief Detection result structure
 */
typedef struct
{
    u32 rule_sid;               /* Matched rule SID */
    ips_action_t action;        /* Recommended action */
    u32 match_count;            /* Number of content matches */
    u64 match_position;         /* Last match position */
    u32 detection_flags;        /* Detection result flags */
    f64 detection_time;         /* Detection timestamp */
} ips_detection_result_t;

/**
 * @brief Detection context structure for packet processing
 */
typedef struct
{
    ips_flow_t *flow;           /* Current flow */
    ips_rule_t *rules;          /* Available rules */
    u32 rule_count;             /* Number of rules */
    u8 *packet_data;            /* Packet data */
    u32 packet_length;          /* Packet length */
    u32 detection_flags;        /* Context flags */
    ips_detection_result_t *results; /* Detection results */
    u32 result_count;           /* Number of results */
} ips_detection_context_t;

#endif /* IPS_DETECTION_TYPES_DEFINED */
#endif /* __included_ips_detection_types_h__ */