/*
 * ips_block.h - VPP IPS Plugin Blocking Module
 *
 * Copyright (c) 2024 VPP IPS Project
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#ifndef __IPS_BLOCK_H__
#define __IPS_BLOCK_H__

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>
#include <vnet/tcp/tcp_packet.h>
#include <vppinfra/pool.h>

#include "session/ips_session.h"

/* Blocking action types */
typedef enum
{
    IPS_BLOCK_ACTION_NONE = 0,
    IPS_BLOCK_ACTION_TCP_RESET,      /* Send TCP RST */
    IPS_BLOCK_ACTION_TCP_FIN,        /* Send TCP FIN */
    IPS_BLOCK_ACTION_ICMP_UNREACH,   /* Send ICMP Unreachable */
    IPS_BLOCK_ACTION_ICMP_ADMIN_PROHIB, /* Send ICMP Admin Prohibited */
    IPS_BLOCK_ACTION_DROP,           /* Silent drop */
    IPS_BLOCK_ACTION_REDIRECT,       /* Redirect (future) */
} ips_block_action_t;

/* Blocking reason codes */
typedef enum
{
    IPS_BLOCK_REASON_ACL = 0,         /* ACL rule match */
    IPS_BLOCK_REASON_RULE_ENGINE,     /* Rule engine detection */
    IPS_BLOCK_REASON_SIGNATURE,       /* Signature match */
    IPS_BLOCK_REASON_ANOMALY,         /* Anomaly detection */
    IPS_BLOCK_REASON_RATE_LIMIT,      /* Rate limiting */
    IPS_BLOCK_REASON_MANUAL,          /* Manual block */
    IPS_BLOCK_REASON_MAX
} ips_block_reason_t;

/* Blocking request structure */
typedef struct
{
    u32 session_index;                /* Session index (optional) */
    u32 thread_index;                 /* Thread index */
    ips_block_action_t action;         /* Blocking action */
    ips_block_reason_t reason;         /* Block reason */
    u8 is_ipv6;                       /* IPv6 flag */

    /* Network layer info */
    ip4_address_t src_ip4;            /* IPv4 source */
    ip4_address_t dst_ip4;            /* IPv4 destination */
    ip6_address_t src_ip6;            /* IPv6 source */
    ip6_address_t dst_ip6;            /* IPv6 destination */

    /* Transport layer info */
    u8 protocol;                      /* IP protocol */
    u16 src_port;                     /* Source port */
    u16 dst_port;                     /* Destination port */

    /* TCP specific info */
    u32 tcp_seq;                      /* TCP sequence number */
    u32 tcp_ack;                      /* TCP acknowledgment number */
    u8 tcp_flags;                     /* Original TCP flags */

    /* Options */
    u8 send_both_directions;          /* Send to both directions */
    u8 log_block;                     /* Log blocking event */
    u64 user_data;                    /* User-defined data */
} ips_block_request_t;

/* Blocking statistics */
typedef struct
{
    u64 total_blocks;                 /* Total blocks sent */
    u64 tcp_resets;                   /* TCP resets sent */
    u64 tcp_fins;                     /* TCP FINs sent */
    u64 icmp_unreach;                 /* ICMP unreachable sent */
    u64 icmp_admin_prohib;            /* ICMP admin prohibited sent */
    u64 silent_drops;                 /* Silent drops */
    u64 failed_blocks;                /* Failed block attempts */
    u64 blocks_by_reason[IPS_BLOCK_REASON_MAX]; /* Blocks by reason */
} ips_block_stats_t;

/* Blocking manager */
typedef struct
{
    /* Per-thread statistics */
    ips_block_stats_t *per_thread_stats;
    u32 num_threads;

    /* Configuration */
    u8 enable_logging;                /* Enable blocking logging */
    u8 rate_limit_enabled;            /* Enable rate limiting */
    u32 max_blocks_per_second;        /* Max blocks per second per thread */

    /* Rate limiting state */
    u32 *block_counters;              /* Per-thread block counters */
    f64 *last_reset_time;             /* Last counter reset time */
} ips_block_manager_t;

/* Global instance */
extern ips_block_manager_t ips_block_manager;

/* Function declarations */

/**
 * @brief Initialize blocking module
 */
clib_error_t *ips_block_init(vlib_main_t *vm);

/**
 * @brief Cleanup blocking module
 */
void ips_block_cleanup(void);

/**
 * @brief Send blocking response
 * @param request Pointer to blocking request
 * @return 0 on success, -1 on error
 */
int ips_block_send(const ips_block_request_t *request);

/**
 * @brief Send TCP reset packet
 * @param thread_index Thread index
 * @param session IPS session (optional)
 * @param ip4 IPv4 header (optional)
 * @param ip6 IPv6 header (optional)
 * @param tcp TCP header (optional)
 * @param is_reply Send in reverse direction
 * @param reason Blocking reason
 * @return 0 on success, -1 on error
 */
int ips_block_send_tcp_reset(u32 thread_index, ips_session_t *session,
                             ip4_header_t *ip4, ip6_header_t *ip6,
                             tcp_header_t *tcp, u8 is_reply,
                             ips_block_reason_t reason);

/**
 * @brief Send ICMP unreachable message
 * @param thread_index Thread index
 * @param is_ipv6 IPv6 flag
 * @param src_ip Source IP
 * @param dst_ip Destination IP
 * @param code ICMP code
 * @param reason Blocking reason
 * @return 0 on success, -1 on error
 */
int ips_block_send_icmp_unreach(u32 thread_index, u8 is_ipv6,
                                const ip4_address_t *src_ip4, const ip6_address_t *src_ip6,
                                const ip4_address_t *dst_ip4, const ip6_address_t *dst_ip6,
                                u8 code, ips_block_reason_t reason);

/**
 * @brief Block session with specified action
 * @param thread_index Thread index
 * @param session IPS session
 * @param action Blocking action
 * @param reason Blocking reason
 * @return 0 on success, -1 on error
 */
int ips_block_session(u32 thread_index, ips_session_t *session,
                      ips_block_action_t action, ips_block_reason_t reason);

/**
 * @brief Block packet flow
 * @param thread_index Thread index
 * @param ip4 IPv4 header
 * @param ip6 IPv6 header
 * @param tcp TCP header
 * @param action Blocking action
 * @param reason Blocking reason
 * @return 0 on success, -1 on error
 */
int ips_block_flow(u32 thread_index,
                   ip4_header_t *ip4, ip6_header_t *ip6,
                   tcp_header_t *tcp,
                   ips_block_action_t action, ips_block_reason_t reason);

/**
 * @brief Get blocking statistics
 * @param thread_index Thread index
 * @param stats Pointer to store statistics
 */
void ips_block_get_stats(u32 thread_index, ips_block_stats_t *stats);

/**
 * @brief Reset blocking statistics
 * @param thread_index Thread index
 */
void ips_block_reset_stats(u32 thread_index);

/**
 * @brief Check if blocking is rate limited
 * @param thread_index Thread index
 * @return 1 if rate limited, 0 if not
 */
int ips_block_is_rate_limited(u32 thread_index);

/**
 * @brief Get action string for logging
 * @param action Blocking action
 * @return Action string
 */
const char *ips_block_action_to_string(ips_block_action_t action);

/**
 * @brief Get reason string for logging
 * @param reason Blocking reason
 * @return Reason string
 */
const char *ips_block_reason_to_string(ips_block_reason_t reason);

#endif /* __IPS_BLOCK_H__ */