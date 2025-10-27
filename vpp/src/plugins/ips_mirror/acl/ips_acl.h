/*
 * ips_acl.h - VPP IPS Plugin ACL Integration Module
 *
 * Copyright (c) 2024 VPP IPS Project
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#ifndef __IPS_ACL_H__
#define __IPS_ACL_H__

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>
#include <vnet/tcp/tcp_packet.h>
#include <vppinfra/pool.h>
#include <vppinfra/vec.h>

#include "../ips.h"

#include "session/ips_session.h"

/* Include ACL plugin exports */
#include <plugins/acl/exports.h>

/* IPS ACL Action Types */
typedef enum
{
    IPS_ACL_ACTION_PERMIT = 0,
    IPS_ACL_ACTION_DENY,
    IPS_ACL_ACTION_RESET,
    IPS_ACL_ACTION_LOG,
} ips_acl_action_t;


/* TCP Flag Definitions */
#define IPS_TCP_FLAG_FIN  0x01
#define IPS_TCP_FLAG_SYN  0x02
#define IPS_TCP_FLAG_RST  0x04
#define IPS_TCP_FLAG_PSH  0x08
#define IPS_TCP_FLAG_ACK  0x10
#define IPS_TCP_FLAG_URG  0x20
#define IPS_TCP_FLAG_ECE  0x40
#define IPS_TCP_FLAG_CWR  0x80

/* IPS ACL Rule - Extended for session-level control */
typedef struct
{
    u32 rule_id;                       /* Rule ID */
    u32 vpp_acl_index;                 /* VPP ACL index */
    u32 vpp_rule_index;                /* VPP rule index within ACL */
    u8 is_ipv6;                        /* IPv6 flag */
    ip46_address_t src_ip;             /* Source IP */
    u8 src_prefixlen;                  /* Source prefix length */
    ip46_address_t dst_ip;             /* Destination IP */
    u8 dst_prefixlen;                  /* Destination prefix length */
    u8 protocol;                       /* Protocol (TCP/UDP) */
    u16 src_port_start;                /* Source port range start */
    u16 src_port_end;                  /* Source port range end */
    u16 dst_port_start;                /* Destination port range start */
    u16 dst_port_end;                  /* Destination port range end */
    u8 tcp_flags_mask;                 /* TCP flags mask */
    u8 tcp_flags_value;                /* TCP flags value */

    /* TCP state matching extensions */
    u8 match_tcp_state;                /* Match TCP state flag */
    ips_tcp_state_t tcp_state;         /* Required TCP state */

    /* Session-level control */
    u8 session_control;                /* 0=packet-level, 1=session-level */
    u8 match_direction;                /* 0=bidirectional, 1=forward-only, 2=reverse-only */

    /* SYN/SYN-ACK blocking flags */
    u8 block_syn;                      /* Block SYN packets */
    u8 block_synack;                   /* Block SYN-ACK packets */

    ips_acl_action_t action;           /* IPS action to take */
    u8 enabled;                        /* Rule enabled flag */
    u64 hit_count;                     /* Rule hit counter */
    u64 session_hit_count;             /* Session hit counter */
    f64 last_hit_time;                 /* Last hit timestamp */

    /* Rule description */
    char description[64];
} ips_acl_rule_t;

/* IPS ACL Context - maps to VPP ACL lookup context */
typedef struct
{
    u32 context_id;                    /* VPP ACL lookup context ID */
    u32 *acl_list;                     /* List of VPP ACL indices */
    u32 acl_user_id;                   /* VPP ACL user module ID */
    u32 ips_thread_index;              /* IPS thread index */
    u8 initialized;                    /* Initialization flag */
} ips_acl_context_t;

/* Session Key for TCP State Tracking */
typedef struct
{
    ip46_address_t src_ip;
    ip46_address_t dst_ip;
    u16 src_port;
    u16 dst_port;
    u8 protocol;
    u8 ip_version;
    u8 padding[1];
} ips_session_key_t;

/* TCP State Entry */
typedef struct
{
    ips_session_key_t key;
    ips_tcp_state_t state;
    u32 seq_number;
    u32 ack_number;
    f64 last_update;
    u8 direction;                      /* 0=client->server, 1=server->client */
    u8 padding[3];
} ips_tcp_state_entry_t;

/* TCP State Table */
typedef struct
{
    clib_bihash_48_8_t tcp_state_hash;
    u32 max_entries;
    u32 current_entries;
} ips_tcp_state_table_t;

/* IPS ACL Statistics - Extended */
typedef struct
{
    u64 total_packets_checked;         /* Total packets checked */
    u64 packets_denied;                /* Packets denied */
    u64 packets_reset;                 /* Packets reset */
    u64 packets_permit;                /* Packets permitted (includes default permit) */
    u64 sessions_blocked;              /* Sessions blocked */
    u64 acl_errors;                    /* ACL errors */

    /* Extended statistics */
    u64 acl_hits;                      /* Total VPP ACL rule hits (permit + deny) */
    u64 acl_deny_hits;                 /* VPP ACL deny rule hits */
    u64 acl_permit_hits;               /* VPP ACL permit rule hits */
    u64 tcp_state_hits;                /* TCP state based blocks */
    u64 session_cache_hits;            /* Session cache hits */
    u64 syn_packets_blocked;           /* SYN packets blocked */
    u64 synack_packets_blocked;        /* SYN-ACK packets blocked */
} ips_acl_stats_t;

/* IPS ACL Manager - Extended */
typedef struct
{
    /* ACL plugin methods */
    acl_plugin_methods_t acl_methods;
    u8 acl_plugin_loaded;              /* ACL plugin loaded flag */

    /* ACL contexts per thread */
    ips_acl_context_t *per_thread_contexts;
    u32 num_threads;

    /* IPS-specific ACL rules */
    ips_acl_rule_t *ips_rules;
    u32 next_rule_id;

    /* Statistics per thread */
    ips_acl_stats_t *per_thread_stats;

    /* TCP state tracking */
    ips_tcp_state_table_t tcp_state_table;
    u8 enable_tcp_state_tracking;      /* TCP state tracking enabled */

    /* Session management */
    u32 max_sessions;                  /* Maximum sessions */
    u32 current_sessions;              /* Current active sessions */

    /* Configuration */
    u8 reset_enabled;                  /* Reset functionality enabled */
    u8 log_denied;                     /* Log denied packets */
    u8 default_action;                /* Default action when no rule matches (0=PASS, 1=BLOCK) */
} ips_acl_manager_t;

/* Global instance */
extern ips_acl_manager_t ips_acl_manager;

/* Function declarations */

/**
 * @brief Initialize IPS ACL module
 */
clib_error_t *ips_acl_init(vlib_main_t *vm);

/**
 * @brief Cleanup IPS ACL module
 */
void ips_acl_cleanup(void);

/**
 * @brief Check packet against VPP ACL rules using VPP ACL plugin
 * @param thread_index Thread index
 * @param session IPS session
 * @param ip4 IPv4 header (if IPv4)
 * @param ip6 IPv6 header (if IPv6)
 * @param tcp TCP header
 * @param action Pointer to store action result
 * @return 0 if allowed, 1 if denied/reset
 */
int ips_acl_check_packet(u32 thread_index, ips_session_t *session,
                         ip4_header_t *ip4, ip6_header_t *ip6,
                         tcp_header_t *tcp, ips_acl_action_t *action);

/**
 * @brief Send TCP reset packet
 * @param thread_index Thread index
 * @param session IPS session
 * @param is_reply Reset direction (0=original direction, 1=reply direction)
 * @return 0 on success, -1 on error
 */
int ips_acl_send_tcp_reset(u32 thread_index, ips_session_t *session, u8 is_reply);

/**
 * @brief Add IPS ACL rule
 * @param rule Pointer to rule structure
 * @return rule ID on success, ~0 on error
 */
u32 ips_acl_add_rule(ips_acl_rule_t *rule);

/**
 * @brief Remove IPS ACL rule
 * @param rule_id Rule ID to remove
 * @return 0 on success, -1 on error
 */
int ips_acl_remove_rule(u32 rule_id);

/**
 * @brief Enable/disable IPS ACL rule
 * @param rule_id Rule ID
 * @param enabled Enable flag
 * @return 0 on success, -1 on error
 */
int ips_acl_set_rule_enabled(u32 rule_id, u8 enabled);

/**
 * @brief Get IPS ACL statistics
 * @param thread_index Thread index
 * @param stats Pointer to store statistics
 */
void ips_acl_get_stats(u32 thread_index, ips_acl_stats_t *stats);

/**
 * @brief Reset IPS ACL statistics
 * @param thread_index Thread index
 */
void ips_acl_reset_stats(u32 thread_index);

/**
 * @brief Check if ACL plugin is available
 * @return 1 if available, 0 if not
 */
int ips_acl_is_available(void);

/* Extended functions for session-level ACL and TCP state tracking */

/**
 * @brief Initialize TCP state tracking
 * @param max_entries Maximum number of TCP state entries
 * @return 0 on success, -1 on error
 */
int ips_acl_tcp_state_init(u32 max_entries);

/**
 * @brief Update TCP state for a session
 * @param key Session key
 * @param tcp TCP header
 * @param direction Packet direction (0=forward, 1=reverse)
 * @return New TCP state
 */
ips_tcp_state_t ips_acl_update_tcp_state(ips_session_key_t *key,
                                        tcp_header_t *tcp,
                                        u8 direction);

/**
 * @brief Check TCP state match for rule
 * @param key Session key
 * @param rule ACL rule to check
 * @return 1 if matches, 0 if not
 */
int ips_acl_check_tcp_state_match(ips_session_key_t *key,
                                 ips_acl_rule_t *rule);

/**
 * @brief Extract session key from packet
 * @param b VPP buffer
 * @param key Output session key
 * @param direction Output direction
 * @return 0 on success, -1 on error
 */
int ips_acl_extract_session_key(vlib_buffer_t *b,
                               ips_session_key_t *key,
                               u8 *direction);

/**
 * @brief Check SYN packet blocking
 * @param key Session key
 * @param b VPP buffer
 * @return 1 if should block, 0 if not
 */
int ips_acl_check_syn_block(ips_session_key_t *key, vlib_buffer_t *b);

/**
 * @brief Check SYN-ACK packet blocking
 * @param key Session key
 * @param b VPP buffer
 * @return 1 if should block, 0 if not
 */
int ips_acl_check_synack_block(ips_session_key_t *key, vlib_buffer_t *b);

/**
 * @brief Batch process packets for ACL checking
 * @param vm VLIB main
 * @param node Node runtime
 * @param frame Frame containing buffers
 * @param buffers Array of buffer indices
 * @param count Number of buffers
 */
void ips_acl_process_batch(vlib_main_t *vm,
                          vlib_node_runtime_t *node,
                          vlib_frame_t *frame,
                          u32 *buffers,
                          u32 count);

/**
 * @brief Add session-level ACL rule with extended features
 * @param rule Pointer to rule structure
 * @return rule ID on success, ~0 on error
 */
u32 ips_acl_add_session_rule(ips_acl_rule_t *rule);

#endif /* __IPS_ACL_H__ */