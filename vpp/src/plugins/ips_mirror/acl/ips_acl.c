/*
 * ips_acl.c - VPP IPS Plugin ACL Integration Module Implementation
 *
 * Copyright (c) 2024 VPP IPS Project
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#include <vlib/vlib.h>
#include <vlib/cli.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/ethernet/ethernet.h>
#include <vppinfra/pool.h>
#include <vppinfra/vec.h>
#include <vppinfra/clib.h>
#include <vppinfra/mem.h>
#include <vppinfra/byte_order.h>
#include <arpa/inet.h>
#include <ctype.h>

#include "../ips.h"
#include "ips_acl.h"
#include "session/ips_session.h"
#include "../block/ips_block.h"


/* Next node indices - these should match the actual node definitions */
#define IPS_NEXT_DROP 0
#define IPS_NEXT_NORMAL 1

/* Global ACL manager instance */
ips_acl_manager_t ips_acl_manager;

/* Forward declaration */
int ips_acl_apply_to_interface(u32 sw_if_index);

/* Forward declaration for helper functions */
static inline u8 *format_acl_rule_cli(u8 *s, ips_acl_rule_t *rule);
static int get_target_acl_index(u8 is_ipv6, ips_acl_action_t action, u32 *acl_index_ptr);
static ips_acl_rule_t **ips_acl_collect_rules_by_acl(u32 acl_index, u8 is_ipv6, u8 is_permit);
static u32 ips_acl_add_replace_vpp(u32 acl_index, ips_acl_rule_t *rules, u32 count);

/**
 * @brief Initialize TCP state tracking table
 */
int
ips_acl_tcp_state_init(u32 max_entries)
{
    ips_acl_manager_t *am = &ips_acl_manager;
    ips_tcp_state_table_t *tst = &am->tcp_state_table;

    /* Initialize bihash for TCP state tracking */
    clib_bihash_init_48_8(&tst->tcp_state_hash, "ips-tcp-state-table",
                         max_entries, max_entries >> 2);

    tst->max_entries = max_entries;
    tst->current_entries = 0;

    clib_warning("IPS TCP state tracking initialized with %u max entries", max_entries);
    return 0;
}

/**
 * @brief Extract session key from packet
 */
int
ips_acl_extract_session_key(vlib_buffer_t *b,
                           ips_session_key_t *key,
                           u8 *direction)
{
    if (!b || !key || !direction)
        return -1;

    ethernet_header_t *eth = vlib_buffer_get_current(b);

    /* Skip Ethernet header */
    u8 *packet_data = (u8 *)eth + sizeof(ethernet_header_t);

    /* Check IP version */
    ip4_header_t *ip4 = (ip4_header_t *)packet_data;
    ip6_header_t *ip6 = (ip6_header_t *)packet_data;

    if ((ip4->ip_version_and_header_length & 0xF0) == 0x40) {
        /* IPv4 */
        key->ip_version = 4;
        key->src_ip.ip4 = ip4->src_address;
        key->dst_ip.ip4 = ip4->dst_address;
        key->protocol = ip4->protocol;

        /* Get TCP header */
        tcp_header_t *tcp = (tcp_header_t *)((u8 *)ip4 + ip4_header_bytes(ip4));
        key->src_port = tcp->src_port;
        key->dst_port = tcp->dst_port;
    } else {
        /* IPv6 */
        key->ip_version = 6;
        key->src_ip.ip6 = ip6->src_address;
        key->dst_ip.ip6 = ip6->dst_address;
        key->protocol = ip6->protocol;

        /* Get TCP header */
        tcp_header_t *tcp = (tcp_header_t *)((u8 *)ip6 + sizeof(ip6_header_t));
        key->src_port = tcp->src_port;
        key->dst_port = tcp->dst_port;
    }

    /* Determine direction based on some heuristic - for now default to forward */
    *direction = 0; /* 0=forward, 1=reverse */

    return 0;
}

/**
 * @brief Update TCP state for a session
 */
ips_tcp_state_t
ips_acl_update_tcp_state(ips_session_key_t *key,
                        tcp_header_t *tcp,
                        u8 direction)
{
    ips_acl_manager_t *am = &ips_acl_manager;
    ips_tcp_state_table_t *tst = &am->tcp_state_table;
    ips_tcp_state_entry_t *state_entry;
    clib_bihash_kv_48_8_t kv, value;

    if (!am->enable_tcp_state_tracking)
        return IPS_TCP_STATE_NONE;

    /* Create hash key from session key */
    clib_memset(&kv, 0, sizeof(kv));
    clib_memcpy(&kv.key, key, sizeof(ips_session_key_t));

    /* Lookup existing state entry */
    if (clib_bihash_search_48_8(&tst->tcp_state_hash, &kv, &value) != 0) {
        /* Create new state entry */
        state_entry = clib_mem_alloc(sizeof(ips_tcp_state_entry_t));
        if (!state_entry)
            return IPS_TCP_STATE_NONE;

        clib_memset(state_entry, 0, sizeof(*state_entry));
        state_entry->key = *key;
        state_entry->state = IPS_TCP_STATE_NONE;
        state_entry->direction = direction;
        state_entry->last_update = vlib_time_now(vlib_get_main());

        /* Add to hash table */
        kv.value = (uword)(uintptr_t)state_entry;
        clib_bihash_add_del_48_8(&tst->tcp_state_hash, &kv, 1);

        tst->current_entries++;
    } else {
        // NOLINTNEXTLINE(performance-no-int-to-ptr)
        state_entry = (ips_tcp_state_entry_t *)(uintptr_t)value.value;
    }

    /* Update TCP state based on flags - Simplified for mirror traffic */
    ips_tcp_state_t old_state = state_entry->state;
    ips_tcp_state_t new_state = old_state;

    u8 flags = tcp->flags;

    switch (old_state) {
        case IPS_TCP_STATE_NONE:
            /* New connection detection - SYN or SYN-ACK */
            if (flags & (IPS_TCP_FLAG_SYN)) {
                new_state = IPS_TCP_STATE_NEW;
            }
            break;

        case IPS_TCP_STATE_NEW:
            /* Transition to established after SYN handshake */
            if ((flags & IPS_TCP_FLAG_ACK) || (flags & IPS_TCP_FLAG_SYN)) {
                new_state = IPS_TCP_STATE_ESTABLISHED;
            } else if (flags & IPS_TCP_FLAG_RST) {
                new_state = IPS_TCP_STATE_CLOSED;
            }
            break;

        case IPS_TCP_STATE_ESTABLISHED:
            /* Established connection - handle normal traffic or closure */
            if (flags & (IPS_TCP_FLAG_FIN | IPS_TCP_FLAG_RST)) {
                new_state = IPS_TCP_STATE_CLOSING;
            }
            break;

        case IPS_TCP_STATE_CLOSING:
            /* Connection closing - handle final shutdown */
            if (flags & (IPS_TCP_FLAG_ACK | IPS_TCP_FLAG_FIN | IPS_TCP_FLAG_RST)) {
                new_state = IPS_TCP_STATE_CLOSED;
            }
            break;

        case IPS_TCP_STATE_CLOSED:
            /* Connection closed - stay in closed state */
            break;

        default:
            /* Unknown state - reset to none */
            new_state = IPS_TCP_STATE_NONE;
            break;
    }

    state_entry->state = new_state;
    state_entry->seq_number = clib_net_to_host_u32(tcp->seq_number);
    state_entry->ack_number = clib_net_to_host_u32(tcp->ack_number);
    state_entry->last_update = vlib_time_now(vlib_get_main());

    return new_state;
}

/**
 * @brief Check TCP state match for rule
 */
int
ips_acl_check_tcp_state_match(ips_session_key_t *key,
                             ips_acl_rule_t *rule)
{
    ips_acl_manager_t *am = &ips_acl_manager;
    ips_tcp_state_table_t *tst = &am->tcp_state_table;
    clib_bihash_kv_48_8_t kv, value;

    if (!am->enable_tcp_state_tracking || !rule->match_tcp_state)
        return 1; /* Rule doesn't require TCP state matching */

    /* Create hash key from session key */
    clib_memset(&kv, 0, sizeof(kv));
    clib_memcpy(&kv.key, key, sizeof(ips_session_key_t));

    /* Lookup state entry */
    if (clib_bihash_search_48_8(&tst->tcp_state_hash, &kv, &value) != 0) {
        return 0; /* No state entry found */
    }

    // NOLINTNEXTLINE(performance-no-int-to-ptr)
    ips_tcp_state_entry_t *state_entry = (ips_tcp_state_entry_t *)(uintptr_t)value.value;

    /* Check if current state matches rule requirement */
    return (state_entry->state == rule->tcp_state);
}

/**
 * @brief Check SYN packet blocking
 */
int
ips_acl_check_syn_block(ips_session_key_t *key, vlib_buffer_t *b)
{
    ips_acl_manager_t *am = &ips_acl_manager;
    ips_acl_rule_t *rule;

    if (!am->ips_rules || pool_len(am->ips_rules) == 0)
        return 0;

    /* Extract TCP header to check SYN flag */
    ethernet_header_t *eth = vlib_buffer_get_current(b);
    u8 *packet_data = (u8 *)eth + sizeof(ethernet_header_t);
    ip4_header_t *ip4 = (ip4_header_t *)packet_data;

    tcp_header_t *tcp;
    if ((ip4->ip_version_and_header_length & 0xF0) == 0x40) {
        tcp = (tcp_header_t *)((u8 *)ip4 + ip4_header_bytes(ip4));
    } else {
        ip6_header_t *ip6 = (ip6_header_t *)packet_data;
        tcp = (tcp_header_t *)((u8 *)ip6 + sizeof(ip6_header_t));
    }

    u8 tcp_flags = tcp->flags;

    /* Check if this is a SYN packet (without ACK) */
    if (!((tcp_flags & IPS_TCP_FLAG_SYN) && !(tcp_flags & IPS_TCP_FLAG_ACK)))
        return 0;

    /* Check against rules that block SYN packets */
    pool_foreach(rule, am->ips_rules) {
        if (!rule->enabled || rule->action != IPS_ACL_ACTION_DENY)
            continue;

        if (!rule->block_syn)
            continue;

        /* Check if rule matches this packet */
        if (rule->src_prefixlen > 0 || rule->dst_prefixlen > 0 ||
            rule->src_port_start > 0 || rule->dst_port_start > 0 ||
            rule->protocol > 0) {

            /* Basic match check */
            if (rule->protocol > 0 && rule->protocol != key->protocol)
                continue;

            /* Check TCP flags match if specified */
            if (rule->tcp_flags_mask > 0) {
                if ((tcp_flags & rule->tcp_flags_mask) != rule->tcp_flags_value)
                    continue;
            }

            /* This rule should block the SYN packet */
            clib_warning("Blocking TCP SYN packet: %U -> %U",
                        format_ip46_address, &key->src_ip, IP46_TYPE_ANY,
                        format_ip46_address, &key->dst_ip, IP46_TYPE_ANY);
            return 1;
        }
    }

    return 0;
}

/**
 * @brief Check SYN-ACK packet blocking
 */
int
ips_acl_check_synack_block(ips_session_key_t *key, vlib_buffer_t *b)
{
    ips_acl_manager_t *am = &ips_acl_manager;
    ips_acl_rule_t *rule;

    if (!am->ips_rules || pool_len(am->ips_rules) == 0)
        return 0;

    /* Extract TCP header to check SYN-ACK flag */
    ethernet_header_t *eth = vlib_buffer_get_current(b);
    u8 *packet_data = (u8 *)eth + sizeof(ethernet_header_t);
    ip4_header_t *ip4 = (ip4_header_t *)packet_data;

    tcp_header_t *tcp;
    if ((ip4->ip_version_and_header_length & 0xF0) == 0x40) {
        tcp = (tcp_header_t *)((u8 *)ip4 + ip4_header_bytes(ip4));
    } else {
        ip6_header_t *ip6 = (ip6_header_t *)packet_data;
        tcp = (tcp_header_t *)((u8 *)ip6 + sizeof(ip6_header_t));
    }

    u8 tcp_flags = tcp->flags;

    /* Check if this is a SYN-ACK packet */
    if (!((tcp_flags & IPS_TCP_FLAG_SYN) && (tcp_flags & IPS_TCP_FLAG_ACK)))
        return 0;

    /* Create reverse key for matching server->client direction */
    ips_session_key_t reverse_key = *key;
    reverse_key.src_ip = key->dst_ip;
    reverse_key.dst_ip = key->src_ip;
    reverse_key.src_port = key->dst_port;
    reverse_key.dst_port = key->src_port;

    /* Check against rules that block SYN-ACK packets */
    pool_foreach(rule, am->ips_rules) {
        if (!rule->enabled || rule->action != IPS_ACL_ACTION_DENY)
            continue;

        if (!rule->block_synack)
            continue;

        /* Check if rule matches this packet (using reverse key) */
        if (rule->src_prefixlen > 0 || rule->dst_prefixlen > 0 ||
            rule->src_port_start > 0 || rule->dst_port_start > 0 ||
            rule->protocol > 0) {

            /* Basic match check with reverse key */
            if (rule->protocol > 0 && rule->protocol != reverse_key.protocol)
                continue;

            /* Check TCP flags match if specified */
            if (rule->tcp_flags_mask > 0) {
                if ((tcp_flags & rule->tcp_flags_mask) != rule->tcp_flags_value)
                    continue;
            }

            /* This rule should block the SYN-ACK packet */
            clib_warning("Blocking TCP SYN-ACK packet: %U -> %U",
                        format_ip46_address, &reverse_key.src_ip, IP46_TYPE_ANY,
                        format_ip46_address, &reverse_key.dst_ip, IP46_TYPE_ANY);
            return 1;
        }
    }

    return 0;
}

/**
 * @brief Batch process packets for ACL checking
 */
void
ips_acl_process_batch(vlib_main_t *vm,
                     vlib_node_runtime_t *node,
                     vlib_frame_t *frame,
                     u32 *buffers,
                     u32 count)
{
    ips_acl_manager_t *am = &ips_acl_manager;

    /* Suppress unused parameter warning */
    (void)node;
    u32 next_indices[4];
    ips_session_key_t keys[4];
    u8 directions[4];
    vlib_buffer_t *bufs[4];

    /* Process in batches of 4 for better cache performance */
    for (u32 i = 0; i < count; i += 4) {
        u32 batch_size = (i + 4 <= count) ? 4 : (count - i);

        /* Extract session keys for the batch */
        for (u32 j = 0; j < batch_size; j++) {
            bufs[j] = vlib_get_buffer(vm, buffers[i + j]);
            ips_acl_extract_session_key(bufs[j], &keys[j], &directions[j]);
        }

        /* Process each packet in the batch */
        for (u32 j = 0; j < batch_size; j++) {
            ips_acl_action_t action = IPS_ACL_ACTION_PERMIT;
            u32 thread_index = vm->thread_index;

            /* Check SYN/SYN-ACK blocking first */
            if (keys[j].protocol == IP_PROTOCOL_TCP) {
                if (ips_acl_check_syn_block(&keys[j], bufs[j])) {
                    action = IPS_ACL_ACTION_DENY;
                    am->per_thread_stats[thread_index].syn_packets_blocked++;
                } else if (ips_acl_check_synack_block(&keys[j], bufs[j])) {
                    action = IPS_ACL_ACTION_DENY;
                    am->per_thread_stats[thread_index].synack_packets_blocked++;
                }
            }

            /* Update TCP state if enabled */
            if (am->enable_tcp_state_tracking && keys[j].protocol == IP_PROTOCOL_TCP) {
                ethernet_header_t *eth = vlib_buffer_get_current(bufs[j]);
                u8 *packet_data = (u8 *)eth + sizeof(ethernet_header_t);
                ip4_header_t *ip4 = (ip4_header_t *)packet_data;

                tcp_header_t *tcp;
                if ((ip4->ip_version_and_header_length & 0xF0) == 0x40) {
                    tcp = (tcp_header_t *)((u8 *)ip4 + ip4_header_bytes(ip4));
                } else {
                    ip6_header_t *ip6 = (ip6_header_t *)packet_data;
                    tcp = (tcp_header_t *)((u8 *)ip6 + sizeof(ip6_header_t));
                }

                ips_tcp_state_t state = ips_acl_update_tcp_state(&keys[j], tcp, directions[j]);

                /* Check if this TCP state should be blocked */
                if (state == IPS_TCP_STATE_NONE && (tcp->flags & IPS_TCP_FLAG_RST)) {
                    /* RST packets - allow through */
                    action = IPS_ACL_ACTION_PERMIT;
                }
            }

            /* Check against IPS ACL rules if not already blocked */
            if (action == IPS_ACL_ACTION_PERMIT) {
                ip4_header_t *ip4 = NULL;
                ip6_header_t *ip6 = NULL;
                tcp_header_t *tcp = NULL;

                /* Extract headers for ACL checking */
                ethernet_header_t *eth = vlib_buffer_get_current(bufs[j]);
                u8 *packet_data = (u8 *)eth + sizeof(ethernet_header_t);

                ip4_header_t *ip4_check = (ip4_header_t *)packet_data;
                if ((ip4_check->ip_version_and_header_length & 0xF0) == 0x40) {
                    ip4 = ip4_check;
                    tcp = (tcp_header_t *)((u8 *)ip4 + ip4_header_bytes(ip4));
                } else {
                    ip6 = (ip6_header_t *)packet_data;
                    tcp = (tcp_header_t *)((u8 *)ip6 + sizeof(ip6_header_t));
                }

                ips_acl_check_packet(thread_index, NULL, ip4, ip6, tcp, &action);

                if (action == IPS_ACL_ACTION_DENY) {
                    am->per_thread_stats[thread_index].tcp_state_hits++;
                }
            }

            /* Determine next node based on action */
            switch (action) {
                case IPS_ACL_ACTION_DENY:
                    next_indices[j] = IPS_NEXT_DROP;
                    am->per_thread_stats[thread_index].packets_denied++;
                    am->per_thread_stats[thread_index].sessions_blocked++;
                    break;

                case IPS_ACL_ACTION_RESET:
                    next_indices[j] = IPS_NEXT_NORMAL; /* Continue, but send reset */
                    am->per_thread_stats[thread_index].packets_reset++;
                    /* Send TCP reset - this would be implemented in blocking module */
                    break;

                case IPS_ACL_ACTION_PERMIT:
                default:
                    next_indices[j] = IPS_NEXT_NORMAL;
                    am->per_thread_stats[thread_index].packets_permit++;
                    break;
            }

            am->per_thread_stats[thread_index].total_packets_checked++;
        }

        /* Enqueue buffers to next nodes */
        for (u32 j = 0; j < batch_size; j++) {
            u32 *to_next = vlib_frame_vector_args(frame);
            to_next[frame->n_vectors] = buffers[i + j];
            frame->n_vectors++;
        }
    }
}

/* VPP ACL API main context */
static vlib_main_t *acl_vlib_main;

/* Forward declarations */
/* static void ips_acl_add_replace_handler(void *arg); */
/* static void ips_acl_add_replace_reply_handler(void *arg); */
/* static void ips_acl_del_handler(void *arg); */

/* Default configuration */
#define IPS_ACL_DEFAULT_RESET_ENABLED   1
#define IPS_ACL_DEFAULT_LOG_DENIED      1
#define IPS_ACL_DEFAULT_ACTION          IPS_ACL_ACTION_PERMIT

/**
 * @brief Initialize ACL context for a thread
 */
static clib_error_t *
ips_acl_init_thread_context(u32 thread_index)
{
    ips_acl_manager_t *am = &ips_acl_manager;
    ips_acl_context_t *ctx;

    if (thread_index >= vec_len(am->per_thread_contexts))
        return clib_error_return(0, "Thread index out of range");

    ctx = &am->per_thread_contexts[thread_index];
    clib_memset(ctx, 0, sizeof(*ctx));

    /* Register as ACL user module */
    ctx->acl_user_id = am->acl_methods.register_user_module("ips_mirror", "thread", "context");
    if (ctx->acl_user_id == ~0)
        return clib_error_return(0, "Failed to register ACL user module");

    /* Get lookup context */
    ctx->context_id = am->acl_methods.get_lookup_context_index(ctx->acl_user_id,
                                                               thread_index, 0);
    if (ctx->context_id < 0)
        return clib_error_return(0, "Failed to get ACL lookup context");

    ctx->ips_thread_index = thread_index;
    ctx->initialized = 1;

    return 0;
}

/**
 * @brief Initialize IPS ACL module
 */
clib_error_t *
ips_acl_init(vlib_main_t *vm)
{
    ips_acl_manager_t *am = &ips_acl_manager;
    clib_error_t *error;
    u32 num_threads;

    /* Clear manager structure */
    clib_memset(am, 0, sizeof(*am));

    /* Store VPP main context for ACL operations */
    acl_vlib_main = vm;

    /* Initialize blocking module */
    clib_error_t *block_error = ips_block_init(vm);
    if (block_error)
    {
        clib_warning("Failed to initialize IPS blocking module: %s", block_error->what);
        /* Continue without blocking functionality */
    }

    /* Initialize ACL plugin interface */
    error = acl_plugin_exports_init(&am->acl_methods);
    if (error)
    {
        clib_warning("Failed to initialize ACL plugin: %s", error->what);
        return clib_error_return(0, "ACL plugin not available: %s", error->what);
    }

    am->acl_plugin_loaded = 1;

    /* Initialize per-thread data */
    num_threads = vlib_num_workers() + 1;
    vec_validate(am->per_thread_contexts, num_threads - 1);
    vec_validate(am->per_thread_stats, num_threads - 1);
    am->num_threads = num_threads;

    /* Initialize each thread's context */
    for (u32 i = 0; i < num_threads; i++)
    {
        error = ips_acl_init_thread_context(i);
        if (error)
        {
            clib_warning("Failed to initialize ACL context for thread %u: %s",
                        i, error->what);
            /* Continue initialization, just mark this thread as failed */
        }
    }

    /* Set default configuration */
    am->reset_enabled = IPS_ACL_DEFAULT_RESET_ENABLED;
    am->log_denied = IPS_ACL_DEFAULT_LOG_DENIED;
    am->default_action = IPS_ACL_DEFAULT_ACTION;
    am->next_rule_id = 1;

    /* Initialize main ACL containers (will be created on first rule add)
     * ~0 means ACL not yet created */
    am->ipv4_whitelist_acl_index = ~0;
    am->ipv4_blacklist_acl_index = ~0;
    am->ipv6_whitelist_acl_index = ~0;
    am->ipv6_blacklist_acl_index = ~0;

    /* Initialize rule counts */
    am->ipv4_whitelist_rule_count = 0;
    am->ipv4_blacklist_rule_count = 0;
    am->ipv6_whitelist_rule_count = 0;
    am->ipv6_blacklist_rule_count = 0;

    /* Initialize rule ID hash table for fast lookup */
    clib_bihash_init_16_8(&am->rule_id_hash, "ips-acl-rule-id", 65536, 65536 >> 2);

    /* Initialize batch mode manager */
    am->batch_manager.next_group_id = 1;
    am->batch_manager.num_groups = 0;
    am->batch_manager.vpp_acl_to_group_map = NULL;

    /* Initialize TCP state tracking */
    am->enable_tcp_state_tracking = 1; /* Enable by default */
    am->max_sessions = 65536; /* Default max sessions */

    int tcp_state_result = ips_acl_tcp_state_init(am->max_sessions);
    if (tcp_state_result != 0) {
        clib_warning("Failed to initialize TCP state tracking: error code %d", tcp_state_result);
        /* Continue without TCP state tracking */
        am->enable_tcp_state_tracking = 0;
    }

    clib_warning("IPS ACL module initialized successfully with TCP state tracking %s",
                am->enable_tcp_state_tracking ? "enabled" : "disabled");
    return 0;
}

/**
 * @brief Cleanup IPS ACL module
 */
void
ips_acl_cleanup(void)
{
    ips_acl_manager_t *am = &ips_acl_manager;
    ips_acl_batch_manager_t *bm = &am->batch_manager;

    if (!am->acl_plugin_loaded)
        return;

    /* Cleanup batch manager */
    if (bm->groups)
    {
        ips_acl_batch_group_t *group;
        pool_foreach(group, bm->groups)
        {
            /* Free rule pointers vector */
            vec_free(group->rules);
            vec_free(group->rule_index_map);
        }
        pool_free(bm->groups);
    }
    vec_free(bm->vpp_acl_to_group_map);

    /* Cleanup per-thread contexts */
    for (u32 i = 0; i < vec_len(am->per_thread_contexts); i++)
    {
        ips_acl_context_t *ctx = &am->per_thread_contexts[i];
        if (ctx->initialized && ctx->context_id >= 0)
        {
            am->acl_methods.put_lookup_context_index(ctx->context_id);
        }
    }

    vec_free(am->per_thread_contexts);
    vec_free(am->per_thread_stats);
    pool_free(am->ips_rules);

    /* Cleanup blocking module */
    ips_block_cleanup();

    clib_memset(am, 0, sizeof(*am));
}

/**
 * @brief Convert VPP ACL action to IPS ACL action
 */
/* static ips_acl_action_t */
/* ips_acl_vpp_to_ips_action(u8 vpp_action) */
/* { */
/*     /\* VPP ACL action: 0 = deny, 1 = permit *\/ */
/*     if (vpp_action == 0) */
/*         return IPS_ACL_ACTION_DENY; */
/*     else */
/*         return IPS_ACL_ACTION_PERMIT; */
/* } */

/* Note: ips_acl_match_rule function removed as we now use VPP ACL plugin's
 * match_5tuple API directly in ips_acl_check_packet for all rule matching. */

/**
 * @brief Update batch rule statistics after VPP ACL match
 *
 * @param am IPS ACL manager
 * @param vpp_acl_index VPP ACL index that matched
 * @param vpp_rule_index Rule index within the VPP ACL
 *
 * This function updates the hit count and last hit time for the specific rule
 * that matched in a batch ACL group.
 */
static void
ips_acl_update_batch_rule_stats(ips_acl_manager_t *am,
                                u32 vpp_acl_index,
                                u32 vpp_rule_index)
{
    ips_acl_batch_manager_t *bm = &am->batch_manager;
    ips_acl_batch_group_t *group = NULL;

    /* Check if the ACL is a batch ACL */
    if (vpp_acl_index >= vec_len(bm->vpp_acl_to_group_map))
        return;

    u32 group_id = bm->vpp_acl_to_group_map[vpp_acl_index];
    if (group_id == ~0)
        return;  /* Not a batch ACL */

    /* Find the batch group */
    pool_foreach(group, bm->groups)
    {
        if (group->group_id == group_id)
            break;
        group = NULL;  /* Reset if not found */
    }

    if (!group || vpp_rule_index >= vec_len(group->rules))
        return;

    /* Get the rule and update its statistics */
    ips_acl_rule_t *rule = group->rules[vpp_rule_index];
    if (rule && rule->enabled)
    {
        rule->hit_count++;
        rule->last_hit_time = vlib_time_now(vlib_get_main());
        group->total_hits++;
        group->last_update_time = rule->last_hit_time;
    }
}

/**
 * @brief Check packet against IPS ACL rules
 */
int
ips_acl_check_packet(u32 thread_index, ips_session_t *session,
                     ip4_header_t *ip4, ip6_header_t *ip6,
                     tcp_header_t *tcp, ips_acl_action_t *action)
{
    ips_acl_manager_t *am = &ips_acl_manager;
    ips_acl_stats_t *stats;
    f64 now = vlib_time_now(vlib_get_main());

    *action = am->default_action;

    if (thread_index >= vec_len(am->per_thread_stats))
        return 0; /* Allow if stats not available */

    stats = &am->per_thread_stats[thread_index];
    stats->total_packets_checked++;

    /* Check against VPP ACL if available
     * Note: session can be NULL for SYN/SYN-ACK packets (new connections)
     * In that case, we match directly against packet headers */
    if (am->acl_plugin_loaded && (ip4 || ip6))
    {
        /* Validate thread context */
        if (thread_index >= vec_len(am->per_thread_contexts))
        {
            clib_warning("Invalid thread_index %u (max: %u)", thread_index, vec_len(am->per_thread_contexts));
            *action = IPS_ACL_ACTION_PERMIT;
            return 0;
        }
        
        ips_acl_context_t *ctx = &am->per_thread_contexts[thread_index];
        
        if (!ctx || !ctx->initialized || ctx->context_id < 0)
        {
            /* Context not ready */
            *action = IPS_ACL_ACTION_PERMIT;
            return 0;
        }
        
        if (vec_len(ctx->acl_list) == 0)
        {
            /* No ACLs configured */
            *action = IPS_ACL_ACTION_PERMIT;
            return 0;
        }
        
        if (ctx->initialized && ctx->context_id >= 0 && vec_len(ctx->acl_list) > 0)
        {
            /* Use VPP ACL plugin for packet matching */
            fa_5tuple_opaque_t pkt_5tuple;
            u8 acl_action = 0;
            u32 acl_pos = 0;
            u32 acl_match = 0;
            u32 rule_match = 0;
            u32 trace_bitmap = 0;
            int is_ip6 = (ip6 != NULL);

            /* 直接使用会话中保存的五元组进行 ACL 匹配
             * 会话方向已标准化为"客户端→服务器"，无需方向判断 */
            clib_memset(&pkt_5tuple, 0, sizeof(pkt_5tuple));

            if (is_ip6)
            {
                /* 使用会话的 IP 地址（已标准化为客户端→服务器方向） */
                ((fa_5tuple_t*)&pkt_5tuple)->ip6_addr[0] = session->src_ip6;
                ((fa_5tuple_t*)&pkt_5tuple)->ip6_addr[1] = session->dst_ip6;
            }
            else
            {
                /* 使用会话的 IP 地址（已标准化为客户端→服务器方向） */
                ((fa_5tuple_t*)&pkt_5tuple)->ip4_addr[0] = session->src_ip4;
                ((fa_5tuple_t*)&pkt_5tuple)->ip4_addr[1] = session->dst_ip4;
            }

            /* 设置 L4 信息（使用会话的端口） */
            if (tcp)
            {
                ((fa_5tuple_t*)&pkt_5tuple)->l4.port[0] = session->src_port;
                ((fa_5tuple_t*)&pkt_5tuple)->l4.port[1] = session->dst_port;
                ((fa_5tuple_t*)&pkt_5tuple)->l4.proto = IP_PROTOCOL_TCP;
                ((fa_5tuple_t*)&pkt_5tuple)->pkt.is_ip6 = is_ip6;
                ((fa_5tuple_t*)&pkt_5tuple)->pkt.l4_valid = 1;
            }
            else
            {
                ((fa_5tuple_t*)&pkt_5tuple)->l4.proto = session->protocol;
                ((fa_5tuple_t*)&pkt_5tuple)->pkt.is_ip6 = is_ip6;
                ((fa_5tuple_t*)&pkt_5tuple)->pkt.l4_valid = 0;
            }

            /* Perform ACL match */
            if (!am->acl_methods.match_5tuple)
            {
                *action = IPS_ACL_ACTION_PERMIT;
                return 0;
            }
            
            /* Call VPP ACL plugin's match function */
            int match_result = am->acl_methods.match_5tuple(ctx->context_id, &pkt_5tuple,
                                                         is_ip6, &acl_action,
                                                         &acl_pos, &acl_match,
                                                         &rule_match, &trace_bitmap);

            if (match_result)
            {
                /* Update batch rule statistics for the matched rule */
                ips_acl_update_batch_rule_stats(am, acl_match, rule_match);

                /* ACL matched - convert VPP ACL action to IPS ACL action
                 * VPP ACL plugin action encoding:
                 * - action=0 → DENY
                 * - action=1 → PERMIT  
                 * - action=2 → REFLECT
                 */
                switch (acl_action)
                {
                case 0: /* Deny */
                    *action = IPS_ACL_ACTION_DENY;
                    stats->packets_denied++;
                    stats->sessions_blocked++;
                    stats->acl_hits++;
                    stats->acl_deny_hits++;
                    return 1;

                case 1: /* Permit */
                    *action = IPS_ACL_ACTION_PERMIT;
                    stats->packets_permit++;
                    stats->acl_hits++;
                    stats->acl_permit_hits++;
                    return 0;

                case 2: /* Reflect */
                default:
                    /* Reflect and other actions - treat as permit for now */
                    *action = IPS_ACL_ACTION_PERMIT;
                    stats->packets_permit++;
                    stats->acl_hits++;
                    return 0;
                }
            }

            /* No VPP ACL match - continue with IPS-specific state tracking */
            /* Create session key for state tracking */
            ips_session_key_t session_key;
            clib_memset(&session_key, 0, sizeof(session_key));

            if (ip4)
            {
                session_key.src_ip.ip4 = ip4->src_address;
                session_key.dst_ip.ip4 = ip4->dst_address;
                session_key.ip_version = 4;
            }
            else if (ip6)
            {
                session_key.src_ip.ip6 = ip6->src_address;
                session_key.dst_ip.ip6 = ip6->dst_address;
                session_key.ip_version = 6;
            }

            if (tcp)
            {
                session_key.src_port = tcp->src_port;
                session_key.dst_port = tcp->dst_port;
                session_key.protocol = IP_PROTOCOL_TCP;

                /* Update TCP state tracking - determine direction based on session */
                u8 direction = 0; /* Default: client->server */
                if (session)
                {
                    /* Check if this packet matches the session direction */
                    if ((ip4 &&
                         ip4_address_compare(&ip4->src_address, &session->src_ip4) == 0 &&
                         clib_net_to_host_u16(tcp->src_port) == session->src_port) ||
                        (ip6 &&
                         ip6_address_compare(&ip6->src_address, &session->src_ip6) == 0 &&
                         clib_net_to_host_u16(tcp->src_port) == session->src_port))
                    {
                        direction = 0; /* Forward direction */
                    }
                    else
                    {
                        direction = 1; /* Reverse direction */
                    }
                }

                ips_tcp_state_t current_state = ips_acl_update_tcp_state(&session_key, tcp, direction);
                
                /* Update session state appropriately (only if session exists) */
                if (session && direction == 0)
                {
                    if (current_state == IPS_TCP_STATE_ESTABLISHED)
                        session->tcp_state_src = IPS_SESSION_STATE_ESTABLISHED;
                    else if (current_state == IPS_TCP_STATE_NEW)
                        session->tcp_state_src = IPS_SESSION_STATE_SYN_RECVED;
                }

                /* Check for TCP state anomalies */
                if (am->enable_tcp_state_tracking)
                {
                    /* Check for suspicious TCP state transitions */
                    /* For example: data packet without proper handshake */
                    if (tcp_doff(tcp) > 5 && /* Has data (data offset > 5) */
                        current_state == IPS_TCP_STATE_NEW && /* But connection not established */
                        !(tcp->flags & TCP_FLAG_SYN)) /* And not a SYN packet */
                    {
                        *action = IPS_ACL_ACTION_RESET;
                        stats->packets_reset++;
                        stats->sessions_blocked++;
                        return 1;
                    }
                }
            }
            else
            {
                session_key.protocol = ip4 ? ip4->protocol : ip6->protocol;
            }

            /* Apply session-based rate limiting */
            if (session && session->packet_count_src > 1000) /* High packet count */
            {
                f64 time_diff = now - session->last_packet_time;
                if (time_diff < 1.0) /* More than 1000 packets in 1 second */
                {
                    *action = IPS_ACL_ACTION_DENY;
                    stats->packets_denied++;
                    stats->sessions_blocked++;
                    return 1;
                }
            }
        }
    }

    /* Since we're using VPP ACL plugin for rule matching,
     * we don't need to check IPS-specific rules anymore.
     * If VPP ACL didn't match, we apply default action. */

    *action = am->default_action;
    switch (am->default_action)
    {
    case IPS_ACL_ACTION_DENY:
        stats->packets_denied++;
        stats->sessions_blocked++;
        return 1;
    case IPS_ACL_ACTION_RESET:
        stats->packets_reset++;
        stats->sessions_blocked++;
        return 1;
    case IPS_ACL_ACTION_PERMIT:
    case IPS_ACL_ACTION_LOG:    /* Log but continue processing */
    default:
        stats->packets_permit++;
        return 0;
    }
}

/**
 * @brief Send TCP reset packet
 */
int
ips_acl_send_tcp_reset(u32 thread_index, ips_session_t *session, u8 is_reply)
{
    if (!session)
        return -1;

    /* Use the blocking module to send TCP reset
     * Note: When called from ACL without original packet context,
     * we use configured block TX interface and NULL MACs (will use broadcast) */
    extern ips_block_manager_t ips_block_manager;
    u32 sw_if_index = ips_block_manager.use_rx_interface ? 
                     0 : ips_block_manager.block_tx_sw_if_index;
    
    return ips_block_send_tcp_reset(thread_index, sw_if_index,
                                   NULL, NULL, /* MAC addresses unknown */
                                   session, NULL, NULL, NULL,
                                   is_reply, IPS_BLOCK_REASON_ACL);
}


/**
 * @brief Create VPP ACL rule using VPP CLI (simpler approach)
 */
static u32
ips_acl_create_vpp_rule(ips_acl_rule_t *ips_rule)
{
    vlib_main_t *vm = acl_vlib_main;
    u8 *cmd = 0;
    u32 acl_index = ~0;
    int ret;

    if (!vm || !ips_rule)
        return ~0;

    /* Build the ACL creation command using VPP ACL plugin format
     * Format: set acl-plugin acl <permit|deny> src <PREFIX> dst <PREFIX> [proto X] [sport X[-Y]] [dport X[-Y]]
     * Note: Don't specify index - let VPP ACL plugin assign one automatically
     */
    const char *action_str = (ips_rule->action == IPS_ACL_ACTION_PERMIT || 
                              ips_rule->action == IPS_ACL_ACTION_LOG) ? "permit" : "deny";
    
    if (ips_rule->is_ipv6)
    {
        vec_reset_length(cmd);
        cmd = format(cmd, "set acl-plugin acl %s src %U/%u dst %U/%u",
                     action_str,
                     format_ip6_address, &ips_rule->src_ip.ip6, ips_rule->src_prefixlen,
                     format_ip6_address, &ips_rule->dst_ip.ip6, ips_rule->dst_prefixlen);
                     
        /* Add protocol if specified */
        if (ips_rule->protocol != 0)
            cmd = format(cmd, " proto %u", ips_rule->protocol);
            
        /* Add source port range if specified */
        if (ips_rule->src_port_start != 0 || ips_rule->src_port_end != 65535)
            cmd = format(cmd, " sport %u-%u", ips_rule->src_port_start, ips_rule->src_port_end);
            
        /* Add destination port range if specified */
        if (ips_rule->dst_port_start != 0 || ips_rule->dst_port_end != 65535)
            cmd = format(cmd, " dport %u-%u", ips_rule->dst_port_start, ips_rule->dst_port_end);
    }
    else
    {
        vec_reset_length(cmd);
        cmd = format(cmd, "set acl-plugin acl %s src %U/%u dst %U/%u",
                     action_str,
                     format_ip4_address, &ips_rule->src_ip.ip4, ips_rule->src_prefixlen,
                     format_ip4_address, &ips_rule->dst_ip.ip4, ips_rule->dst_prefixlen);
                     
        /* Add protocol if specified */
        if (ips_rule->protocol != 0)
            cmd = format(cmd, " proto %u", ips_rule->protocol);
            
        /* Add source port range if specified */
        if (ips_rule->src_port_start != 0 || ips_rule->src_port_end != 65535)
            cmd = format(cmd, " sport %u-%u", ips_rule->src_port_start, ips_rule->src_port_end);
            
        /* Add destination port range if specified */
        if (ips_rule->dst_port_start != 0 || ips_rule->dst_port_end != 65535)
            cmd = format(cmd, " dport %u-%u", ips_rule->dst_port_start, ips_rule->dst_port_end);
    }

    if (vec_len(cmd) == 0)
    {
        vec_free(cmd);
        return ~0;
    }

    clib_warning("Executing VPP ACL command: %s", cmd);

    /* Execute the command via VPP CLI to create ACL
     * Note: unformat_init_vector takes ownership of the cmd vector,
     * so we don't need to free it manually after this point.
     */
    unformat_input_t cli_input;
    unformat_init_vector(&cli_input, cmd);
    
    /* Use vlib_cli_input to execute the ACL command */
    ret = vlib_cli_input(vm, &cli_input, 0, 0);
    
    /* unformat_free will free the cmd vector */
    unformat_free(&cli_input);

    if (ret == 0)
    {
        /* ACL was created successfully
         * VPP ACL plugin automatically assigns an index starting from 0
         * We track the next expected index ourselves
         */
        static u32 next_expected_acl_index = 0;
        acl_index = next_expected_acl_index++;
        clib_warning("VPP ACL rule created successfully, expected index: %u", acl_index);
    }
    else
    {
        clib_warning("Failed to create VPP ACL rule, error code: %d", ret);
        /* cmd was already freed by unformat_free above */
        acl_index = ~0;
    }

    return acl_index;
}

/**
 * @brief Add session-level ACL rule with extended features
 */
u32
ips_acl_add_session_rule(ips_acl_rule_t *rule)
{
    ips_acl_manager_t *am = &ips_acl_manager;
    ips_acl_rule_t *new_rule;

    if (!rule)
        return ~0;

    /* Create VPP ACL rule first */
    u32 vpp_acl_index = ips_acl_create_vpp_rule(rule);
    if (vpp_acl_index == ~0)
        return ~0;

    pool_get_zero(am->ips_rules, new_rule);
    clib_memcpy(new_rule, rule, sizeof(*rule));
    new_rule->rule_id = am->next_rule_id++;
    new_rule->vpp_acl_index = vpp_acl_index; /* VPP ACL index assigned by plugin */
    new_rule->vpp_rule_index = 0; /* Rule index within ACL (0 for single-rule ACL) */
    new_rule->hit_count = 0;
    new_rule->session_hit_count = 0;
    new_rule->last_hit_time = 0;
    new_rule->enabled = 1;

    /* Set default values for extended features */
    if (new_rule->match_tcp_state == 0)
        new_rule->match_tcp_state = 0; /* Disabled by default */

    if (new_rule->session_control == 0)
        new_rule->session_control = 1; /* Session-level by default */

    if (new_rule->match_direction == 0)
        new_rule->match_direction = 0; /* Bidirectional by default */

    clib_warning("Added session ACL rule %u: %s", new_rule->rule_id,
                new_rule->description[0] ? new_rule->description : "no description");

    return new_rule->rule_id;
}

/**
 * @brief Add IPS ACL rule to the appropriate main ACL
 * Routes rule to IPv4/IPv6 whitelist/blacklist ACL based on IP version and action
 */
u32
ips_acl_add_rule(ips_acl_rule_t *rule)
{
    ips_acl_manager_t *am = &ips_acl_manager;
    ips_acl_rule_t *rule_metadata;
    u32 target_acl_index;
    u8 is_permit;
    u32 new_acl_index;
    ips_acl_rule_t **all_rules = NULL;
    ips_acl_rule_t *temp_rules = NULL;
    u32 count = 0;

    if (!rule)
        return ~0;

    /* Determine target ACL based on IP version and action */
    is_permit = (rule->action == IPS_ACL_ACTION_PERMIT);
    get_target_acl_index(rule->is_ipv6, rule->action, &target_acl_index);

    /* Collect existing rules from target ACL */
    all_rules = ips_acl_collect_rules_by_acl(target_acl_index, rule->is_ipv6, is_permit);
    count = vec_len(all_rules);

    /* Create rule metadata */
    pool_get_zero(am->ips_rules, rule_metadata);
    clib_memcpy(rule_metadata, rule, sizeof(ips_acl_rule_t));
    rule_metadata->rule_id = am->next_rule_id++;
    rule_metadata->vpp_acl_index = target_acl_index;
    rule_metadata->vpp_rule_index = count;  /* Position in the ACL */
    rule_metadata->enabled = 1;
    rule_metadata->hit_count = 0;

    /* Build temporary array for VPP ACL creation */
    vec_validate(temp_rules, count);
    for (u32 i = 0; i < count; i++)
    {
        temp_rules[i] = *all_rules[i];
        /* Update vpp_rule_index for existing rules */
        all_rules[i]->vpp_rule_index = i;
    }
    /* Add new rule at the end */
    temp_rules[count] = *rule_metadata;

    /* Replace/create VPP ACL with updated rules */
    new_acl_index = ips_acl_add_replace_vpp(target_acl_index, temp_rules, count + 1);
    if (new_acl_index == ~0)
    {
        /* Rollback: remove metadata */
        pool_put(am->ips_rules, rule_metadata);
        vec_free(all_rules);
        vec_free(temp_rules);
        return ~0;
    }

    /* Update main ACL index if this was a new ACL */
    if (target_acl_index == ~0)
    {
        if (rule->is_ipv6)
        {
            if (is_permit)
                am->ipv6_whitelist_acl_index = new_acl_index;
            else
                am->ipv6_blacklist_acl_index = new_acl_index;
        }
        else
        {
            if (is_permit)
                am->ipv4_whitelist_acl_index = new_acl_index;
            else
                am->ipv4_blacklist_acl_index = new_acl_index;
        }
        /* Update rule_metadata's vpp_acl_index to actual index */
        rule_metadata->vpp_acl_index = new_acl_index;
    }

    /* Update rule count */
    if (rule->is_ipv6)
    {
        if (is_permit)
            am->ipv6_whitelist_rule_count = count + 1;
        else
            am->ipv6_blacklist_rule_count = count + 1;
    }
    else
    {
        if (is_permit)
            am->ipv4_whitelist_rule_count = count + 1;
        else
            am->ipv4_blacklist_rule_count = count + 1;
    }

    /* Update ACL contexts for all threads */
    for (u32 i = 0; i < am->num_threads; i++)
    {
        ips_acl_context_t *ctx = &am->per_thread_contexts[i];
        if (ctx->initialized)
        {
            /* Ensure main ACL is in the context's ACL list */
            u8 found = 0;
            for (u32 j = 0; j < vec_len(ctx->acl_list); j++)
            {
                if (ctx->acl_list[j] == new_acl_index)
                {
                    found = 1;
                    break;
                }
            }
            if (!found)
            {
                vec_add1(ctx->acl_list, new_acl_index);
                am->acl_methods.set_acl_vec_for_context(ctx->context_id, ctx->acl_list);
            }
        }
    }

    /* Cleanup */
    vec_free(all_rules);
    vec_free(temp_rules);

    clib_warning("Added ACL rule %u: %s (IPv%d %s ACL index: %u, total rules: %u)",
                rule_metadata->rule_id,
                rule_metadata->description[0] ? rule_metadata->description : "no description",
                rule->is_ipv6 ? 6 : 4,
                is_permit ? "whitelist" : "blacklist",
                new_acl_index,
                count + 1);

    return rule_metadata->rule_id;
}

/**
 * @brief Get target ACL index based on IP version and action type
 * @param is_ipv6 IP version flag (0=IPv4, 1=IPv6)
 * @param action ACL action (permit/deny/reset/log)
 * @param acl_index_ptr Output: pointer to store the target ACL index
 * @return 0 on success, -1 on error
 */
static int
get_target_acl_index(u8 is_ipv6, ips_acl_action_t action, u32 *acl_index_ptr)
{
    ips_acl_manager_t *am = &ips_acl_manager;

    if (!acl_index_ptr)
        return -1;

    /* Route to appropriate ACL based on IP version and action */
    if (is_ipv6)
    {
        if (action == IPS_ACL_ACTION_PERMIT)
            *acl_index_ptr = am->ipv6_whitelist_acl_index;
        else
            *acl_index_ptr = am->ipv6_blacklist_acl_index;
    }
    else
    {
        if (action == IPS_ACL_ACTION_PERMIT)
            *acl_index_ptr = am->ipv4_whitelist_acl_index;
        else
            *acl_index_ptr = am->ipv4_blacklist_acl_index;
    }

    return 0;
}

/**
 * @brief Collect all rules belonging to a specific ACL
 * @param acl_index ACL index to collect rules for
 * @param is_ipv6 IP version filter
 * @param is_permit Action type filter (1=permit, 0=deny/reset/log)
 * @return Vector of rule pointers (must be freed by caller)
 */
static ips_acl_rule_t **
ips_acl_collect_rules_by_acl(u32 acl_index, u8 is_ipv6, u8 is_permit)
{
    ips_acl_manager_t *am = &ips_acl_manager;
    ips_acl_rule_t **rules = NULL;
    ips_acl_rule_t *r;

    pool_foreach(r, am->ips_rules)
    {
        /* Check if rule belongs to the specified ACL */
        if (r->vpp_acl_index == acl_index &&
            r->is_ipv6 == is_ipv6 &&
            (is_permit ? (r->action == IPS_ACL_ACTION_PERMIT) :
                        (r->action != IPS_ACL_ACTION_PERMIT)))
        {
            vec_add1(rules, r);
        }
    }

    return rules;
}

/**
 * @brief Replace VPP ACL with new rules using acl_add_replace mechanism
 * @param acl_index ACL index to replace (or ~0 to create new)
 * @param rules Array of IPS ACL rules
 * @param count Number of rules
 * @return New ACL index on success, ~0 on error
 */
static u32
ips_acl_add_replace_vpp(u32 acl_index, ips_acl_rule_t *rules, u32 count)
{
    vlib_main_t *vm = acl_vlib_main;
    u8 *cmd = 0;
    int ret;
    u32 new_acl_index;

    if (!vm || !rules || count == 0)
        return ~0;

    /* Build ACL replace/create command
     * Format: set acl-plugin acl [replace_index] <rule1>, <rule2>, ...
     * If acl_index is ~0, create new ACL; otherwise replace existing
     */
    if (acl_index == ~0)
        cmd = format(cmd, "set acl-plugin acl ");
    else
        cmd = format(cmd, "set acl-plugin acl %u ", acl_index);

    for (u32 i = 0; i < count; i++)
    {
        ips_acl_rule_t *rule = &rules[i];

        /* Add separator before each rule except the first */
        if (i > 0)
            cmd = format(cmd, ", ");

        /* Format the rule using existing helper */
        cmd = format_acl_rule_cli(cmd, rule);
    }

    clib_warning("VPP ACL %s with %u rules",
                (acl_index == ~0) ? "create" : "replace", count);

    /* Execute the command via VPP CLI
     * Note: unformat_init_vector takes ownership of the vector
     * unformat_free will clean it up, so don't call vec_free
     */
    unformat_input_t cli_input;
    unformat_init_vector(&cli_input, cmd);

    ret = vlib_cli_input(vm, &cli_input, 0, 0);
    unformat_free(&cli_input);
    /* cmd is now owned and freed by unformat_free, don't call vec_free */

    if (ret != 0)
    {
        clib_warning("Failed to %s VPP ACL, error code: %d",
                    (acl_index == ~0) ? "create" : "replace", ret);
        return ~0;
    }

    /* VPP assigns ACL index sequentially
     * If creating new, return next expected index
     * If replacing, return the same index
     */
    static u32 next_acl_index = 0;
    if (acl_index == ~0)
        new_acl_index = next_acl_index++;
    else
        new_acl_index = acl_index;

    clib_warning("VPP ACL %s successfully, index: %u",
                (acl_index == ~0) ? "created" : "replaced", new_acl_index);
    return new_acl_index;
}

/**
 * @brief Remove IPS ACL rule from its main ACL
 */
int
ips_acl_remove_rule(u32 rule_id)
{
    ips_acl_manager_t *am = &ips_acl_manager;
    ips_acl_rule_t *rule_to_delete = NULL;
    ips_acl_rule_t *r;
    ips_acl_rule_t **remaining_rules = NULL;
    ips_acl_rule_t *temp_rules = NULL;
    u32 acl_index;
    u8 is_ipv6;
    u8 is_permit;
    u32 count = 0;
    u32 new_acl_index;

    /* Find the rule to delete */
    pool_foreach(r, am->ips_rules)
    {
        if (r->rule_id == rule_id)
        {
            rule_to_delete = r;
            break;
        }
    }

    if (!rule_to_delete)
        return -1;

    /* Get ACL and rule properties */
    acl_index = rule_to_delete->vpp_acl_index;
    is_ipv6 = rule_to_delete->is_ipv6;
    is_permit = (rule_to_delete->action == IPS_ACL_ACTION_PERMIT);

    /* Collect remaining rules (excluding the one to delete) */
    pool_foreach(r, am->ips_rules)
    {
        if (r->rule_id != rule_id &&
            r->vpp_acl_index == acl_index &&
            r->is_ipv6 == is_ipv6 &&
            (is_permit ? (r->action == IPS_ACL_ACTION_PERMIT) :
                        (r->action != IPS_ACL_ACTION_PERMIT)))
        {
            vec_add1(remaining_rules, r);
            count++;
        }
    }

    /* Build temporary array for VPP ACL update */
    vec_validate(temp_rules, count > 0 ? count - 1 : 0);
    for (u32 i = 0; i < count; i++)
    {
        temp_rules[i] = *remaining_rules[i];
        /* Update vpp_rule_index */
        remaining_rules[i]->vpp_rule_index = i;
    }

    /* Replace VPP ACL with remaining rules */
    new_acl_index = ips_acl_add_replace_vpp(acl_index, temp_rules, count);
    if (new_acl_index == ~0)
    {
        vec_free(remaining_rules);
        vec_free(temp_rules);
        return -1;
    }

    /* Update rule count */
    if (is_ipv6)
    {
        if (is_permit)
            am->ipv6_whitelist_rule_count = count;
        else
            am->ipv6_blacklist_rule_count = count;
    }
    else
    {
        if (is_permit)
            am->ipv4_whitelist_rule_count = count;
        else
            am->ipv4_blacklist_rule_count = count;
    }

    /* Remove from pool */
    pool_put(am->ips_rules, rule_to_delete);

    /* Cleanup */
    vec_free(remaining_rules);
    vec_free(temp_rules);

    clib_warning("Removed ACL rule %u from IPv%d %s ACL index %u (remaining rules: %u)",
                rule_id, is_ipv6 ? 6 : 4,
                is_permit ? "whitelist" : "blacklist",
                acl_index, count);

    return 0;
}

/**
 * @brief Enable/disable IPS ACL rule
 */
int
ips_acl_set_rule_enabled(u32 rule_id, u8 enabled)
{
    ips_acl_manager_t *am = &ips_acl_manager;
    ips_acl_rule_t *rule;

    pool_foreach(rule, am->ips_rules)
    {
        if (rule->rule_id == rule_id)
        {
            rule->enabled = enabled;
            return 0;
        }
    }

    return -1;
}

/**
 * @brief Get IPS ACL statistics
 */
void
ips_acl_get_stats(u32 thread_index, ips_acl_stats_t *stats)
{
    ips_acl_manager_t *am = &ips_acl_manager;

    if (thread_index < vec_len(am->per_thread_stats) && stats)
    {
        *stats = am->per_thread_stats[thread_index];
    }
}

/**
 * @brief Reset IPS ACL statistics
 */
void
ips_acl_reset_stats(u32 thread_index)
{
    ips_acl_manager_t *am = &ips_acl_manager;

    if (thread_index < vec_len(am->per_thread_stats))
    {
        clib_memset(&am->per_thread_stats[thread_index], 0,
                   sizeof(am->per_thread_stats[thread_index]));
    }
}

/**
 * @brief Check if ACL plugin is available
 */
int
ips_acl_is_available(void)
{
    return ips_acl_manager.acl_plugin_loaded;
}

/**
 * @brief Apply all ACLs to an interface
 * This function applies all created VPP ACL rules to the specified interface
 */
int
ips_acl_apply_to_interface(u32 sw_if_index)
{
    ips_acl_manager_t *am = &ips_acl_manager;
    vlib_main_t *vm = vlib_get_main();
    
    if (!am->acl_plugin_loaded || !vm)
        return -1;
    
    /* Build list of ACL indices */
    u32 *acl_indices = 0;
    ips_acl_rule_t *rule;
    
    /* Collect all VPP ACL indices from IPS rules */
    pool_foreach(rule, am->ips_rules)
    {
        if (rule->enabled)
        {
            vec_add1(acl_indices, rule->vpp_acl_index);
        }
    }
    
    if (vec_len(acl_indices) == 0)
    {
        clib_warning("No ACL rules to apply to interface %u", sw_if_index);
        vec_free(acl_indices);
        return 0;
    }
    
    /* Build command to apply ACLs to interface
     * Format: set acl-plugin interface sw_if_index input <acl1> <acl2> ...
     */
    u8 *cmd = format(0, "set acl-plugin interface sw_if_index %u input", sw_if_index);
    
    for (u32 i = 0; i < vec_len(acl_indices); i++)
    {
        cmd = format(cmd, " %u", acl_indices[i]);
    }
    
    clib_warning("Applying ACLs to interface %u: %s", sw_if_index, cmd);
    
    /* Execute the command */
    unformat_input_t cli_input;
    unformat_init_vector(&cli_input, cmd);

    int ret = vlib_cli_input(vm, &cli_input, 0, 0);
    unformat_free(&cli_input);

    if (ret != 0)
    {
        clib_warning("Failed to apply ACLs to interface %u, error: %d", sw_if_index, ret);
        vec_free(acl_indices);
        return -1;
    }

    clib_warning("Successfully applied %u ACL rules to interface %u",
                 vec_len(acl_indices), sw_if_index);

    vec_free(acl_indices);
    return 0;
}

/*
 * ========================================================================
 * Batch ACL Rule Operations for Large-Scale Rule Support
 * ========================================================================
 */

/**
 * @brief Convert IPS ACL rule to VPP CLI format for batch operation
 */
static inline u8 *
format_acl_rule_cli(u8 *s, ips_acl_rule_t *rule)
{
    const char *action_str;

    /* Format action */
    switch (rule->action)
    {
        case IPS_ACL_ACTION_PERMIT:
        case IPS_ACL_ACTION_LOG:
            action_str = "permit";
            break;
        case IPS_ACL_ACTION_DENY:
        case IPS_ACL_ACTION_RESET:
        default:
            action_str = "deny";
            break;
    }

    /* Format: permit|deny src IP/prefix dst IP/prefix [proto] [sport] [dport] */
    if (rule->is_ipv6)
    {
        s = format(s, "%s src %U/%u dst %U/%u",
                  action_str,
                  format_ip6_address, &rule->src_ip.ip6, rule->src_prefixlen,
                  format_ip6_address, &rule->dst_ip.ip6, rule->dst_prefixlen);
    }
    else
    {
        s = format(s, "%s src %U/%u dst %U/%u",
                  action_str,
                  format_ip4_address, &rule->src_ip.ip4, rule->src_prefixlen,
                  format_ip4_address, &rule->dst_ip.ip4, rule->dst_prefixlen);
    }

    /* Add protocol if specified */
    if (rule->protocol != 0)
        s = format(s, " proto %u", rule->protocol);

    /* Add source port range if specified */
    if (rule->src_port_start != 0 || rule->src_port_end != 65535)
    {
        if (rule->src_port_start == rule->src_port_end)
            s = format(s, " sport %u", rule->src_port_start);
        else
            s = format(s, " sport %u-%u", rule->src_port_start, rule->src_port_end);
    }

    /* Add destination port range if specified */
    if (rule->dst_port_start != 0 || rule->dst_port_end != 65535)
    {
        if (rule->dst_port_start == rule->dst_port_end)
            s = format(s, " dport %u", rule->dst_port_start);
        else
            s = format(s, " dport %u-%u", rule->dst_port_start, rule->dst_port_end);
    }

    return s;
}

/**
 * @brief Create a single VPP ACL containing multiple IPS ACL rules
 * Uses VPP's batch rule feature (comma-separated rules in CLI)
 */
int
ips_acl_create_vpp_acl_batch(ips_acl_rule_t *ips_rules, u32 count, u32 *acl_index)
{
    vlib_main_t *vm = acl_vlib_main;
    u8 *cmd = 0;
    int ret;

    if (!vm || !ips_rules || !acl_index || count == 0)
        return -1;

    /* Build batch ACL command with comma-separated rules
     * Format: set acl-plugin acl <rule1>, <rule2>, <rule3>, ...
     */
    cmd = format(cmd, "set acl-plugin acl ");
    for (u32 i = 0; i < count; i++)
    {
        ips_acl_rule_t *rule = &ips_rules[i];

        /* Add separator before each rule except the first */
        if (i > 0)
            cmd = format(cmd, ", ");

        /* Format the rule */
        cmd = format_acl_rule_cli(cmd, rule);
    }

    if (vec_len(cmd) == 0)
        return -1;

    clib_warning("Creating VPP ACL with %u rules", count);

    /* Execute the command via VPP CLI */
    unformat_input_t cli_input;
    unformat_init_vector(&cli_input, cmd);

    ret = vlib_cli_input(vm, &cli_input, 0, 0);
    unformat_free(&cli_input);

    if (ret != 0)
    {
        clib_warning("Failed to create VPP ACL, error code: %d", ret);
        return -1;
    }

    /* VPP assigns ACL index sequentially - return the next expected index */
    static u32 next_acl_index = 0;
    *acl_index = next_acl_index++;

    clib_warning("VPP ACL created successfully with %u rules, index: %u", count, *acl_index);
    return 0;
}

/**
 * @brief Add multiple IPS ACL rules in a single VPP ACL with metadata storage
 *
 * @param rules Array of rule structures
 * @param count Number of rules in the array
 * @param acl_index Output: VPP ACL index created (optional, can be NULL)
 * @param group_id Output: Batch group ID created (optional, can be NULL)
 * @return 0 on success, -1 on error
 *
 * This function creates a batch group containing all rules, creates a single
 * VPP ACL for all rules, and stores metadata for each rule to enable
 * single-rule level operations (statistics, enable/disable, etc.)
 */
int
ips_acl_add_rules_batch(ips_acl_rule_t *rules, u32 count, u32 *acl_index, u32 *group_id)
{
    ips_acl_manager_t *am = &ips_acl_manager;
    ips_acl_batch_manager_t *bm = &am->batch_manager;
    vlib_main_t *vm = vlib_get_main();
    u32 vpp_acl_index;

    if (!rules || count == 0)
        return -1;

    /* Create VPP ACL containing all rules */
    if (ips_acl_create_vpp_acl_batch(rules, count, &vpp_acl_index) != 0)
        return -1;

    /* Create batch group */
    ips_acl_batch_group_t *group;
    pool_get_zero(bm->groups, group);
    group->group_id = bm->next_group_id++;
    group->vpp_acl_index = vpp_acl_index;
    group->rule_count = count;
    group->is_enabled = 1;
    group->create_time = vlib_time_now(vm);
    group->total_hits = 0;

    /* Allocate rule pointers and index map */
    vec_validate(group->rules, count - 1);
    vec_validate(group->rule_index_map, count - 1);

    /* Create metadata for each rule */
    for (u32 i = 0; i < count; i++)
    {
        ips_acl_rule_t *rule_metadata;
        pool_get_zero(am->ips_rules, rule_metadata);
        clib_memcpy(rule_metadata, &rules[i], sizeof(ips_acl_rule_t));

        rule_metadata->rule_id = am->next_rule_id++;
        rule_metadata->batch_group_id = group->group_id;
        rule_metadata->vpp_acl_index = vpp_acl_index;
        rule_metadata->vpp_rule_index = i;  /* VPP ACL internal rule index */
        rule_metadata->enabled = 1;

        /* Initialize counters */
        rule_metadata->hit_count = 0;
        rule_metadata->session_hit_count = 0;
        rule_metadata->last_hit_time = 0;

        /* Store in batch group */
        group->rules[i] = rule_metadata;
        group->rule_index_map[i] = rule_metadata->rule_id;
    }

    /* Establish VPP ACL -> batch group mapping */
    if (vpp_acl_index >= vec_len(bm->vpp_acl_to_group_map))
    {
        /* Expand mapping array */
        u32 old_len = vec_len(bm->vpp_acl_to_group_map);
        vec_resize(bm->vpp_acl_to_group_map, vpp_acl_index + 1);
        /* Initialize new entries */
        for (u32 i = old_len; i < vec_len(bm->vpp_acl_to_group_map); i++)
            bm->vpp_acl_to_group_map[i] = ~0;
    }
    bm->vpp_acl_to_group_map[vpp_acl_index] = group->group_id;

    /* Update ACL contexts for all threads */
    for (u32 i = 0; i < am->num_threads; i++)
    {
        ips_acl_context_t *ctx = &am->per_thread_contexts[i];
        if (ctx->initialized)
        {
            /* Add VPP ACL to context */
            vec_add1(ctx->acl_list, vpp_acl_index);
            am->acl_methods.set_acl_vec_for_context(ctx->context_id, ctx->acl_list);
        }
    }

    bm->num_groups++;

    /* Output parameters */
    if (acl_index)
        *acl_index = vpp_acl_index;
    if (group_id)
        *group_id = group->group_id;

    clib_warning("Added %u ACL rules in VPP ACL %u (batch group %u)",
                 count, vpp_acl_index, group->group_id);

    return 0;
}

/**
 * @brief Parse a single line from ACL rules file
 */
static int
parse_acl_rule_line(const char *line, ips_acl_rule_t *rule)
{
    char *copy, *token, *saveptr = NULL;
    int rv = -1;

    if (!line || !rule)
        return -1;

    /* Skip empty lines and comments */
    while (*line && isspace(*line)) line++;
    if (*line == '\0' || *line == '#')
        return 0;

    /* Make a mutable copy */
    copy = strdup(line);
    if (!copy)
        return -1;

    /* Initialize rule with defaults */
    clib_memset(rule, 0, sizeof(*rule));
    rule->action = IPS_ACL_ACTION_PERMIT;
    rule->src_port_start = 0;
    rule->src_port_end = 65535;
    rule->dst_port_start = 0;
    rule->dst_port_end = 65535;
    rule->protocol = 0;  /* 0 = any */

    /* Parse action (permit|deny) */
    token = strtok_r(copy, " \t\n", &saveptr);
    if (!token)
        goto cleanup;

    if (strcmp(token, "permit") == 0 || strcmp(token, "allow") == 0)
        rule->action = IPS_ACL_ACTION_PERMIT;
    else if (strcmp(token, "deny") == 0 || strcmp(token, "block") == 0)
        rule->action = IPS_ACL_ACTION_DENY;
    else if (strcmp(token, "reset") == 0)
        rule->action = IPS_ACL_ACTION_RESET;
    else
        goto cleanup;

    /* Parse src IP/prefix */
    token = strtok_r(NULL, " \t\n", &saveptr);
    if (!token || strcmp(token, "src") != 0)
        goto cleanup;

    token = strtok_r(NULL, " \t\n", &saveptr);
    if (!token)
        goto cleanup;

    if (strchr(token, ':'))  /* IPv6 */
    {
        rule->is_ipv6 = 1;
        /* Parse IPv6 address with prefix - simpler approach using inet_pton */
        char *slash = strchr(token, '/');
        if (slash)
        {
            *slash = '\0';
            rule->src_prefixlen = atoi(slash + 1);
        }
        /* Convert IPv6 string to binary format */
        if (inet_pton(AF_INET6, token, &rule->src_ip.ip6) != 1)
            goto cleanup;
    }
    else  /* IPv4 */
    {
        rule->is_ipv6 = 0;
        if (sscanf(token, "%hhu.%hhu.%hhu.%hhu/%hhu",
                   &rule->src_ip.ip4.as_u8[0], &rule->src_ip.ip4.as_u8[1],
                   &rule->src_ip.ip4.as_u8[2], &rule->src_ip.ip4.as_u8[3],
                   &rule->src_prefixlen) != 5)
            goto cleanup;
    }

    /* Parse dst IP/prefix */
    token = strtok_r(NULL, " \t\n", &saveptr);
    if (!token || strcmp(token, "dst") != 0)
        goto cleanup;

    token = strtok_r(NULL, " \t\n", &saveptr);
    if (!token)
        goto cleanup;

    if (strchr(token, ':'))  /* IPv6 */
    {
        /* Parse IPv6 address with prefix - simpler approach using inet_pton */
        char *slash = strchr(token, '/');
        if (slash)
        {
            *slash = '\0';
            rule->dst_prefixlen = atoi(slash + 1);
        }
        /* Convert IPv6 string to binary format */
        if (inet_pton(AF_INET6, token, &rule->dst_ip.ip6) != 1)
            goto cleanup;
    }
    else  /* IPv4 */
    {
        if (sscanf(token, "%hhu.%hhu.%hhu.%hhu/%hhu",
                   &rule->dst_ip.ip4.as_u8[0], &rule->dst_ip.ip4.as_u8[1],
                   &rule->dst_ip.ip4.as_u8[2], &rule->dst_ip.ip4.as_u8[3],
                   &rule->dst_prefixlen) != 5)
            goto cleanup;
    }

    /* Parse optional fields */
    while ((token = strtok_r(NULL, " \t\n", &saveptr)))
    {
        if (strcmp(token, "proto") == 0 || strcmp(token, "protocol") == 0)
        {
            token = strtok_r(NULL, " \t\n", &saveptr);
            if (!token)
                goto cleanup;
            rule->protocol = atoi(token);
        }
        else if (strcmp(token, "sport") == 0)
        {
            token = strtok_r(NULL, " \t\n", &saveptr);
            if (!token)
                goto cleanup;
            rule->src_port_start = rule->src_port_end = atoi(token);
        }
        else if (strcmp(token, "dport") == 0)
        {
            token = strtok_r(NULL, " \t\n", &saveptr);
            if (!token)
                goto cleanup;
            rule->dst_port_start = rule->dst_port_end = atoi(token);
        }
    }

    rv = 0;  /* Success */

cleanup:
    free(copy);
    return rv;
}

/**
 * @brief Load ACL rules from a file
 * Supports simple text format:
 * permit|deny src IP/prefix dst IP/prefix [proto X] [sport X] [dport X]
 */
int
ips_acl_load_rules_from_file(const char *filename, u32 *acl_index, u32 *rules_loaded)
{
    FILE *fp;
    char line[1024];
    ips_acl_rule_t *rules = NULL;
    u32 count = 0;

    if (!filename || !acl_index || !rules_loaded)
        return -1;

    fp = fopen(filename, "r");
    if (!fp)
    {
        clib_warning("Failed to open ACL rules file: %s", filename);
        return -1;
    }

    clib_warning("Loading ACL rules from file: %s", filename);

    /* Read and parse rules */
    while (fgets(line, sizeof(line), fp))
    {
        ips_acl_rule_t rule;

        /* Skip empty lines and comments */
        int i = 0;
        while (line[i] && isspace(line[i])) i++;
        if (line[i] == '\0' || line[i] == '#')
            continue;

        /* Parse rule line */
        if (parse_acl_rule_line(line, &rule) != 0)
        {
            clib_warning("Failed to parse rule line %u: %s", count + 1, line);
            continue;
        }

        /* Add to rules array */
        vec_add1(rules, rule);
        count++;

        /* Process in batches of 1000 to avoid overly long CLI commands */
        if (count >= 1000)
        {
            clib_warning("Loaded batch of %u rules", count);
            break;
        }
    }

    fclose(fp);

    if (count == 0)
    {
        clib_warning("No valid rules found in file: %s", filename);
        return -1;
    }

    /* Create VPP ACL with all rules using unified batch mode */
    u32 group_id;
    if (ips_acl_add_rules_batch(rules, count, acl_index, &group_id) != 0)
    {
        vec_free(rules);
        return -1;
    }

    vec_free(rules);

    *rules_loaded = count;
    clib_warning("Successfully loaded %u ACL rules from %s into VPP ACL %u (batch group %u)",
                 count, filename, *acl_index, group_id);

    return 0;
}