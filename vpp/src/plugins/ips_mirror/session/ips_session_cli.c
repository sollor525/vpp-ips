/*
 * ips_session_cli.c - VPP IPS Plugin Session Management CLI Commands
 *
 * Copyright (c) 2024 VPP IPS Project
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>
#include <vnet/ip/format.h>

#include "session/ips_session.h"

/**
 * @brief 显示会话统计信息
 */
static clib_error_t *
ips_session_show_stats_command_fn (vlib_main_t * vm,
                                   unformat_input_t * __clib_unused input,
                                   vlib_cli_command_t * __clib_unused cmd)
{
    ips_session_manager_t *sm = &ips_session_manager;
    u32 num_threads = vec_len (sm->per_thread_data);
    u32 total_active = 0, total_created = 0, total_deleted = 0;

    vlib_cli_output (vm, "IPS Session Statistics:");
    vlib_cli_output (vm, "======================");

    for (u32 i = 0; i < num_threads; i++)
    {
        u32 active, created, deleted;
        ips_session_get_stats_args_t stats_args = { .thread_index = i, .active_sessions = &active, .total_created = &created, .total_deleted = &deleted };
        ips_session_get_stats (&stats_args);

        total_active += active;
        total_created += created;
        total_deleted += deleted;

        vlib_cli_output (vm, "Thread %u:", i);
        vlib_cli_output (vm, "  Active sessions: %u", active);
        vlib_cli_output (vm, "  Total created: %u", created);
        vlib_cli_output (vm, "  Total deleted: %u", deleted);
        vlib_cli_output (vm, "  Pool utilization: %.2f%%",
                        (f64) active / sm->session_pool_size * 100.0);
    }

    vlib_cli_output (vm, "");
    vlib_cli_output (vm, "Global Totals:");
    vlib_cli_output (vm, "  Active sessions: %u", total_active);
    vlib_cli_output (vm, "  Total created: %u", total_created);
    vlib_cli_output (vm, "  Total deleted: %u", total_deleted);
    vlib_cli_output (vm, "  Overall utilization: %.2f%%",
                    (f64) total_active / (sm->session_pool_size * num_threads) * 100.0);

    return 0;
}

VLIB_CLI_COMMAND (ips_session_show_stats_command, static) = {
    .path = "show ips sessions stats",
    .short_help = "show ips sessions stats",
    .function = ips_session_show_stats_command_fn,
};

/**
 * @brief 显示会话老化统计
 */
static clib_error_t *
ips_session_show_aging_command_fn (vlib_main_t * vm,
                                   unformat_input_t * __clib_unused input,
                                   vlib_cli_command_t * __clib_unused cmd)
{
    ips_session_manager_t *sm = &ips_session_manager;
    u32 num_threads = vec_len (sm->per_thread_data);

    vlib_cli_output (vm, "IPS Session Aging Statistics:");
    vlib_cli_output (vm, "=============================");

    for (u32 i = 0; i < num_threads; i++)
    {
        ips_session_aging_stats_t aging_stats;
        ips_session_per_thread_data_t *ptd = &sm->per_thread_data[i];

        ips_session_get_aging_stats (i, &aging_stats);

        vlib_cli_output (vm, "Thread %u:", i);
        vlib_cli_output (vm, "  Sessions expired by timers: %llu", aging_stats.expired_sessions);
        vlib_cli_output (vm, "  Sessions cleaned by force: %llu", aging_stats.forced_cleanup_sessions);
        vlib_cli_output (vm, "  Emergency cleanup count: %u",
                        ptd->aging_state.emergency_cleanup_count);
        vlib_cli_output (vm, "  Last cleanup time: %.3f",
                        ptd->aging_state.last_cleanup_time);

        /* 显示老化阈值 */
        vlib_cli_output (vm, "  Aging thresholds:");
        vlib_cli_output (vm, "    Normal: %u", ptd->aging_config.normal_threshold);
        vlib_cli_output (vm, "    Aggressive: %u", ptd->aging_config.aggressive_threshold);
        vlib_cli_output (vm, "    Emergency: %u", ptd->aging_config.emergency_threshold);
        vlib_cli_output (vm, "    Force cleanup target: %u", ptd->aging_config.force_cleanup_target);
    }

    return 0;
}

VLIB_CLI_COMMAND (ips_session_show_aging_command, static) = {
    .path = "show ips sessions aging",
    .short_help = "show ips sessions aging",
    .function = ips_session_show_aging_command_fn,
};

/**
 * @brief 显示具体会话信息
 */
static clib_error_t *
ips_session_show_detail_command_fn (vlib_main_t * vm,
                                    unformat_input_t * input,
                                    vlib_cli_command_t * __clib_unused cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    ip4_address_t src_ip4, dst_ip4;
    ip6_address_t src_ip6, dst_ip6;
    u32 src_port = 0, dst_port = 0;
    u32 protocol = 6; /* TCP */
    u8 is_ipv6 = 0;
    u32 thread_index = ~0;
    clib_error_t *error = 0;

    if (!unformat_user (input, unformat_line_input, line_input))
        return 0;

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "src %U", unformat_ip4_address, &src_ip4))
        {
            is_ipv6 = 0; /* parsed IPv4 src */
            /* unique no-op to avoid repeated-branch warning */
            do { (void)0; } while (0);
        }
        else if (unformat (line_input, "src %U", unformat_ip6_address, &src_ip6))
        {
            is_ipv6 = 1; /* parsed IPv6 src */
            /* unique no-op to avoid repeated-branch warning */
            do { (void)1; } while (0);
        }
        else if (unformat (line_input, "dst %U", unformat_ip4_address, &dst_ip4))
        {
            is_ipv6 = 0; /* parsed IPv4 dst */
            /* unique no-op to avoid repeated-branch warning */
            do { (void)2; } while (0);
        }
        else if (unformat (line_input, "dst %U", unformat_ip6_address, &dst_ip6))
        {
            is_ipv6 = 1; /* parsed IPv6 dst */
            /* unique no-op to avoid repeated-branch warning */
            do { (void)3; } while (0);
        }
        else if (unformat (line_input, "sport %u", &src_port))
        {
            /* unique no-op to avoid repeated-branch warning */
            do { (void)4; } while (0);
        }
        else if (unformat (line_input, "dport %u", &dst_port))
        {
            /* unique no-op to avoid repeated-branch warning */
            do { (void)5; } while (0);
        }
        else if (unformat (line_input, "protocol %u", &protocol))
        {
            /* unique no-op to avoid repeated-branch warning */
            do { (void)6; } while (0);
        }
        else if (unformat (line_input, "thread %u", &thread_index))
        {
            /* unique no-op to avoid repeated-branch warning */
            do { (void)7; } while (0);
        }
        else
        {
            error = clib_error_return (0, "unknown input `%U'",
                                      format_unformat_error, line_input);
            goto done;
        }
    }

    /* 查找会话 */
    ips_session_t *session = NULL;
    ips_session_manager_t *sm = &ips_session_manager;
    u32 num_threads = vec_len (sm->per_thread_data);

    if (thread_index == ~0)
    {
        /* 在所有线程中查找 */
        for (u32 i = 0; i < num_threads && !session; i++)
        {
            if (is_ipv6)
            {
                ips_session_key6_t key;
                clib_memset (&key, 0, sizeof (key));
                key.src_ip = src_ip6;
                key.dst_ip = dst_ip6;
                key.src_port = clib_host_to_net_u16 (src_port);
                key.dst_port = clib_host_to_net_u16 (dst_port);
                key.protocol = protocol;

                session = ips_session_lookup_ipv6 (i, &key);
                if (session)
                    thread_index = i;
            }
            else
            {
                ips_session_key4_t key;
                clib_memset (&key, 0, sizeof (key));
                key.src_ip = src_ip4;
                key.dst_ip = dst_ip4;
                key.src_port = clib_host_to_net_u16 (src_port);
                key.dst_port = clib_host_to_net_u16 (dst_port);
                key.protocol = protocol;

                session = ips_session_lookup_ipv4 (i, &key);
                if (session)
                    thread_index = i;
            }
        }
    }
    else
    {
        /* 在指定线程中查找 */
        if (thread_index < num_threads)
        {
            if (is_ipv6)
            {
                ips_session_key6_t key;
                clib_memset (&key, 0, sizeof (key));
                key.src_ip = src_ip6;
                key.dst_ip = dst_ip6;
                key.src_port = clib_host_to_net_u16 (src_port);
                key.dst_port = clib_host_to_net_u16 (dst_port);
                key.protocol = protocol;

                session = ips_session_lookup_ipv6 (thread_index, &key);
            }
            else
            {
                ips_session_key4_t key;
                clib_memset (&key, 0, sizeof (key));
                key.src_ip = src_ip4;
                key.dst_ip = dst_ip4;
                key.src_port = clib_host_to_net_u16 (src_port);
                key.dst_port = clib_host_to_net_u16 (dst_port);
                key.protocol = protocol;

                session = ips_session_lookup_ipv4 (thread_index, &key);
            }
        }
    }

    if (!session)
    {
        vlib_cli_output (vm, "Session not found");
        goto done;
    }

    /* 显示会话详细信息 */
    vlib_cli_output (vm, "Session Details:");
    vlib_cli_output (vm, "===============");
    vlib_cli_output (vm, "Thread index: %u", session->thread_index);
    vlib_cli_output (vm, "Session index: %u", session->session_index);
    vlib_cli_output (vm, "Protocol: %u", session->protocol);
    vlib_cli_output (vm, "IP version: %s", session->is_ipv6 ? "IPv6" : "IPv4");

    if (session->is_ipv6)
    {
        vlib_cli_output (vm, "Source: %U:%u",
                        format_ip6_address, &session->src_ip6,
                        clib_net_to_host_u16 (session->src_port));
        vlib_cli_output (vm, "Destination: %U:%u",
                        format_ip6_address, &session->dst_ip6,
                        clib_net_to_host_u16 (session->dst_port));
    }
    else
    {
        vlib_cli_output (vm, "Source: %U:%u",
                        format_ip4_address, &session->src_ip4,
                        clib_net_to_host_u16 (session->src_port));
        vlib_cli_output (vm, "Destination: %U:%u",
                        format_ip4_address, &session->dst_ip4,
                        clib_net_to_host_u16 (session->dst_port));
    }

    /* TCP 状态信息 */
    vlib_cli_output (vm, "TCP state src: %u", session->tcp_state_src);
    vlib_cli_output (vm, "TCP state dst: %u", session->tcp_state_dst);
    vlib_cli_output (vm, "TCP seq src: %u", session->tcp_seq_src);
    vlib_cli_output (vm, "TCP seq dst: %u", session->tcp_seq_dst);
    vlib_cli_output (vm, "TCP ack src: %u", session->tcp_ack_src);
    vlib_cli_output (vm, "TCP ack dst: %u", session->tcp_ack_dst);

    /* 时间信息 */
    f64 now = vlib_time_now (vm);
    vlib_cli_output (vm, "Session start time: %.3f", session->session_start_time);
    vlib_cli_output (vm, "Last packet time: %.3f", session->last_packet_time);
    vlib_cli_output (vm, "Session age: %.3f seconds", now - session->session_start_time);
    vlib_cli_output (vm, "Idle time: %.3f seconds", now - session->last_packet_time);
    vlib_cli_output (vm, "Timeout: %u seconds", session->timeout_seconds);

    /* 统计信息 */
    vlib_cli_output (vm, "Packets src->dst: %llu", session->packet_count_src);
    vlib_cli_output (vm, "Packets dst->src: %llu", session->packet_count_dst);

    /* 检测信息 */
    vlib_cli_output (vm, "Detection flags: 0x%x", session->detection_flags);
    vlib_cli_output (vm, "Alert count: %u", session->alert_count);

    /* 标志信息 */
    vlib_cli_output (vm, "Flags: 0x%x", session->flags);
    if (session->flags & IPS_SESSION_FLAG_ESTABLISHED)
        vlib_cli_output (vm, "  - ESTABLISHED");
    if (session->flags & IPS_SESSION_FLAG_STATELESS)
        vlib_cli_output (vm, "  - STATELESS");
    if (session->flags & IPS_SESSION_FLAG_MIRRORED)
        vlib_cli_output (vm, "  - MIRRORED");
    if (session->flags & IPS_SESSION_FLAG_DETECTED)
        vlib_cli_output (vm, "  - DETECTED");
    if (session->flags & IPS_SESSION_FLAG_BLOCKED)
        vlib_cli_output (vm, "  - BLOCKED");

 done:
    unformat_free (line_input);
    return error;
}

VLIB_CLI_COMMAND (ips_session_show_detail_command, static) = {
    .path = "show ips session detail",
    .short_help = "show ips session detail src <ip4|ip6> dst <ip4|ip6> sport <u16> dport <u16> [protocol <u8>] [thread <thread_index>]",
    .function = ips_session_show_detail_command_fn,
};

/**
 * @brief 强制清理会话
 */
static clib_error_t *
ips_session_clear_command_fn (vlib_main_t * vm,
                              unformat_input_t * __clib_unused input,
                              vlib_cli_command_t * __clib_unused cmd)
{
    ips_session_manager_t *sm = &ips_session_manager;
    u32 num_threads = vec_len (sm->per_thread_data);
    u32 total_cleaned = 0;

    for (u32 i = 0; i < num_threads; i++)
    {
        ips_session_aging_process (i);
        ips_session_cleanup_expired_args_t cleanup_args = { .thread_index = i, .timeout = 0 };
        u32 cleaned = ips_session_cleanup_expired (&cleanup_args);
        total_cleaned += cleaned;
    }

    vlib_cli_output (vm, "Cleaned %u expired sessions", total_cleaned);
    return 0;
}

VLIB_CLI_COMMAND (ips_session_clear_command, static) = {
    .path = "clear ips sessions",
    .short_help = "clear ips sessions",
    .function = ips_session_clear_command_fn,
};

/**
 * @brief 配置会话超时时间
 */
static clib_error_t *
ips_session_set_timeout_command_fn (vlib_main_t * vm,
                                    unformat_input_t * input,
                                    vlib_cli_command_t * __clib_unused cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    u32 syn_timeout = 0, established_timeout = 0;
    u32 fin_timeout = 0, rst_timeout = 0;
    clib_error_t *error = 0;

    if (!unformat_user (input, unformat_line_input, line_input))
        return clib_error_return (0, "missing arguments");

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "syn %u", &syn_timeout))
        {
        }
        else if (unformat (line_input, "established %u", &established_timeout))
        {
            /* unique no-op to avoid repeated-branch warning */
            do { (void)8; } while (0);
        }
        else if (unformat (line_input, "fin %u", &fin_timeout))
        {
            /* unique no-op to avoid repeated-branch warning */
            do { (void)9; } while (0);
        }
        else if (unformat (line_input, "rst %u", &rst_timeout))
        {
            /* unique no-op to avoid repeated-branch warning */
            do { (void)10; } while (0);
        }
        else
        {
            error = clib_error_return (0, "unknown input `%U'",
                                      format_unformat_error, line_input);
            goto done;
        }
    }

    /* 设置超时配置 */
    ips_session_manager_t *sm = &ips_session_manager;

    if (syn_timeout > 0 || established_timeout > 0 || fin_timeout > 0 || rst_timeout > 0)
    {
        ips_session_set_timeouts_args_t to_args = {
            .syn_timeout = syn_timeout > 0 ? syn_timeout : sm->tcp_syn_timeout,
            .established_timeout = established_timeout > 0 ? established_timeout : sm->tcp_established_timeout,
            .fin_timeout = fin_timeout > 0 ? fin_timeout : sm->tcp_fin_timeout,
            .rst_timeout = rst_timeout > 0 ? rst_timeout : sm->tcp_rst_timeout,
        };
        ips_session_set_timeouts (&to_args);
    }

    vlib_cli_output (vm, "Session timeouts updated:");
    vlib_cli_output (vm, "  SYN timeout: %u seconds", sm->tcp_syn_timeout);
    vlib_cli_output (vm, "  Established timeout: %u seconds", sm->tcp_established_timeout);
    vlib_cli_output (vm, "  FIN timeout: %u seconds", sm->tcp_fin_timeout);
    vlib_cli_output (vm, "  RST timeout: %u seconds", sm->tcp_rst_timeout);

 done:
    unformat_free (line_input);
    return error;
}

VLIB_CLI_COMMAND (ips_session_set_timeout_command, static) = {
    .path = "set ips session timeout",
    .short_help = "set ips session timeout [syn <u32_seconds>] [established <u32_seconds>] [fin <u32_seconds>] [rst <u32_seconds>]",
    .function = ips_session_set_timeout_command_fn,
};

/**
 * @brief 显示会话配置
 */
static clib_error_t *
ips_session_show_config_command_fn (vlib_main_t * vm,
                                    unformat_input_t * __clib_unused input,
                                    vlib_cli_command_t * __clib_unused cmd)
{
    ips_session_manager_t *sm = &ips_session_manager;

    vlib_cli_output (vm, "IPS Session Configuration:");
    vlib_cli_output (vm, "=========================");
    vlib_cli_output (vm, "Session pool size: %u", sm->session_pool_size);
    vlib_cli_output (vm, "IPv4 hash buckets: %u", sm->ipv4_hash_buckets);
    vlib_cli_output (vm, "IPv6 hash buckets: %u", sm->ipv6_hash_buckets);
    vlib_cli_output (vm, "IPv4 hash memory: %u MB", sm->ipv4_hash_memory_size >> 20);
    vlib_cli_output (vm, "IPv6 hash memory: %u MB", sm->ipv6_hash_memory_size >> 20);
    vlib_cli_output (vm, "");
    vlib_cli_output (vm, "Timeout Configuration:");
    vlib_cli_output (vm, "  SYN timeout: %u seconds", sm->tcp_syn_timeout);
    vlib_cli_output (vm, "  Established timeout: %u seconds", sm->tcp_established_timeout);
    vlib_cli_output (vm, "  FIN timeout: %u seconds", sm->tcp_fin_timeout);
    vlib_cli_output (vm, "  RST timeout: %u seconds", sm->tcp_rst_timeout);
    vlib_cli_output (vm, "");
    vlib_cli_output (vm, "Aging Configuration:");
    vlib_cli_output (vm, "  Check interval: %u seconds", sm->aging_check_interval);
    vlib_cli_output (vm, "  Batch size: %u", sm->aging_batch_size);
    vlib_cli_output (vm, "  Stats enabled: %s", sm->aging_stats_enabled ? "Yes" : "No");

    return 0;
}

VLIB_CLI_COMMAND (ips_session_show_config_command, static) = {
    .path = "show ips session config",
    .short_help = "show ips session config",
    .function = ips_session_show_config_command_fn,
};
