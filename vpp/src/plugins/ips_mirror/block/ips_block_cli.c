/*
 * ips_block_cli.c - VPP IPS Plugin Blocking Module CLI Commands
 *
 * Copyright (c) 2024 VPP IPS Project
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#include <vlib/vlib.h>
#include <vlib/cli.h>
#include <vppinfra/vec.h>
#include <vppinfra/error.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip46_address.h>
#include <arpa/inet.h>

#include "ips_block.h"


/**
 * @brief CLI command to show blocking statistics
 */
static clib_error_t *
ips_block_show_stats_command_fn(vlib_main_t *vm,
                               unformat_input_t *input,
                               vlib_cli_command_t *cmd)
{
    u32 thread_index = 0;
    ips_block_stats_t stats;

    unformat(input, "thread %u", &thread_index);

    ips_block_get_stats(thread_index, &stats);

    vlib_cli_output(vm, "IPS Blocking Statistics (thread %u):", thread_index);
    vlib_cli_output(vm, "  Total blocks:          %lu", stats.total_blocks);
    vlib_cli_output(vm, "  TCP resets:            %lu", stats.tcp_resets);
    vlib_cli_output(vm, "  TCP FINs:              %lu", stats.tcp_fins);
    vlib_cli_output(vm, "  ICMP unreachable:      %lu", stats.icmp_unreach);
    vlib_cli_output(vm, "  ICMP admin prohibited: %lu", stats.icmp_admin_prohib);
    vlib_cli_output(vm, "  Silent drops:          %lu", stats.silent_drops);
    vlib_cli_output(vm, "  Failed blocks:         %lu", stats.failed_blocks);

    vlib_cli_output(vm, "  Blocks by reason:");
    vlib_cli_output(vm, "    ACL:          %lu", stats.blocks_by_reason[IPS_BLOCK_REASON_ACL]);
    vlib_cli_output(vm, "    Rule engine:  %lu", stats.blocks_by_reason[IPS_BLOCK_REASON_RULE_ENGINE]);
    vlib_cli_output(vm, "    Signature:    %lu", stats.blocks_by_reason[IPS_BLOCK_REASON_SIGNATURE]);
    vlib_cli_output(vm, "    Anomaly:      %lu", stats.blocks_by_reason[IPS_BLOCK_REASON_ANOMALY]);
    vlib_cli_output(vm, "    Rate limit:   %lu", stats.blocks_by_reason[IPS_BLOCK_REASON_RATE_LIMIT]);
    vlib_cli_output(vm, "    Manual:       %lu", stats.blocks_by_reason[IPS_BLOCK_REASON_MANUAL]);

    return 0;
}

/**
 * @brief CLI command to reset blocking statistics
 */
static clib_error_t *
ips_block_reset_stats_command_fn(vlib_main_t *vm,
                                unformat_input_t *input,
                                vlib_cli_command_t *cmd)
{
    u32 thread_index = 0;

    unformat(input, "thread %u", &thread_index);

    ips_block_reset_stats(thread_index);
    vlib_cli_output(vm, "IPS blocking statistics reset for thread %u", thread_index);

    return 0;
}

/**
 * @brief CLI command to manually block a session
 */
static clib_error_t *
ips_block_session_command_fn(vlib_main_t *vm,
                            unformat_input_t *input,
                            vlib_cli_command_t *cmd)
{
    u32 session_index;
    u32 thread_index = 0;
    u32 action_val = IPS_BLOCK_ACTION_TCP_RESET;
    u32 reason_val = IPS_BLOCK_REASON_MANUAL;
    ips_block_action_t action;
    ips_block_reason_t reason;

    if (!unformat(input, "%u", &session_index))
        return clib_error_return(0, "Missing session index");

    unformat(input, "thread %u", &thread_index);
    unformat(input, "action %u", &action_val);
    unformat(input, "reason %u", &reason_val);

    if (action_val >= IPS_BLOCK_ACTION_REDIRECT)
        return clib_error_return(0, "Invalid action: %u", action_val);

    if (reason_val >= IPS_BLOCK_REASON_MAX)
        return clib_error_return(0, "Invalid reason: %u", reason_val);

    action = (ips_block_action_t)action_val;
    reason = (ips_block_reason_t)reason_val;

    /* TODO: Find session by index and block it */
    /* This would require access to the session pool */

    vlib_cli_output(vm, "Session blocking requested: session=%u, thread=%u, action=%s, reason=%s",
                   session_index, thread_index,
                   ips_block_action_to_string(action),
                   ips_block_reason_to_string(reason));

    return 0;
}

/**
 * @brief CLI command to block a flow
 */
static clib_error_t *
ips_block_flow_command_fn(vlib_main_t *vm,
                         unformat_input_t *input,
                         vlib_cli_command_t *cmd)
{
    ips_block_request_t request = {0};
    u32 thread_index = 0;
    u32 action_val = IPS_BLOCK_ACTION_TCP_RESET;
    u32 reason_val = IPS_BLOCK_REASON_MANUAL;
    u8 have_src_ip = 0, have_dst_ip = 0;
    u8 is_ipv6 = 0;
    ip46_address_t src_ip, dst_ip;

    /* Parse source IP */
    if (unformat(input, "src %U", unformat_ip4_address, &src_ip.ip4))
    {
        is_ipv6 = 0;
        have_src_ip = 1;
    }
    else if (unformat(input, "src %U", unformat_ip6_address, &src_ip.ip6))
    {
        is_ipv6 = 1;
        have_src_ip = 1;
    }

    /* Parse destination IP */
    if (unformat(input, "dst %U", unformat_ip4_address, &dst_ip.ip4))
    {
        is_ipv6 = 0;
        have_dst_ip = 1;
    }
    else if (unformat(input, "dst %U", unformat_ip6_address, &dst_ip.ip6))
    {
        is_ipv6 = 1;
        have_dst_ip = 1;
    }

    /* Parse ports */
    unformat(input, "src-port %u", &request.src_port);
    unformat(input, "dst-port %u", &request.dst_port);

    /* Parse protocol */
    if (unformat(input, "tcp"))
        request.protocol = IP_PROTOCOL_TCP;
    else if (unformat(input, "udp"))
        request.protocol = IP_PROTOCOL_UDP;

    /* Parse action */
    if (unformat(input, "action %U", unformat_ip4_address, &action_val))
    {
        /* Use custom action mapping if needed */
    }
    else if (unformat(input, "action reset"))
        action_val = IPS_BLOCK_ACTION_TCP_RESET;
    else if (unformat(input, "action drop"))
        action_val = IPS_BLOCK_ACTION_DROP;
    else if (unformat(input, "action icmp-unreach"))
        action_val = IPS_BLOCK_ACTION_ICMP_UNREACH;

    /* Parse reason */
    unformat(input, "reason %u", &reason_val);

    /* Parse thread index */
    unformat(input, "thread %u", &thread_index);

    /* Validate required fields */
    if (!have_src_ip || !have_dst_ip)
        return clib_error_return(0, "Both source and destination IP are required");

    if (request.protocol == 0)
        request.protocol = IP_PROTOCOL_TCP; /* Default to TCP */

    /* Fill request structure */
    request.thread_index = thread_index;
    request.action = (ips_block_action_t)action_val;
    request.reason = (ips_block_reason_t)reason_val;
    request.is_ipv6 = is_ipv6;

    if (is_ipv6)
    {
        request.src_ip6 = src_ip.ip6;
        request.dst_ip6 = dst_ip.ip6;
    }
    else
    {
        request.src_ip4 = src_ip.ip4;
        request.dst_ip4 = dst_ip.ip4;
    }

    request.log_block = 1;

    /* Send blocking request */
    if (ips_block_send(&request) == 0)
    {
        char src_str[46], dst_str[46];  // INET6_ADDRSTRLEN is 46

        if (is_ipv6)
        {
            inet_ntop(AF_INET6, &src_ip.ip6, src_str, sizeof(src_str));
            inet_ntop(AF_INET6, &dst_ip.ip6, dst_str, sizeof(dst_str));
        }
        else
        {
            inet_ntop(AF_INET, &src_ip.ip4, src_str, sizeof(src_str));
            inet_ntop(AF_INET, &dst_ip.ip4, dst_str, sizeof(dst_str));
        }

        vlib_cli_output(vm, "Flow blocking sent: %s:%u -> %s:%u, action=%s, reason=%s",
                       src_str, request.src_port, dst_str, request.dst_port,
                       ips_block_action_to_string(request.action),
                       ips_block_reason_to_string(request.reason));
    }
    else
    {
        return clib_error_return(0, "Failed to send blocking request");
    }

    return 0;
}

/**
 * @brief CLI command to show blocking status
 */
static clib_error_t *
ips_block_show_status_command_fn(vlib_main_t *vm,
                                unformat_input_t *input,
                                vlib_cli_command_t *cmd)
{
    ips_block_manager_t *bm = &ips_block_manager;
    u32 total_blocks = 0;
    u32 total_failed = 0;

    vlib_cli_output(vm, "IPS Blocking Module Status:");
    vlib_cli_output(vm, "  Rate limiting:      %s", bm->rate_limit_enabled ? "enabled" : "disabled");
    vlib_cli_output(vm, "  Max blocks/sec:    %u", bm->max_blocks_per_second);
    vlib_cli_output(vm, "  Logging:           %s", bm->enable_logging ? "enabled" : "disabled");
    vlib_cli_output(vm, "  Thread count:      %u", bm->num_threads);

    /* Aggregate statistics */
    for (u32 i = 0; i < vec_len(bm->per_thread_stats); i++)
    {
        ips_block_stats_t *stats = &bm->per_thread_stats[i];
        total_blocks += stats->total_blocks;
        total_failed += stats->failed_blocks;
    }

    vlib_cli_output(vm, "  Total blocks:      %u", total_blocks);
    vlib_cli_output(vm, "  Total failures:    %u", total_failed);

    return 0;
}

/* CLI command definitions */
VLIB_CLI_COMMAND(ips_block_show_stats_command, static) = {
    .path = "ips block show stats",
    .short_help = "ips block show stats [thread <n>]",
    .function = ips_block_show_stats_command_fn,
};

VLIB_CLI_COMMAND(ips_block_reset_stats_command, static) = {
    .path = "ips block reset stats",
    .short_help = "ips block reset stats [thread <n>]",
    .function = ips_block_reset_stats_command_fn,
};

VLIB_CLI_COMMAND(ips_block_session_command, static) = {
    .path = "ips block session",
    .short_help = "ips block session <session-index> [thread <n>] [action <n>] [reason <n>]",
    .function = ips_block_session_command_fn,
};

VLIB_CLI_COMMAND(ips_block_flow_command, static) = {
    .path = "ips block flow",
    .short_help = "ips block flow src <IP> dst <IP> [src-port <port>] [dst-port <port>] [tcp|udp] [action <reset|drop|icmp-unreach>] [thread <n>]",
    .function = ips_block_flow_command_fn,
};

VLIB_CLI_COMMAND(ips_block_show_status_command, static) = {
    .path = "ips block show status",
    .short_help = "ips block show status",
    .function = ips_block_show_status_command_fn,
};