/*
 * ips_acl_cli.c - VPP IPS Plugin ACL CLI Commands
 *
 * Copyright (c) 2024 VPP IPS Project
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#include <vlib/vlib.h>
#include <vlib/cli.h>
#include <vppinfra/error.h>
#include <vppinfra/vec.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip46_address.h>
#include <arpa/inet.h>

#include "ips_acl.h"
/* #include "session/ips_session.h" - Not used in this file */


/* Helper function to parse TCP state - Simplified for mirror traffic */
static int
parse_tcp_state(unformat_input_t *input, ips_tcp_state_t *tcp_state)
{
    if (unformat(input, "none"))
        *tcp_state = IPS_TCP_STATE_NONE;
    else if (unformat(input, "new"))
        *tcp_state = IPS_TCP_STATE_NEW;
    else if (unformat(input, "established"))
        *tcp_state = IPS_TCP_STATE_ESTABLISHED;
    else if (unformat(input, "closing"))
        *tcp_state = IPS_TCP_STATE_CLOSING;
    else if (unformat(input, "closed"))
        *tcp_state = IPS_TCP_STATE_CLOSED;
    else
        return -1;

    return 0;
}

/* Helper function to parse ACL action */
static int
parse_acl_action(unformat_input_t *input, ips_acl_action_t *action)
{
    if (unformat(input, "permit"))
    {
        *action = IPS_ACL_ACTION_PERMIT;
        return 0;
    }
    else if (unformat(input, "deny"))
    {
        *action = IPS_ACL_ACTION_DENY;
        return 0;
    }
    else if (unformat(input, "reset"))
    {
        *action = IPS_ACL_ACTION_RESET;
        return 0;
    }
    else if (unformat(input, "log"))
    {
        *action = IPS_ACL_ACTION_LOG;
        return 0;
    }
    return -1;
}

/**
 * @brief CLI command to add ACL rule
 */
static clib_error_t *
ips_acl_add_rule_command_fn(vlib_main_t *vm,
                           unformat_input_t *input,
                           vlib_cli_command_t *cmd)
{
    /* Suppress unused parameter warning */
    (void)cmd;

    ips_acl_rule_t rule = {0};
    u32 src_port = 0, dst_port = 0;
    u8 have_src_ip = 0, have_dst_ip = 0;
    u8 is_ipv4 = 0, is_ipv6 = 0;

    /* Parse source IP */
    if (unformat(input, "src %U", unformat_ip4_address, &rule.src_ip.ip4))
    {
        is_ipv4 = 1;
        rule.src_prefixlen = 32; /* Default to single host */
        have_src_ip = 1;
    }
    else if (unformat(input, "src %U", unformat_ip6_address, &rule.src_ip.ip6))
    {
        is_ipv6 = 1;
        rule.src_prefixlen = 128; /* Default to single host */
        have_src_ip = 1;
    }

    /* Parse destination IP and port */
    if (unformat(input, "dst %U", unformat_ip4_address, &rule.dst_ip.ip4))
    {
        is_ipv4 = 1;
        rule.dst_prefixlen = 32; /* Default to single host */
        have_dst_ip = 1;
    }
    else if (unformat(input, "dst %U", unformat_ip6_address, &rule.dst_ip.ip6))
    {
        is_ipv6 = 1;
        rule.dst_prefixlen = 128; /* Default to single host */
        have_dst_ip = 1;
    }
    
    /* Validate IP version consistency */
    if (is_ipv4 && is_ipv6)
    {
        return clib_error_return(0, "Cannot mix IPv4 and IPv6 addresses in the same rule");
    }
    
    /* Set IP version for the rule (default to IPv4 if no IPs specified) */
    rule.is_ipv6 = is_ipv6;

    /* Parse destination port */
    if (unformat(input, "dst-port %u", &dst_port))
    {
        rule.dst_port_start = dst_port;
        rule.dst_port_end = dst_port;
    }

    /* Parse source port */
    if (unformat(input, "src-port %u", &src_port))
    {
        rule.src_port_start = src_port;
        rule.src_port_end = src_port;
    }

    /* Parse protocol */
    if (unformat(input, "tcp"))
    {
        rule.protocol = IP_PROTOCOL_TCP;
    }
    else if (unformat(input, "udp"))
    {
        rule.protocol = IP_PROTOCOL_UDP;
    }

    /* Parse action */
    if (unformat(input, "action %U", parse_acl_action, &rule.action))
    {
        /* Action parsed successfully */
    }
    else
    {
        /* Default to block if no action specified */
        rule.action = IPS_ACL_ACTION_DENY;
    }

    /* Parse extended session-level options */
    u8 block_syn = 0, block_synack = 0;
    while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat(input, "block-syn"))
        {
            block_syn = 1;
            rule.block_syn = 1;
        }
        else if (unformat(input, "block-synack"))
        {
            block_synack = 1;
            rule.block_synack = 1;
        }
        else if (unformat(input, "session-level"))
        {
            rule.session_control = 1;
        }
        else if (unformat(input, "packet-level"))
        {
            rule.session_control = 0;
        }
        else if (unformat(input, "bidirectional"))
        {
            rule.match_direction = 0;
        }
        else if (unformat(input, "forward-only"))
        {
            rule.match_direction = 1;
        }
        else if (unformat(input, "reverse-only"))
        {
            rule.match_direction = 2;
        }
        else if (parse_tcp_state(input, &rule.tcp_state) == 0)
        {
            rule.match_tcp_state = 1;
        }
        else if (unformat(input, "description %v", &rule.description))
        {
            /* Description parsed */
        }
        else
        {
            return clib_error_return(0, "unknown input `%U'", format_unformat_error, input);
        }
    }

    /* Set TCP flags for SYN/SYN-ACK blocking */
    if (block_syn)
    {
        rule.tcp_flags_value = IPS_TCP_FLAG_SYN;
        rule.tcp_flags_mask = IPS_TCP_FLAG_SYN | IPS_TCP_FLAG_ACK;
    }
    else if (block_synack)
    {
        rule.tcp_flags_value = IPS_TCP_FLAG_SYN | IPS_TCP_FLAG_ACK;
        rule.tcp_flags_mask = IPS_TCP_FLAG_SYN | IPS_TCP_FLAG_ACK;
    }

    /* Validate that at least one match criterion is specified */
    if (!have_src_ip && !have_dst_ip && rule.protocol == 0 && 
        src_port == 0 && dst_port == 0)
    {
        return clib_error_return(0, "At least one match criterion required (src, dst, protocol, or port)");
    }

    /* Set default values for unspecified fields */
    
    /* If no source IP specified, match any source */
    if (!have_src_ip)
    {
        if (rule.is_ipv6)
        {
            clib_memset(&rule.src_ip.ip6, 0, sizeof(ip6_address_t));
            rule.src_prefixlen = 0; /* Match any IPv6 */
        }
        else
        {
            rule.src_ip.ip4.as_u32 = 0;
            rule.src_prefixlen = 0; /* Match any IPv4 */
        }
    }
    
    /* If no destination IP specified, match any destination */
    if (!have_dst_ip)
    {
        if (rule.is_ipv6)
        {
            clib_memset(&rule.dst_ip.ip6, 0, sizeof(ip6_address_t));
            rule.dst_prefixlen = 0; /* Match any IPv6 */
        }
        else
        {
            rule.dst_ip.ip4.as_u32 = 0;
            rule.dst_prefixlen = 0; /* Match any IPv4 */
        }
    }
    
    /* If no protocol specified, match any protocol (0 = any) */
    if (rule.protocol == 0)
    {
        /* 0 means match any protocol */
    }

    /* Set default port ranges if not specified */
    if (rule.src_port_start == 0 && rule.src_port_end == 0)
    {
        rule.src_port_start = 0;
        rule.src_port_end = 65535; /* Any source port */
    }
    if (rule.dst_port_start == 0 && rule.dst_port_end == 0)
    {
        rule.dst_port_start = 0;
        rule.dst_port_end = 65535; /* Any destination port */
    }

    /* Set default TCP flags */
    rule.tcp_flags_mask = 0;
    rule.tcp_flags_value = 0;

    /* Add the rule */
    u32 rule_id = ips_acl_add_rule(&rule);
    if (rule_id == ~0)
        return clib_error_return(0, "Failed to add ACL rule");

    vlib_cli_output(vm, "ACL rule added successfully with ID %u", rule_id);
    return 0;
}

/**
 * @brief CLI command to remove ACL rule
 */
static clib_error_t *
ips_acl_remove_rule_command_fn(vlib_main_t *vm,
                              unformat_input_t *input,
                              vlib_cli_command_t *cmd)
{
    /* Suppress unused parameter warning */
    (void)cmd;

    u32 rule_id;

    if (!unformat(input, "%u", &rule_id))
        return clib_error_return(0, "Missing rule ID");

    if (ips_acl_remove_rule(rule_id) < 0)
        return clib_error_return(0, "Failed to remove ACL rule %u", rule_id);

    vlib_cli_output(vm, "ACL rule %u removed successfully", rule_id);
    return 0;
}

/**
 * @brief CLI command to enable/disable ACL rule
 */
static clib_error_t *
ips_acl_set_rule_command_fn(vlib_main_t *vm,
                            unformat_input_t *input,
                            vlib_cli_command_t *cmd)
{
    /* Suppress unused parameter warning */
    (void)cmd;

    u32 rule_id;
    u8 enable;

    if (!unformat(input, "%u", &rule_id))
        return clib_error_return(0, "Missing rule ID");

    if (unformat(input, "enable"))
        enable = 1;
    else if (unformat(input, "disable"))
        enable = 0;
    else
        return clib_error_return(0, "Missing enable/disable");

    if (ips_acl_set_rule_enabled(rule_id, enable) < 0)
        return clib_error_return(0, "Failed to %s ACL rule %u",
                               enable ? "enable" : "disable", rule_id);

    vlib_cli_output(vm, "ACL rule %u %sd successfully", rule_id,
                   enable ? "enable" : "disable");
    return 0;
}

/**
 * @brief CLI command to show ACL statistics
 */
static clib_error_t *
ips_acl_show_stats_command_fn(vlib_main_t *vm,
                             unformat_input_t *input,
                             vlib_cli_command_t *cmd)
{
    /* Suppress unused parameter warning */
    (void)cmd;

    u32 thread_index = 0;
    ips_acl_stats_t stats;

    unformat(input, "thread %u", &thread_index);

    ips_acl_get_stats(thread_index, &stats);

    vlib_cli_output(vm, "IPS ACL Statistics (thread %u):", thread_index);
    vlib_cli_output(vm, "  Total packets checked: %lu", stats.total_packets_checked);
    vlib_cli_output(vm, "  Packets permitted:    %lu", stats.packets_permit);
    vlib_cli_output(vm, "  Packets denied:       %lu", stats.packets_denied);
    vlib_cli_output(vm, "  Packets reset:        %lu", stats.packets_reset);
    vlib_cli_output(vm, "  Sessions blocked:     %lu", stats.sessions_blocked);
    vlib_cli_output(vm, "  ACL errors:           %lu", stats.acl_errors);

    /* Extended statistics */
    vlib_cli_output(vm, "  VPP ACL rule hits:    %lu", stats.acl_hits);
    vlib_cli_output(vm, "  TCP state hits:       %lu", stats.tcp_state_hits);
    vlib_cli_output(vm, "  Session cache hits:   %lu", stats.session_cache_hits);
    vlib_cli_output(vm, "  SYN packets blocked:  %lu", stats.syn_packets_blocked);
    vlib_cli_output(vm, "  SYN-ACK packets blocked: %lu", stats.synack_packets_blocked);

    /* Calculate hit rates */
    if (stats.total_packets_checked > 0) {
        f64 total_packets = (f64)stats.total_packets_checked;
        f64 acl_hit_rate = (f64)stats.acl_hits / total_packets * 100.0;
        f64 cache_hit_rate = (f64)stats.session_cache_hits / total_packets * 100.0;
        f64 tcp_state_rate = (f64)stats.tcp_state_hits / total_packets * 100.0;

        vlib_cli_output(vm, "  ACL hit rate:         %.2f%%", acl_hit_rate);
        vlib_cli_output(vm, "  Cache hit rate:       %.2f%%", cache_hit_rate);
        vlib_cli_output(vm, "  TCP state hit rate:   %.2f%%", tcp_state_rate);
    }

    return 0;
}

/**
 * @brief CLI command to reset ACL statistics
 */
static clib_error_t *
ips_acl_reset_stats_command_fn(vlib_main_t *vm,
                              unformat_input_t *input,
                              vlib_cli_command_t *cmd)
{
    /* Suppress unused parameter warning */
    (void)cmd;

    u32 thread_index = 0;

    unformat(input, "thread %u", &thread_index);

    ips_acl_reset_stats(thread_index);
    vlib_cli_output(vm, "IPS ACL statistics reset for thread %u", thread_index);

    return 0;
}

/**
 * @brief CLI command to test ACL rule (example: block 1.1.1.1 to port 80)
 */
static clib_error_t *
ips_acl_test_block_command_fn(vlib_main_t *vm,
                             unformat_input_t *input,
                             vlib_cli_command_t *cmd)
{
    /* Suppress unused parameter warning */
    (void)cmd;

    ips_acl_rule_t rule = {0};

    /* Parse source IP */
    if (!unformat(input, "src %U", unformat_ip4_address, &rule.src_ip.ip4))
        return clib_error_return(0, "Missing source IP (format: src 1.1.1.1)");

    rule.is_ipv6 = 0;
    rule.src_prefixlen = 32;

    /* Parse destination port */
    if (!unformat(input, "dst-port %u", &rule.dst_port_start))
        return clib_error_return(0, "Missing destination port (format: dst-port 80)");

    rule.dst_port_end = rule.dst_port_start;
    rule.protocol = IP_PROTOCOL_TCP;
    rule.action = IPS_ACL_ACTION_RESET;

    /* Add the rule */
    u32 rule_id = ips_acl_add_rule(&rule);
    if (rule_id == ~0)
        return clib_error_return(0, "Failed to add test ACL rule");

    /* Format IP address for output */
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &rule.src_ip.ip4, ip_str, sizeof(ip_str));

    vlib_cli_output(vm, "Test ACL rule added: block TCP from %s to port %u (rule ID: %u)",
                   ip_str, rule.dst_port_start, rule_id);
    vlib_cli_output(vm, "This rule will send TCP reset to %s when it connects to port %u",
                   ip_str, rule.dst_port_start);

    return 0;
}

/* CLI command definitions */
VLIB_CLI_COMMAND(ips_acl_add_rule_command, static) = {
    .path = "ips acl add rule",
    .short_help = 
        "ips acl add rule [src <IP>] [dst <IP>] [dst-port <port>] [src-port <port>] [tcp|udp] action <permit|deny|reset|log>\n"
        "  At least one match criterion is required (src, dst, protocol, or port)\n"
        "  Examples:\n"
        "    - Block specific IP: ips acl add rule src 192.168.1.100 action deny\n"
        "    - Block all to port 22: ips acl add rule dst-port 22 tcp action deny\n"
        "    - Allow specific connection: ips acl add rule src 10.0.0.1 dst 10.0.0.2 dst-port 80 tcp action permit",
    .function = ips_acl_add_rule_command_fn,
};

VLIB_CLI_COMMAND(ips_acl_remove_rule_command, static) = {
    .path = "ips acl remove rule",
    .short_help = "ips acl remove rule <rule-id>",
    .function = ips_acl_remove_rule_command_fn,
};

VLIB_CLI_COMMAND(ips_acl_set_rule_command, static) = {
    .path = "ips acl set rule",
    .short_help = "ips acl set rule <rule-id> <enable|disable>",
    .function = ips_acl_set_rule_command_fn,
};

VLIB_CLI_COMMAND(ips_acl_show_stats_command, static) = {
    .path = "ips acl show stats",
    .short_help = "ips acl show stats [thread <n>]",
    .function = ips_acl_show_stats_command_fn,
};

/* CLI command to control TCP state tracking */
static clib_error_t *
ips_acl_tcp_state_command(vlib_main_t *vm,
                         unformat_input_t *input,
                         vlib_cli_command_t *cmd)
{
    /* Suppress unused parameter warning */
    (void)cmd;

    ips_acl_manager_t *am = &ips_acl_manager;
    u8 enable = 1;
    u8 show = 0;

    while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat(input, "enable"))
            enable = 1;
        else if (unformat(input, "disable"))
            enable = 0;
        else if (unformat(input, "show"))
            show = 1;
        else
            return clib_error_return(0, "unknown input `%U'", format_unformat_error, input);
    }

    if (show)
    {
        vlib_cli_output(vm, "TCP State Tracking Status:");
        vlib_cli_output(vm, "  Enabled: %s", am->enable_tcp_state_tracking ? "Yes" : "No");
        vlib_cli_output(vm, "  Max Sessions: %u", am->max_sessions);
        vlib_cli_output(vm, "  Current TCP State Entries: %u", am->tcp_state_table.current_entries);
        vlib_cli_output(vm, "  Max TCP State Entries: %u", am->tcp_state_table.max_entries);
        return 0;
    }

    am->enable_tcp_state_tracking = enable;
    vlib_cli_output(vm, "TCP state tracking %s", enable ? "enabled" : "disabled");

    return 0;
}

VLIB_CLI_COMMAND(ips_acl_tcp_state_command_node, static) = {
    .path = "ips acl tcp-state",
    .short_help = "Control TCP state tracking for IPS ACL [enable|disable|show]",
    .function = ips_acl_tcp_state_command,
};

VLIB_CLI_COMMAND(ips_acl_reset_stats_command, static) = {
    .path = "ips acl reset stats",
    .short_help = "ips acl reset stats [thread <n>]",
    .function = ips_acl_reset_stats_command_fn,
};

VLIB_CLI_COMMAND(ips_acl_test_block_command, static) = {
    .path = "ips acl test block",
    .short_help = "ips acl test block src <IP> dst-port <port>",
    .function = ips_acl_test_block_command_fn,
};