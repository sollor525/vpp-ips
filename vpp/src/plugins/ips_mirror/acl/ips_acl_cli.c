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

#include "../ips.h"
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
static uword
parse_acl_action(unformat_input_t *input, va_list *args)
{
    ips_acl_action_t *action = va_arg (*args, ips_acl_action_t *);
    
    if (unformat(input, "permit"))
    {
        *action = IPS_ACL_ACTION_PERMIT;
        return 1;
    }
    else if (unformat(input, "deny"))
    {
        *action = IPS_ACL_ACTION_DENY;
        return 1;
    }
    else if (unformat(input, "reset"))
    {
        *action = IPS_ACL_ACTION_RESET;
        return 1;
    }
    else if (unformat(input, "log"))
    {
        *action = IPS_ACL_ACTION_LOG;
        return 1;
    }
    return 0;
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

    /* Parse source IP with optional CIDR prefix */
    if (unformat(input, "src %U/%d", unformat_ip4_address, &rule.src_ip.ip4, &rule.src_prefixlen))
    {
        is_ipv4 = 1;
        have_src_ip = 1;
    }
    else if (unformat(input, "src %U", unformat_ip4_address, &rule.src_ip.ip4))
    {
        is_ipv4 = 1;
        rule.src_prefixlen = 32; /* Default to single host */
        have_src_ip = 1;
    }
    else if (unformat(input, "src %U/%d", unformat_ip6_address, &rule.src_ip.ip6, &rule.src_prefixlen))
    {
        is_ipv6 = 1;
        have_src_ip = 1;
    }
    else if (unformat(input, "src %U", unformat_ip6_address, &rule.src_ip.ip6))
    {
        is_ipv6 = 1;
        rule.src_prefixlen = 128; /* Default to single host */
        have_src_ip = 1;
    }

    /* Parse destination IP with optional CIDR prefix */
    if (unformat(input, "dst %U/%d", unformat_ip4_address, &rule.dst_ip.ip4, &rule.dst_prefixlen))
    {
        is_ipv4 = 1;
        have_dst_ip = 1;
    }
    else if (unformat(input, "dst %U", unformat_ip4_address, &rule.dst_ip.ip4))
    {
        is_ipv4 = 1;
        rule.dst_prefixlen = 32; /* Default to single host */
        have_dst_ip = 1;
    }
    else if (unformat(input, "dst %U/%d", unformat_ip6_address, &rule.dst_ip.ip6, &rule.dst_prefixlen))
    {
        is_ipv6 = 1;
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

    /* Apply ACL to all enabled IPS interfaces */
    extern void ips_apply_acls_to_all_interfaces(void);
    ips_apply_acls_to_all_interfaces();

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

    u32 thread_index = ~0;  /* ~0 means show all threads */
    u8 show_specific_thread = 0;

    if (unformat(input, "thread %u", &thread_index))
    {
        show_specific_thread = 1;
    }

    if (show_specific_thread)
    {
        /* Show specific thread statistics */
        ips_acl_stats_t stats;
        ips_acl_get_stats(thread_index, &stats);

        vlib_cli_output(vm, "IPS ACL Statistics (thread %u):", thread_index);
        vlib_cli_output(vm, "  Total packets checked: %lu", stats.total_packets_checked);
        vlib_cli_output(vm, "  Packets permitted:    %lu", stats.packets_permit);
        vlib_cli_output(vm, "  Packets denied:       %lu", stats.packets_denied);
        vlib_cli_output(vm, "  Packets reset:        %lu", stats.packets_reset);
        vlib_cli_output(vm, "  Sessions blocked:     %lu", stats.sessions_blocked);
        vlib_cli_output(vm, "  ACL errors:           %lu", stats.acl_errors);
        vlib_cli_output(vm, "  VPP ACL rule hits:    %lu (deny: %lu, permit: %lu)", 
                       stats.acl_hits, stats.acl_deny_hits, stats.acl_permit_hits);
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
    }
    else
    {
        /* Show aggregated statistics across all threads */
        ips_acl_manager_t *am = &ips_acl_manager;
        ips_acl_stats_t total_stats = {0};

        vlib_cli_output(vm, "IPS ACL Statistics (all threads):");
        vlib_cli_output(vm, "");

        /* Aggregate stats from all threads */
        for (u32 i = 0; i < vec_len(am->per_thread_stats); i++)
        {
            ips_acl_stats_t *stats = &am->per_thread_stats[i];
            total_stats.total_packets_checked += stats->total_packets_checked;
            total_stats.packets_permit += stats->packets_permit;
            total_stats.packets_denied += stats->packets_denied;
            total_stats.packets_reset += stats->packets_reset;
            total_stats.sessions_blocked += stats->sessions_blocked;
            total_stats.acl_errors += stats->acl_errors;
            total_stats.acl_hits += stats->acl_hits;
            total_stats.acl_deny_hits += stats->acl_deny_hits;
            total_stats.acl_permit_hits += stats->acl_permit_hits;
            total_stats.tcp_state_hits += stats->tcp_state_hits;
            total_stats.session_cache_hits += stats->session_cache_hits;
            total_stats.syn_packets_blocked += stats->syn_packets_blocked;
            total_stats.synack_packets_blocked += stats->synack_packets_blocked;

            /* Show per-thread if it has activity */
            if (stats->total_packets_checked > 0)
            {
                vlib_cli_output(vm, "Thread %u:", i);
                vlib_cli_output(vm, "  Packets checked: %lu, denied: %lu, VPP ACL hits: %lu",
                              stats->total_packets_checked, stats->packets_denied, stats->acl_hits);
            }
        }

        vlib_cli_output(vm, "");
        vlib_cli_output(vm, "Global Totals:");
        vlib_cli_output(vm, "  Total packets checked: %lu", total_stats.total_packets_checked);
        vlib_cli_output(vm, "  Packets permitted:    %lu", total_stats.packets_permit);
        vlib_cli_output(vm, "  Packets denied:       %lu", total_stats.packets_denied);
        vlib_cli_output(vm, "  Packets reset:        %lu", total_stats.packets_reset);
        vlib_cli_output(vm, "  Sessions blocked:     %lu", total_stats.sessions_blocked);
        vlib_cli_output(vm, "  ACL errors:           %lu", total_stats.acl_errors);
        vlib_cli_output(vm, "  VPP ACL rule hits:    %lu (deny: %lu, permit: %lu)", 
                       total_stats.acl_hits, total_stats.acl_deny_hits, total_stats.acl_permit_hits);
        vlib_cli_output(vm, "  TCP state hits:       %lu", total_stats.tcp_state_hits);
        vlib_cli_output(vm, "  Session cache hits:   %lu", total_stats.session_cache_hits);
        vlib_cli_output(vm, "  SYN packets blocked:  %lu", total_stats.syn_packets_blocked);
        vlib_cli_output(vm, "  SYN-ACK packets blocked: %lu", total_stats.synack_packets_blocked);

        /* Calculate hit rates */
        if (total_stats.total_packets_checked > 0) {
            f64 total_packets = (f64)total_stats.total_packets_checked;
            f64 acl_hit_rate = (f64)total_stats.acl_hits / total_packets * 100.0;
            f64 cache_hit_rate = (f64)total_stats.session_cache_hits / total_packets * 100.0;
            f64 tcp_state_rate = (f64)total_stats.tcp_state_hits / total_packets * 100.0;

            vlib_cli_output(vm, "  ACL hit rate:         %.2f%%", acl_hit_rate);
            vlib_cli_output(vm, "  Cache hit rate:       %.2f%%", cache_hit_rate);
            vlib_cli_output(vm, "  TCP state hit rate:   %.2f%%", tcp_state_rate);
        }
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

/*
 * ========================================================================
 * Batch ACL Rule Import Commands for Large-Scale Rule Support
 * ========================================================================
 */

/**
 * @brief CLI command to load ACL rules from a file
 */
static clib_error_t *
ips_acl_load_from_file_command_fn(vlib_main_t *vm,
                                  unformat_input_t *input,
                                  vlib_cli_command_t *cmd)
{
    (void)cmd;
    char *filename = NULL;
    u32 acl_index;
    u32 rules_loaded;

    while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat(input, "%s", &filename))
            ;
        else
            return clib_error_return(0, "unknown input `%U'", format_unformat_error, input);
    }

    if (!filename)
        return clib_error_return(0, "Filename must be specified");

    /* Load rules from file */
    if (ips_acl_load_rules_from_file(filename, &acl_index, &rules_loaded) != 0)
    {
        return clib_error_return(0, "Failed to load ACL rules from file: %s", filename);
    }

    vlib_cli_output(vm, "Successfully loaded %u ACL rules from file '%s'", rules_loaded, filename);
    vlib_cli_output(vm, "VPP ACL index: %u", acl_index);

    /* Free filename */
    vec_free(filename);

    return 0;
}

VLIB_CLI_COMMAND(ips_acl_load_from_file_command, static) = {
    .path = "ips acl load from file",
    .short_help = "ips acl load from file <filename>\n"
                  "  Load ACL rules from a text file (one rule per line)\n"
                  "  Format: permit|deny src IP/prefix dst IP/prefix [proto X] [sport X] [dport X]\n"
                  "  Example:\n"
                  "    deny src 192.168.1.0/24 dst 10.0.0.0/8 proto tcp dport 80\n"
                  "    permit src 0.0.0.0/0 dst 0.0.0.0/0\n"
                  "  Supports up to 10000+ rules per file",
    .function = ips_acl_load_from_file_command_fn,
};

/**
 * @brief CLI command to create a sample ACL rules file for testing
 */
static clib_error_t *
ips_acl_create_sample_file_command_fn(vlib_main_t *vm,
                                     unformat_input_t *input,
                                     vlib_cli_command_t *cmd)
{
    (void)cmd;
    char *filename = NULL;
    u32 num_rules = 100;
    FILE *fp;

    while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat(input, "%s", &filename))
            ;
        else if (unformat(input, "count %u", &num_rules))
            ;
        else
            return clib_error_return(0, "unknown input `%U'", format_unformat_error, input);
    }

    if (!filename)
        return clib_error_return(0, "Filename must be specified");

    if (num_rules == 0 || num_rules > 100000)
        return clib_error_return(0, "Rule count must be between 1 and 100000");

    fp = fopen(filename, "w");
    if (!fp)
        return clib_error_return(0, "Failed to create file: %s", filename);

    vlib_cli_output(vm, "Creating sample ACL file with %u rules: %s", num_rules, filename);

    /* Write sample rules - mix of permit and deny rules */
    fprintf(fp, "# IPS ACL Rules Sample File\n");
    fprintf(fp, "# Format: permit|deny src IP/prefix dst IP/prefix [proto] [sport] [dport]\n");
    fprintf(fp, "#\n");

    for (u32 i = 0; i < num_rules; i++)
    {
        u32 src_net = (i / 256) % 256;
        u32 dst_net = (i / 65536) % 256;

        /* Alternate between permit and deny */
        const char *action = (i % 10 == 0) ? "deny" : "permit";

        /* Write rule: deny/permit src 10.src_net.0.0/24 dst 172.dst_net.0.0/16 proto tcp dport 80 */
        fprintf(fp, "%s src 10.%u.0.0/24 dst 172.%u.0.0/16 proto tcp dport 80\n",
                action, src_net, dst_net);
    }

    fclose(fp);

    vlib_cli_output(vm, "Sample ACL file created: %s", filename);
    vlib_cli_output(vm, "  Total rules: %u", num_rules);
    vlib_cli_output(vm, "\nTo load these rules, use:");
    vlib_cli_output(vm, "  ips acl load from file %s", filename);

    vec_free(filename);
    return 0;
}

VLIB_CLI_COMMAND(ips_acl_create_sample_file_command, static) = {
    .path = "ips acl create sample file",
    .short_help = "ips acl create sample file <filename> [count <n>]\n"
                  "  Create a sample ACL rules file for testing\n"
                  "  Default count: 100 rules, Max: 100000 rules",
    .function = ips_acl_create_sample_file_command_fn,
};

/*
 * ========================================================================
 * Batch Mode Management Commands - Unified Batch/Single Rule Architecture
 * ========================================================================
 */

/**
 * @brief CLI command to show all batch ACL groups
 */
static clib_error_t *
ips_acl_show_batch_groups_command_fn(vlib_main_t *vm,
                                     unformat_input_t *input,
                                     vlib_cli_command_t *cmd)
{
    (void)input;
    (void)cmd;
    ips_acl_manager_t *am = &ips_acl_manager;
    ips_acl_batch_manager_t *bm = &am->batch_manager;
    ips_acl_batch_group_t *group;

    if (pool_elts(bm->groups) == 0)
    {
        vlib_cli_output(vm, "No ACL batch groups configured.");
        return 0;
    }

    vlib_cli_output(vm, "IPS ACL Batch Groups:");
    vlib_cli_output(vm, "%-10s %-12s %-10s %-10s %-15s %-20s",
                   "Group ID", "VPP ACL Idx", "Rule Count", "Enabled", "Total Hits", "Created (sec ago)");
    vlib_cli_output(vm, "%-10s %-12s %-10s %-10s %-15s %-20s",
                   "---------", "------------", "----------", "----------", "---------------", "-------------------");

    pool_foreach(group, bm->groups)
    {
        f64 time_ago = vlib_time_now(vm) - group->create_time;
        vlib_cli_output(vm, "%-10u %-12u %-10u %-10s %-15lu %-20.2f",
                       group->group_id,
                       group->vpp_acl_index,
                       group->rule_count,
                       group->is_enabled ? "Yes" : "No",
                       group->total_hits,
                       time_ago);
    }

    vlib_cli_output(vm, "");
    vlib_cli_output(vm, "Total batch groups: %u", pool_elts(bm->groups));
    vlib_cli_output(vm, "");
    vlib_cli_output(vm, "Use 'ips acl show batch rules <group-id>' to see rules in a group.");

    return 0;
}

VLIB_CLI_COMMAND(ips_acl_show_batch_groups_command, static) = {
    .path = "ips acl show batch groups",
    .short_help = "ips acl show batch groups\n"
                  "  Display all ACL batch groups with statistics",
    .function = ips_acl_show_batch_groups_command_fn,
};

/**
 * @brief CLI command to show rules within a batch group
 */
static clib_error_t *
ips_acl_show_batch_rules_command_fn(vlib_main_t *vm,
                                    unformat_input_t *input,
                                    vlib_cli_command_t *cmd)
{
    (void)cmd;
    ips_acl_manager_t *am = &ips_acl_manager;
    ips_acl_batch_manager_t *bm = &am->batch_manager;
    ips_acl_batch_group_t *group;
    u32 group_id = ~0;

    while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat(input, "%u", &group_id))
            ;
        else
            return clib_error_return(0, "unknown input `%U'", format_unformat_error, input);
    }

    if (group_id == ~0)
        return clib_error_return(0, "Group ID must be specified");

    /* Find the batch group */
    group = NULL;
    pool_foreach(group, bm->groups)
    {
        if (group->group_id == group_id)
            break;
        group = NULL;
    }

    if (!group)
        return clib_error_return(0, "Batch group %u not found", group_id);

    vlib_cli_output(vm, "Batch Group ID: %u", group->group_id);
    vlib_cli_output(vm, "  VPP ACL Index: %u", group->vpp_acl_index);
    vlib_cli_output(vm, "  Rule Count: %u", group->rule_count);
    vlib_cli_output(vm, "  Enabled: %s", group->is_enabled ? "Yes" : "No");
    vlib_cli_output(vm, "  Total Hits: %lu", group->total_hits);
    vlib_cli_output(vm, "  Created: %.2f seconds ago", vlib_time_now(vm) - group->create_time);
    vlib_cli_output(vm, "");
    vlib_cli_output(vm, "Rules in this group:");

    /* Display each rule with its statistics */
    vlib_cli_output(vm, "%-8s %-8s %-25s %-25s %-10s %-10s %-10s %-15s",
                   "VPP Idx", "Rule ID", "Source IP", "Dest IP", "Proto", "Dst Port", "Enabled", "Hit Count");
    vlib_cli_output(vm, "%-8s %-8s %-25s %-25s %-10s %-10s %-10s %-15s",
                   "--------", "--------", "-------------------------",
                   "-------------------------", "----------", "----------", "----------", "---------------");

    for (u32 i = 0; i < vec_len(group->rules); i++)
    {
        ips_acl_rule_t *rule = group->rules[i];
        if (!rule)
            continue;

        /* Format IP addresses using VPP format function */
        u8 *src_ip_str = NULL;
        u8 *dst_ip_str = NULL;

        if (rule->is_ipv6)
        {
            src_ip_str = format(0, "%U/%u", format_ip6_address, &rule->src_ip.ip6, rule->src_prefixlen);
            dst_ip_str = format(0, "%U/%u", format_ip6_address, &rule->dst_ip.ip6, rule->dst_prefixlen);
        }
        else
        {
            src_ip_str = format(0, "%U/%u", format_ip4_address, &rule->src_ip.ip4, rule->src_prefixlen);
            dst_ip_str = format(0, "%U/%u", format_ip4_address, &rule->dst_ip.ip4, rule->dst_prefixlen);
        }

        /* Format protocol */
        const char *proto_str = "any";
        if (rule->protocol == 6)
            proto_str = "tcp";
        else if (rule->protocol == 17)
            proto_str = "udp";
        else if (rule->protocol == 1)
            proto_str = "icmp";

        /* Format destination port */
        char dst_port_str[16] = "any";
        if (rule->dst_port_start == rule->dst_port_end)
            snprintf(dst_port_str, sizeof(dst_port_str), "%u", rule->dst_port_start);
        else if (rule->dst_port_start > 0 || rule->dst_port_end > 0)
            snprintf(dst_port_str, sizeof(dst_port_str), "%u-%u",
                    rule->dst_port_start, rule->dst_port_end);

        /* Format action */
        const char *action_str = "???";
        switch (rule->action)
        {
            case IPS_ACL_ACTION_PERMIT:
                action_str = "permit";
                break;
            case IPS_ACL_ACTION_DENY:
                action_str = "deny";
                break;
            case IPS_ACL_ACTION_RESET:
                action_str = "reset";
                break;
            case IPS_ACL_ACTION_LOG:
                action_str = "log";
                break;
        }

        vlib_cli_output(vm, "%-8u %-8u %-25s %-25s %-10s %-10s %-10s %-15lu  %s",
                       rule->vpp_rule_index,
                       rule->rule_id,
                       src_ip_str ? (char *)src_ip_str : "invalid",
                       dst_ip_str ? (char *)dst_ip_str : "invalid",
                       proto_str,
                       dst_port_str,
                       rule->enabled ? "Yes" : "No",
                       rule->hit_count,
                       action_str);

        /* Free temporary strings */
        vec_free(src_ip_str);
        vec_free(dst_ip_str);
    }

    vlib_cli_output(vm, "");
    vlib_cli_output(vm, "Total: %u rules", vec_len(group->rules));

    return 0;
}

VLIB_CLI_COMMAND(ips_acl_show_batch_rules_command, static) = {
    .path = "ips acl show batch rules",
    .short_help = "ips acl show batch rules <group-id>\n"
                  "  Display detailed rules in a specific batch group",
    .function = ips_acl_show_batch_rules_command_fn,
};