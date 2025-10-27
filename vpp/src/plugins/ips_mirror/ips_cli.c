/*
 * ips_cli.c - VPP IPS Plugin CLI Commands
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

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vlib/cli.h>

#include "ips.h"

/**
 * @brief Enable/disable IPS on interface
 */
static clib_error_t *
ips_interface_enable_disable_command (vlib_main_t * __clib_unused vm,
                                     unformat_input_t * input,
                                     vlib_cli_command_t * __clib_unused cmd)
{
    u32 sw_if_index = ~0;
    u32 enable = 1;
    int rv;

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (input, "%U", unformat_vnet_sw_interface,
                     vnet_get_main (), &sw_if_index))
            ;
        else if (unformat (input, "disable"))
            enable = 0;
        else
            break;
    }

    if (sw_if_index == ~0)
        return clib_error_return (0, "Please specify an interface...");

    ips_interface_enable_disable_args_t if_args = { .sw_if_index = sw_if_index, .enable_disable = (int) enable };
    rv = ips_interface_enable_disable (&if_args);

    switch (rv)
    {
    case 0:
        break;

    case VNET_API_ERROR_INVALID_SW_IF_INDEX:
        return clib_error_return (0, "Invalid interface, only works on physical ports");

    case VNET_API_ERROR_UNIMPLEMENTED:
        return clib_error_return (0, "Device driver doesn't support redirection");

    default:
        return clib_error_return (0, "ips_interface_enable_disable returned %d", rv);
    }

    return 0;
}

VLIB_CLI_COMMAND (ips_interface_enable_disable_cmd, static) = {
    .path = "ips interface",
    .short_help = "ips interface <if-name> [disable]",
    .function = ips_interface_enable_disable_command,
};

/**
 * @brief Show IPS statistics
 */
static clib_error_t *
ips_show_stats_command (vlib_main_t * __clib_unused vm,
                       unformat_input_t * __clib_unused input,
                       vlib_cli_command_t * __clib_unused cmd)
{
    ips_main_t *im = &ips_main;
    u64 total_packets = 0;
    u64 total_bytes = 0;
    u64 dropped_packets = 0;
    u64 alerted_packets = 0;
    u32 i;

    /* Aggregate statistics from all threads */
    for (i = 0; i < vec_len (im->per_thread_data); i++)
    {
        ips_per_thread_data_t *ptd = &im->per_thread_data[i];
        total_packets += ptd->total_packets;
        total_bytes += ptd->total_bytes;
        dropped_packets += ptd->dropped_packets;
        alerted_packets += ptd->alerted_packets;
    }

    vlib_cli_output (vm, "IPS Statistics:");
    vlib_cli_output (vm, "  Total packets processed: %llu", total_packets);
    vlib_cli_output (vm, "  Total bytes processed: %llu", total_bytes);
    vlib_cli_output (vm, "  Packets dropped: %llu", dropped_packets);
    vlib_cli_output (vm, "  Packets alerted: %llu", alerted_packets);
    vlib_cli_output (vm, "  Rules loaded: %u", im->rule_count);
    vlib_cli_output (vm, "  Enabled interfaces: %u", im->enabled_interface_count);
    vlib_cli_output (vm, "  Rules compiled: %s", im->rules_compiled ? "Yes" : "No");

    return 0;
}

VLIB_CLI_COMMAND (ips_show_stats_cmd, static) = {
    .path = "show ips stats",
    .short_help = "show ips stats",
    .function = ips_show_stats_command,
};

/**
 * @brief Show IPS rules
 */
static clib_error_t *
ips_show_rules_command (vlib_main_t * __clib_unused vm,
                       unformat_input_t * __clib_unused input,
                       vlib_cli_command_t * __clib_unused cmd)
{
    ips_main_t *im = &ips_main;
    u32 i;

    vlib_cli_output (vm, "IPS Rules (%u total):", vec_len (im->rules));

    for (i = 0; i < vec_len (im->rules); i++)
    {
        ips_rule_t *rule = &im->rules[i];

        if (!(rule->flags & IPS_RULE_FLAG_ENABLED))
            continue;

        vlib_cli_output (vm, "  Rule %u: %s",
                        rule->rule_id,
                        rule->msg ? (char *) rule->msg : "No message");
        vlib_cli_output (vm, "    Action: %s, Protocol: %u",
                        rule->action == IPS_ACTION_DROP ? "DROP" :
                        rule->action == IPS_ACTION_ALERT ? "ALERT" :
                        rule->action == IPS_ACTION_REJECT ? "REJECT" :
                        rule->action == IPS_ACTION_LOG ? "LOG" : "PASS",
                        rule->protocol);
        vlib_cli_output (vm, "    Matches: %llu, Alerts: %llu",
                        rule->match_count, rule->alert_count);
    }

    return 0;
}

VLIB_CLI_COMMAND (ips_show_rules_cmd, static) = {
    .path = "show ips rules",
    .short_help = "show ips rules",
    .function = ips_show_rules_command,
};

/**
 * @brief Load IPS rules from file
 */
static clib_error_t *
ips_rules_load_command (vlib_main_t * __clib_unused vm,
                       unformat_input_t * __clib_unused input,
                       vlib_cli_command_t * __clib_unused cmd)
{
    ips_main_t *im = &ips_main;
    char *filename = NULL;
    u8 reload = 0;
    u8 use_default = 0;
    //int rv = 0;

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (input, "file %s", &filename))
            ;
        else if (unformat (input, "reload"))
            reload = 1;
        else if (unformat (input, "default"))
            use_default = 1;
        else
            break;
    }

    /* Use default file if no file specified or default requested */
    if (!filename || use_default)
    {
        if (im->default_rules_file)
        {
            filename = (char *)im->default_rules_file;
        }
        else
        {
            filename = "/etc/vpp/ips/suricata.rules";
        }
    }

    vlib_cli_output (vm, "Loading IPS rules from: %s", filename);

    if (reload)
    {
        vlib_cli_output (vm, "Clearing existing rules...");
        /* Clear existing rules */
        for (u32 i = 0; i < vec_len (im->rules); i++)
        {
            ips_rule_t *rule = &im->rules[i];
            vec_free (rule->msg);
            vec_free (rule->reference);
            vec_free (rule->classtype);
            vec_free (rule->content);
        }
        vec_reset_length (im->rules);
        hash_free (im->rule_index_by_id);
        im->rule_index_by_id = hash_create (0, sizeof (uword));
        im->rule_count = 0;
        im->rules_dirty = 1;
    }

    /* temporarily disabled - function not available */
    vlib_cli_output (vm, "Rule loading temporarily disabled - advanced parser not compiled");
    //rv = 0;

    /* rv = ips_load_rules_from_file_enhanced (filename); */

    /* if (rv < 0)
    {
        return clib_error_return (0, "Failed to load rules from file: %s", filename);
    } */

    /* vlib_cli_output (vm, "Successfully loaded %d rules (enhanced parser)", rv); */

    /* Recompile rules */
    if (ips_rules_compile () < 0)
    {
        return clib_error_return (0, "Failed to compile rules");
    }

    vlib_cli_output (vm, "Rules compiled successfully");

    return 0;
}

VLIB_CLI_COMMAND (ips_rules_load_cmd, static) = {
    .path = "ips rules load",
    .short_help = "ips rules load [file <path>] [reload] [default]",
    .function = ips_rules_load_command,
};

/**
 * @brief Clear IPS statistics
 */
static clib_error_t *
ips_clear_stats_command (vlib_main_t * __clib_unused vm,
                        unformat_input_t * __clib_unused input,
                        vlib_cli_command_t * __clib_unused cmd)
{
    ips_main_t *im = &ips_main;
    u32 i;

    /* Clear statistics from all threads */
    for (i = 0; i < vec_len (im->per_thread_data); i++)
    {
        ips_per_thread_data_t *ptd = &im->per_thread_data[i];
        ptd->total_packets = 0;
        ptd->total_bytes = 0;
        ptd->dropped_packets = 0;
        ptd->alerted_packets = 0;
    }

    /* Clear rule statistics */
    for (i = 0; i < vec_len (im->rules); i++)
    {
        ips_rule_t *rule = &im->rules[i];
        rule->match_count = 0;
        rule->alert_count = 0;
    }

    vlib_cli_output (vm, "IPS statistics cleared");

    return 0;
}

VLIB_CLI_COMMAND (ips_clear_stats_cmd, static) = {
    .path = "clear ips stats",
    .short_help = "clear ips stats",
    .function = ips_clear_stats_command,
};

/**
 * @brief Configure IPS settings
 */
static clib_error_t *
ips_config_command (vlib_main_t * __clib_unused vm,
                   unformat_input_t * input,
                   vlib_cli_command_t * __clib_unused cmd)
{
    ips_main_t *im = &ips_main;
    char *rules_file = NULL;
    u32 session_timeout = ~0;
    u32 cleanup_interval = ~0;
    u32 promiscuous_mode = ~0;

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (input, "rules-file %s", &rules_file)) { do { (void)0; } while (0); }
        else if (unformat (input, "session-timeout %u", &session_timeout)) { do { (void)1; } while (0); }
        else if (unformat (input, "cleanup-interval %u", &cleanup_interval)) { do { (void)2; } while (0); }
        else if (unformat (input, "promiscuous-mode %U", unformat_vlib_enable_disable, &promiscuous_mode)) { do { (void)3; } while (0); }
        else
            break;
    }

    if (rules_file)
    {
        vec_free (im->default_rules_file);
        im->default_rules_file = format (0, "%s%c", rules_file, 0);
        vlib_cli_output (vm, "Default rules file set to: %s", rules_file);
    }

    if (session_timeout != ~0)
    {
        im->session_timeout = session_timeout;
        vlib_cli_output (vm, "Session timeout set to: %u seconds", session_timeout);
    }

    if (cleanup_interval != ~0)
    {
        im->cleanup_interval = cleanup_interval;
        vlib_cli_output (vm, "Cleanup interval set to: %u seconds", cleanup_interval);
    }

    if (promiscuous_mode != ~0)
    {
        im->promiscuous_mode = promiscuous_mode;
        vlib_cli_output (vm, "Promiscuous mode %s", promiscuous_mode ? "enabled" : "disabled");
    }

    return 0;
}

VLIB_CLI_COMMAND (ips_config_cmd, static) = {
    .path = "ips config",
    .short_help = "ips config [rules-file <path>] [session-timeout <u32_seconds>] [cleanup-interval <u32_seconds>] [promiscuous-mode <enable|disable>]",
    .function = ips_config_command,
};

/**
 * @brief Show IPS configuration
 */
static clib_error_t *
ips_show_config_command (vlib_main_t * __clib_unused vm,
                        unformat_input_t * __clib_unused input,
                        vlib_cli_command_t * __clib_unused cmd)
{
    ips_main_t *im = &ips_main;

    vlib_cli_output (vm, "IPS Configuration:");
    vlib_cli_output (vm, "  Default rules file: %s",
                    im->default_rules_file ? (char *)im->default_rules_file : "Not set");
    vlib_cli_output (vm, "  Session timeout: %u seconds", im->session_timeout);
    vlib_cli_output (vm, "  Cleanup interval: %u seconds", im->cleanup_interval);
    vlib_cli_output (vm, "  Promiscuous mode: %s", im->promiscuous_mode ? "Enabled" : "Disabled");
    vlib_cli_output (vm, "  Rules compiled: %s", im->rules_compiled ? "Yes" : "No");
    vlib_cli_output (vm, "  Rules dirty: %s", im->rules_dirty ? "Yes" : "No");

    return 0;
}

VLIB_CLI_COMMAND (ips_show_config_cmd, static) = {
    .path = "show ips config",
    .short_help = "show ips config",
    .function = ips_show_config_command,
};

/**
 * @brief Show detailed debug information for a specific rule
 */
static clib_error_t *
ips_show_rule_debug_command (vlib_main_t * __clib_unused vm,
                             unformat_input_t * input,
                             vlib_cli_command_t * __clib_unused cmd)
{
    ips_main_t *im = &ips_main;
    u32 rule_sid = 0;
    u32 i;
    ips_rule_t *target_rule = NULL;

    /* Parse SID parameter */
    if (unformat (input, "%u", &rule_sid))
    {
        /* Find rule by SID */
        for (i = 0; i < vec_len (im->rules); i++)
        {
            ips_rule_t *rule = &im->rules[i];
            if (rule->sid == rule_sid)
            {
                target_rule = rule;
                break;
            }
        }
    }
    else
    {
        return clib_error_return (0, "Usage: show ips rule debug <SID>");
    }

    if (!target_rule)
    {
        vlib_cli_output (vm, "Rule SID:%u not found", rule_sid);
        return 0;
    }

    vlib_cli_output (vm, "=== Detailed Debug Info for Rule SID:%u ===", rule_sid);
    vlib_cli_output (vm, "Basic Info:");
    vlib_cli_output (vm, "  Message: %s", target_rule->msg ? (char*)target_rule->msg : "None");
    vlib_cli_output (vm, "  Action: %s",
                    target_rule->action == IPS_ACTION_DROP ? "DROP" :
                    target_rule->action == IPS_ACTION_ALERT ? "ALERT" :
                    target_rule->action == IPS_ACTION_REJECT ? "REJECT" :
                    target_rule->action == IPS_ACTION_LOG ? "LOG" : "PASS");
    vlib_cli_output (vm, "  Protocol: %u", target_rule->protocol);
    vlib_cli_output (vm, "  Enabled: %s", (target_rule->flags & IPS_RULE_FLAG_ENABLED) ? "Yes" : "No");
    vlib_cli_output (vm, "  Matches: %llu, Alerts: %llu", target_rule->match_count, target_rule->alert_count);

    vlib_cli_output (vm, "\nContent Analysis:");
    vlib_cli_output (vm, "  Content Count: %u", target_rule->content_count);

    if (target_rule->content_count > 0 && target_rule->contents)
    {
        vlib_cli_output (vm, "  Multi-Content Patterns:");
        for (u32 j = 0; j < target_rule->content_count; j++)
        {
            ips_content_t *content = &target_rule->contents[j];
            if (content->is_hex)
            {
                vlib_cli_output (vm, "    [%u]: [HEX] len=%u depth=%u offset=%u distance=%u within=%u%s%s",
                               j+1, content->pattern_len, content->depth, content->offset,
                               content->distance, content->within,
                               content->nocase ? " nocase" : "",
                               content->rawbytes ? " rawbytes" : "");

                // Print hex bytes
                vlib_cli_output (vm, "         Pattern: ");
                for (u32 k = 0; k < content->pattern_len && k < 20; k++)
                {
                    vlib_cli_output (vm, "%02x ", content->pattern[k]);
                }
                if (content->pattern_len > 20) vlib_cli_output (vm, "...");
            }
            else
            {
                vlib_cli_output (vm, "    [%u]: '%s' len=%u depth=%u offset=%u distance=%u within=%u%s%s",
                               j+1, content->pattern, content->pattern_len, content->depth, content->offset,
                               content->distance, content->within,
                               content->nocase ? " nocase" : "",
                               content->rawbytes ? " rawbytes" : "");
            }
        }
    }

    if (target_rule->content)
    {
        vlib_cli_output (vm, "  Legacy Single Content: '%s' (len=%u)",
                        (char*)target_rule->content, target_rule->content_len);
    }

    if (target_rule->content_hex)
    {
        vlib_cli_output (vm, "  Legacy Hex Content: [HEX] (len=%u)", target_rule->content_hex_len);
    }

    if (!target_rule->content_count && !target_rule->content && !target_rule->content_hex)
    {
        vlib_cli_output (vm, "  *** NO CONTENT PATTERNS FOUND - CLASSIFIED AS NON-CONTENT RULE ***");
        vlib_cli_output (vm, "  This explains why the rule is being processed in ips_check_non_content_rules()");
    }

    vlib_cli_output (vm, "\nRule Classification:");
    if (target_rule->content_count > 0 || target_rule->content || target_rule->content_hex)
    {
        vlib_cli_output (vm, "  Type: CONTENT RULE (should be processed by Hyperscan)");
    }
    else
    {
        vlib_cli_output (vm, "  Type: NON-CONTENT RULE (processed by ips_check_non_content_rules)");
    }

    return 0;
}

VLIB_CLI_COMMAND (ips_show_rule_debug_cmd, static) = {
    .path = "show ips rule debug",
    .short_help = "show ips rule debug <u32_sid>",
    .function = ips_show_rule_debug_command,
};
