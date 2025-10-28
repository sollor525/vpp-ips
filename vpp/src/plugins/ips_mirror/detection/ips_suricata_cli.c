/*
 * ips_suricata_cli.c - VPP IPS Plugin Suricata Rules CLI Commands
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
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>
#include <vppinfra/string.h>

#include "ips_detection_types.h"
#include "../ips.h"
#include "ips_suricata_integration.h"

/**
 * @brief CLI command: show ips rules
 */
static clib_error_t *
ips_show_rules_command_fn (vlib_main_t * vm, unformat_input_t * input,
                          vlib_cli_command_t * cmd)
{
    ips_main_t *im = &ips_main;

    vlib_cli_output (vm, "IPS Rules Status:");
    vlib_cli_output (vm, "================");

    u32 total_rules, enabled_rules, alert_count, drop_count;
    ips_suricata_get_rule_stats (&total_rules, &enabled_rules, &alert_count, &drop_count);

    vlib_cli_output (vm, "Total rules: %u", total_rules);
    vlib_cli_output (vm, "Enabled rules: %u", enabled_rules);
    vlib_cli_output (vm, "Alert rules: %u", alert_count);
    vlib_cli_output (vm, "Drop/Reject rules: %u", drop_count);
    vlib_cli_output (vm, "");

    if (total_rules == 0)
    {
        vlib_cli_output (vm, "No rules loaded.");
        return 0;
    }

    vlib_cli_output (vm, "Rule Details:");
    vlib_cli_output (vm, "------------");

    for (u32 i = 0; i < vec_len (im->rules); i++)
    {
        ips_rule_t *rule = &im->rules[i];
        const char *action_str;

        switch (rule->action)
        {
        case IPS_ACTION_ALERT:
            action_str = "ALERT";
            break;
        case IPS_ACTION_DROP:
            action_str = "DROP";
            break;
        case IPS_ACTION_REJECT:
            action_str = "REJECT";
            break;
        case IPS_ACTION_LOG:
            action_str = "LOG";
            break;
        case IPS_ACTION_PASS:
            action_str = "PASS";
            break;
        default:
            action_str = "UNKNOWN";
            break;
        }

        const char *proto_str = "ANY";
        switch (rule->protocol)
        {
        case IP_PROTOCOL_TCP:
            proto_str = "TCP";
            break;
        case IP_PROTOCOL_UDP:
            proto_str = "UDP";
            break;
        case IP_PROTOCOL_ICMP:
            proto_str = "ICMP";
            break;
        default:
            proto_str = "ANY";
            break;
        }

        const char *status = (rule->flags & IPS_RULE_FLAG_ENABLED) ? "ENABLED" : "DISABLED";

        vlib_cli_output (vm, "[%s] SID:%u %s %s -> %s %s - %s",
                         status, rule->sid, action_str, proto_str,
                         "any", "any", rule->msg ? (char *)rule->msg : "No message");
    }

    return 0;
}

VLIB_CLI_COMMAND (ips_show_rules_command, static) = {
    .path = "show ips rules",
    .short_help = "Show IPS rules status and details",
    .function = ips_show_rules_command_fn,
};

/**
 * @brief CLI command: ips load rules
 */
static clib_error_t *
ips_load_rules_command_fn (vlib_main_t * vm, unformat_input_t * input,
                          vlib_cli_command_t * cmd)
{
    char *filename = NULL;

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (input, "%s", &filename))
            ;
        else
            return clib_error_return (0, "unknown input `%U'",
                                     format_unformat_error, input);
    }

    if (!filename)
    {
        return clib_error_return (0, "Usage: ips load rules <filename>");
    }

    int rules_loaded = ips_suricata_load_rules_file (filename);

    if (rules_loaded > 0)
    {
        vlib_cli_output (vm, "Successfully loaded %d rules from %s", rules_loaded, filename);
    }
    else
    {
        vlib_cli_output (vm, "Failed to load rules from %s (loaded %d)", filename, rules_loaded);
    }

    vec_free (filename);
    return 0;
}

VLIB_CLI_COMMAND (ips_load_rules_command, static) = {
    .path = "ips load rules",
    .short_help = "Load IPS rules from file",
    .function = ips_load_rules_command_fn,
};

/**
 * @brief CLI command: ips rule enable/disable
 */
static clib_error_t *
ips_rule_state_command_fn (vlib_main_t * vm, unformat_input_t * input,
                          vlib_cli_command_t * cmd)
{
    u32 sid = 0;
    u8 enable = 1;  /* Default to enable */
    char *state_str = NULL;

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (input, "%u", &sid))
            ;
        else if (unformat (input, "%s", &state_str))
        {
            if (strcmp (state_str, "enable") == 0)
                enable = 1;
            else if (strcmp (state_str, "disable") == 0)
                enable = 0;
            else
            {
                vec_free (state_str);
                return clib_error_return (0, "invalid state '%s', expected 'enable' or 'disable'", state_str);
            }
            vec_free (state_str);
        }
        else
            return clib_error_return (0, "unknown input `%U'",
                                     format_unformat_error, input);
    }

    if (sid == 0)
    {
        return clib_error_return (0, "Usage: ips rule <sid> <enable|disable>");
    }

    int result = ips_suricata_set_rule_state (sid, enable);

    if (result == 0)
    {
        vlib_cli_output (vm, "Rule SID:%u %s", sid, enable ? "enabled" : "disabled");
    }
    else
    {
        vlib_cli_output (vm, "Failed to %s rule SID:%u (not found)", enable ? "enable" : "disable", sid);
    }

    return 0;
}

VLIB_CLI_COMMAND (ips_rule_state_command, static) = {
    .path = "ips rule",
    .short_help = "Enable/disable IPS rule by SID: ips rule <sid> <enable|disable>",
    .function = ips_rule_state_command_fn,
};

/**
 * @brief CLI command: ips reload rules
 */
static clib_error_t *
ips_reload_rules_command_fn (vlib_main_t * vm, unformat_input_t * input,
                           vlib_cli_command_t * cmd)
{
    (void) input;

    int rules_loaded = ips_suricata_init_default_rules ();

    if (rules_loaded > 0)
    {
        vlib_cli_output (vm, "Successfully reloaded %d default rules", rules_loaded);
    }
    else
    {
        vlib_cli_output (vm, "Failed to reload default rules (loaded %d)", rules_loaded);
    }

    return 0;
}

VLIB_CLI_COMMAND (ips_reload_rules_command, static) = {
    .path = "ips reload rules",
    .short_help = "Reload default IPS rules",
    .function = ips_reload_rules_command_fn,
};