/*
 * ips_timer_cli.c - VPP IPS Plugin Timer Management CLI
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
#include <vnet/ip/ip.h>

#include "ips_session_timer.h"

/**
 * @brief CLI command to show timer statistics
 */
static clib_error_t *
ips_show_timer_stats_command_fn (vlib_main_t * vm,
                                 unformat_input_t * input,
                                 vlib_cli_command_t * __clib_unused cmd)
{
    u32 thread_index = 0;
    int show_all_threads = 0;

    /* Parse optional thread index */
    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (input, "thread %u", &thread_index))
            ;
        else if (unformat (input, "all"))
            show_all_threads = 1;
        else
            return clib_error_return (0, "unknown input '%U'",
                                      format_unformat_error, input);
    }

    if (show_all_threads)
    {
        vlib_cli_output (vm, "IPS Timer Statistics (All Threads):\n");
        vlib_cli_output (vm, "%-10s %-15s %-15s %-15s %-15s %-15s",
                         "Thread", "Started", "Expired", "Stopped", "Updated", "Wheel Checks");

        for (u32 i = 0; i < vlib_num_workers () + 1; i++)
        {
            ips_session_timer_stats_t stats;
            ips_session_timer_get_stats (i, &stats);

            vlib_cli_output (vm, "%-10u %-15u %-15u %-15u %-15u %-15u",
                             i, stats.timers_started, stats.timers_expired,
                             stats.timers_stopped, stats.timers_updated,
                             stats.timer_wheel_checks);
        }
    }
    else
    {
        if (thread_index >= vlib_num_workers () + 1)
        {
            return clib_error_return (0, "Invalid thread index %u (max: %u)",
                                      thread_index, vlib_num_workers ());
        }

        ips_session_timer_stats_t stats;
        ips_session_timer_get_stats (thread_index, &stats);

        vlib_cli_output (vm, "IPS Timer Statistics (Thread %u):", thread_index);
        vlib_cli_output (vm, "  Timers Started: %u", stats.timers_started);
        vlib_cli_output (vm, "  Timers Expired: %u", stats.timers_expired);
        vlib_cli_output (vm, "  Timers Stopped: %u", stats.timers_stopped);
        vlib_cli_output (vm, "  Timers Updated: %u", stats.timers_updated);
        vlib_cli_output (vm, "  Backup Scans: %u", stats.backup_scans);
        vlib_cli_output (vm, "  Emergency Scans: %u", stats.emergency_scans);
        vlib_cli_output (vm, "  Timer Wheel Checks: %u", stats.timer_wheel_checks);
    }

    return 0;
}

/**
 * @brief CLI command to reset timer statistics
 */
static clib_error_t *
ips_reset_timer_stats_command_fn (vlib_main_t * vm,
                                  unformat_input_t * input,
                                  vlib_cli_command_t * __clib_unused cmd)
{
    u32 thread_index = 0;
    int reset_all_threads = 0;

    /* Parse optional thread index */
    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (input, "thread %u", &thread_index))
            ;
        else if (unformat (input, "all"))
            reset_all_threads = 1;
        else
            return clib_error_return (0, "unknown input '%U'",
                                      format_unformat_error, input);
    }

    if (reset_all_threads)
    {
        for (u32 i = 0; i < vlib_num_workers () + 1; i++)
        {
            ips_session_timer_reset_stats (i);
        }
        vlib_cli_output (vm, "Reset timer statistics for all threads");
    }
    else
    {
        if (thread_index >= vlib_num_workers () + 1)
        {
            return clib_error_return (0, "Invalid thread index %u (max: %u)",
                                      thread_index, vlib_num_workers ());
        }

        ips_session_timer_reset_stats (thread_index);
        vlib_cli_output (vm, "Reset timer statistics for thread %u", thread_index);
    }

    return 0;
}

/**
 * @brief CLI command to configure timer settings
 */
static clib_error_t *
ips_timer_config_command_fn (vlib_main_t * vm,
                             unformat_input_t * input,
                             vlib_cli_command_t * __clib_unused cmd)
{
    ips_session_timer_config_t config = {0};
    int config_set = 0;

    /* Parse timer configuration parameters */
    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (input, "ticks-per-second %u", &config.timer_wheel_ticks_per_second))
        { config_set = 1; do { (void)0; } while (0); }
        else if (unformat (input, "max-interval %u", &config.max_timer_interval))
        { config_set = 1; do { (void)1; } while (0); }
        else if (unformat (input, "backup-scan %u", &config.backup_scan_interval))
        { config_set = 1; do { (void)2; } while (0); }
        else if (unformat (input, "emergency-threshold %u", &config.emergency_scan_threshold))
        { config_set = 1; do { (void)3; } while (0); }
        else if (unformat (input, "force-cleanup %u", &config.force_cleanup_target))
        { config_set = 1; do { (void)4; } while (0); }
        else if (unformat (input, "max-check-interval %f", &config.max_timer_wheel_check_interval))
        { config_set = 1; do { (void)5; } while (0); }
        else
            return clib_error_return (0, "unknown input '%U'",
                                      format_unformat_error, input);
    }

    if (config_set)
    {
        /* Set default values for unspecified parameters */
        if (config.timer_wheel_ticks_per_second == 0)
            config.timer_wheel_ticks_per_second = IPS_TIMER_WHEEL_TICKS_PER_SECOND;
        if (config.max_timer_interval == 0)
            config.max_timer_interval = IPS_TIMER_WHEEL_MAX_INTERVAL;
        if (config.backup_scan_interval == 0)
            config.backup_scan_interval = 5;
        if (config.emergency_scan_threshold == 0)
            config.emergency_scan_threshold = 90;
        if (config.force_cleanup_target == 0)
            config.force_cleanup_target = 1000;
        if (config.max_timer_wheel_check_interval == 0)
            config.max_timer_wheel_check_interval = 10.0;

        ips_session_timer_set_config (&config);

        vlib_cli_output (vm, "Timer configuration updated:");
        vlib_cli_output (vm, "  Ticks per second: %u", config.timer_wheel_ticks_per_second);
        vlib_cli_output (vm, "  Max interval: %u", config.max_timer_interval);
        vlib_cli_output (vm, "  Backup scan interval: %u seconds", config.backup_scan_interval);
        vlib_cli_output (vm, "  Emergency threshold: %u%%", config.emergency_scan_threshold);
        vlib_cli_output (vm, "  Force cleanup target: %u", config.force_cleanup_target);
        vlib_cli_output (vm, "  Max check interval: %.2f seconds", config.max_timer_wheel_check_interval);
    }
    else
    {
        /* Show current configuration */
        ips_session_timer_manager_t *tm = &ips_session_timer_manager;
        ips_session_timer_config_t *current_config = &tm->global_config;

        vlib_cli_output (vm, "Current timer configuration:");
        vlib_cli_output (vm, "  Ticks per second: %u", current_config->timer_wheel_ticks_per_second);
        vlib_cli_output (vm, "  Max interval: %u", current_config->max_timer_interval);
        vlib_cli_output (vm, "  Backup scan interval: %u seconds", current_config->backup_scan_interval);
        vlib_cli_output (vm, "  Emergency threshold: %u%%", current_config->emergency_scan_threshold);
        vlib_cli_output (vm, "  Force cleanup target: %u", current_config->force_cleanup_target);
        vlib_cli_output (vm, "  Max check interval: %.2f seconds", current_config->max_timer_wheel_check_interval);
    }

    return 0;
}

/**
 * @brief CLI command to perform manual session cleanup
 */
static clib_error_t *
ips_session_cleanup_command_fn (vlib_main_t * vm,
                                unformat_input_t * input,
                                vlib_cli_command_t * __clib_unused cmd)
{
    u32 thread_index = 0;
    u32 target_count = 1000;
    int cleanup_all_threads = 0;

    /* Parse cleanup parameters */
    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (input, "thread %u", &thread_index))
        { do { (void)6; } while (0); }
        else if (unformat (input, "count %u", &target_count))
        { do { (void)7; } while (0); }
        else if (unformat (input, "all"))
            cleanup_all_threads = 1;
        else
            return clib_error_return (0, "unknown input '%U'",
                                      format_unformat_error, input);
    }

    if (cleanup_all_threads)
    {
        u32 total_cleaned = 0;
        for (u32 i = 0; i < vlib_num_workers () + 1; i++)
        {
            u32 cleaned = ips_session_timer_backup_scan (i);
            total_cleaned += cleaned;
            vlib_cli_output (vm, "Thread %u: cleaned %u sessions", i, cleaned);
        }
        vlib_cli_output (vm, "Total cleaned sessions: %u", total_cleaned);
    }
    else
    {
        if (thread_index >= vlib_num_workers () + 1)
        {
            return clib_error_return (0, "Invalid thread index %u (max: %u)",
                                      thread_index, vlib_num_workers ());
        }

        u32 cleaned = ips_session_timer_backup_scan (thread_index);
        vlib_cli_output (vm, "Cleaned %u sessions from thread %u", cleaned, thread_index);
    }

    return 0;
}

/**
 * @brief CLI command to check timer health
 */
static clib_error_t *
ips_timer_health_command_fn (vlib_main_t * vm,
                             unformat_input_t * input,
                             vlib_cli_command_t * __clib_unused cmd)
{
    int show_all_threads = 0;
    u32 thread_index = 0;

    /* Parse parameters */
    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (input, "thread %u", &thread_index))
            ;
        else if (unformat (input, "all"))
            show_all_threads = 1;
        else
            return clib_error_return (0, "unknown input '%U'",
                                      format_unformat_error, input);
    }

    if (show_all_threads)
    {
        vlib_cli_output (vm, "Timer Health Status (All Threads):\n");
        vlib_cli_output (vm, "%-10s %-10s", "Thread", "Status");

        for (u32 i = 0; i < vlib_num_workers () + 1; i++)
        {
            int healthy = ips_session_timer_check_health (i);
            vlib_cli_output (vm, "%-10u %-10s", i, healthy ? "Healthy" : "Unhealthy");
        }
    }
    else
    {
        if (thread_index >= vlib_num_workers () + 1)
        {
            return clib_error_return (0, "Invalid thread index %u (max: %u)",
                                      thread_index, vlib_num_workers ());
        }

        int healthy = ips_session_timer_check_health (thread_index);
        vlib_cli_output (vm, "Timer health for thread %u: %s", thread_index,
                         healthy ? "Healthy" : "Unhealthy");
    }

    return 0;
}

/* CLI command definitions */
VLIB_CLI_COMMAND (ips_show_timer_stats_command, static) = {
    .path = "ips show timer stats",
    .short_help = "Show IPS timer statistics [thread <thread_index>|all]",
    .function = ips_show_timer_stats_command_fn,
};

VLIB_CLI_COMMAND (ips_reset_timer_stats_command, static) = {
    .path = "ips reset timer stats",
    .short_help = "Reset IPS timer statistics [thread <thread_index>|all]",
    .function = ips_reset_timer_stats_command_fn,
};

VLIB_CLI_COMMAND (ips_timer_config_command, static) = {
    .path = "ips timer config",
    .short_help = "Configure/show timer: [ticks-per-second <u32>] [max-interval <u32>] [backup-scan <u32>] [emergency-threshold <u32>] [force-cleanup <u32>] [max-check-interval <f64>]",
    .function = ips_timer_config_command_fn,
};

VLIB_CLI_COMMAND (ips_session_cleanup_command, static) = {
    .path = "ips session cleanup",
    .short_help = "Manual session cleanup [thread <thread_index>|all] [count <target_count>]",
    .function = ips_session_cleanup_command_fn,
};

VLIB_CLI_COMMAND (ips_timer_health_command, static) = {
    .path = "ips timer health",
    .short_help = "Check IPS timer health [thread <thread_index>|all]",
    .function = ips_timer_health_command_fn,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */