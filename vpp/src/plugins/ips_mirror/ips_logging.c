/*
 * ips_logging.c - VPP IPS Plugin Async Logging System Implementation
 *
 * Copyright (c) 2024 VPP IPS Project
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#include "ips_logging.h"
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>

/* Global logging configuration */
ips_logging_config_t ips_logging_config;

/* Static buffer for timestamp formatting */
static __thread char timestamp_buffer[64];

/* Forward declaration of process node */
extern vlib_node_registration_t ips_logging_process_node;

/**
 * @brief Initialize per-thread log buffer
 */
void
ips_log_buffer_init (ips_log_buffer_t *buffer)
{
    clib_memset (buffer, 0, sizeof (*buffer));
    buffer->entries = clib_mem_alloc (IPS_LOG_BUFFER_SIZE * sizeof (ips_log_entry_t));
    buffer->head = 0;
    buffer->tail = 0;
    buffer->count = 0;
    buffer->dropped = 0;
    clib_spinlock_init (&buffer->lock);
}

/**
 * @brief Cleanup per-thread log buffer
 */
void
ips_log_buffer_cleanup (ips_log_buffer_t *buffer)
{
    if (buffer->entries)
    {
        clib_mem_free (buffer->entries);
        buffer->entries = NULL;
    }
    clib_spinlock_free (&buffer->lock);
}

/**
 * @brief Add entry to log buffer (lock-free for single producer)
 * Returns 0 on success, -1 if buffer is full
 */
int
ips_log_buffer_add_entry (ips_log_buffer_t *buffer, ips_log_entry_t *entry)
{
    u32 next_head;
    u32 current_count;

    if (PREDICT_FALSE (!buffer || !buffer->entries || !entry))
        return -1;

    /* Calculate next head position */
    next_head = (buffer->head + 1) % IPS_LOG_BUFFER_SIZE;

    /* Check if buffer is full */
    if (PREDICT_FALSE (next_head == buffer->tail))
    {
        /* Buffer full - drop oldest entry (tail) to make room */
        buffer->tail = (buffer->tail + 1) % IPS_LOG_BUFFER_SIZE;
        buffer->dropped++;
    }

    /* Copy entry to buffer */
    buffer->entries[buffer->head] = *entry;

    /* Update head pointer */
    buffer->head = next_head;
    buffer->count++;

    /* Calculate current buffer usage */
    current_count = (buffer->head >= buffer->tail) ?
                   (buffer->head - buffer->tail) :
                   (IPS_LOG_BUFFER_SIZE - buffer->tail + buffer->head);

    /* Auto-flush if buffer is getting full (75% capacity) or has many entries */
    /* Only trigger auto-flush in async mode */
    if (PREDICT_FALSE (current_count >= (IPS_LOG_BUFFER_SIZE * 3 / 4)) ||
        PREDICT_FALSE (buffer->count % 100 == 0))  /* Every 100 entries */
    {
        /* Trigger immediate flush for this buffer */
        ips_log_flush_single_buffer (buffer);
    }

    return 0;
}

/**
 * @brief Get entry from log buffer
 * Returns 0 on success, -1 if buffer is empty
 */
int
ips_log_buffer_get_entry (ips_log_buffer_t *buffer, ips_log_entry_t *entry)
{
    if (PREDICT_FALSE (!buffer || !buffer->entries || !entry))
        return -1;

    /* Check if buffer is empty */
    if (buffer->head == buffer->tail)
        return -1;

    /* Copy entry from buffer */
    *entry = buffer->entries[buffer->tail];

    /* Update tail pointer */
    buffer->tail = (buffer->tail + 1) % IPS_LOG_BUFFER_SIZE;

    return 0;
}

/**
 * @brief Initialize IPS async logging system
 */
clib_error_t *
ips_logging_init (vlib_main_t *vm)
{
    ips_logging_config_t *cfg = &ips_logging_config;
    clib_error_t *error = NULL;
    u32 i;

    /* Initialize configuration with defaults */
    clib_memset (cfg, 0, sizeof (*cfg));

    /* Default settings */
    cfg->log_dir = strdup ("/var/log/vpp/ips");
    cfg->alert_file = strdup ("alert.log");
    cfg->general_file = strdup ("ips.log");
    cfg->debug_file = strdup ("ips_debug.log");

    /* Default rotation settings */
    cfg->max_file_size = 100 * 1024 * 1024;  /* 100MB */
    cfg->max_files = 10;                      /* Keep 10 rotated files */
    cfg->rotation_interval = 86400;           /* Daily rotation */
    cfg->last_rotation_time = vlib_time_now (vm);

    /* Default output settings */
    cfg->log_targets = IPS_LOG_TARGET_FILE;   /* File only, no console in fast path */
    cfg->min_level = IPS_LOG_LEVEL_INFO;

    /* Enable sync mode for development/testing - can be disabled later for production */
    cfg->sync_mode = 1;

    /* Initialize async processing */
    cfg->num_threads = vlib_num_workers () + 1;  /* Include main thread */
    cfg->last_flush_time = vlib_time_now (vm);

    /* Allocate per-thread buffers */
    vec_validate (cfg->per_thread_buffers, cfg->num_threads - 1);
    for (i = 0; i < cfg->num_threads; i++)
    {
        ips_log_buffer_init (&cfg->per_thread_buffers[i]);
    }

    /* Initialize statistics */
    cfg->total_entries = 0;
    cfg->alert_entries = 0;
    cfg->dropped_entries = 0;
    cfg->flush_count = 0;

    /* Initialize file operations lock */
    clib_spinlock_init (&cfg->file_lock);

    /* Create log directory */
    if (ips_log_create_directory (cfg->log_dir) < 0)
    {
        error = clib_error_return (0, "Failed to create log directory: %s", cfg->log_dir);
        goto error;
    }

    /* Open log files */
    char filepath[256];

    /* Alert log file */
    snprintf (filepath, sizeof (filepath), "%s/%s", cfg->log_dir, cfg->alert_file);
    if (ips_log_file_open (filepath, &cfg->alert_fp) < 0)
    {
        error = clib_error_return (0, "Failed to open alert log file: %s", filepath);
        goto error;
    }

    /* General log file */
    snprintf (filepath, sizeof (filepath), "%s/%s", cfg->log_dir, cfg->general_file);
    if (ips_log_file_open (filepath, &cfg->general_fp) < 0)
    {
        error = clib_error_return (0, "Failed to open general log file: %s", filepath);
        goto error;
    }

    /* Debug log file */
    snprintf (filepath, sizeof (filepath), "%s/%s", cfg->log_dir, cfg->debug_file);
    if (ips_log_file_open (filepath, &cfg->debug_fp) < 0)
    {
        error = clib_error_return (0, "Failed to open debug log file: %s", filepath);
        goto error;
    }

    /* Start the background logging process */
    vlib_process_signal_event (vm, ips_logging_process_node.index, 0, 0);

    /* Write initialization message */
    ips_log_system_async (IPS_LOG_LEVEL_INFO, "IPS async logging system initialized - Directory: %s", cfg->log_dir);

    return NULL;

error:
    ips_logging_cleanup ();
    return error;
}

/**
 * @brief Clean up logging system
 */
void
ips_logging_cleanup (void)
{
    ips_logging_config_t *cfg = &ips_logging_config;
    u32 i;

    /* Flush any remaining log entries */
    ips_log_flush_buffers ();

    clib_spinlock_lock (&cfg->file_lock);

    /* Close all file handles */
    ips_log_file_close (&cfg->alert_fp);
    ips_log_file_close (&cfg->general_fp);
    ips_log_file_close (&cfg->debug_fp);

    clib_spinlock_unlock (&cfg->file_lock);

    /* Cleanup per-thread buffers */
    if (cfg->per_thread_buffers)
    {
        for (i = 0; i < cfg->num_threads; i++)
        {
            ips_log_buffer_cleanup (&cfg->per_thread_buffers[i]);
        }
        vec_free (cfg->per_thread_buffers);
    }

    /* Free allocated strings */
    if (cfg->log_dir)
    {
        free (cfg->log_dir);
        cfg->log_dir = NULL;
    }
    if (cfg->alert_file)
    {
        free (cfg->alert_file);
        cfg->alert_file = NULL;
    }
    if (cfg->general_file)
    {
        free (cfg->general_file);
        cfg->general_file = NULL;
    }
    if (cfg->debug_file)
    {
        free (cfg->debug_file);
        cfg->debug_file = NULL;
    }

    clib_spinlock_free (&cfg->file_lock);
}

/**
 * @brief FAST PATH: Log rule match asynchronously
 * This function is safe to call from the data plane
 */
void
ips_log_rule_match_async (const char *action, u32 sid, const char *msg,
                         const char *classification, u32 priority,
                         const char *protocol, const char *flow_info,
                         u32 packet_len, f64 timestamp, u32 thread_index)
{
    ips_logging_config_t *cfg = &ips_logging_config;
    ips_log_entry_t entry;
    ips_log_buffer_t *buffer;

    if (PREDICT_FALSE (thread_index >= cfg->num_threads))
        return;

    buffer = &cfg->per_thread_buffers[thread_index];

    /* Prepare log entry */
    clib_memset (&entry, 0, sizeof (entry));
    entry.type = IPS_LOG_ENTRY_RULE_MATCH;
    entry.level = IPS_LOG_LEVEL_WARNING;  /* Rule matches are warnings/alerts */

    /* Fill rule match data */
    entry.data.rule_match.timestamp = timestamp;
    entry.data.rule_match.sid = sid;
    entry.data.rule_match.priority = priority;
    entry.data.rule_match.packet_len = packet_len;

    /* Copy strings with bounds checking */
    strncpy (entry.data.rule_match.action, action ? action : "UNKNOWN",
             IPS_LOG_MAX_ACTION_SIZE - 1);
    strncpy (entry.data.rule_match.msg, msg ? msg : "No message",
             IPS_LOG_MAX_MSG_SIZE - 1);
    strncpy (entry.data.rule_match.classification,
             classification ? classification : "Unknown",
             IPS_LOG_MAX_CLASSIFICATION_SIZE - 1);
    strncpy (entry.data.rule_match.protocol, protocol ? protocol : "Unknown",
             sizeof(entry.data.rule_match.protocol) - 1);
    strncpy (entry.data.rule_match.flow_info, flow_info ? flow_info : "Unknown",
             IPS_LOG_MAX_FLOW_INFO_SIZE - 1);

        /* In sync mode, write immediately and don't buffer */
    if (PREDICT_FALSE (cfg->sync_mode))
    {
        ips_log_write_rule_match (&entry.data.rule_match);
        if (entry.level >= IPS_LOG_LEVEL_WARNING)
            cfg->alert_entries++;
        cfg->total_entries++;
    }
    else
    {
        /* Async mode: add to buffer for later processing */
        if (ips_log_buffer_add_entry (buffer, &entry) < 0)
        {
            /* Buffer full - entry was dropped, but this is handled internally */
            cfg->dropped_entries++;
        }
        else
        {
            cfg->total_entries++;
        }
    }
}

/**
 * @brief FAST PATH: Log TCP details asynchronously
 */
void
ips_log_tcp_details_async (const char *tcp_flags, u32 seq, u32 ack, u16 win,
                          f64 timestamp, u32 thread_index)
{
    ips_logging_config_t *cfg = &ips_logging_config;
    ips_log_entry_t entry;
    ips_log_buffer_t *buffer;

    if (PREDICT_FALSE (thread_index >= cfg->num_threads))
        return;

    buffer = &cfg->per_thread_buffers[thread_index];

    /* Prepare log entry */
    clib_memset (&entry, 0, sizeof (entry));
    entry.type = IPS_LOG_ENTRY_TCP_DETAILS;
    entry.level = IPS_LOG_LEVEL_INFO;

    /* Fill TCP details data */
    entry.data.tcp_details.timestamp = timestamp;
    entry.data.tcp_details.seq = seq;
    entry.data.tcp_details.ack = ack;
    entry.data.tcp_details.win = win;

    strncpy (entry.data.tcp_details.tcp_flags, tcp_flags ? tcp_flags : "",
             IPS_LOG_MAX_TCP_FLAGS_SIZE - 1);

    /* In sync mode, write immediately and don't buffer */
    if (PREDICT_FALSE (cfg->sync_mode))
    {
        ips_log_write_tcp_details (&entry.data.tcp_details);
        cfg->total_entries++;
    }
    else
    {
        /* Async mode: add to buffer for later processing */
        if (ips_log_buffer_add_entry (buffer, &entry) < 0)
        {
            cfg->dropped_entries++;
        }
        else
        {
            cfg->total_entries++;
        }
    }
}

/**
 * @brief Log system message asynchronously
 */
void
ips_log_system_async (ips_log_level_t level, const char *format, ...)
{
    ips_logging_config_t *cfg = &ips_logging_config;
    ips_log_entry_t entry;
    ips_log_buffer_t *buffer;
    va_list args;
    u32 thread_index = vlib_get_thread_index ();

    if (PREDICT_FALSE (thread_index >= cfg->num_threads))
        return;

    buffer = &cfg->per_thread_buffers[thread_index];

    /* Prepare log entry */
    clib_memset (&entry, 0, sizeof (entry));
    entry.type = IPS_LOG_ENTRY_SYSTEM;
    entry.level = level;

    /* Format message */
    va_start (args, format);
    vsnprintf (entry.data.system_msg, IPS_LOG_MAX_MSG_SIZE, format, args);
    va_end (args);

    /* In sync mode, write immediately and don't buffer */
    if (PREDICT_FALSE (cfg->sync_mode))
    {
        ips_log_write_system_msg (entry.data.system_msg, level, vlib_time_now (vlib_get_main ()));
        cfg->total_entries++;
    }
    else
    {
        /* Async mode: add to buffer for later processing */
        ips_log_buffer_add_entry (buffer, &entry);
    }
}

/**
 * @brief Flush single log buffer (called from fast path when needed)
 */
void
ips_log_flush_single_buffer (ips_log_buffer_t *buffer)
{
    ips_log_entry_t entry;

    if (PREDICT_FALSE (!buffer))
        return;

    /* Process all entries in this buffer */
    while (ips_log_buffer_get_entry (buffer, &entry) == 0)
    {
        switch (entry.type)
        {
        case IPS_LOG_ENTRY_RULE_MATCH:
            ips_log_write_rule_match (&entry.data.rule_match);
            break;

        case IPS_LOG_ENTRY_TCP_DETAILS:
            ips_log_write_tcp_details (&entry.data.tcp_details);
            break;

        case IPS_LOG_ENTRY_SYSTEM:
            ips_log_write_system_msg (entry.data.system_msg, entry.level,
                                    vlib_time_now (vlib_get_main ()));
            break;
        }
    }
}

/**
 * @brief Background flush of all log buffers
 */
void
ips_log_flush_buffers (void)
{
    ips_logging_config_t *cfg = &ips_logging_config;
    ips_log_entry_t entry;
    u32 i;

    for (i = 0; i < cfg->num_threads; i++)
    {
        ips_log_buffer_t *buffer = &cfg->per_thread_buffers[i];

        /* Process all entries in this thread's buffer */
        while (ips_log_buffer_get_entry (buffer, &entry) == 0)
        {
            switch (entry.type)
            {
            case IPS_LOG_ENTRY_RULE_MATCH:
                ips_log_write_rule_match (&entry.data.rule_match);
                if (entry.level >= IPS_LOG_LEVEL_WARNING)
                    cfg->alert_entries++;
                break;

            case IPS_LOG_ENTRY_TCP_DETAILS:
                ips_log_write_tcp_details (&entry.data.tcp_details);
                break;

            case IPS_LOG_ENTRY_SYSTEM:
                ips_log_write_system_msg (entry.data.system_msg, entry.level,
                                        vlib_time_now (vlib_get_main ()));
                break;
            }
        }
    }

    cfg->flush_count++;
    cfg->last_flush_time = vlib_time_now (vlib_get_main ());
}

/**
 * @brief Write rule match entry to file
 */
void
ips_log_write_rule_match (ips_log_rule_match_entry_t *entry)
{
    ips_logging_config_t *cfg = &ips_logging_config;
    FILE *target_fp;
    const char *timestamp_str;

    clib_spinlock_lock (&cfg->file_lock);

    /* Select target file */
    target_fp = cfg->alert_fp;  /* All rule matches go to alert log */

    if (target_fp)
    {
        timestamp_str = ips_log_get_timestamp_string (entry->timestamp);

        fprintf (target_fp,
                "%s [%s] [SID:%u] %s [Classification: %s] [Priority: %u] %s %s [Length: %u bytes]\n",
                timestamp_str, entry->action, entry->sid, entry->msg,
                entry->classification, entry->priority, entry->protocol,
                entry->flow_info, entry->packet_len);

        fflush (target_fp);
    }

    clib_spinlock_unlock (&cfg->file_lock);
}

/**
 * @brief Write TCP details entry to file
 */
void
ips_log_write_tcp_details (ips_log_tcp_details_entry_t *entry)
{
    ips_logging_config_t *cfg = &ips_logging_config;
    FILE *target_fp;

    clib_spinlock_lock (&cfg->file_lock);

    target_fp = cfg->alert_fp;  /* TCP details accompany alerts */

    if (target_fp)
    {
        fprintf (target_fp, "    TCP Flags: %s Seq:%u Ack:%u Win:%u\n",
                entry->tcp_flags, entry->seq, entry->ack, entry->win);
        fflush (target_fp);
    }

    clib_spinlock_unlock (&cfg->file_lock);
}

/**
 * @brief Write system message to file
 */
void
ips_log_write_system_msg (const char *msg, ips_log_level_t level, f64 timestamp)
{
    ips_logging_config_t *cfg = &ips_logging_config;
    FILE *target_fp;
    const char *timestamp_str;
    const char *level_str;

    clib_spinlock_lock (&cfg->file_lock);

    /* Select target file based on level */
    if (level >= IPS_LOG_LEVEL_WARNING)
        target_fp = cfg->alert_fp;
    else if (level == IPS_LOG_LEVEL_DEBUG)
        target_fp = cfg->debug_fp;
    else
        target_fp = cfg->general_fp;

    if (target_fp)
    {
        timestamp_str = ips_log_get_timestamp_string (timestamp);
        level_str = ips_log_level_to_string (level);

        fprintf (target_fp, "%s [%s] %s\n", timestamp_str, level_str, msg);
        fflush (target_fp);
    }

    clib_spinlock_unlock (&cfg->file_lock);
}

/* Implementation of utility functions */
int ips_log_create_directory (const char *path) {
    struct stat st = {0};
    if (stat (path, &st) == -1) {
        if (mkdir (path, 0755) == -1 && errno != EEXIST) {
            return -1;
        }
    }
    return 0;
}

int ips_log_file_open (const char *filename, FILE **fp) {
    *fp = fopen (filename, "a");
    if (*fp == NULL) return -1;
    setvbuf (*fp, NULL, _IOLBF, 0);
    return 0;
}

int ips_log_file_close (FILE **fp) {
    if (*fp) { fclose (*fp); *fp = NULL; }
    return 0;
}

const char *ips_log_level_to_string (ips_log_level_t level) {
    switch (level) {
        case IPS_LOG_LEVEL_DEBUG: return "DEBUG";
        case IPS_LOG_LEVEL_INFO: return "INFO";
        case IPS_LOG_LEVEL_NOTICE: return "NOTICE";
        case IPS_LOG_LEVEL_WARNING: return "WARNING";
        case IPS_LOG_LEVEL_ERROR: return "ERROR";
        case IPS_LOG_LEVEL_CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

const char *ips_log_get_timestamp_string (f64 timestamp) {
    time_t sec = (time_t) timestamp;
    u32 usec = (u32) ((timestamp - sec) * 1000000);
    struct tm *tm_info = localtime (&sec);
    snprintf (timestamp_buffer, sizeof (timestamp_buffer),
             "%04d-%02d-%02d %02d:%02d:%02d.%06u",
             tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday,
             tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec, usec);
    return timestamp_buffer;
}

/**
 * @brief Background logging process
 * Periodically flushes log buffers to files
 */
static uword
ips_logging_process (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
    ips_logging_config_t *cfg = &ips_logging_config;
    f64 timeout = IPS_LOG_FLUSH_INTERVAL;

    while (1)
    {
        /* Wait for timeout or wakeup event */
        vlib_process_wait_for_event_or_clock (vm, timeout);

        /* Process any events (currently none) */
        vlib_process_get_events (vm, NULL);

        /* Flush all log buffers */
        ips_log_flush_buffers ();

        /* Update last flush time */
        cfg->last_flush_time = vlib_time_now (vm);
    }

    return 0;
}

/* Register the logging process node */
VLIB_REGISTER_NODE (ips_logging_process_node) = {
    .function = ips_logging_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "ips-logging-process",
    .state = VLIB_NODE_STATE_POLLING,  /* Change to POLLING for auto-start */
};

/**
 * @brief CLI command to manually flush log buffers
 */
static clib_error_t *
ips_log_flush_command (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
    ips_logging_config_t *cfg = &ips_logging_config;

    vlib_cli_output (vm, "Flushing IPS log buffers...");

    /* Manual flush */
    ips_log_flush_buffers ();

    vlib_cli_output (vm, "Flush complete. Statistics:");
    vlib_cli_output (vm, "  Total entries: %llu", cfg->total_entries);
    vlib_cli_output (vm, "  Alert entries: %llu", cfg->alert_entries);
    vlib_cli_output (vm, "  Dropped entries: %llu", cfg->dropped_entries);
    vlib_cli_output (vm, "  Flush count: %llu", cfg->flush_count);

    return 0;
}

VLIB_CLI_COMMAND (ips_log_flush_cmd, static) = {
    .path = "ips log flush",
    .short_help = "Manually flush IPS log buffers",
    .function = ips_log_flush_command,
};

/**
 * @brief CLI command to show IPS logging statistics
 */
static clib_error_t *
ips_log_stats_command (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
    ips_logging_config_t *cfg = &ips_logging_config;
    u32 i;
    u32 total_buffered = 0;

    vlib_cli_output (vm, "IPS Logging Statistics:");
    vlib_cli_output (vm, "  Log directory: %s", cfg->log_dir ? cfg->log_dir : "NULL");
    vlib_cli_output (vm, "  Total entries: %llu", cfg->total_entries);
    vlib_cli_output (vm, "  Alert entries: %llu", cfg->alert_entries);
    vlib_cli_output (vm, "  Dropped entries: %llu", cfg->dropped_entries);
    vlib_cli_output (vm, "  Flush count: %llu", cfg->flush_count);
    vlib_cli_output (vm, "  Number of threads: %u", cfg->num_threads);

    /* Show per-thread buffer status */
    if (cfg->per_thread_buffers)
    {
        vlib_cli_output (vm, "Per-thread buffer status:");
        for (i = 0; i < cfg->num_threads; i++)
        {
            ips_log_buffer_t *buffer = &cfg->per_thread_buffers[i];
            u32 buffered = (buffer->head >= buffer->tail) ?
                           (buffer->head - buffer->tail) :
                           (IPS_LOG_BUFFER_SIZE - buffer->tail + buffer->head);
            total_buffered += buffered;

            vlib_cli_output (vm, "  Thread %u: %u entries buffered, %u dropped",
                           i, buffered, buffer->dropped);
        }
    }

    vlib_cli_output (vm, "  Total buffered entries: %u", total_buffered);

    return 0;
}

VLIB_CLI_COMMAND (ips_log_stats_cmd, static) = {
    .path = "show ips logging",
    .short_help = "show ips logging",
    .function = ips_log_stats_command,
};

/**
 * @brief CLI command to control sync mode
 */
static clib_error_t *
ips_log_sync_command (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
    ips_logging_config_t *cfg = &ips_logging_config;
    unformat_input_t _line_input, *line_input = &_line_input;
    u8 enable = 0;
    u8 disable = 0;

    /* Get a line of input */
    if (!unformat_user (input, unformat_line_input, line_input))
    {
        vlib_cli_output (vm, "Sync mode: %s", cfg->sync_mode ? "enabled" : "disabled");
        return 0;
    }

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "enable"))
            enable = 1;
        else if (unformat (line_input, "disable"))
            disable = 1;
        else
        {
            unformat_free (line_input);
            return clib_error_return (0, "unknown input '%U'", format_unformat_error, line_input);
        }
    }

    unformat_free (line_input);

    if (enable && disable)
        return clib_error_return (0, "cannot enable and disable at the same time");

    if (enable)
    {
        cfg->sync_mode = 1;
        vlib_cli_output (vm, "IPS logging sync mode enabled");
    }
    else if (disable)
    {
        cfg->sync_mode = 0;
        vlib_cli_output (vm, "IPS logging sync mode disabled");
    }
    else
    {
        vlib_cli_output (vm, "Sync mode: %s", cfg->sync_mode ? "enabled" : "disabled");
    }

    return 0;
}

VLIB_CLI_COMMAND (ips_log_sync_cmd, static) = {
    .path = "ips logging sync",
    .short_help = "ips logging sync [enable|disable]",
    .function = ips_log_sync_command,
};
