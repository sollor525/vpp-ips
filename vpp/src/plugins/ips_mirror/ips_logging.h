/*
 * ips_logging.h - VPP IPS Plugin Async Logging System
 *
 * Copyright (c) 2024 VPP IPS Project
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#ifndef __included_ips_logging_h__
#define __included_ips_logging_h__

#include <vlib/vlib.h>
#include <stdio.h>
#include <time.h>
#include <sys/stat.h>

/* Log levels */
typedef enum
{
    IPS_LOG_LEVEL_DEBUG = 0,
    IPS_LOG_LEVEL_INFO,
    IPS_LOG_LEVEL_NOTICE,
    IPS_LOG_LEVEL_WARNING,
    IPS_LOG_LEVEL_ERROR,
    IPS_LOG_LEVEL_CRITICAL,
} ips_log_level_t;

/* Log output targets */
typedef enum
{
    IPS_LOG_TARGET_FILE = (1 << 0),
    IPS_LOG_TARGET_SYSLOG = (1 << 1),
    IPS_LOG_TARGET_CONSOLE = (1 << 2),
} ips_log_target_t;

/* Log entry types */
typedef enum
{
    IPS_LOG_ENTRY_RULE_MATCH = 0,
    IPS_LOG_ENTRY_TCP_DETAILS,
    IPS_LOG_ENTRY_SYSTEM,
} ips_log_entry_type_t;

/* Maximum sizes for log entry fields */
#define IPS_LOG_MAX_MSG_SIZE 256
#define IPS_LOG_MAX_CLASSIFICATION_SIZE 64
#define IPS_LOG_MAX_FLOW_INFO_SIZE 128
#define IPS_LOG_MAX_TCP_FLAGS_SIZE 16
#define IPS_LOG_MAX_ACTION_SIZE 16

/* Log entry for rule match */
typedef struct
{
    f64 timestamp;
    u32 sid;
    u32 priority;
    u32 packet_len;
    char action[IPS_LOG_MAX_ACTION_SIZE];
    char msg[IPS_LOG_MAX_MSG_SIZE];
    char classification[IPS_LOG_MAX_CLASSIFICATION_SIZE];
    char protocol[8];  /* TCP/UDP/ICMP etc */
    char flow_info[IPS_LOG_MAX_FLOW_INFO_SIZE];
} ips_log_rule_match_entry_t;

/* Log entry for TCP details */
typedef struct
{
    f64 timestamp;
    u32 seq;
    u32 ack;
    u16 win;
    char tcp_flags[IPS_LOG_MAX_TCP_FLAGS_SIZE];
} ips_log_tcp_details_entry_t;

/* Generic log entry */
typedef struct
{
    ips_log_entry_type_t type;
    ips_log_level_t level;
    union {
        ips_log_rule_match_entry_t rule_match;
        ips_log_tcp_details_entry_t tcp_details;
        char system_msg[IPS_LOG_MAX_MSG_SIZE];
    } data;
} ips_log_entry_t;

/* Log buffer configuration */
#define IPS_LOG_BUFFER_SIZE 1024  /* Number of log entries in buffer */
#define IPS_LOG_FLUSH_INTERVAL 1.0  /* Flush interval in seconds */

/* Per-thread log buffer */
typedef struct
{
    ips_log_entry_t *entries;
    u32 head;
    u32 tail;
    u32 count;
    u32 dropped;  /* Counter for dropped entries when buffer full */
    clib_spinlock_t lock;
} ips_log_buffer_t;

/* Log file configuration */
typedef struct
{
    /* File settings */
    char *log_dir;                    /* Log directory path */
    char *alert_file;                 /* Alert log file name */
    char *general_file;               /* General log file name */
    char *debug_file;                 /* Debug log file name */

    /* File handles */
    FILE *alert_fp;                   /* Alert file pointer */
    FILE *general_fp;                 /* General file pointer */
    FILE *debug_fp;                   /* Debug file pointer */

    /* Rotation settings */
    u64 max_file_size;                /* Maximum file size before rotation */
    u32 max_files;                    /* Maximum number of rotated files */
    u32 rotation_interval;            /* Rotation interval in seconds */
    f64 last_rotation_time;           /* Last rotation timestamp */

    /* Output control */
    u32 log_targets;                  /* Bitmask of output targets */
    ips_log_level_t min_level;        /* Minimum log level */

    /* Async processing */
    ips_log_buffer_t *per_thread_buffers;  /* Per-thread log buffers */
    u32 num_threads;                  /* Number of worker threads */
    f64 last_flush_time;              /* Last flush timestamp */

    /* Statistics */
    u64 total_entries;                /* Total log entries processed */
    u64 alert_entries;                /* Alert entries written */
    u64 dropped_entries;              /* Dropped entries (buffer full) */
    u64 flush_count;                  /* Number of flush operations */

        /* Global lock for file operations */
    clib_spinlock_t file_lock;

    /* Development/debug options */
    u8 sync_mode;                     /* Force synchronous logging for debug */

} ips_logging_config_t;

/* Global logging configuration */
extern ips_logging_config_t ips_logging_config;

/* Function prototypes */
clib_error_t *ips_logging_init (vlib_main_t *vm);
void ips_logging_cleanup (void);

/* Log file management */
int ips_log_file_open (const char *filename, FILE **fp);
int ips_log_file_close (FILE **fp);
int ips_log_file_rotate (const char *base_filename, FILE **fp);
int ips_log_create_directory (const char *path);

/* Async logging functions - FAST PATH SAFE */
void ips_log_rule_match_async (const char *action, u32 sid, const char *msg,
                              const char *classification, u32 priority,
                              const char *protocol, const char *flow_info,
                              u32 packet_len, f64 timestamp, u32 thread_index);

void ips_log_tcp_details_async (const char *tcp_flags, u32 seq, u32 ack, u16 win,
                               f64 timestamp, u32 thread_index);

void ips_log_system_async (ips_log_level_t level, const char *format, ...);

/* Background processing functions */
void ips_log_flush_buffers (void);
void ips_log_flush_single_buffer (ips_log_buffer_t *buffer);

/* Buffer management */
int ips_log_buffer_add_entry (ips_log_buffer_t *buffer, ips_log_entry_t *entry);
int ips_log_buffer_get_entry (ips_log_buffer_t *buffer, ips_log_entry_t *entry);
void ips_log_buffer_init (ips_log_buffer_t *buffer);
void ips_log_buffer_cleanup (ips_log_buffer_t *buffer);

/* File writing functions (called from background thread) */
void ips_log_write_rule_match (ips_log_rule_match_entry_t *entry);
void ips_log_write_tcp_details (ips_log_tcp_details_entry_t *entry);
void ips_log_write_system_msg (const char *msg, ips_log_level_t level, f64 timestamp);

/* Configuration functions */
int ips_logging_set_directory (const char *dir);
int ips_logging_set_level (ips_log_level_t level);
int ips_logging_set_targets (u32 targets);
int ips_logging_set_rotation (u64 max_size, u32 max_files);
int ips_logging_set_flush_interval (f64 interval);

/* Utility functions */
const char *ips_log_level_to_string (ips_log_level_t level);
const char *ips_log_get_timestamp_string (f64 timestamp);
u64 ips_log_get_file_size (FILE *fp);

/* Statistics */
typedef struct
{
    u64 total_entries;
    u64 alert_entries;
    u64 dropped_entries;
    u64 flush_count;
    u64 buffer_overruns;
    f64 avg_flush_time;
} ips_log_stats_t;

void ips_log_get_stats (ips_log_stats_t *stats);
void ips_log_clear_stats (void);

#endif /* __included_ips_logging_h__ */
