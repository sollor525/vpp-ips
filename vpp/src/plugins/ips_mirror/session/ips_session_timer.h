/*
 * ips_session_timer.h - VPP IPS Plugin Timer Wheel-based Session Aging
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

#ifndef __IPS_SESSION_TIMER_H__
#define __IPS_SESSION_TIMER_H__

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/pool.h>
#include <vppinfra/vec.h>
#include <vppinfra/clib.h>
#include <vppinfra/tw_timer_2t_1w_2048sl.h>

#include "ips_session.h"

/* Timer wheel configuration */
#define IPS_TIMER_WHEEL_TICKS_PER_SECOND 100    /* 10ms granularity */
#define IPS_TIMER_WHEEL_MAX_INTERVAL (3600 * IPS_TIMER_WHEEL_TICKS_PER_SECOND) /* 1 hour max */

/* Timer IDs - we use bit 30 for timer ID encoding to avoid sign bit issues */
#define IPS_SESSION_EXPIRE_TIMER_ID 0
#define IPS_SESSION_TIMER_ID_MASK   0x40000000

/* Timer handle encoding: [30:timer_id][29:0:session_index] */
#define IPS_TIMER_HANDLE_MAKE(session_index, timer_id) \
    (((session_index) & 0x3FFFFFFF) | ((timer_id) << 30))

#define IPS_TIMER_HANDLE_SESSION_INDEX(handle)  ((handle) & 0x3FFFFFFF)
#define IPS_TIMER_HANDLE_TIMER_ID(handle)       (((handle) >> 30) & 0x3)

/* Timer handle invalid value - following TCP pattern */
#define IPS_TIMER_HANDLE_INVALID              ((u32) ~0)

/* Hybrid aging configuration */
typedef struct ips_session_timer_config_
{
    u32 timer_wheel_ticks_per_second;      /* Timer wheel granularity */
    u32 max_timer_interval;                /* Maximum timer interval */
    u32 backup_scan_interval;              /* Backup scan interval (seconds) */
    u32 emergency_scan_threshold;          /* Emergency scan threshold */
    u32 force_cleanup_target;              /* Target for force cleanup */
    f64 max_timer_wheel_check_interval;    /* Max time without timer wheel check */
} ips_session_timer_config_t;

/* Per-thread timer data */
typedef struct ips_session_timer_per_thread_
{
    /* Timer wheel instance */
    tw_timer_wheel_2t_1w_2048sl_t timer_wheel;

    /* Timer statistics */
    struct {
        u32 timers_started;                 /* Total timers started */
        u32 timers_expired;                 /* Total timers expired */
        u32 timers_stopped;                 /* Total timers stopped */
        u32 timers_updated;                 /* Total timers updated */
        u32 backup_scans;                   /* Backup scans performed */
        u32 timer_wheel_checks;             /* Timer wheel expiration checks */
    } stats;

    /* Backup scan state */
    struct {
        f64 last_scan_time;                 /* Last backup scan time */
        f64 last_timer_wheel_check;         /* Last timer wheel check time */
        u32 scan_cursor;                    /* Scan cursor for backup scans */
        u32 emergency_scan_count;           /* Emergency scan counter */
    } backup_state;

    /* Configuration */
    ips_session_timer_config_t config;

    /* Expired session buffer for batch processing */
    u32 *expired_sessions;
} ips_session_timer_per_thread_t;

/* Global timer manager */
typedef struct ips_session_timer_manager_
{
    /* Per-thread timer data */
    ips_session_timer_per_thread_t *per_thread_data;
    u32 num_threads;

    /* Global configuration */
    ips_session_timer_config_t global_config;

    /* Global statistics */
    struct {
        u64 total_sessions_timed_out;
        u64 total_backup_scans;
        u64 total_timer_wheel_checks;
        f64 total_processing_time;
    } global_stats;

    /* Timer process node handle */
    u32 timer_process_node_index;

    /* Lock for cross-thread operations */
    clib_spinlock_t global_lock;
} ips_session_timer_manager_t;

/* Global instance */
extern ips_session_timer_manager_t ips_session_timer_manager;

/* Function declarations */

/*
 * Strongly-typed arguments for starting a session timer to avoid parameter swaps.
 */
typedef struct ips_session_timer_start_args_
{
    u32 thread_index;      /* Thread index owning the session */
    u32 session_index;     /* Session pool index */
    u32 timeout_seconds;   /* Expiration timeout in seconds */
} ips_session_timer_start_args_t;

typedef struct ips_session_timer_stop_args_
{
    u32 thread_index;    /* Thread index */
    u32 timer_handle;    /* Timer handle */
} ips_session_timer_stop_args_t;

typedef struct ips_session_timer_update_args_
{
    u32 thread_index;      /* Thread index */
    u32 timer_handle;      /* Timer handle */
    u32 timeout_seconds;   /* New timeout */
} ips_session_timer_update_args_t;

/**
 * @brief Initialize session timer manager
 */
clib_error_t *ips_session_timer_manager_init(vlib_main_t *vm);

/**
 * @brief Cleanup session timer manager
 */
void ips_session_timer_manager_cleanup(void);

/**
 * @brief Initialize per-thread timer data
 */
clib_error_t *ips_session_timer_per_thread_init(u32 thread_index);

/**
 * @brief Cleanup per-thread timer data
 */
void ips_session_timer_per_thread_cleanup(u32 thread_index);

/**
 * @brief Start session expiration timer
 * @param args Pointer to start arguments
 * @return Timer handle or ~0 if failed
 */
u32 ips_session_timer_start(const ips_session_timer_start_args_t *args);

/**
 * @brief Stop session timer
 * @param thread_index Thread index
 * @param timer_handle Timer handle
 */
void ips_session_timer_stop(const ips_session_timer_stop_args_t *args);

/**
 * @brief Update session timer
 * @param thread_index Thread index
 * @param timer_handle Timer handle
 * @param timeout_seconds New timeout in seconds
 */
void ips_session_timer_update(const ips_session_timer_update_args_t *args);

/**
 * @brief Perform backup scan for expired sessions
 * @param thread_index Thread index
 * @return Number of sessions cleaned up
 */
u32 ips_session_timer_backup_scan(u32 thread_index);

/**
 * @brief Check if emergency scan is needed
 * @param thread_index Thread index
 * @return 1 if emergency scan needed, 0 otherwise
 */
int ips_session_timer_needs_emergency_scan(u32 thread_index);

/**
 * @brief Expire timers for the current thread
 *
 * Called from packet processing nodes to check for and process expired timers.
 * Thread-safe because each thread only processes its own timer wheel.
 *
 * @param thread_index Thread index (must match current thread)
 */
void ips_session_timer_expire_timers(u32 thread_index);

/**
 * @brief Get timer statistics
 */
void ips_session_timer_get_stats(u32 thread_index, ips_session_timer_stats_t *stats);

/**
 * @brief Set timer configuration
 */
void ips_session_timer_set_config(const ips_session_timer_config_t *config);

/**
 * @brief Timer process node function (deprecated - use per-thread expiration)
 *
 * This process node is kept for compatibility but no longer processes timers.
 * Timer expiration now happens in each worker thread during packet processing.
 */
uword ips_session_timer_process(vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f);

/**
 * @brief Timer process node declaration
 */
extern vlib_node_registration_t ips_session_timer_process_node;

/**
 * @brief Check timer wheel health
 */
int ips_session_timer_check_health(u32 thread_index);

/**
 * @brief Reset timer statistics
 */
void ips_session_timer_reset_stats(u32 thread_index);

#endif /* __IPS_SESSION_TIMER_H__ */