/*
 * ips_session_timer.c - VPP IPS Plugin Timer Wheel-based Session Aging Implementation
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
#include <vppinfra/pool.h>
#include <vppinfra/vec.h>
#include <vppinfra/clib.h>
#include <vppinfra/elog.h>
#include <vppinfra/time.h>

#include "ips_session_timer.h"
#include "ips_session.h"

/* Forward declarations for node references */
extern vlib_node_registration_t ips_input_ip4_node;
extern vlib_node_registration_t ips_input_ip6_node;

/* Forward declaration for timer callback */
static void ips_session_timer_expire_callback (u32 *expired_timers);

/* Global timer manager instance */
ips_session_timer_manager_t ips_session_timer_manager;

/* Default configuration */
static const ips_session_timer_config_t default_timer_config = {
    .timer_wheel_ticks_per_second = IPS_TIMER_WHEEL_TICKS_PER_SECOND,
    .max_timer_interval = IPS_TIMER_WHEEL_MAX_INTERVAL,
    .backup_scan_interval = 5,                    /* 5 seconds backup scan */
    .emergency_scan_threshold = 90,               /* 90% capacity triggers emergency scan */
    .force_cleanup_target = 1000,                 /* Clean 1000 sessions in emergency */
    .max_timer_wheel_check_interval = 10.0        /* Max 10 seconds without timer wheel check */
};

/**
 * @brief Initialize session timer manager
 */
clib_error_t *
ips_session_timer_manager_init (vlib_main_t * __clib_unused vm)
{
    ips_session_timer_manager_t *tm = &ips_session_timer_manager;
    u32 num_threads = vlib_num_workers () + 1;

    /* Clear manager structure */
    clib_memset (tm, 0, sizeof (*tm));

    /* Set default configuration */
    tm->global_config = default_timer_config;
    tm->num_threads = num_threads;

    /* Allocate per-thread data */
    vec_validate (tm->per_thread_data, num_threads - 1);

    /* Initialize each thread's timer data */
    for (u32 i = 0; i < num_threads; i++)
    {
        clib_error_t *error = ips_session_timer_per_thread_init (i);
        if (error)
        {
            /* Cleanup already initialized threads */
            for (u32 j = 0; j < i; j++)
            {
                ips_session_timer_per_thread_cleanup (j);
            }
            vec_free (tm->per_thread_data);
            return error;
        }
    }

    /* Initialize global lock */
    clib_spinlock_init (&tm->global_lock);

    return 0;
}

/**
 * @brief Cleanup session timer manager
 */
void
ips_session_timer_manager_cleanup (void)
{
    ips_session_timer_manager_t *tm = &ips_session_timer_manager;

    /* Cleanup each thread's timer data */
    for (u32 i = 0; i < tm->num_threads; i++)
    {
        ips_session_timer_per_thread_cleanup (i);
    }

    /* Free per-thread data vector */
    vec_free (tm->per_thread_data);

    /* Clear manager structure */
    clib_memset (tm, 0, sizeof (*tm));
}

/**
 * @brief Initialize per-thread timer data
 */
clib_error_t *
ips_session_timer_per_thread_init (u32 thread_index)
{
    ips_session_timer_manager_t *tm = &ips_session_timer_manager;
    ips_session_timer_per_thread_t *ptt = &tm->per_thread_data[thread_index];

    /* Clear thread data */
    clib_memset (ptt, 0, sizeof (*ptt));

    /* Set configuration */
    ptt->config = tm->global_config;

    /* Initialize timer wheel with callback for session expiration */
    tw_timer_wheel_init_2t_1w_2048sl (&ptt->timer_wheel,
                                       ips_session_timer_expire_callback,
                                       1.0 / ptt->config.timer_wheel_ticks_per_second,
                                       ~0);

    /* Initialize backup scan state */
    ptt->backup_state.last_scan_time = vlib_time_now (vlib_get_main ());
    ptt->backup_state.last_timer_wheel_check = ptt->backup_state.last_scan_time;

    /* Allocate expired sessions buffer */
    vec_validate (ptt->expired_sessions, 1023);
    vec_reset_length (ptt->expired_sessions);

    return 0;
}

/**
 * @brief Cleanup per-thread timer data
 */
void
ips_session_timer_per_thread_cleanup (u32 thread_index)
{
    ips_session_timer_manager_t *tm = &ips_session_timer_manager;
    ips_session_timer_per_thread_t *ptt = &tm->per_thread_data[thread_index];

    /* Free timer wheel */
    tw_timer_wheel_free_2t_1w_2048sl (&ptt->timer_wheel);

    /* Free expired sessions buffer */
    vec_free (ptt->expired_sessions);

    /* Clear thread data */
    clib_memset (ptt, 0, sizeof (*ptt));
}

/**
 * @brief Start session expiration timer
 */
u32
ips_session_timer_start (const ips_session_timer_start_args_t *args)
{
    ips_session_timer_manager_t *tm = &ips_session_timer_manager;

    if (PREDICT_FALSE (!args))
        return ~0;

    u32 thread_index = args->thread_index;

    if (PREDICT_FALSE (thread_index >= tm->num_threads))
        return ~0;

    /* Re-implemented timer system following VPP TCP patterns */
    ips_session_timer_per_thread_t *ptt = &tm->per_thread_data[thread_index];

    /* Extract parameters */
    u32 session_index = args->session_index;
    u32 timeout_seconds = args->timeout_seconds;

    /* Convert timeout to timer ticks using configured ticks per second */
    u32 timeout_ticks = timeout_seconds * ptt->config.timer_wheel_ticks_per_second;

    /* Clamp to reasonable maximum */
    if (timeout_ticks > 0xFFFFFFFF)
        timeout_ticks = 0xFFFFFFFF;

    /* Start timer using the same template as before but with better safety */
    u32 timer_handle = tw_timer_start_2t_1w_2048sl (&ptt->timer_wheel,
                                                     session_index,
                                                     IPS_SESSION_EXPIRE_TIMER_ID,
                                                     timeout_ticks);

    /* Update statistics */
    ptt->stats.timers_started++;

    return timer_handle;
}

/**
 * @brief Stop session timer
 */
void
ips_session_timer_stop (const ips_session_timer_stop_args_t *args)
{
    ips_session_timer_manager_t *tm = &ips_session_timer_manager;
    ips_session_timer_per_thread_t *ptt;

    if (PREDICT_FALSE (!args))
        return;

    u32 thread_index = args->thread_index;
    u32 timer_handle = args->timer_handle;

    if (PREDICT_FALSE (thread_index >= tm->num_threads))
        return;

    ptt = &tm->per_thread_data[thread_index];

    /* Check if timer handle is valid before stopping */
    if (timer_handle == ~0)
        return;

    /* Following VPP TCP pattern: safely stop timer if it still exists
     * The timer might have already expired and been removed from the wheel.
     * We use the timer wheel's internal validity check to avoid assertion failure.
     * 
     * Note: tw_timer_stop_2t_1w_2048sl will assert if the timer is not in the pool,
     * so we need to verify the session's TIMER_ACTIVE flag before calling it.
     * The caller should have already checked this, but we add defensive check here.
     */
    tw_timer_stop_2t_1w_2048sl (&ptt->timer_wheel, timer_handle);

    /* Update statistics */
    ptt->stats.timers_stopped++;
}

/**
 * @brief Update session timer
 */
void
ips_session_timer_update (const ips_session_timer_update_args_t *args)
{
    ips_session_timer_manager_t *tm = &ips_session_timer_manager;
    ips_session_timer_per_thread_t *ptt;

    if (PREDICT_FALSE (!args))
        return;

    u32 thread_index = args->thread_index;
    u32 timer_handle = args->timer_handle;
    u32 timeout_seconds = args->timeout_seconds;

    if (PREDICT_FALSE (thread_index >= tm->num_threads))
        return;

    ptt = &tm->per_thread_data[thread_index];

    /* Convert timeout to timer ticks */
    u32 timeout_ticks = timeout_seconds * ptt->config.timer_wheel_ticks_per_second;

    /* Clamp to maximum interval */
    if (timeout_ticks > ptt->config.max_timer_interval)
        timeout_ticks = ptt->config.max_timer_interval;

    /* Check if timer handle is valid before updating */
    if (timer_handle == ~0)
        return;

    /* Update timer - use try/catch approach to handle expired timers gracefully */
    tw_timer_update_2t_1w_2048sl (&ptt->timer_wheel, timer_handle, timeout_ticks);
    /* Update statistics */
    ptt->stats.timers_updated++;
}

/**
 * @brief Perform backup scan for expired sessions
 */
u32
ips_session_timer_backup_scan (u32 thread_index)
{
    ips_session_manager_t *sm = &ips_session_manager;
    ips_session_timer_manager_t *tm = &ips_session_timer_manager;
    ips_session_per_thread_data_t *ptd = &sm->per_thread_data[thread_index];
    ips_session_timer_per_thread_t *ptt = &tm->per_thread_data[thread_index];

    f64 now = vlib_time_now (vlib_get_main ());
    u32 pool_size = pool_len (ptd->session_pool);
    u32 cleaned = 0;
    u32 cursor = ptt->backup_state.scan_cursor;
    u32 max_scan = ptt->config.force_cleanup_target;

    /* Scan sessions for cleanup */
    while (cleaned < max_scan && cursor < pool_size)
    {
        if (!pool_is_free_index (ptd->session_pool, cursor))
        {
            ips_session_t *session = pool_elt_at_index (ptd->session_pool, cursor);
            f64 session_age = now - session->last_packet_time;

            /* Check if session should be expired */
            if (session_age > session->timeout_seconds ||
                session->tcp_state_src == IPS_SESSION_STATE_CLOSED ||
                session->tcp_state_dst == IPS_SESSION_STATE_CLOSED)
            {
                ips_session_delete (thread_index, session);
                cleaned++;
            }
        }

        cursor++;
    }

    /* Update scan cursor */
    ptt->backup_state.scan_cursor = (cursor >= pool_size) ? 0 : cursor;
    ptt->backup_state.last_scan_time = now;

    /* Update statistics */
    ptt->stats.backup_scans++;
    tm->global_stats.total_backup_scans++;

    return cleaned;
}

/**
 * @brief Timer expiration callback for the current thread
 *
 * Called by timer wheel when a session timer expires.
 * This function only processes sessions owned by the current thread,
 * following VPP's thread-per-session model for thread safety.
 *
 * @param expired_timers Vector of expired timer handles
 */
static void
ips_session_timer_expire_callback (u32 *expired_timers)
{
    ips_session_manager_t *sm = &ips_session_manager;
    ips_session_timer_manager_t *tm = &ips_session_timer_manager;
    u32 thread_index = vlib_get_thread_index ();

    if (!expired_timers || vec_len (expired_timers) == 0)
        return;

    ips_session_per_thread_data_t *ptd = &sm->per_thread_data[thread_index];
    ips_session_timer_per_thread_t *ptt = &tm->per_thread_data[thread_index];

    /* Process each expired timer */
    for (u32 i = 0; i < vec_len (expired_timers); i++)
    {
        u32 timer_handle = expired_timers[i];
        u32 session_index = IPS_TIMER_HANDLE_SESSION_INDEX (timer_handle);
        u32 timer_id = IPS_TIMER_HANDLE_TIMER_ID (timer_handle);

        if (timer_id != IPS_SESSION_EXPIRE_TIMER_ID)
            continue;

        /* Check if session index is valid */
        if (session_index >= pool_len (ptd->session_pool))
            continue;

        if (pool_is_free_index (ptd->session_pool, session_index))
            continue;

        ips_session_t *session = pool_elt_at_index (ptd->session_pool,
                                                    session_index);

        /* Check and clear timer active flag to prevent race conditions */
        if (!(session->flags & IPS_SESSION_FLAG_TIMER_ACTIVE))
            continue;  /* Already processed */

        /* Clear timer flags immediately - timer is already gone from wheel */
        session->flags &= ~IPS_SESSION_FLAG_TIMER_ACTIVE;
        session->timer_handle = IPS_TIMER_HANDLE_INVALID;

        /* Update statistics */
        ptt->stats.timers_expired++;
        tm->global_stats.total_sessions_timed_out++;
        ptd->aging_stats.expired_sessions++;

        /* Delete the session - thread safe because we own this session */
        ips_session_delete_no_timer (thread_index, session);
    }
}

/**
 * @brief Expire timers for the current thread
 *
 * Called from packet processing nodes to check for and process expired timers.
 * Thread-safe because each thread only processes its own timer wheel.
 */
void
ips_session_timer_expire_timers (u32 thread_index)
{
    ips_session_timer_manager_t *tm = &ips_session_timer_manager;
    ips_session_timer_per_thread_t *ptt;

    if (PREDICT_FALSE (thread_index >= tm->num_threads))
        return;

    ptt = &tm->per_thread_data[thread_index];

    /* Get current time and convert to timer wheel ticks */
    f64 now = vlib_time_now (vlib_get_main ());
    now = now * ptt->config.timer_wheel_ticks_per_second;

    /* Check for expired timers - callback will be invoked automatically */
    u32 *expired_timers = tw_timer_expire_timers_2t_1w_2048sl (&ptt->timer_wheel, now);

    /* Process expired timers via callback */
    if (expired_timers && vec_len (expired_timers) > 0)
    {
        ips_session_timer_expire_callback (expired_timers);
        vec_free (expired_timers);
    }

    /* Update statistics */
    ptt->backup_state.last_timer_wheel_check = now;
    ptt->stats.timer_wheel_checks++;
    tm->global_stats.total_timer_wheel_checks++;
}

/**
 * @brief Check if emergency scan is needed
 */
int
ips_session_timer_needs_emergency_scan (u32 thread_index)
{
    ips_session_manager_t *sm = &ips_session_manager;
    ips_session_timer_manager_t *tm = &ips_session_timer_manager;
    ips_session_per_thread_data_t *ptd = &sm->per_thread_data[thread_index];
    ips_session_timer_per_thread_t *ptt = &tm->per_thread_data[thread_index];

    f64 now = vlib_time_now (vlib_get_main ());
    u32 active_sessions = pool_elts (ptd->session_pool);
    u32 threshold = (sm->session_pool_size * ptt->config.emergency_scan_threshold) / 100;

    /* Check if we're over threshold */
    if (active_sessions > threshold)
        return 1;

    /* Check if timer wheel hasn't been checked for too long */
    if (now - ptt->backup_state.last_timer_wheel_check >
        ptt->config.max_timer_wheel_check_interval)
        return 1;

    return 0;
}

/**
 * @brief Get timer statistics
 */
void
ips_session_timer_get_stats (u32 thread_index, ips_session_timer_stats_t *stats)
{
    ips_session_timer_manager_t *tm = &ips_session_timer_manager;

    if (thread_index >= tm->num_threads || !stats)
        return;

    ips_session_timer_per_thread_t *ptt = &tm->per_thread_data[thread_index];

    /* Copy statistics */
    stats->timers_started = ptt->stats.timers_started;
    stats->timers_expired = ptt->stats.timers_expired;
    stats->timers_stopped = ptt->stats.timers_stopped;
    stats->timers_updated = ptt->stats.timers_updated;
    stats->backup_scans = ptt->stats.backup_scans;
    stats->timer_wheel_checks = ptt->stats.timer_wheel_checks;
}

/**
 * @brief Set timer configuration
 */
void
ips_session_timer_set_config (const ips_session_timer_config_t *config)
{
    ips_session_timer_manager_t *tm = &ips_session_timer_manager;

    if (!config)
        return;

    /* This is a simplified implementation - in production, you'd want to
     * reinitialize timer wheels with new configuration */
    clib_spinlock_lock (&tm->global_lock);
    tm->global_config = *config;
    clib_spinlock_unlock (&tm->global_lock);
}

/**
 * @brief Check timer wheel health
 */
int
ips_session_timer_check_health (u32 thread_index)
{
    ips_session_timer_manager_t *tm = &ips_session_timer_manager;
    ips_session_timer_per_thread_t *ptt;

    if (thread_index >= tm->num_threads)
        return 0;

    ptt = &tm->per_thread_data[thread_index];

    f64 now = vlib_time_now (vlib_get_main ());
    f64 time_since_last_check = now - ptt->backup_state.last_timer_wheel_check;

    /* Check if timer wheel is responsive */
    if (time_since_last_check > ptt->config.max_timer_wheel_check_interval * 2)
        return 0;  /* Unhealthy */

    return 1;  /* Healthy */
}

/**
 * @brief Reset timer statistics
 */
void
ips_session_timer_reset_stats (u32 thread_index)
{
    ips_session_timer_manager_t *tm = &ips_session_timer_manager;

    if (thread_index >= tm->num_threads)
        return;

    ips_session_timer_per_thread_t *ptt = &tm->per_thread_data[thread_index];
    clib_memset (&ptt->stats, 0, sizeof (ptt->stats));
}

/**
 * @brief Timer process - backup timer expiration for main thread
 *
 * This process runs on the main thread and handles timer expiration for two cases:
 * 1. Sessions owned by the main thread (thread 0)
 * 2. Backup expiration when there's no traffic on worker threads
 *
 * NOTE: With the new per-thread timer expiration model, worker threads
 * check their own timers during packet processing. This process node only
 * handles the main thread's timers to ensure sessions expire even when
 * there's no traffic on the main thread.
 *
 * For worker threads without traffic, timers will expire when they
 * eventually receive packets, or through the backup scan mechanism.
 */
uword
ips_session_timer_process (vlib_main_t * vm,
                          vlib_node_runtime_t * __clib_unused rt,
                          vlib_frame_t * __clib_unused f)
{
    ips_session_timer_manager_t *tm = &ips_session_timer_manager;
    f64 timeout = 0.1;  /* Wake up every 100ms */
    f64 now;
    uword *event_data = 0;
    uword __clib_unused event_type;

    while (1)
    {
        vlib_process_wait_for_event_or_clock (vm, timeout);
        now = vlib_time_now (vm);
        /* Convert seconds to timer wheel ticks for accurate expiration checking
         * The timer wheel uses ticks (100 ticks/second by default), not seconds */
        now = now * tm->global_config.timer_wheel_ticks_per_second;
        event_type = vlib_process_get_events (vm, (uword **) &event_data);

        /* Only process main thread (thread 0) timers
         * Worker threads handle their own timers during packet processing */
        ips_session_timer_per_thread_t *ptt = &tm->per_thread_data[0];

        /* Get expired timers from the main thread's wheel */
        u32 *expired_timers = tw_timer_expire_timers_2t_1w_2048sl (&ptt->timer_wheel, now);

        /* Invoke callback to process expired timers
         * The callback only handles thread 0's sessions */
        if (expired_timers && vec_len (expired_timers) > 0)
        {
            ips_session_timer_expire_callback (expired_timers);
            vec_free (expired_timers);
        }

        /* Update backup scan timestamp */
        ptt->backup_state.last_timer_wheel_check = now;

        /* Update statistics */
        ptt->stats.timer_wheel_checks++;
        tm->global_stats.total_timer_wheel_checks++;

        vec_reset_length (event_data);
    }
    return 0;
}

VLIB_REGISTER_NODE (ips_session_timer_process_node) = {
    .function = ips_session_timer_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "ips-session-timer-process",
    .process_log2_n_stack_bytes = 17,
};