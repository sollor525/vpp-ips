/*
 * ips_timer_api.c - VPP IPS Plugin Timer Management API
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

#include "ips.h"
#include "session/ips_session_timer.h"

/* Timer management API definitions */

/**
 * @brief Set timer configuration API
 */
static void
vl_api_ips_timer_set_config_t_handler (vl_api_ips_timer_set_config_t * mp)
{
    vl_api_ips_timer_set_config_reply_t *rmp;
    ips_main_t *im = &ips_main;
    u32 context = ntohl (mp->context);

    ips_session_timer_config_t config = {
        .timer_wheel_ticks_per_second = ntohl (mp->timer_wheel_ticks_per_second),
        .max_timer_interval = ntohl (mp->max_timer_interval),
        .backup_scan_interval = ntohl (mp->backup_scan_interval),
        .emergency_scan_threshold = ntohl (mp->emergency_scan_threshold),
        .force_cleanup_target = ntohl (mp->force_cleanup_target),
        .max_timer_wheel_check_interval = clib_net_to_host_f64 (mp->max_timer_wheel_check_interval)
    };

    /* Apply configuration */
    ips_session_timer_set_config (&config);

    /* Send reply */
    REPLY_MACRO (VL_API_IPS_TIMER_SET_CONFIG_REPLY);
}

/**
 * @brief Get timer statistics API
 */
static void
vl_api_ips_timer_get_stats_t_handler (vl_api_ips_timer_get_stats_t * mp)
{
    vl_api_ips_timer_get_stats_reply_t *rmp;
    ips_main_t *im = &ips_main;
    u32 context = ntohl (mp->context);
    u32 thread_index = ntohl (mp->thread_index);

    ips_session_timer_stats_t stats;
    ips_session_timer_get_stats (thread_index, &stats);

    /* Send reply with statistics */
    rmp = vl_msg_api_alloc (sizeof (*rmp));
    rmp->_vl_msg_id = ntohs (VL_API_IPS_TIMER_GET_STATS_REPLY);
    rmp->context = context;
    rmp->timers_started = htonl (stats.timers_started);
    rmp->timers_expired = htonl (stats.timers_expired);
    rmp->timers_stopped = htonl (stats.timers_stopped);
    rmp->timers_updated = htonl (stats.timers_updated);
    rmp->backup_scans = htonl (stats.backup_scans);
    rmp->emergency_scans = htonl (stats.emergency_scans);
    rmp->timer_wheel_checks = htonl (stats.timer_wheel_checks);

    vl_api_send_msg (im->vl_api_rx, (u8 *) rmp);
}

/**
 * @brief Reset timer statistics API
 */
static void
vl_api_ips_timer_reset_stats_t_handler (vl_api_ips_timer_reset_stats_t * mp)
{
    vl_api_ips_timer_reset_stats_reply_t *rmp;
    ips_main_t *im = &ips_main;
    u32 context = ntohl (mp->context);
    u32 thread_index = ntohl (mp->thread_index);

    ips_session_timer_reset_stats (thread_index);

    /* Send reply */
    REPLY_MACRO (VL_API_IPS_TIMER_RESET_STATS_REPLY);
}

/**
 * @brief Manual session cleanup API
 */
static void
vl_api_ips_session_cleanup_t_handler (vl_api_ips_session_cleanup_t * mp)
{
    vl_api_ips_session_cleanup_reply_t *rmp;
    ips_main_t *im = &ips_main;
    u32 context = ntohl (mp->context);
    u32 thread_index = ntohl (mp->thread_index);
    u32 target_count = ntohl (mp->target_count);

    u32 cleaned = ips_session_timer_backup_scan (thread_index);

    /* Send reply with cleanup results */
    rmp = vl_msg_api_alloc (sizeof (*rmp));
    rmp->_vl_msg_id = ntohs (VL_API_IPS_SESSION_CLEANUP_REPLY);
    rmp->context = context;
    rmp->cleaned_sessions = htonl (cleaned);

    vl_api_send_msg (im->vl_api_rx, (u8 *) rmp);
}

/**
 * @brief Check timer health API
 */
static void
vl_api_ips_timer_health_check_t_handler (vl_api_ips_timer_health_check_t * mp)
{
    vl_api_ips_timer_health_check_reply_t *rmp;
    ips_main_t *im = &ips_main;
    u32 context = ntohl (mp->context);
    u32 thread_index = ntohl (mp->thread_index);

    int healthy = ips_session_timer_check_health (thread_index);

    /* Send reply with health status */
    rmp = vl_msg_api_alloc (sizeof (*rmp));
    rmp->_vl_msg_id = ntohs (VL_API_IPS_TIMER_HEALTH_CHECK_REPLY);
    rmp->context = context;
    rmp->is_healthy = healthy ? 1 : 0;

    vl_api_send_msg (im->vl_api_rx, (u8 *) rmp);
}

/**
 * @brief Enable/disable timer process API
 */
static void
vl_api_ips_timer_process_enable_disable_t_handler (vl_api_ips_timer_process_enable_disable_t * mp)
{
    vl_api_ips_timer_process_enable_disable_reply_t *rmp;
    ips_main_t *im = &ips_main;
    u32 context = ntohl (mp->context);
    u8 enable_disable = mp->enable_disable;

    vlib_main_t *vm = vlib_get_main ();
    vlib_node_t *n = vlib_get_node_by_name (vm, (u8 *) "ips-session-timer-process");

    if (n)
    {
        if (enable_disable)
        {
            vlib_start_process (vm, n->index);
        }
        else
        {
            vlib_stop_process (vm, n->index);
        }
    }

    /* Send reply */
    REPLY_MACRO (VL_API_IPS_TIMER_PROCESS_ENABLE_DISABLE_REPLY);
}

#include <ips/ips.api_enum.h>
#include <ips/ips.api_types.h>

/* API message handlers */
#define vl_msg_name(addr_list, addr) addr,
static u8 *ips_timer_msg_names[] = {
    foreach_ips_timer_api_msg
};
#undef vl_msg_name

/* API message structure size table */
static u32 ips_timer_msg_sizes[] = {
    foreach_ips_timer_api_msg_size
};

/* API message CRC table */
static u32 ips_timer_msg_crcs[VL_API_IPS_TIMER_MSG_ID_MAX] = {
    foreach_ips_timer_api_msg_crc
};

/* Setup API */
clib_error_t *
ips_timer_api_init (vlib_main_t * vm)
{
    /* Register API messages */
#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                    \
                           vl_api_##n##_t_endian,              \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 0);
    foreach_ips_timer_api_msg;
#undef _

    /* Set up message names and sizes */
    vl_msg_api_set_msg_name_table (ips_timer_msg_names,
                                   IPS_TIMER_MSG_ID_MAX);
    vl_msg_api_set_msg_size_table (ips_timer_msg_sizes,
                                   IPS_TIMER_MSG_ID_MAX);

    return 0;
}

VLIB_API_INIT_FUNCTION (ips_timer_api_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */