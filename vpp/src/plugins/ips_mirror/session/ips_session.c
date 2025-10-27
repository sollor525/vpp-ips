/*
 * ips_session.c - VPP IPS Plugin TCP Session Management Implementation
 *
 * Copyright (c) 2024 VPP IPS Project
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/tcp/tcp_packet.h>
#include <vppinfra/pool.h>
#include <vppinfra/bihash_16_8.h>
#include <vppinfra/bihash_48_8.h>

#include "ips_session.h"
#include "ips_session_timer.h"
#include "../acl/ips_acl.h"


/* 全局会话管理器实例 */
ips_session_manager_t ips_session_manager;


/* Forward declarations for ACL functions */
static int ips_session_check_acl(u32 thread_index, ips_session_t *session,
                                ip4_header_t *ip4, ip6_header_t *ip6,
                                tcp_header_t *tcp);

/* 默认配置参数 */
#define IPS_SESSION_DEFAULT_POOL_SIZE           (1024 * 1024)
#define IPS_SESSION_DEFAULT_IPV4_HASH_BUCKETS   (64 * 1024)
#define IPS_SESSION_DEFAULT_IPV6_HASH_BUCKETS   (16 * 1024)
#define IPS_SESSION_DEFAULT_IPV4_HASH_MEMORY    (64 << 20)  /* 64MB */
#define IPS_SESSION_DEFAULT_IPV6_HASH_MEMORY    (32 << 20)  /* 32MB */

/* 默认超时配置 (秒) */
#define IPS_SESSION_DEFAULT_TCP_SYN_TIMEOUT         30
#define IPS_SESSION_DEFAULT_TCP_ESTABLISHED_TIMEOUT 3600
#define IPS_SESSION_DEFAULT_TCP_FIN_TIMEOUT         30
#define IPS_SESSION_DEFAULT_TCP_RST_TIMEOUT         5

/* 老化配置 */
#define IPS_SESSION_DEFAULT_AGING_CHECK_INTERVAL    1   /* 1秒 */
#define IPS_SESSION_DEFAULT_AGING_BATCH_SIZE        100

/* 老化阈值百分比 */
#define IPS_SESSION_NORMAL_THRESHOLD_PCT        70
#define IPS_SESSION_AGGRESSIVE_THRESHOLD_PCT    85
#define IPS_SESSION_EMERGENCY_THRESHOLD_PCT     95

/**
 * @brief 初始化会话管理器
 */
clib_error_t *
ips_session_manager_init (vlib_main_t * vm)
{
    ips_session_manager_t *sm = &ips_session_manager;
    u32 num_threads = vlib_num_workers () + 1;

    /* 清零管理器结构 */
    clib_memset (sm, 0, sizeof (*sm));

    /* Initialize ACL module */
    clib_error_t *acl_error = ips_acl_init (vm);
    if (acl_error)
    {
        clib_warning("Failed to initialize IPS ACL module: %s", acl_error->what);
        /* Continue without ACL functionality */
    }

    /* 设置默认配置 */
    sm->session_pool_size = IPS_SESSION_DEFAULT_POOL_SIZE;
    sm->ipv4_hash_buckets = IPS_SESSION_DEFAULT_IPV4_HASH_BUCKETS;
    sm->ipv6_hash_buckets = IPS_SESSION_DEFAULT_IPV6_HASH_BUCKETS;
    sm->ipv4_hash_memory_size = IPS_SESSION_DEFAULT_IPV4_HASH_MEMORY;
    sm->ipv6_hash_memory_size = IPS_SESSION_DEFAULT_IPV6_HASH_MEMORY;

    /* 设置超时配置 */
    sm->tcp_syn_timeout = IPS_SESSION_DEFAULT_TCP_SYN_TIMEOUT;
    sm->tcp_established_timeout = IPS_SESSION_DEFAULT_TCP_ESTABLISHED_TIMEOUT;
    sm->tcp_fin_timeout = IPS_SESSION_DEFAULT_TCP_FIN_TIMEOUT;
    sm->tcp_rst_timeout = IPS_SESSION_DEFAULT_TCP_RST_TIMEOUT;

    /* 设置老化配置 */
    sm->aging_check_interval = IPS_SESSION_DEFAULT_AGING_CHECK_INTERVAL;
    sm->aging_batch_size = IPS_SESSION_DEFAULT_AGING_BATCH_SIZE;

    /* 分配每线程数据 */
    vec_validate (sm->per_thread_data, num_threads - 1);

    /* 初始化每个线程的数据 */
    for (u32 i = 0; i < num_threads; i++)
    {
        clib_error_t *error = ips_session_per_thread_init (i);
        if (error)
            return error;
    }

    /* 初始化定时器管理器 */
    clib_error_t *timer_error = ips_session_timer_manager_init (vm);
    if (timer_error)
        return timer_error;

    return 0;
}

/**
 * @brief 清理会话管理器
 */
void
ips_session_manager_cleanup (void)
{
    ips_session_manager_t *sm = &ips_session_manager;
    u32 num_threads = vec_len (sm->per_thread_data);

    /* 清理定时器管理器 */
    ips_session_timer_manager_cleanup ();

    /* Cleanup ACL module */
    ips_acl_cleanup();

    /* 清理每个线程的数据 */
    for (u32 i = 0; i < num_threads; i++)
    {
        ips_session_per_thread_cleanup (i);
    }

    /* 释放每线程数据向量 */
    vec_free (sm->per_thread_data);

    /* 清零管理器结构 */
    clib_memset (sm, 0, sizeof (*sm));
}

/**
 * @brief 初始化每线程数据
 */
clib_error_t *
ips_session_per_thread_init (u32 thread_index)
{
    ips_session_manager_t *sm = &ips_session_manager;
    ips_session_per_thread_data_t *ptd = &sm->per_thread_data[thread_index];

    /* 清零线程数据 */
    clib_memset (ptd, 0, sizeof (*ptd));

    /* 初始化会话池 */
    pool_alloc_aligned (ptd->session_pool, sm->session_pool_size, CLIB_CACHE_LINE_BYTES);

    /* 初始化 IPv4 哈希表 */
    clib_bihash_init_16_8 (&ptd->ipv4_session_hash, "ips-session-ipv4",
                           sm->ipv4_hash_buckets, sm->ipv4_hash_memory_size);

    /* 初始化 IPv6 哈希表 */
    clib_bihash_init_48_8 (&ptd->ipv6_session_hash, "ips-session-ipv6",
                           sm->ipv6_hash_buckets, sm->ipv6_hash_memory_size);

    /* 初始化老化配置 */
    ptd->aging_config.normal_threshold =
        (sm->session_pool_size * IPS_SESSION_NORMAL_THRESHOLD_PCT) / 100;
    ptd->aging_config.aggressive_threshold =
        (sm->session_pool_size * IPS_SESSION_AGGRESSIVE_THRESHOLD_PCT) / 100;
    ptd->aging_config.emergency_threshold =
        (sm->session_pool_size * IPS_SESSION_EMERGENCY_THRESHOLD_PCT) / 100;
    ptd->aging_config.force_cleanup_target = sm->session_pool_size / 10; /* 10% */

    /* 初始化老化状态 */
    ptd->aging_state.last_cleanup_time = vlib_time_now (vlib_get_main ());
    ptd->aging_state.cleanup_cursor = 0;
    ptd->aging_state.cleanup_batch_size = sm->aging_batch_size;
    ptd->aging_state.emergency_cleanup_count = 0;
    ptd->aging_state.packet_driven_check_count = 0;

    return 0;
}

/**
 * @brief 清理每线程数据
 */
void
ips_session_per_thread_cleanup (u32 thread_index)
{
    ips_session_manager_t *sm = &ips_session_manager;
    ips_session_per_thread_data_t *ptd = &sm->per_thread_data[thread_index];

    /* 清理会话池 */
    pool_free (ptd->session_pool);

    /* 清理哈希表 */
    clib_bihash_free_16_8 (&ptd->ipv4_session_hash);
    clib_bihash_free_48_8 (&ptd->ipv6_session_hash);

    /* 清零线程数据 */
    clib_memset (ptd, 0, sizeof (*ptd));
}

/**
 * @brief Check session against ACL rules
 * @return 1 if session should be blocked, 0 if allowed
 */
static int
ips_session_check_acl(u32 thread_index, ips_session_t *session,
                      ip4_header_t *ip4, ip6_header_t *ip6,
                      tcp_header_t *tcp)
{
    ips_acl_action_t action;

    if (!ips_acl_is_available())
        return 0; /* ACL not available, allow */

    if (ips_acl_check_packet(thread_index, session, ip4, ip6, tcp, &action))
    {
        switch (action)
        {
        case IPS_ACL_ACTION_DENY:
            /* Mark session as blocked */
            session->flags |= IPS_SESSION_FLAG_BLOCKED;
            return 1;

        case IPS_ACL_ACTION_RESET:
            /* Send TCP reset and mark as blocked */
            ips_acl_send_tcp_reset(thread_index, session, 0);
            session->flags |= IPS_SESSION_FLAG_BLOCKED;
            return 1;

        case IPS_ACL_ACTION_PERMIT:
        case IPS_ACL_ACTION_LOG:
        default:
            return 0;
        }
    }

    return 0; /* Allow by default */
}

/**
 * @brief 根据 TCP 状态计算超时时间
 */
static inline u32
ips_session_calculate_timeout (ips_session_state_t state)
{
    ips_session_manager_t *sm = &ips_session_manager;

    switch (state)
    {
    case IPS_SESSION_STATE_SYN_RECVED:
    case IPS_SESSION_STATE_SYNACK_RECVED:
        return sm->tcp_syn_timeout;

    case IPS_SESSION_STATE_ESTABLISHED:
        return sm->tcp_established_timeout;

    case IPS_SESSION_STATE_FIN_WAIT1:
    case IPS_SESSION_STATE_FIN_WAIT2:
        return sm->tcp_fin_timeout;

    case IPS_SESSION_STATE_CLOSED:
        return sm->tcp_rst_timeout;

    default:
        return sm->tcp_established_timeout;
    }
}

/**
 * @brief 查找或创建 IPv4 会话
 */
ips_session_t *
ips_session_lookup_or_create_ipv4 (u32 thread_index,
                                    ip4_header_t * ip4,
                                    tcp_header_t * tcp)
{
    ips_session_manager_t *sm = &ips_session_manager;

    /* 线程索引边界检查 */
    if (PREDICT_FALSE (thread_index >= vec_len (sm->per_thread_data)))
        return NULL;

    ips_session_per_thread_data_t *ptd = &sm->per_thread_data[thread_index];
    ips_session_key4_t key, reverse_key;
    ips_session_t *session;
    clib_bihash_kv_16_8_t kv;
    f64 now = vlib_time_now (vlib_get_main ());

    /* 构造会话键 */
    clib_memset (&key, 0, sizeof (key));
    key.src_ip = ip4->src_address;
    key.dst_ip = ip4->dst_address;
    key.src_port = tcp->src_port;
    key.dst_port = tcp->dst_port;
    key.protocol = ip4->protocol;

    /* 首先尝试正向查找 */
    ips_session_set_bihash_key4 (&kv, &key);
    if (clib_bihash_search_16_8 (&ptd->ipv4_session_hash, &kv, &kv) == 0)
    {
        session = pool_elt_at_index (ptd->session_pool, kv.value);
        session->last_packet_time = now;

        /* Check ACL rules for existing session */
        if (!(session->flags & IPS_SESSION_FLAG_BLOCKED))
        {
            /* Only check ACL if session is not already blocked */
            ips_session_check_acl(thread_index, session, ip4, NULL, tcp);
        }

        /* If session is blocked (either previously or just now), don't allow processing */
        if (session->flags & IPS_SESSION_FLAG_BLOCKED)
        {
            return NULL;
        }

        /* 根据查找方向更新TCP状态与统计（正向=客户端->服务器） */
        u8 tcp_flags = tcp->flags;
        session->tcp_seq_src = clib_net_to_host_u32 (tcp->seq_number);
        session->tcp_ack_src = clib_net_to_host_u32 (tcp->ack_number);
        session->packet_count_src++;

        switch (session->tcp_state_src)
        {
        case IPS_SESSION_STATE_NONE:
            if ((tcp_flags & TCP_FLAG_SYN) && !(tcp_flags & TCP_FLAG_ACK))
                session->tcp_state_src = IPS_SESSION_STATE_SYN_RECVED;
            else if ((tcp_flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == (TCP_FLAG_SYN | TCP_FLAG_ACK))
                session->tcp_state_src = IPS_SESSION_STATE_SYNACK_RECVED;
            else if (tcp_flags & TCP_FLAG_RST)
                session->tcp_state_src = IPS_SESSION_STATE_CLOSED;
            break;
        case IPS_SESSION_STATE_SYN_RECVED:
        case IPS_SESSION_STATE_SYNACK_RECVED:
            if (tcp_flags & TCP_FLAG_ACK)
            {
                session->tcp_state_src = IPS_SESSION_STATE_ESTABLISHED;
                session->flags |= IPS_SESSION_FLAG_ESTABLISHED;
            }
            else if (tcp_flags & TCP_FLAG_RST)
            {
                session->tcp_state_src = IPS_SESSION_STATE_CLOSED;
            }
            break;
        case IPS_SESSION_STATE_ESTABLISHED:
            if (tcp_flags & TCP_FLAG_FIN)
                session->tcp_state_src = IPS_SESSION_STATE_FIN_WAIT1;
            else if (tcp_flags & TCP_FLAG_RST)
                session->tcp_state_src = IPS_SESSION_STATE_CLOSED;
            break;
        case IPS_SESSION_STATE_FIN_WAIT1:
            if (tcp_flags & TCP_FLAG_ACK)
                session->tcp_state_src = IPS_SESSION_STATE_FIN_WAIT2;
            else if (tcp_flags & TCP_FLAG_RST)
                session->tcp_state_src = IPS_SESSION_STATE_CLOSED;
            break;
        case IPS_SESSION_STATE_FIN_WAIT2:
            if ((tcp_flags & TCP_FLAG_FIN) || (tcp_flags & TCP_FLAG_RST))
                session->tcp_state_src = IPS_SESSION_STATE_CLOSED;
            break;
        default:
            break;
        }

        /* 更新超时与定时器 */
        session->timeout_seconds = ips_session_calculate_timeout (session->tcp_state_src);
        if (session->flags & IPS_SESSION_FLAG_TIMER_ACTIVE)
        {
            ips_session_timer_update_args_t upd_args_1;
            upd_args_1.thread_index = thread_index;
            upd_args_1.timer_handle = session->timer_handle;
            upd_args_1.timeout_seconds = session->timeout_seconds;
            ips_session_timer_update (&upd_args_1);
            /* 如果定时器更新失败，清除定时器标志 */
            if (upd_args_1.timer_handle == ~0)
            {
                session->flags &= ~IPS_SESSION_FLAG_TIMER_ACTIVE;
            }
        }

        return session;
    }

    /* 尝试反向查找 */
    clib_memset (&reverse_key, 0, sizeof (reverse_key));
    reverse_key.src_ip = ip4->dst_address;
    reverse_key.dst_ip = ip4->src_address;
    reverse_key.src_port = tcp->dst_port;
    reverse_key.dst_port = tcp->src_port;
    reverse_key.protocol = ip4->protocol;

    ips_session_set_bihash_key4 (&kv, &reverse_key);
    if (clib_bihash_search_16_8 (&ptd->ipv4_session_hash, &kv, &kv) == 0)
    {
        /* 安全检查：验证会话池索引是否有效 */
        if (PREDICT_FALSE (kv.value >= pool_len (ptd->session_pool) ||
                         pool_is_free_index (ptd->session_pool, kv.value)))
        {
            /* 哈希表指向已释放的会话，需要清理哈希表条目 */
            clib_bihash_add_del_16_8 (&ptd->ipv4_session_hash, &kv, 0 /* is_add */);
            goto create_new_session;
        }

        session = pool_elt_at_index (ptd->session_pool, kv.value);
        session->last_packet_time = now;

        /* Check ACL rules for existing session */
        if (!(session->flags & IPS_SESSION_FLAG_BLOCKED))
        {
            /* Only check ACL if session is not already blocked */
            ips_session_check_acl(thread_index, session, ip4, NULL, tcp);
        }

        /* If session is blocked (either previously or just now), don't allow processing */
        if (session->flags & IPS_SESSION_FLAG_BLOCKED)
        {
            return NULL;
        }

        /* 反向=服务器->客户端 */
        u8 tcp_flags = tcp->flags;
        session->tcp_seq_dst = clib_net_to_host_u32 (tcp->seq_number);
        session->tcp_ack_dst = clib_net_to_host_u32 (tcp->ack_number);
        session->packet_count_dst++;

        switch (session->tcp_state_dst)
        {
        case IPS_SESSION_STATE_NONE:
            if ((tcp_flags & TCP_FLAG_SYN) && !(tcp_flags & TCP_FLAG_ACK))
                session->tcp_state_dst = IPS_SESSION_STATE_SYN_RECVED;
            else if ((tcp_flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == (TCP_FLAG_SYN | TCP_FLAG_ACK))
                session->tcp_state_dst = IPS_SESSION_STATE_SYNACK_RECVED;
            else if (tcp_flags & TCP_FLAG_RST)
                session->tcp_state_dst = IPS_SESSION_STATE_CLOSED;
            break;
        case IPS_SESSION_STATE_SYN_RECVED:
        case IPS_SESSION_STATE_SYNACK_RECVED:
            if (tcp_flags & TCP_FLAG_ACK)
            {
                session->tcp_state_dst = IPS_SESSION_STATE_ESTABLISHED;
                session->flags |= IPS_SESSION_FLAG_ESTABLISHED;
            }
            else if (tcp_flags & TCP_FLAG_RST)
            {
                session->tcp_state_dst = IPS_SESSION_STATE_CLOSED;
            }
            break;
        case IPS_SESSION_STATE_ESTABLISHED:
            if (tcp_flags & TCP_FLAG_FIN)
                session->tcp_state_dst = IPS_SESSION_STATE_FIN_WAIT1;
            else if (tcp_flags & TCP_FLAG_RST)
                session->tcp_state_dst = IPS_SESSION_STATE_CLOSED;
            break;
        case IPS_SESSION_STATE_FIN_WAIT1:
            if (tcp_flags & TCP_FLAG_ACK)
                session->tcp_state_dst = IPS_SESSION_STATE_FIN_WAIT2;
            else if (tcp_flags & TCP_FLAG_RST)
                session->tcp_state_dst = IPS_SESSION_STATE_CLOSED;
            break;
        case IPS_SESSION_STATE_FIN_WAIT2:
            if ((tcp_flags & TCP_FLAG_FIN) || (tcp_flags & TCP_FLAG_RST))
                session->tcp_state_dst = IPS_SESSION_STATE_CLOSED;
            break;
        default:
            break;
        }

        session->timeout_seconds = ips_session_calculate_timeout (session->tcp_state_dst);
        if (session->flags & IPS_SESSION_FLAG_TIMER_ACTIVE)
        {
            ips_session_timer_update_args_t upd_args_2;
            upd_args_2.thread_index = thread_index;
            upd_args_2.timer_handle = session->timer_handle;
            upd_args_2.timeout_seconds = session->timeout_seconds;
            ips_session_timer_update (&upd_args_2);
            /* 如果定时器更新失败，清除定时器标志 */
            if (upd_args_2.timer_handle == ~0)
            {
                session->flags &= ~IPS_SESSION_FLAG_TIMER_ACTIVE;
            }
        }

        return session;
    }

    /* 会话不存在，创建新会话 */
create_new_session:
    /* 只有 SYN/SYNACK 报文才能创建新会话 */
    if (!(tcp->flags & TCP_FLAG_SYN))
    {
        return NULL;
    }

    /* 检查会话池是否满 */
    if (pool_elts (ptd->session_pool) >= sm->session_pool_size)
    {
        /* 尝试强制清理过期会话，增加清理目标 */
        u32 cleanup_target = ptd->aging_config.force_cleanup_target * 2;
        ips_session_force_cleanup_args_t fc_args_1 = { .thread_index = thread_index, .target_count = cleanup_target };
        ips_session_force_cleanup (&fc_args_1);

        /* 如果仍然满，执行更激进的清理策略 */
        if (pool_elts (ptd->session_pool) >= sm->session_pool_size)
        {
            /* 清理超过一半超时时间的会话 */
            ips_session_cleanup_expired_args_t cleanup_args = {
                .thread_index = thread_index,
                .timeout = sm->tcp_established_timeout * 0.5
            };
            ips_session_cleanup_expired (&cleanup_args);

            /* 最后检查，如果还是满，只清理最老的会话 */
            if (pool_elts (ptd->session_pool) >= sm->session_pool_size)
            {
                /* 清理最老的 10% 会话 */
                u32 emergency_target = sm->session_pool_size / 10;
                ips_session_force_cleanup_args_t emergency_args = {
                    .thread_index = thread_index,
                    .target_count = emergency_target
                };
                ips_session_force_cleanup (&emergency_args);

                /* 如果最终还是满，拒绝创建但记录统计 */
                if (pool_elts (ptd->session_pool) >= sm->session_pool_size)
                {
                    return NULL;
                }
            }
        }
    }

    /* 分配新会话 */
    pool_get_zero (ptd->session_pool, session);
    session->session_index = session - ptd->session_pool;
    session->thread_index = thread_index;

    /* 设置会话信息 */
    session->is_ipv6 = 0;
    session->protocol = ip4->protocol;
    session->src_ip4 = ip4->src_address;
    session->dst_ip4 = ip4->dst_address;
    session->src_port = tcp->src_port;
    session->dst_port = tcp->dst_port;

    /* 设置时间信息 */
    session->session_start_time = now;
    session->last_packet_time = now;

    /* 设置初始 TCP 状态：仅基于报文类型确定最小状态，并记录当前方向的序列/统计 */
    if ((tcp->flags & TCP_FLAG_SYN) && !(tcp->flags & TCP_FLAG_ACK))
    {
        /* 纯 SYN：认为是客户端->服务器方向 */
        session->tcp_state_src = IPS_SESSION_STATE_SYN_RECVED;
        session->tcp_state_dst = IPS_SESSION_STATE_NONE;
        session->tcp_seq_src = clib_net_to_host_u32 (tcp->seq_number);
        session->tcp_ack_src = clib_net_to_host_u32 (tcp->ack_number);
        session->packet_count_src++;
    }
    else if ((tcp->flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == (TCP_FLAG_SYN | TCP_FLAG_ACK))
    {
        /* SYN+ACK：认为是服务器->客户端方向 */
        session->tcp_state_src = IPS_SESSION_STATE_NONE;
        session->tcp_state_dst = IPS_SESSION_STATE_SYNACK_RECVED;
        session->tcp_seq_dst = clib_net_to_host_u32 (tcp->seq_number);
        session->tcp_ack_dst = clib_net_to_host_u32 (tcp->ack_number);
        session->packet_count_dst++;
    }

    /* 设置超时时间 */
    session->timeout_seconds = ips_session_calculate_timeout (session->tcp_state_src);

    /* 设置标志 */
    session->flags |= IPS_SESSION_FLAG_MIRRORED;

    /* 启动会话过期定时器 */
    ips_session_timer_start_args_t start_args_1;
    start_args_1.thread_index = thread_index;
    start_args_1.session_index = session->session_index;
    start_args_1.timeout_seconds = session->timeout_seconds;
    session->timer_handle = ips_session_timer_start (&start_args_1);
    if (session->timer_handle != ~0)
    {
        session->flags |= IPS_SESSION_FLAG_TIMER_ACTIVE;
    }

    /* 将会话添加到哈希表 */
    ips_session_set_bihash_key4 (&kv, &key);
    kv.value = session->session_index;
    clib_bihash_add_del_16_8 (&ptd->ipv4_session_hash, &kv, 1 /* is_add */);

    /* 更新统计 */
    ptd->total_sessions_created++;

    return session;
}

/**
 * @brief 查找或创建 IPv6 会话
 */
ips_session_t *
ips_session_lookup_or_create_ipv6 (u32 thread_index,
                                    ip6_header_t * ip6,
                                    tcp_header_t * tcp)
{
    ips_session_manager_t *sm = &ips_session_manager;

    /* 线程索引边界检查 */
    if (PREDICT_FALSE (thread_index >= vec_len (sm->per_thread_data)))
        return NULL;

    ips_session_per_thread_data_t *ptd = &sm->per_thread_data[thread_index];
    ips_session_key6_t key, reverse_key;
    ips_session_t *session;
    clib_bihash_kv_48_8_t kv;
    f64 now = vlib_time_now (vlib_get_main ());

    /* 构造会话键 */
    clib_memset (&key, 0, sizeof (key));
    key.src_ip = ip6->src_address;
    key.dst_ip = ip6->dst_address;
    key.src_port = tcp->src_port;
    key.dst_port = tcp->dst_port;
    key.protocol = ip6->protocol;

    /* 首先尝试正向查找 */
    ips_session_set_bihash_key6 (&kv, &key);
    if (clib_bihash_search_48_8 (&ptd->ipv6_session_hash, &kv, &kv) == 0)
    {
        /* 安全检查：验证会话池索引是否有效 */
        if (PREDICT_FALSE (kv.value >= pool_len (ptd->session_pool) ||
                         pool_is_free_index (ptd->session_pool, kv.value)))
        {
            /* 哈希表指向已释放的会话，需要清理哈希表条目 */
            clib_bihash_add_del_48_8 (&ptd->ipv6_session_hash, &kv, 0 /* is_add */);
            goto create_new_session_v6;
        }

        session = pool_elt_at_index (ptd->session_pool, kv.value);
        session->last_packet_time = now;

        /* Check ACL rules for existing session */
        if (!(session->flags & IPS_SESSION_FLAG_BLOCKED))
        {
            /* Only check ACL if session is not already blocked */
            ips_session_check_acl(thread_index, session, NULL, ip6, tcp);
        }

        /* If session is blocked (either previously or just now), don't allow processing */
        if (session->flags & IPS_SESSION_FLAG_BLOCKED)
        {
            return NULL;
        }

        /* 根据查找方向更新TCP状态与统计（正向=客户端->服务器） */
        u8 tcp_flags = tcp->flags;
        session->tcp_seq_src = clib_net_to_host_u32 (tcp->seq_number);
        session->tcp_ack_src = clib_net_to_host_u32 (tcp->ack_number);
        session->packet_count_src++;

        switch (session->tcp_state_src)
        {
        case IPS_SESSION_STATE_NONE:
            if ((tcp_flags & TCP_FLAG_SYN) && !(tcp_flags & TCP_FLAG_ACK))
                session->tcp_state_src = IPS_SESSION_STATE_SYN_RECVED;
            else if ((tcp_flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == (TCP_FLAG_SYN | TCP_FLAG_ACK))
                session->tcp_state_src = IPS_SESSION_STATE_SYNACK_RECVED;
            else if (tcp_flags & TCP_FLAG_RST)
                session->tcp_state_src = IPS_SESSION_STATE_CLOSED;
            break;
        case IPS_SESSION_STATE_SYN_RECVED:
        case IPS_SESSION_STATE_SYNACK_RECVED:
            if (tcp_flags & TCP_FLAG_ACK)
            {
                session->tcp_state_src = IPS_SESSION_STATE_ESTABLISHED;
                session->flags |= IPS_SESSION_FLAG_ESTABLISHED;
            }
            else if (tcp_flags & TCP_FLAG_RST)
            {
                session->tcp_state_src = IPS_SESSION_STATE_CLOSED;
            }
            break;
        case IPS_SESSION_STATE_ESTABLISHED:
            if (tcp_flags & TCP_FLAG_FIN)
                session->tcp_state_src = IPS_SESSION_STATE_FIN_WAIT1;
            else if (tcp_flags & TCP_FLAG_RST)
                session->tcp_state_src = IPS_SESSION_STATE_CLOSED;
            break;
        case IPS_SESSION_STATE_FIN_WAIT1:
            if (tcp_flags & TCP_FLAG_ACK)
                session->tcp_state_src = IPS_SESSION_STATE_FIN_WAIT2;
            else if (tcp_flags & TCP_FLAG_RST)
                session->tcp_state_src = IPS_SESSION_STATE_CLOSED;
            break;
        case IPS_SESSION_STATE_FIN_WAIT2:
            if ((tcp_flags & TCP_FLAG_FIN) || (tcp_flags & TCP_FLAG_RST))
                session->tcp_state_src = IPS_SESSION_STATE_CLOSED;
            break;
        default:
            break;
        }

        /* 更新超时与定时器 */
        session->timeout_seconds = ips_session_calculate_timeout (session->tcp_state_src);
        if (session->flags & IPS_SESSION_FLAG_TIMER_ACTIVE)
        {
            ips_session_timer_update_args_t upd_args_3;
            upd_args_3.thread_index = thread_index;
            upd_args_3.timer_handle = session->timer_handle;
            upd_args_3.timeout_seconds = session->timeout_seconds;
            ips_session_timer_update (&upd_args_3);
            /* 如果定时器更新失败，清除定时器标志 */
            if (upd_args_3.timer_handle == ~0)
            {
                session->flags &= ~IPS_SESSION_FLAG_TIMER_ACTIVE;
            }
        }

        return session;
    }

    /* 尝试反向查找 */
    clib_memset (&reverse_key, 0, sizeof (reverse_key));
    reverse_key.src_ip = ip6->dst_address;
    reverse_key.dst_ip = ip6->src_address;
    reverse_key.src_port = tcp->dst_port;
    reverse_key.dst_port = tcp->src_port;
    reverse_key.protocol = ip6->protocol;

    ips_session_set_bihash_key6 (&kv, &reverse_key);
    if (clib_bihash_search_48_8 (&ptd->ipv6_session_hash, &kv, &kv) == 0)
    {
        /* 安全检查：验证会话池索引是否有效 */
        if (PREDICT_FALSE (kv.value >= pool_len (ptd->session_pool) ||
                         pool_is_free_index (ptd->session_pool, kv.value)))
        {
            /* 哈希表指向已释放的会话，需要清理哈希表条目 */
            clib_bihash_add_del_48_8 (&ptd->ipv6_session_hash, &kv, 0 /* is_add */);
            goto create_new_session_v6;
        }

        session = pool_elt_at_index (ptd->session_pool, kv.value);
        session->last_packet_time = now;

        /* Check ACL rules for existing session */
        if (!(session->flags & IPS_SESSION_FLAG_BLOCKED))
        {
            /* Only check ACL if session is not already blocked */
            ips_session_check_acl(thread_index, session, NULL, ip6, tcp);
        }

        /* If session is blocked (either previously or just now), don't allow processing */
        if (session->flags & IPS_SESSION_FLAG_BLOCKED)
        {
            return NULL;
        }

        /* 反向=服务器->客户端 */
        u8 tcp_flags = tcp->flags;
        session->tcp_seq_dst = clib_net_to_host_u32 (tcp->seq_number);
        session->tcp_ack_dst = clib_net_to_host_u32 (tcp->ack_number);
        session->packet_count_dst++;

        switch (session->tcp_state_dst)
        {
        case IPS_SESSION_STATE_NONE:
            if ((tcp_flags & TCP_FLAG_SYN) && !(tcp_flags & TCP_FLAG_ACK))
                session->tcp_state_dst = IPS_SESSION_STATE_SYN_RECVED;
            else if ((tcp_flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == (TCP_FLAG_SYN | TCP_FLAG_ACK))
                session->tcp_state_dst = IPS_SESSION_STATE_SYNACK_RECVED;
            else if (tcp_flags & TCP_FLAG_RST)
                session->tcp_state_dst = IPS_SESSION_STATE_CLOSED;
            break;
        case IPS_SESSION_STATE_SYN_RECVED:
        case IPS_SESSION_STATE_SYNACK_RECVED:
            if (tcp_flags & TCP_FLAG_ACK)
            {
                session->tcp_state_dst = IPS_SESSION_STATE_ESTABLISHED;
                session->flags |= IPS_SESSION_FLAG_ESTABLISHED;
            }
            else if (tcp_flags & TCP_FLAG_RST)
            {
                session->tcp_state_dst = IPS_SESSION_STATE_CLOSED;
            }
            break;
        case IPS_SESSION_STATE_ESTABLISHED:
            if (tcp_flags & TCP_FLAG_FIN)
                session->tcp_state_dst = IPS_SESSION_STATE_FIN_WAIT1;
            else if (tcp_flags & TCP_FLAG_RST)
                session->tcp_state_dst = IPS_SESSION_STATE_CLOSED;
            break;
        case IPS_SESSION_STATE_FIN_WAIT1:
            if (tcp_flags & TCP_FLAG_ACK)
                session->tcp_state_dst = IPS_SESSION_STATE_FIN_WAIT2;
            else if (tcp_flags & TCP_FLAG_RST)
                session->tcp_state_dst = IPS_SESSION_STATE_CLOSED;
            break;
        case IPS_SESSION_STATE_FIN_WAIT2:
            if ((tcp_flags & TCP_FLAG_FIN) || (tcp_flags & TCP_FLAG_RST))
                session->tcp_state_dst = IPS_SESSION_STATE_CLOSED;
            break;
        default:
            break;
        }

        session->timeout_seconds = ips_session_calculate_timeout (session->tcp_state_dst);
        if (session->flags & IPS_SESSION_FLAG_TIMER_ACTIVE)
        {
            ips_session_timer_update_args_t upd_args_4;
            upd_args_4.thread_index = thread_index;
            upd_args_4.timer_handle = session->timer_handle;
            upd_args_4.timeout_seconds = session->timeout_seconds;
            ips_session_timer_update (&upd_args_4);
            /* 如果定时器更新失败，清除定时器标志 */
            if (upd_args_4.timer_handle == ~0)
            {
                session->flags &= ~IPS_SESSION_FLAG_TIMER_ACTIVE;
            }
        }

        return session;
    }

    /* 会话不存在，创建新会话 */
create_new_session_v6:
    /* 只有 SYN 报文才能创建新会话 */
    if (!(tcp->flags & TCP_FLAG_SYN))
    {
        return NULL;
    }

    /* 检查会话池是否满 */
    if (pool_elts (ptd->session_pool) >= sm->session_pool_size)
    {
        /* 尝试强制清理过期会话，增加清理目标 */
        u32 cleanup_target = ptd->aging_config.force_cleanup_target * 2;
        ips_session_force_cleanup_args_t fc_args_2 = { .thread_index = thread_index, .target_count = cleanup_target };
        ips_session_force_cleanup (&fc_args_2);

        /* 如果仍然满，执行更激进的清理策略 */
        if (pool_elts (ptd->session_pool) >= sm->session_pool_size)
        {
            /* 清理超过一半超时时间的会话 */
            ips_session_cleanup_expired_args_t cleanup_args = {
                .thread_index = thread_index,
                .timeout = sm->tcp_established_timeout * 0.5
            };
            ips_session_cleanup_expired (&cleanup_args);

            /* 最后检查，如果还是满，只清理最老的会话 */
            if (pool_elts (ptd->session_pool) >= sm->session_pool_size)
            {
                /* 清理最老的 10% 会话 */
                u32 emergency_target = sm->session_pool_size / 10;
                ips_session_force_cleanup_args_t emergency_args = {
                    .thread_index = thread_index,
                    .target_count = emergency_target
                };
                ips_session_force_cleanup (&emergency_args);

                /* 如果最终还是满，拒绝创建但记录统计 */
                if (pool_elts (ptd->session_pool) >= sm->session_pool_size)
                {
                    return NULL;
                }
            }
        }
    }

    /* 分配新会话 */
    pool_get_zero (ptd->session_pool, session);
    session->session_index = session - ptd->session_pool;
    session->thread_index = thread_index;

    /* 设置会话信息 */
    session->is_ipv6 = 1;
    session->protocol = ip6->protocol;
    session->src_ip6 = ip6->src_address;
    session->dst_ip6 = ip6->dst_address;
    session->src_port = tcp->src_port;
    session->dst_port = tcp->dst_port;

    /* 设置时间信息 */
    session->session_start_time = now;
    session->last_packet_time = now;

    /* 设置初始 TCP 状态：仅基于报文类型确定最小状态，并记录当前方向的序列/统计 */
    if ((tcp->flags & TCP_FLAG_SYN) && !(tcp->flags & TCP_FLAG_ACK))
    {
        /* 纯 SYN：认为是客户端->服务器方向 */
        session->tcp_state_src = IPS_SESSION_STATE_SYN_RECVED;
        session->tcp_state_dst = IPS_SESSION_STATE_NONE;
        session->tcp_seq_src = clib_net_to_host_u32 (tcp->seq_number);
        session->tcp_ack_src = clib_net_to_host_u32 (tcp->ack_number);
        session->packet_count_src++;
    }
    else if ((tcp->flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == (TCP_FLAG_SYN | TCP_FLAG_ACK))
    {
        /* SYN+ACK：认为是服务器->客户端方向 */
        session->tcp_state_src = IPS_SESSION_STATE_NONE;
        session->tcp_state_dst = IPS_SESSION_STATE_SYNACK_RECVED;
        session->tcp_seq_dst = clib_net_to_host_u32 (tcp->seq_number);
        session->tcp_ack_dst = clib_net_to_host_u32 (tcp->ack_number);
        session->packet_count_dst++;
    }

    /* 设置超时时间 */
    session->timeout_seconds = ips_session_calculate_timeout (session->tcp_state_src);

    /* 设置标志 */
    session->flags |= IPS_SESSION_FLAG_MIRRORED;

    /* 启动会话过期定时器 */
    ips_session_timer_start_args_t start_args_2;
    start_args_2.thread_index = thread_index;
    start_args_2.session_index = session->session_index;
    start_args_2.timeout_seconds = session->timeout_seconds;
    session->timer_handle = ips_session_timer_start (&start_args_2);
    if (session->timer_handle != ~0)
    {
        session->flags |= IPS_SESSION_FLAG_TIMER_ACTIVE;
    }

    /* 将会话添加到哈希表 */
    ips_session_set_bihash_key6 (&kv, &key);
    kv.value = session->session_index;
    clib_bihash_add_del_48_8 (&ptd->ipv6_session_hash, &kv, 1 /* is_add */);

    /* 更新统计 */
    ptd->total_sessions_created++;

    return session;
}

/**
 * @brief 查找 IPv4 会话
 */
ips_session_t *
ips_session_lookup_ipv4 (u32 thread_index, ips_session_key4_t * key)
{
    ips_session_manager_t *sm = &ips_session_manager;

    /* 线程索引边界检查 */
    if (PREDICT_FALSE (thread_index >= vec_len (sm->per_thread_data)))
        return NULL;

    ips_session_per_thread_data_t *ptd = &sm->per_thread_data[thread_index];
    clib_bihash_kv_16_8_t kv;

    ips_session_set_bihash_key4 (&kv, key);
    if (clib_bihash_search_16_8 (&ptd->ipv4_session_hash, &kv, &kv) == 0)
    {
        return pool_elt_at_index (ptd->session_pool, kv.value);
    }

    return NULL;
}

/**
 * @brief 查找 IPv6 会话
 */
ips_session_t *
ips_session_lookup_ipv6 (u32 thread_index, ips_session_key6_t * key)
{
    ips_session_manager_t *sm = &ips_session_manager;

    /* 线程索引边界检查 */
    if (PREDICT_FALSE (thread_index >= vec_len (sm->per_thread_data)))
        return NULL;

    ips_session_per_thread_data_t *ptd = &sm->per_thread_data[thread_index];
    clib_bihash_kv_48_8_t kv;

    ips_session_set_bihash_key6 (&kv, key);
    if (clib_bihash_search_48_8 (&ptd->ipv6_session_hash, &kv, &kv) == 0)
    {
        /* 安全检查：验证会话池索引是否有效 */
        if (PREDICT_FALSE (kv.value >= pool_len (ptd->session_pool) ||
                         pool_is_free_index (ptd->session_pool, kv.value)))
        {
            /* 哈希表指向已释放的会话，返回 NULL */
            return NULL;
        }

        return pool_elt_at_index (ptd->session_pool, kv.value);
    }

    return NULL;
}

/**
 * @brief 删除会话
 */
void
ips_session_delete (u32 thread_index, ips_session_t * session)
{
    ips_session_manager_t *sm = &ips_session_manager;

    /* 线程索引边界检查 */
    if (PREDICT_FALSE (thread_index >= vec_len (sm->per_thread_data) || !session))
        return;

    ips_session_per_thread_data_t *ptd = &sm->per_thread_data[thread_index];
    clib_bihash_kv_16_8_t kv4;
    clib_bihash_kv_48_8_t kv6;

    /* 停止定时器（如果还没有过期）*/
    if (session->flags & IPS_SESSION_FLAG_TIMER_ACTIVE)
    {
        ips_session_timer_stop_args_t stop_args;
        stop_args.thread_index = thread_index;
        stop_args.timer_handle = session->timer_handle;
        ips_session_timer_stop (&stop_args);
        session->flags &= ~IPS_SESSION_FLAG_TIMER_ACTIVE;
        session->timer_handle = ~0;  /* Clear timer handle to prevent double-free */
    }

    /* 从哈希表中删除 */
    if (session->is_ipv6)
    {
        ips_session_key6_t key;
        clib_memset (&key, 0, sizeof (key));
        key.src_ip = session->src_ip6;
        key.dst_ip = session->dst_ip6;
        key.src_port = session->src_port;
        key.dst_port = session->dst_port;
        key.protocol = session->protocol;

        ips_session_set_bihash_key6 (&kv6, &key);
        clib_bihash_add_del_48_8 (&ptd->ipv6_session_hash, &kv6, 0 /* is_add */);
    }
    else
    {
        ips_session_key4_t key;
        clib_memset (&key, 0, sizeof (key));
        key.src_ip = session->src_ip4;
        key.dst_ip = session->dst_ip4;
        key.src_port = session->src_port;
        key.dst_port = session->dst_port;
        key.protocol = session->protocol;

        ips_session_set_bihash_key4 (&kv4, &key);
        clib_bihash_add_del_16_8 (&ptd->ipv4_session_hash, &kv4, 0 /* is_add */);
    }

    /* 从池中删除 */
    pool_put (ptd->session_pool, session);

    /* 更新统计 */
    ptd->total_sessions_deleted++;
}

/**
 * @brief 删除会话（不停止定时器 - 用于定时器过期回调）
 */
void
ips_session_delete_no_timer (u32 thread_index, ips_session_t * session)
{
    ips_session_manager_t *sm = &ips_session_manager;

    /* 线程索引边界检查 */
    if (PREDICT_FALSE (thread_index >= vec_len (sm->per_thread_data) || !session))
        return;

    ips_session_per_thread_data_t *ptd = &sm->per_thread_data[thread_index];
    clib_bihash_kv_16_8_t kv4;
    clib_bihash_kv_48_8_t kv6;

    /* Timer handle should already be cleared by the expiration callback
     * following VPP TCP pattern. No need to clear it again here. */
    if (session->flags & IPS_SESSION_FLAG_TIMER_ACTIVE)
    {
        session->flags &= ~IPS_SESSION_FLAG_TIMER_ACTIVE;
    }

    /* 从哈希表中删除 */
    if (session->is_ipv6)
    {
        ips_session_key6_t key;
        clib_memset (&key, 0, sizeof (key));
        key.src_ip = session->src_ip6;
        key.dst_ip = session->dst_ip6;
        key.src_port = session->src_port;
        key.dst_port = session->dst_port;
        key.protocol = session->protocol;

        ips_session_set_bihash_key6 (&kv6, &key);
        clib_bihash_add_del_48_8 (&ptd->ipv6_session_hash, &kv6, 0 /* is_add */);
    }
    else
    {
        ips_session_key4_t key;
        clib_memset (&key, 0, sizeof (key));
        key.src_ip = session->src_ip4;
        key.dst_ip = session->dst_ip4;
        key.src_port = session->src_port;
        key.dst_port = session->dst_port;
        key.protocol = session->protocol;

        ips_session_set_bihash_key4 (&kv4, &key);
        clib_bihash_add_del_16_8 (&ptd->ipv4_session_hash, &kv4, 0 /* is_add */);
    }

    /* 从池中删除 */
    pool_put (ptd->session_pool, session);

    /* 更新统计 */
    ptd->total_sessions_deleted++;
}

/**
 * @brief 会话老化处理
 */
void
ips_session_aging_process (u32 thread_index)
{
    ips_session_manager_t *sm = &ips_session_manager;

    /* 线程索引边界检查 */
    if (PREDICT_FALSE (thread_index >= vec_len (sm->per_thread_data)))
        return;

    ips_session_per_thread_data_t *ptd = &sm->per_thread_data[thread_index];
    ips_session_aging_state_t *aging_state = &ptd->aging_state;
    f64 now = vlib_time_now (vlib_get_main ());
    u32 pool_size = pool_len (ptd->session_pool);
    u32 active_sessions = pool_elts (ptd->session_pool);

    /* 检查是否需要执行老化 */
    if ((now - aging_state->last_cleanup_time) < sm->aging_check_interval)
    {
        return;
    }

    aging_state->last_cleanup_time = now;

    /* 根据会话数量决定老化策略 */
    u32 cleanup_count = 0;
    if (active_sessions > ptd->aging_config.emergency_threshold)
    {
        /* 紧急老化：清理更多会话 */
        cleanup_count = aging_state->cleanup_batch_size * 4;
        aging_state->emergency_cleanup_count++;
    }
    else if (active_sessions > ptd->aging_config.aggressive_threshold)
    {
        /* 激进老化：清理更多会话 */
        cleanup_count = aging_state->cleanup_batch_size * 2;
    }
    else if (active_sessions > ptd->aging_config.normal_threshold)
    {
        /* 正常老化 */
        cleanup_count = aging_state->cleanup_batch_size;
    }
    else
    {
        /* 会话数量正常，不需要老化 */
        return;
    }

    /* 执行批量老化 */
    u32 cursor = aging_state->cleanup_cursor;
    u32 cleaned = 0;
    u32 checked = 0;

    while (cleaned < cleanup_count && checked < pool_size)
    {
        if (cursor >= pool_size)
        {
            cursor = 0;
        }

        if (!pool_is_free_index (ptd->session_pool, cursor))
        {
            ips_session_t *session = pool_elt_at_index (ptd->session_pool, cursor);
            f64 session_age = now - session->last_packet_time;

            /* 检查会话是否过期 */
            if (session_age > session->timeout_seconds ||
                session->tcp_state_src == IPS_SESSION_STATE_CLOSED ||
                session->tcp_state_dst == IPS_SESSION_STATE_CLOSED)
            {
                ips_session_delete (thread_index, session);
                cleaned++;

                /* 更新统计 */
                ptd->aging_stats.expired_sessions++;
            }
        }

        cursor++;
        checked++;
    }

    aging_state->cleanup_cursor = cursor;
}

/**
 * @brief 强制清理会话
 */
void
ips_session_force_cleanup (const ips_session_force_cleanup_args_t *args)
{
    if (!args)
        return;
    u32 thread_index = args->thread_index;
    u32 target_count = args->target_count;
    ips_session_manager_t *sm = &ips_session_manager;
    ips_session_per_thread_data_t *ptd = &sm->per_thread_data[thread_index];
    f64 now = vlib_time_now (vlib_get_main ());
    u32 pool_size = pool_len (ptd->session_pool);
    u32 cleaned = 0;
    u32 cursor = 0;

    /* 遍历所有会话，优先清理老的会话 */
    while (cleaned < target_count && cursor < pool_size)
    {
        if (!pool_is_free_index (ptd->session_pool, cursor))
        {
            ips_session_t *session = pool_elt_at_index (ptd->session_pool, cursor);
            f64 session_age = now - session->last_packet_time;

            /* 强制清理条件：过期或者老会话 */
            if (session_age > session->timeout_seconds ||
                session->tcp_state_src == IPS_SESSION_STATE_CLOSED ||
                session->tcp_state_dst == IPS_SESSION_STATE_CLOSED ||
                session_age > (session->timeout_seconds * 0.5)) /* 超过一半超时时间 */
            {
                ips_session_delete (thread_index, session);
                cleaned++;

                /* 更新统计 */
                ptd->aging_stats.forced_cleanup_sessions++;
            }
        }

        cursor++;
    }
}

/**
 * @brief 清理过期会话
 */
u32
ips_session_cleanup_expired (const ips_session_cleanup_expired_args_t *args)
{
    if (!args)
        return 0;
    u32 thread_index = args->thread_index;
    f64 timeout = args->timeout;
    ips_session_manager_t *sm = &ips_session_manager;
    ips_session_per_thread_data_t *ptd = &sm->per_thread_data[thread_index];
    f64 now = vlib_time_now (vlib_get_main ());
    u32 pool_size = pool_len (ptd->session_pool);
    u32 cleaned = 0;
    u32 cursor = 0;

    /* 遍历所有会话，清理过期会话 */
    while (cursor < pool_size)
    {
        if (!pool_is_free_index (ptd->session_pool, cursor))
        {
            ips_session_t *session = pool_elt_at_index (ptd->session_pool, cursor);
            f64 session_age = now - session->last_packet_time;

            if (session_age > timeout)
            {
                ips_session_delete (thread_index, session);
                cleaned++;

                /* 更新统计 */
                ptd->aging_stats.expired_sessions++;
            }
        }

        cursor++;
    }

    return cleaned;
}

/**
 * @brief 获取会话统计信息
 */
void
ips_session_get_stats (const ips_session_get_stats_args_t *args)
{
    if (!args)
        return;
    ips_session_manager_t *sm = &ips_session_manager;
    ips_session_per_thread_data_t *ptd = &sm->per_thread_data[args->thread_index];

    *args->active_sessions = pool_elts (ptd->session_pool);
    *args->total_created = ptd->total_sessions_created;
    *args->total_deleted = ptd->total_sessions_deleted;
}

/**
 * @brief 获取老化统计信息
 */
void
ips_session_get_aging_stats (u32 thread_index,
                             ips_session_aging_stats_t * stats)
{
    ips_session_manager_t *sm = &ips_session_manager;
    ips_session_per_thread_data_t *ptd = &sm->per_thread_data[thread_index];

    *stats = ptd->aging_stats;
}

/**
 * @brief 设置超时配置
 */
void
ips_session_set_timeouts (const ips_session_set_timeouts_args_t *args)
{
    if (!args)
        return;
    ips_session_manager_t *sm = &ips_session_manager;

    sm->tcp_syn_timeout = args->syn_timeout;
    sm->tcp_established_timeout = args->established_timeout;
    sm->tcp_fin_timeout = args->fin_timeout;
    sm->tcp_rst_timeout = args->rst_timeout;
}

/**
 * @brief 设置老化配置
 */
void
ips_session_set_aging_config (const ips_session_set_aging_config_args_t *args)
{
    if (!args)
        return;
    ips_session_manager_t *sm = &ips_session_manager;

    sm->aging_check_interval = args->check_interval;
    sm->aging_batch_size = args->batch_size;
}
