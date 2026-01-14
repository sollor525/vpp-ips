/*
 * ips_session.h - VPP IPS Plugin TCP Session Management
 *
 * Copyright (c) 2024 VPP IPS Project
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#ifndef __IPS_SESSION_H__
#define __IPS_SESSION_H__

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>
#include <vnet/tcp/tcp_packet.h>
#include <vppinfra/pool.h>
#include <vppinfra/bihash_16_8.h>
#include <vppinfra/bihash_48_8.h>



/* Forward declarations for timer structures */
typedef struct ips_session_timer_manager_ ips_session_timer_manager_t;
typedef struct ips_session_timer_per_thread_ ips_session_timer_per_thread_t;

/* TCP 会话状态枚举 */
typedef enum
{
    IPS_SESSION_STATE_NONE = 0,
    IPS_SESSION_STATE_SYN_RECVED,
    IPS_SESSION_STATE_SYNACK_RECVED,
    IPS_SESSION_STATE_ESTABLISHED,
    IPS_SESSION_STATE_FIN_WAIT1,
    IPS_SESSION_STATE_FIN_WAIT2,
    IPS_SESSION_STATE_CLOSED,
} ips_session_state_t;

/* 会话方向枚举 */
typedef enum
{
    IPS_SESSION_DIR_TO_SERVER = 0,
    IPS_SESSION_DIR_TO_CLIENT = 1,
} ips_session_direction_t;

/* 会话标志位 */
#define IPS_SESSION_FLAG_ESTABLISHED     (1 << 0)
#define IPS_SESSION_FLAG_STATELESS       (1 << 1)
#define IPS_SESSION_FLAG_MIRRORED         (1 << 2)
#define IPS_SESSION_FLAG_DETECTED        (1 << 3)
#define IPS_SESSION_FLAG_BLOCKED         (1 << 4)
#define IPS_SESSION_FLAG_TIMER_ACTIVE    (1 << 5)  /* 定时器激活标志 */
#define IPS_SESSION_FLAG_PENDING_CLEANUP (1 << 6)  /* 待清理标志 */

/* IPv4 会话键 */
typedef struct
{
    ip4_address_t src_ip;
    ip4_address_t dst_ip;
    u16 src_port;
    u16 dst_port;
    u8 protocol;
    u8 pad[3];
} ips_session_key4_t;

/* IPv6 会话键 */
typedef struct
{
    ip6_address_t src_ip;
    ip6_address_t dst_ip;
    u16 src_port;
    u16 dst_port;
    u8 protocol;
    u8 pad[3];
} ips_session_key6_t;

/* TCP 会话结构体 - 优化为 2 个 cacheline (128 字节) */
typedef struct
{
    CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

    /* 第一个 cacheline: 最频繁访问的字段 (64字节) */

    /* 时间信息 - 老化检查时最频繁访问 (16 bytes) */
    f64 last_packet_time;           /* 最后报文时间 - 8 bytes */
    f64 session_start_time;         /* 会话开始时间 - 8 bytes */

    /* 网络地址和端口 - IPv4 (16 bytes) */
    ip4_address_t src_ip4;          /* 源 IPv4 地址 - 4 bytes */
    ip4_address_t dst_ip4;          /* 目标 IPv4 地址 - 4 bytes */
    u16 src_port;                   /* 源端口 - 2 bytes */
    u16 dst_port;                   /* 目标端口 - 2 bytes */
    u16 timeout_seconds;            /* 超时时间(秒) - 2 bytes */
    u8 is_ipv6;                     /* IP 版本标志 - 1 byte */
    u8 protocol;                    /* 协议类型 - 1 byte */

    /* TCP 状态和标志 (16 bytes) */
    ips_session_state_t tcp_state_src;  /* TCP 源状态 - 4 bytes */
    ips_session_state_t tcp_state_dst;  /* TCP 目标状态 - 4 bytes */
    u32 flags;                      /* 会话标志 - 4 bytes */
    u32 session_index;              /* 会话索引 - 4 bytes */

    /* 管理信息 (16 bytes) */
    u32 thread_index;               /* 线程索引 - 4 bytes */
    u32 detection_flags;            /* 检测标志 - 4 bytes */
    u32 timer_handle;               /* 定时器句柄 - 4 bytes */
    u32 alert_count;                /* 告警数量 - 4 bytes */

    /* 第二个 cacheline: 中等频率访问的字段 (64字节) */
    CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);

    /* IPv6 地址 (32 bytes) */
    ip6_address_t src_ip6;          /* 源 IPv6 地址 - 16 bytes */
    ip6_address_t dst_ip6;          /* 目标 IPv6 地址 - 16 bytes */

      /* TCP 序列号跟踪 (16 bytes) */
  u32 tcp_seq_src;                /* TCP 源序列号 - 4 bytes */
  u32 tcp_seq_dst;                /* TCP 目标序列号 - 4 bytes */
  u32 tcp_ack_src;                /* TCP 源确认号 - 4 bytes */
  u32 tcp_ack_dst;                /* TCP 目标确认号 - 4 bytes */

  /* 统计信息 (16 bytes) */
  u64 packet_count_src;           /* 源方向报文数 - 8 bytes */
  u64 packet_count_dst;           /* 目标方向报文数 - 8 bytes */

} ips_session_t;

/* 静态断言：确保结构体大小是 2 个 cacheline (128字节) */
STATIC_ASSERT (sizeof (ips_session_t) == 128, "ips_session_t must be exactly 128 bytes (2 cache lines)");

/* 定时器统计结构 */
typedef struct
{
    u32 timers_started;             /* 启动的定时器数量 */
    u32 timers_expired;             /* 过期的定时器数量 */
    u32 timers_stopped;             /* 停止的定时器数量 */
    u32 timers_updated;             /* 更新的定时器数量 */
    u32 backup_scans;               /* 备用扫描次数 */
    u32 timer_wheel_checks;         /* 定时器轮检查次数 */
} ips_session_timer_stats_t;

/* 会话老化统计 */
typedef struct
{
    u64 expired_sessions;           /* 过期会话数量 */
    u64 forced_cleanup_sessions;    /* 强制清理会话数量 */
} ips_session_aging_stats_t;

/* 每线程会话数据 */
typedef struct
{
    /* 会话池 */
    ips_session_t *session_pool;

    /* IPv4 和 IPv6 哈希表 */
    clib_bihash_16_8_t ipv4_session_hash;
    clib_bihash_48_8_t ipv6_session_hash;

    /* 老化管理 */
    ips_session_aging_stats_t aging_stats;
    f64 last_cleanup_time;            /* 上次清理时间（CLI 调用限频） */

    /* 统计信息 */
    u64 total_sessions_created;
    u64 total_sessions_deleted;
    u64 total_packets_processed;
    u64 total_bytes_processed;

    /* 定时器检查状态 */
    f64 last_timer_check;             /* 上次检查定时器的时间 */

} ips_session_per_thread_data_t;

/* 全局会话管理器 */
typedef struct
{
    /* 每线程数据 */
    ips_session_per_thread_data_t *per_thread_data;

    /* 配置参数 */
    u32 session_pool_size;          /* 会话池大小 */
    u32 ipv4_hash_buckets;          /* IPv4 哈希桶数量 */
    u32 ipv6_hash_buckets;          /* IPv6 哈希桶数量 */
    u32 ipv4_hash_memory_size;      /* IPv4 哈希内存大小 */
    u32 ipv6_hash_memory_size;      /* IPv6 哈希内存大小 */

    /* 超时配置 */
    u32 tcp_syn_timeout;            /* TCP SYN 超时 */
    u32 tcp_established_timeout;    /* TCP 建立连接超时 */
    u32 tcp_fin_timeout;            /* TCP FIN 超时 */
    u32 tcp_rst_timeout;            /* TCP RST 超时 */

    /* 老化配置 */
    u32 aging_check_interval;       /* 老化检查间隔 */
    u32 aging_batch_size;           /* 老化批处理大小 */

    /* 统计开关 */
    u8 aging_stats_enabled;

} ips_session_manager_t;

extern ips_session_manager_t ips_session_manager;

/* 内联辅助函数 */

/**
 * @brief 计算 IPv4 会话键的哈希值
 */
static inline u32
ips_session_key4_hash (ips_session_key4_t * key)
{
    u32 hash = 0;

    hash = clib_xxhash (key->src_ip.as_u32);
    hash = clib_xxhash (hash ^ key->dst_ip.as_u32);
    hash = clib_xxhash (hash ^ ((u32) key->src_port << 16 | key->dst_port));
    hash = clib_xxhash (hash ^ key->protocol);

    return hash;
}

/**
 * @brief 计算 IPv6 会话键的哈希值
 */
static inline u32
ips_session_key6_hash (ips_session_key6_t * key)
{
    u32 hash = 0;

    hash = clib_xxhash (key->src_ip.as_u64[0]);
    hash = clib_xxhash (hash ^ key->src_ip.as_u64[1]);
    hash = clib_xxhash (hash ^ key->dst_ip.as_u64[0]);
    hash = clib_xxhash (hash ^ key->dst_ip.as_u64[1]);
    hash = clib_xxhash (hash ^ ((u32) key->src_port << 16 | key->dst_port));
    hash = clib_xxhash (hash ^ key->protocol);

    return hash;
}

/**
 * @brief 比较两个 IPv4 会话键是否相等
 */
static inline int
ips_session_key4_equal (ips_session_key4_t * k1, ips_session_key4_t * k2)
{
    return (k1->src_ip.as_u32 == k2->src_ip.as_u32 &&
            k1->dst_ip.as_u32 == k2->dst_ip.as_u32 &&
            k1->src_port == k2->src_port &&
            k1->dst_port == k2->dst_port &&
            k1->protocol == k2->protocol);
}

/**
 * @brief 比较两个 IPv6 会话键是否相等
 */
static inline int
ips_session_key6_equal (ips_session_key6_t * k1, ips_session_key6_t * k2)
{
    return (ip6_address_is_equal (&k1->src_ip, &k2->src_ip) &&
            ip6_address_is_equal (&k1->dst_ip, &k2->dst_ip) &&
            k1->src_port == k2->src_port &&
            k1->dst_port == k2->dst_port &&
            k1->protocol == k2->protocol);
}

/**
 * @brief 设置 IPv4 bihash 键值
 */
static inline void
ips_session_set_bihash_key4 (clib_bihash_kv_16_8_t * kv, ips_session_key4_t * key)
{
    kv->key[0] = key->src_ip.as_u32 | ((u64) key->dst_ip.as_u32 << 32);
    kv->key[1] = ((u64) key->protocol << 32) | ((u32) key->src_port << 16) | key->dst_port;
    kv->value = ~0ULL;
}

/**
 * @brief 设置 IPv6 bihash 键值
 */
static inline void
ips_session_set_bihash_key6 (clib_bihash_kv_48_8_t * kv, ips_session_key6_t * key)
{
    kv->key[0] = key->src_ip.as_u64[0];
    kv->key[1] = key->src_ip.as_u64[1];
    kv->key[2] = key->dst_ip.as_u64[0];
    kv->key[3] = key->dst_ip.as_u64[1];
    kv->key[4] = ((u64) key->protocol << 32) | ((u32) key->src_port << 16) | key->dst_port;
    kv->key[5] = 0;
    kv->value = ~0ULL;
}

/* 函数声明 */

/* 会话管理器初始化和清理 */
clib_error_t *ips_session_manager_init (vlib_main_t * vm);
void ips_session_manager_cleanup (void);

/* 每线程数据初始化 */
clib_error_t *ips_session_per_thread_init (u32 thread_index);
void ips_session_per_thread_cleanup (u32 thread_index);

/* 会话查找和管理 */
ips_session_t *ips_session_lookup_or_create_ipv4 (u32 thread_index,
                                                   ip4_header_t * ip4,
                                                   tcp_header_t * tcp);

ips_session_t *ips_session_lookup_or_create_ipv6 (u32 thread_index,
                                                   ip6_header_t * ip6,
                                                   tcp_header_t * tcp);

ips_session_t *ips_session_lookup_ipv4 (u32 thread_index,
                                         ips_session_key4_t * key);

ips_session_t *ips_session_lookup_ipv6 (u32 thread_index,
                                         ips_session_key6_t * key);

void ips_session_delete (u32 thread_index, ips_session_t * session);
void ips_session_delete_no_timer (u32 thread_index, ips_session_t * session);

/* 会话老化管理 */
void ips_session_aging_process (u32 thread_index);

typedef struct ips_session_force_cleanup_args_
{
    u32 thread_index;
    u32 target_count;
} ips_session_force_cleanup_args_t;
void ips_session_force_cleanup (const ips_session_force_cleanup_args_t *args);

typedef struct ips_session_cleanup_expired_args_
{
    u32 thread_index;
    f64 timeout;
} ips_session_cleanup_expired_args_t;
u32 ips_session_cleanup_expired (const ips_session_cleanup_expired_args_t *args);

/* 统计信息 */
typedef struct ips_session_get_stats_args_
{
    u32 thread_index;
    u32 *active_sessions;
    u32 *total_created;
    u32 *total_deleted;
} ips_session_get_stats_args_t;
void ips_session_get_stats (const ips_session_get_stats_args_t *args);

void ips_session_get_aging_stats (u32 thread_index,
                                   ips_session_aging_stats_t * stats);

/* 配置接口 */
typedef struct ips_session_set_timeouts_args_
{
    u32 syn_timeout;
    u32 established_timeout;
    u32 fin_timeout;
    u32 rst_timeout;
} ips_session_set_timeouts_args_t;
void ips_session_set_timeouts (const ips_session_set_timeouts_args_t *args);

typedef struct ips_session_set_aging_config_args_
{
    u32 check_interval;
    u32 batch_size;
} ips_session_set_aging_config_args_t;
void ips_session_set_aging_config (const ips_session_set_aging_config_args_t *args);

#endif /* __IPS_SESSION_H__ */
