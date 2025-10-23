# IPS Session Module - VPP IPS Plugin Session Management

## 概述

IPS Session 模块是 VPP IPS 插件的核心会话管理系统，提供高效的五元组会话跟踪、状态管理和超时处理功能。该模块支持 IPv4/IPv6 双栈协议，提供精确的会话识别和管理能力，为 IPS 系统的检测和阻断功能提供基础支撑。

## 架构设计

### 核心组件

```
IPS Session 架构
├── 会话管理器 (ips_session_manager_t)
│   ├── 线程本地会话池
│   ├── 全局会话统计
│   ├── 配置管理
│   └── 生命周期管理
├── 会话数据结构 (ips_session_t)
│   ├── 五元组键值
│   ├── 协议状态信息
│   ├── 计时器和超时
│   └── 统计和元数据
├── 会话键值管理
│   ├── IPv4/IPv6 支持
│   ├── 协议适配
│   └── 哈希优化
└── 计时器系统
    ├── 超时管理
    ├── 批量清理
    └── 性能优化
```

### 数据结构

#### 会话管理器
```c
typedef struct {
    /* 线程本地会话池 */
    ips_session_per_thread_data_t *per_thread_data;
    u32 num_threads;

    /* 全局统计 */
    u64 total_sessions_created;
    u64 total_sessions_destroyed;
    u64 current_active_sessions;

    /* 配置参数 */
    u32 max_sessions_per_thread;
    u32 default_session_timeout;
    u32 cleanup_interval;
    u8 enable_session_tracking;

    /* 内存管理 */
    clib_mem_heap_t *session_heap;
    clib_spinlock_t stats_lock;
} ips_session_manager_t;
```

#### 会话结构
```c
typedef struct {
    /* 会话标识 */
    ips_session_key_t key;             /* 五元组键值 */
    u32 session_id;                    /* 会话 ID */
    u32 thread_index;                  /* 线程索引 */

    /* 协议状态 */
    u8 protocol;                       /* 协议类型 */
    u8 ip_version;                     /* IP 版本 */
    u8 tcp_state;                      /* TCP 状态 */
    u8 session_state;                  /* 会话状态 */

    /* 时间信息 */
    f64 create_time;                   /* 创建时间 */
    f64 last_packet_time;              /* 最后包时间 */
    f64 expiry_time;                   /* 过期时间 */
    u32 timeout_handle;                /* 超时句柄 */

    /* 计数器 */
    u64 packet_count;                  /* 包计数 */
    u64 byte_count;                    /* 字节计数 */
    u64 syn_count;                     /* SYN 计数 */
    u64 fin_count;                     /* FIN 计数 */
    u64 rst_count;                     /* RST 计数 */

    /* 元数据 */
    u8 flags;                          /* 标志位 */
    u8 priority;                       /* 优先级 */
    u16 padding;                       /* 填充 */

    /* 扩展数据 */
    void *extension_data;              /* 扩展数据指针 */
} ips_session_t;
```

#### 会话键值
```c
typedef struct {
    /* 五元组 */
    ip46_address_t src_ip;             /* 源 IP 地址 */
    ip46_address_t dst_ip;             /* 目标 IP 地址 */
    u16 src_port;                      /* 源端口 */
    u16 dst_port;                      /* 目标端口 */
    u8 protocol;                       /* 协议类型 */
    u8 ip_version;                     /* IP 版本 */
    u8 padding[2];                     /* 填充 */
} ips_session_key_t;
```

## 核心功能

### 1. 会话创建和管理

提供高效的会话创建、查找和销毁功能：

```c
/* 创建新会话 */
int ips_session_create(ips_session_t **session,
                     u32 thread_index,
                     ips_session_key_t *key,
                     vlib_buffer_t *b)
{
    ips_session_per_thread_data_t *ptd = &session_manager.per_thread_data[thread_index];

    /* 检查会话数量限制 */
    if (pool_len(ptd->session_pool) >= session_manager.max_sessions_per_thread)
        return IPS_SESSION_ERROR_LIMIT_EXCEEDED;

    /* 分配会话结构 */
    pool_get_zero(ptd->session_pool, *session);

    /* 初始化会话数据 */
    (*session)->session_id = ++ptd->next_session_id;
    (*session)->thread_index = thread_index;
    (*session)->key = *key;
    (*session)->create_time = vlib_time_now(vlib_get_main());
    (*session)->last_packet_time = (*session)->create_time;
    (*session)->expiry_time = (*session)->create_time + session_manager.default_session_timeout;

    /* 从包中提取协议信息 */
    ips_session_extract_packet_info(*session, b);

    /* 添加到哈希表 */
    ips_session_hash_add(ptd, *session);

    /* 设置超时计时器 */
    ips_session_timer_set(*session);

    /* 更新统计 */
    ptd->stats.sessions_created++;
    session_manager.total_sessions_created++;

    return IPS_SESSION_SUCCESS;
}
```

### 2. 高效会话查找

使用优化的哈希算法实现快速会话查找：

```c
/* 查找会话 */
int ips_session_lookup(ips_session_t **session,
                     u32 thread_index,
                     ips_session_key_t *key)
{
    ips_session_per_thread_data_t *ptd = &session_manager.per_thread_data[thread_index];

    /* 从哈希表查找 */
    clib_bihash_kv_48_8_t kv, value;
    ips_session_key_to_hash_key(key, &kv);

    if (clib_bihash_search_48_8(&ptd->session_hash, &kv, &value) == 0) {
        *session = uword_to_pointer(value.value, ips_session_t *);

        /* 更新访问时间 */
        (*session)->last_packet_time = vlib_time_now(vlib_get_main());

        /* 更新统计 */
        ptd->stats.sessions_lookup++;
        ptd->stats.sessions_hit++;

        return IPS_SESSION_SUCCESS;
    }

    ptd->stats.sessions_lookup++;
    ptd->stats.sessions_miss++;
    return IPS_SESSION_ERROR_NOT_FOUND;
}
```

### 3. 会话状态管理

支持 TCP 状态机和会话生命周期管理：

```c
/* 更新会话状态 */
int ips_session_update_state(ips_session_t *session,
                           vlib_buffer_t *b,
                           ips_session_event_t event)
{
    /* 提取协议信息 */
    ips_session_packet_info_t pkt_info;
    ips_session_extract_packet_info_extended(b, &pkt_info);

    /* 更新计数器 */
    session->packet_count++;
    session->byte_count += pkt_info.length;
    session->last_packet_time = vlib_time_now(vlib_get_main());

    /* TCP 状态机更新 */
    if (session->protocol == IP_PROTOCOL_TCP) {
        ips_session_update_tcp_state(session, &pkt_info, event);
    }

    /* 延长会话超时 */
    ips_session_extend_timeout(session);

    /* 检查会话状态转换 */
    ips_session_check_state_transition(session, event);

    return IPS_SESSION_SUCCESS;
}
```

### 4. 超时管理和清理

实现高效的超时检测和批量清理机制：

```c
/* 会话超时处理 */
void ips_session_timeout_handler(u32 *session_indices, u32 count)
{
    f64 now = vlib_time_now(vlib_get_main());

    for (u32 i = 0; i < count; i++) {
        ips_session_t *session;
        u32 session_index = session_indices[i];
        u32 thread_index = session->thread_index;

        /* 查找会话 */
        if (ips_session_get_by_index(thread_index, session_index, &session) == 0) {
            /* 检查是否真正超时 */
            if (session->expiry_time <= now) {
                /* 清理会话 */
                ips_session_destroy(session);
            } else {
                /* 重新调度计时器 */
                ips_session_timer_set(session);
            }
        }
    }
}
```

### 5. 协议适配

支持多种协议的会话跟踪：

```c
/* 从包中提取协议信息 */
void ips_session_extract_packet_info(ips_session_t *session, vlib_buffer_t *b)
{
    ethernet_header_t *eth = vlib_buffer_get_current(b);
    u8 *packet_data = (u8 *)eth + sizeof(ethernet_header_t);

    if (session->ip_version == 4) {
        ip4_header_t *ip4 = (ip4_header_t *)packet_data;
        session->protocol = ip4->protocol;

        if (session->protocol == IP_PROTOCOL_TCP) {
            tcp_header_t *tcp = (tcp_header_t *)((u8 *)ip4 + ip4_header_bytes(ip4));
            session->tcp_state = ips_session_get_tcp_state(tcp->flags);
        }
    } else {
        ip6_header_t *ip6 = (ip6_header_t *)packet_data;
        session->protocol = ip6->protocol;

        if (session->protocol == IP_PROTOCOL_TCP) {
            tcp_header_t *tcp = (tcp_header_t *)((u8 *)ip6 + sizeof(ip6_header_t));
            session->tcp_state = ips_session_get_tcp_state(tcp->flags);
        }
    }
}
```

## 配置和使用

### 配置参数

```c
/* 默认配置值 */
#define IPS_SESSION_DEFAULT_MAX_SESSIONS      65536
#define IPS_SESSION_DEFAULT_TIMEOUT          300    /* 5 分钟 */
#define IPS_SESSION_DEFAULT_CLEANUP_INTERVAL 60     /* 1 分钟 */
#define IPS_SESSION_DEFAULT_TCP_TIMEOUT      3600   /* 1 小时 */
#define IPS_SESSION_DEFAULT_UDP_TIMEOUT      30     /* 30 秒 */
```

### CLI 命令

#### 会话管理
```bash
# 显示会话统计信息
show ips session stats

# 显示活跃会话
show ips session active

# 显示特定协议会话
show ips session protocol tcp
show ips session protocol udp

# 显示会话详细信息
show ips session details <session-id>

# 清理过期会话
clear ips session expired

# 手动销毁会话
clear ips session <session-id>
```

#### 配置管理
```bash
# 配置最大会话数
set ips session max-sessions 100000

# 配置默认超时时间
set ips session timeout 600

# 配置清理间隔
set ips session cleanup-interval 120

# 启用/禁用会话跟踪
set ips session tracking enable
set ips session tracking disable

# 配置协议特定超时
set ips session tcp-timeout 7200
set ips session udp-timeout 60
```

#### 调试功能
```bash
# 启用会话调试
set ips session debug on

# 显示会话哈希表状态
show ips session hash-table

# 显示会话内存使用
show ips session memory

# 跟踪特定会话
trace ips session <session-id>
```

### 使用示例

#### 基础会话跟踪
```c
/* 在节点处理中跟踪会话 */
static uword ips_session_node_fn(vlib_main_t *vm,
                                vlib_node_runtime_t *node,
                                vlib_frame_t *frame)
{
    u32 *buffers = vlib_frame_vector_args(frame);
    u32 n_buffers = frame->n_vectors;

    for (u32 i = 0; i < n_buffers; i++) {
        vlib_buffer_t *b = vlib_get_buffer(vm, buffers[i]);
        ips_session_key_t key;
        ips_session_t *session;
        u32 thread_index = vlib_get_worker_index(vm);

        /* 提取会话键值 */
        ips_session_extract_key(b, &key);

        /* 查找或创建会话 */
        if (ips_session_lookup(&session, thread_index, &key) != 0) {
            if (ips_session_create(&session, thread_index, &key, b) == 0) {
                /* 新会话创建成功 */
                clib_warning("New session created: %U", format_session_key, &key);
            }
        }

        if (session) {
            /* 更新会话状态 */
            ips_session_update_state(session, b, IPS_SESSION_EVENT_PACKET);

            /* 会话处理逻辑 */
            process_session_packet(session, b);
        }
    }

    return n_buffers;
}
```

#### 与其他模块集成
```c
/* 与 ACL 模块集成 */
int ips_session_acl_check(ips_session_t *session, vlib_buffer_t *b)
{
    /* 检查会话级别的 ACL 决策 */
    if (session->flags & IPS_SESSION_FLAG_BLOCKED) {
        return IPS_ACL_ACTION_DENY;
    }

    /* 调用 ACL 模块进行检查 */
    ips_acl_action_t action;
    ips_acl_check_packet(session->thread_index, session, NULL, NULL, NULL, &action);

    /* 应用 ACL 决策到会话 */
    if (action == IPS_ACL_ACTION_DENY) {
        session->flags |= IPS_SESSION_FLAG_BLOCKED;
        ips_session_timer_set(session, 10); /* 10 秒后清理 */
    }

    return action;
}
```

## 性能优化

### 内存管理优化

```c
/* 线程本地内存池 */
typedef struct {
    /* 会话池 */
    ips_session_t *session_pool;

    /* 哈希表 */
    clib_bihash_48_8_t session_hash;

    /* 计时器池 */
    ips_session_timer_t *timer_pool;

    /* 统计信息 */
    ips_session_stats_t stats;
} ips_session_per_thread_data_t;
```

### 哈希优化

```c
/* 优化的键值哈希函数 */
static u32 ips_session_key_hash(ips_session_key_t *key)
{
    u32 hash = 0;

    /* 混合 IP 地址 */
    hash ^= clib_net_to_host_u32(key->src_ip.ip4.as_u32);
    hash ^= clib_net_to_host_u32(key->dst_ip.ip4.as_u32);

    /* 混合端口 */
    hash ^= (key->src_port << 16) | key->dst_port;

    /* 混合协议 */
    hash ^= key->protocol;

    return hash;
}
```

### 批量操作优化

```c
/* 批量会话清理 */
void ips_session_cleanup_batch(u32 thread_index)
{
    ips_session_per_thread_data_t *ptd = &session_manager.per_thread_data[thread_index];
    f64 now = vlib_time_now(vlib_get_main());
    u32 cleanup_count = 0;
    u32 cleanup_batch[128];

    /* 扫描会话池，收集过期会话 */
    pool_foreach(session, ptd->session_pool) {
        if (session->expiry_time <= now) {
            cleanup_batch[cleanup_count++] = session->session_index;

            if (cleanup_count >= 128) {
                /* 批量清理 */
                ips_session_destroy_batch(cleanup_batch, cleanup_count);
                cleanup_count = 0;
            }
        }
    }

    /* 清理剩余会话 */
    if (cleanup_count > 0) {
        ips_session_destroy_batch(cleanup_batch, cleanup_count);
    }
}
```

## 监控和统计

### 统计指标

```c
typedef struct {
    /* 会话统计 */
    u64 sessions_created;              /* 创建的会话数 */
    u64 sessions_destroyed;            /* 销毁的会话数 */
    u64 sessions_active;               /* 活跃会话数 */
    u64 sessions_expired;              /* 过期会话数 */
    u64 sessions_timeout;              /* 超时会话数 */

    /* 查找统计 */
    u64 sessions_lookup;               /* 查找次数 */
    u64 sessions_hit;                  /* 命中次数 */
    u64 sessions_miss;                 /* 未命中次数 */

    /* 协议统计 */
    u64 tcp_sessions;                  /* TCP 会话数 */
    u64 udp_sessions;                  /* UDP 会话数 */
    u64 icmp_sessions;                 /* ICMP 会话数 */

    /* 性能统计 */
    u64 avg_session_lifetime;          /* 平均会话生存时间 */
    u64 max_concurrent_sessions;       /* 最大并发会话数 */
    u64 memory_usage;                  /* 内存使用量 */
} ips_session_stats_t;
```

### CLI 统计显示

```bash
# 显示详细统计
show ips session stats

# 输出示例：
IPS Session Statistics:
  Session Management:
    Total Sessions Created:  1,234,567
    Total Sessions Destroyed: 1,200,000
    Current Active Sessions: 34,567
    Sessions Expired:       23,456
    Sessions Timeout:       1,111

  Lookup Performance:
    Total Lookups:          5,678,901
    Cache Hits:             5,500,123
    Cache Misses:           178,778
    Hit Rate:               96.85%

  Protocol Distribution:
    TCP Sessions:           28,901
    UDP Sessions:           5,234
    ICMP Sessions:          432

  Performance Metrics:
    Avg Session Lifetime:   245.67 seconds
    Max Concurrent Sessions: 45,678
    Memory Usage:           12.34 MB
```

## 集成接口

### 与检测引擎集成

```c
/* 检测引擎获取会话上下文 */
ips_session_context_t *ips_detection_get_session_context(vlib_buffer_t *b)
{
    ips_session_key_t key;
    ips_session_t *session;
    u32 thread_index = vlib_get_worker_index(vlib_get_main());

    /* 提取会话键值 */
    ips_session_extract_key(b, &key);

    /* 查找会话 */
    if (ips_session_lookup(&session, thread_index, &key) == 0) {
        return &session->detection_context;
    }

    return NULL;
}
```

### 与阻断模块集成

```c
/* 阻断模块获取会话信息 */
int ips_block_get_session_info(u32 session_id,
                              ips_session_info_t *info)
{
    ips_session_t *session;

    /* 通过 ID 查找会话 */
    if (ips_session_get_by_id(session_id, &session) == 0) {
        info->key = session->key;
        info->created_time = session->create_time;
        info->packet_count = session->packet_count;
        info->byte_count = session->byte_count;
        info->tcp_state = session->tcp_state;

        return 0;
    }

    return -1;
}
```

### 与日志系统集成

```c
/* 日志系统记录会话事件 */
void ips_log_session_event(ips_session_t *session,
                          ips_log_event_type_t event_type,
                          const char *description)
{
    ips_log_entry_t log_entry;

    log_entry.timestamp = vlib_time_now(vlib_get_main());
    log_entry.session_id = session->session_id;
    log_entry.event_type = event_type;
    log_entry.session_key = session->key;
    log_entry.packet_count = session->packet_count;
    strncpy(log_entry.description, description, sizeof(log_entry.description) - 1);

    ips_log_write(&log_entry);
}
```

## 故障排除

### 常见问题

1. **会话创建失败**
   - 检查会话数量限制
   - 验证内存分配
   - 确认键值提取正确

2. **会话查找性能差**
   - 监控哈希冲突率
   - 检查键值分布
   - 优化哈希函数

3. **会话泄漏**
   - 监控会话生命周期
   - 检查超时机制
   - 验证清理逻辑

### 调试命令

```bash
# 显示会话创建/销毁跟踪
debug ips session create
debug ips session destroy

# 显示哈希表详细信息
show ips session hash-detail

# 监控会话性能
monitor ips session performance

# 转储会话表
dump ips session table
```

## API 参考

### 核心函数
- `ips_session_init()` - 初始化会话模块
- `ips_session_create()` - 创建新会话
- `ips_session_lookup()` - 查找会话
- `ips_session_update_state()` - 更新会话状态
- `ips_session_destroy()` - 销毁会话
- `ips_session_extract_key()` - 提取会话键值

### 数据结构
- `ips_session_manager_t` - 会话管理器
- `ips_session_t` - 会话结构
- `ips_session_key_t` - 会话键值
- `ips_session_stats_t` - 统计信息

### 回调函数
- `ips_session_timeout_callback()` - 超时回调
- `ips_session_state_change_callback()` - 状态变化回调
- `ips_session_cleanup_callback()` - 清理回调

## 版本历史

- **v1.0.0** - 基础会话管理功能
- **v1.1.0** - TCP 状态机支持
- **v1.2.0** - 性能优化和批量处理
- **v1.3.0** - 多协议支持扩展
- **v2.0.0** - 线程本地优化和内存管理改进

## 许可证

Copyright (c) 2024 VPP IPS Project
Licensed under the Apache License, Version 2.0