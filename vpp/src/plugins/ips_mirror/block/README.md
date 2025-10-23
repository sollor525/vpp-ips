# IPS Block Module - VPP IPS Plugin Blocking System

## 概述

IPS Block 模块是 VPP IPS 插件的阻断系统，提供多种网络攻击响应和阻断机制。该模块支持 TCP Reset、ICMP 不可达、包丢弃等多种阻断方式，集成了速率限制、统计监控和策略管理功能，为 IPS 系统提供全面的安全响应能力。

## 架构设计

### 核心组件

```
IPS Block 架构
├── 阻断管理器 (ips_block_manager_t)
│   ├── 阻断策略管理
│   ├── 速率限制控制
│   ├── 统计信息收集
│   └── 配置参数管理
├── 阻断动作引擎
│   ├── TCP Reset 生成
│   ├── ICMP 错误包生成
│   ├── 包丢弃处理
│   └── 自定义动作支持
├── 会话阻断系统
│   ├── 会话级阻断
│   ├── 连接状态管理
│   ├── 超时处理
│   └── 状态同步
└── 速率限制器
    ├── 令牌桶算法
    ├── 滑动窗口计数
    ├── 动态调整
    └── 阈值管理
```

### 数据结构

#### 阻断管理器
```c
typedef struct {
    /* 阻断配置 */
    u8 reset_enabled;                  /* TCP Reset 启用 */
    u8 icmp_enabled;                   /* ICMP 启用 */
    u8 drop_enabled;                   /* 丢弃启用 */
    u8 custom_enabled;                 /* 自定义动作启用 */

    /* 速率限制 */
    ips_block_rate_limiter_t reset_limiter;
    ips_block_rate_limiter_t icmp_limiter;
    ips_block_rate_limiter_t drop_limiter;

    /* 会话阻断 */
    ips_block_session_table_t session_table;
    u32 session_block_timeout;         /* 会话阻断超时 */

    /* 统计信息 */
    ips_block_stats_t *per_thread_stats;
    u32 num_threads;

    /* 策略管理 */
    ips_block_policy_t *policies;
    u32 default_policy_id;

    /* 内存管理 */
    clib_mem_heap_t *block_heap;
} ips_block_manager_t;
```

#### 阻断动作结构
```c
typedef struct {
    u32 action_id;                     /* 动作 ID */
    ips_block_action_type_t type;      /* 动作类型 */
    u8 enabled;                        /* 启用标志 */

    /* 动作参数 */
    union {
        struct {
            u8 send_reset;             /* 发送 Reset */
            u8 send_to_source;         /* 向源发送 */
            u8 send_to_destination;    /* 向目标发送 */
            u8 reset_reason;           /* Reset 原因 */
        } tcp_reset;

        struct {
            u8 icmp_type;              /* ICMP 类型 */
            u8 icmp_code;              /* ICMP 代码 */
            u8 send_to_source;         /* 向源发送 */
            char custom_message[64];   /* 自定义消息 */
        } icmp_error;

        struct {
            u8 silent_drop;            /* 静默丢弃 */
            u8 log_drop;               /* 记录丢弃 */
            u8 send_feedback;          /* 发送反馈 */
        } drop_action;

        struct {
            u32 custom_handler_id;     /* 自定义处理器 ID */
            void *custom_data;         /* 自定义数据 */
            u32 custom_data_len;       /* 自定义数据长度 */
        } custom_action;
    } params;

    /* 速率限制 */
    ips_block_rate_limit_t rate_limit;

    /* 统计 */
    u64 action_count;                  /* 动作计数 */
    u64 last_action_time;              /* 最后动作时间 */
} ips_block_action_t;
```

#### 阻断统计信息
```c
typedef struct {
    /* 总体统计 */
    u64 total_blocks;                  /* 总阻断数 */
    u64 total_resets_sent;             /* 总 Reset 发送数 */
    u64 total_icmp_sent;               /* 总 ICMP 发送数 */
    u64 total_drops;                   /* 总丢弃数 */

    /* 会话统计 */
    u64 sessions_blocked;              /* 会话阻断数 */
    u64 sessions_unblocked;            /* 会话解封数 */
    u64 active_blocked_sessions;       /* 活跃阻断会话数 */

    /* 协议统计 */
    u64 tcp_blocks;                    /* TCP 阻断数 */
    u64 udp_blocks;                    /* UDP 阻断数 */
    u64 icmp_blocks;                   /* ICMP 阻断数 */

    /* 速率限制统计 */
    u64 rate_limit_blocks;             /* 速率限制阻断数 */
    u64 rate_limit_exceeded;           /* 速率限制超出数 */

    /* 错误统计 */
    u64 block_errors;                  /* 阻断错误数 */
    u64 send_errors;                   /* 发送错误数 */
    u64 resource_errors;               /* 资源错误数 */
} ips_block_stats_t;
```

## 核心功能

### 1. TCP Reset 阻断

实现精确的 TCP 连接重置功能：

```c
/* 发送 TCP Reset 包 */
int ips_block_send_tcp_reset(u32 thread_index,
                           ips_session_t *session,
                           u8 direction,
                           ips_block_reset_reason_t reason)
{
    ips_block_manager_t *bm = &block_manager;
    ips_block_stats_t *stats = &bm->per_thread_stats[thread_index];

    /* 检查速率限制 */
    if (ips_block_rate_limit_check(&bm->reset_limiter, thread_index) != 0) {
        stats->rate_limit_blocks++;
        return IPS_BLOCK_ERROR_RATE_LIMITED;
    }

    /* 构造 TCP Reset 包 */
    vlib_buffer_t *reset_buf;
    if (ips_block_create_tcp_reset_packet(&reset_buf, session, direction) != 0) {
        stats->send_errors++;
        return IPS_BLOCK_ERROR_CREATE_FAILED;
    }

    /* 发送包 */
    if (ips_block_send_packet(thread_index, reset_buf) != 0) {
        stats->send_errors++;
        return IPS_BLOCK_ERROR_SEND_FAILED;
    }

    /* 更新统计 */
    stats->total_resets_sent++;
    stats->tcp_blocks++;

    /* 记录日志 */
    clib_warning("TCP Reset sent: session=%u direction=%s reason=%d",
                session->session_id,
                direction == IPS_BLOCK_DIRECTION_TO_SOURCE ? "to_source" : "to_dest",
                reason);

    return IPS_BLOCK_SUCCESS;
}

/* 创建 TCP Reset 包 */
int ips_block_create_tcp_reset_packet(vlib_buffer_t **buf,
                                    ips_session_t *session,
                                    u8 direction)
{
    vlib_main_t *vm = vlib_get_main();

    /* 分配缓冲区 */
    *buf = vlib_buffer_alloc(vm, 1);
    if (!*buf)
        return -1;

    vlib_buffer_t *b = *buf;
    ethernet_header_t *eth;
    ip4_header_t *ip4;
    ip6_header_t *ip6;
    tcp_header_t *tcp;

    /* 根据会话 IP 版本构造包 */
    if (session->key.ip_version == 4) {
        /* IPv4 TCP Reset */
        ips_block_build_ipv4_tcp_reset(b, session, direction);
    } else {
        /* IPv6 TCP Reset */
        ips_block_build_ipv6_tcp_reset(b, session, direction);
    }

    return 0;
}
```

### 2. ICMP 错误响应

提供灵活的 ICMP 错误包生成：

```c
/* 发送 ICMP 不可达消息 */
int ips_block_send_icmp_unreachable(u32 thread_index,
                                   ips_session_t *session,
                                   u8 icmp_code,
                                   const char *message)
{
    ips_block_manager_t *bm = &block_manager;
    ips_block_stats_t *stats = &bm->per_thread_stats[thread_index];

    /* 检查 ICMP 是否启用 */
    if (!bm->icmp_enabled)
        return IPS_BLOCK_ERROR_DISABLED;

    /* 检查速率限制 */
    if (ips_block_rate_limit_check(&bm->icmp_limiter, thread_index) != 0) {
        stats->rate_limit_blocks++;
        return IPS_BLOCK_ERROR_RATE_LIMITED;
    }

    /* 构造 ICMP 包 */
    vlib_buffer_t *icmp_buf;
    if (ips_block_create_icmp_packet(&icmp_buf, session, ICMP_UNREACHABLE, icmp_code, message) != 0) {
        stats->send_errors++;
        return IPS_BLOCK_ERROR_CREATE_FAILED;
    }

    /* 发送包 */
    if (ips_block_send_packet(thread_index, icmp_buf) != 0) {
        stats->send_errors++;
        return IPS_BLOCK_ERROR_SEND_FAILED;
    }

    /* 更新统计 */
    stats->total_icmp_sent++;
    stats->icmp_blocks++;

    /* 记录日志 */
    clib_warning("ICMP Unreachable sent: session=%u code=%d message=%s",
                session->session_id, icmp_code, message ? message : "");

    return IPS_BLOCK_SUCCESS;
}
```

### 3. 会话级阻断

实现基于会话的阻断管理：

```c
/* 阻断会话 */
int ips_block_session(ips_session_t *session,
                     ips_block_action_t action,
                     u32 timeout)
{
    ips_block_manager_t *bm = &block_manager;
    ips_block_session_entry_t *entry;
    u32 thread_index = session->thread_index;

    /* 创建会话阻断条目 */
    pool_get_zero(bm->session_table.entries, entry);
    entry->session_id = session->session_id;
    entry->action = action;
    entry->block_time = vlib_time_now(vlib_get_main());
    entry->expiry_time = entry->block_time + timeout;
    entry->thread_index = thread_index;

    /* 复制会话键值 */
    entry->key = session->key;

    /* 添加到哈希表 */
    clib_bihash_kv_48_8_t kv;
    ips_session_key_to_hash_key(&session->key, &kv);
    kv.value = pointer_to_uword(entry);
    clib_bihash_add_del_48_8(&bm->session_table.hash, &kv, 1);

    /* 立即执行阻断动作 */
    ips_block_execute_action(session, &action);

    /* 设置超时计时器 */
    ips_block_session_timer_set(entry);

    /* 更新统计 */
    bm->per_thread_stats[thread_index].sessions_blocked++;
    bm->per_thread_stats[thread_index].active_blocked_sessions++;

    clib_warning("Session blocked: session=%u action=%d timeout=%u",
                session->session_id, action.type, timeout);

    return IPS_BLOCK_SUCCESS;
}

/* 检查会话是否被阻断 */
int ips_block_is_session_blocked(u32 thread_index,
                                ips_session_key_t *key,
                                ips_block_action_t **action)
{
    ips_block_manager_t *bm = &block_manager;
    clib_bihash_kv_48_8_t kv, value;

    /* 查找会话阻断条目 */
    ips_session_key_to_hash_key(key, &kv);
    if (clib_bihash_search_48_8(&bm->session_table.hash, &kv, &value) == 0) {
        ips_block_session_entry_t *entry = uword_to_pointer(value.value, ips_block_session_entry_t *);

        /* 检查是否过期 */
        f64 now = vlib_time_now(vlib_get_main());
        if (entry->expiry_time > now) {
            if (action)
                *action = &entry->action;
            return 1; /* 会话被阻断 */
        } else {
            /* 清理过期条目 */
            ips_block_session_entry_remove(entry);
        }
    }

    if (action)
        *action = NULL;
    return 0; /* 会话未被阻断 */
}
```

### 4. 速率限制

实现基于令牌桶算法的速率控制：

```c
/* 令牌桶速率限制器 */
typedef struct {
    u64 capacity;                      /* 桶容量 */
    u64 rate;                          /* 生成速率 (tokens/second) */
    u64 tokens;                        /* 当前令牌数 */
    f64 last_refill_time;              /* 上次填充时间 */

    /* 统计 */
    u64 total_requests;                /* 总请求数 */
    u64 allowed_requests;              /* 允许的请求数 */
    u64 denied_requests;               /* 拒绝的请求数 */
} ips_block_token_bucket_t;

/* 检查速率限制 */
int ips_block_rate_limit_check(ips_block_rate_limiter_t *limiter,
                              u32 thread_index)
{
    ips_block_token_bucket_t *bucket = &limiter->buckets[thread_index];
    f64 now = vlib_time_now(vlib_get_main());

    /* 填充令牌 */
    f64 time_diff = now - bucket->last_refill_time;
    if (time_diff > 0) {
        u64 new_tokens = (u64)(time_diff * bucket->rate);
        bucket->tokens = CLIB_MIN(bucket->capacity, bucket->tokens + new_tokens);
        bucket->last_refill_time = now;
    }

    bucket->total_requests++;

    /* 检查是否有足够令牌 */
    if (bucket->tokens >= 1) {
        bucket->tokens--;
        bucket->allowed_requests++;
        return 0; /* 允许 */
    } else {
        bucket->denied_requests++;
        return -1; /* 拒绝 */
    }
}
```

### 5. 策略管理

提供灵活的阻断策略配置：

```c
/* 阻断策略结构 */
typedef struct {
    u32 policy_id;                     /* 策略 ID */
    char name[64];                     /* 策略名称 */
    char description[256];             /* 策略描述 */

    /* 策略条件 */
    ips_block_condition_t conditions;  /* 阻断条件 */

    /* 策略动作 */
    ips_block_action_t action;         /* 阻断动作 */

    /* 策略参数 */
    u32 priority;                      /* 优先级 */
    u32 timeout;                       /* 超时时间 */
    u8 enabled;                        /* 启用标志 */

    /* 统计 */
    u64 match_count;                   /* 匹配次数 */
    u64 action_count;                  /* 动作次数 */
    f64 last_match_time;               /* 最后匹配时间 */
} ips_block_policy_t;

/* 应用阻断策略 */
int ips_block_apply_policy(ips_session_t *session,
                          vlib_buffer_t *b,
                          ips_block_policy_t *policy)
{
    /* 检查策略条件 */
    if (ips_block_policy_match(policy, session, b) != 0) {
        /* 条件匹配，执行策略动作 */
        int result = ips_block_execute_action(session, &policy->action);

        /* 更新统计 */
        policy->match_count++;
        policy->action_count++;
        policy->last_match_time = vlib_time_now(vlib_get_main());

        clib_warning("Policy applied: policy=%u (%s) session=%u result=%d",
                    policy->policy_id, policy->name, session->session_id, result);

        return result;
    }

    return IPS_BLOCK_ERROR_NO_MATCH;
}
```

## 配置和使用

### CLI 命令

#### 基础阻断配置
```bash
# 启用 TCP Reset 功能
set ips block reset enable

# 配置 TCP Reset 参数
set ips block reset send-to-source on
set ips block reset send-to-destination on

# 启用 ICMP 错误响应
set ips block icmp enable

# 配置 ICMP 参数
set ips block icmp type unreachable
set ips block icmp code port-unreachable

# 启用包丢弃
set ips block drop enable
set ips block drop silent on
```

#### 速率限制配置
```bash
# 配置 TCP Reset 速率限制
set ips block rate-limit reset 100 per-second
set ips block rate-limit reset burst 200

# 配置 ICMP 速率限制
set ips block rate-limit icmp 50 per-minute
set ips block rate-limit icmp burst 100

# 配置包丢弃速率限制
set ips block rate-limit drop 1000 per-second
set ips block rate-limit drop burst 5000
```

#### 会话阻断配置
```bash
# 配置会话阻断超时
set ips block session-timeout 300

# 手动阻断会话
block ips session <session-id> action reset timeout 600

# 查看活跃阻断会话
show ips block sessions

# 解除会话阻断
unblock ips session <session-id>
```

#### 策略管理
```bash
# 创建阻断策略
create ips block policy "Block Malicious IPs"
set ips block policy "Block Malicious IPs" description "Block connections from known malicious IPs"
set ips block policy "Block Malicious IPs" condition src-ip 192.168.1.100/32
set ips block policy "Block Malicious IPs" action reset
set ips block policy "Block Malicious IPs" timeout 3600
set ips block policy "Block Malicious IPs" enable

# 查看策略列表
show ips block policies

# 应用策略
apply ips block policy "Block Malicious IPs" to session <session-id>

# 删除策略
delete ips block policy "Block Malicious IPs"
```

#### 统计和监控
```bash
# 查看阻断统计
show ips block stats

# 查看特定线程统计
show ips block stats thread 1

# 查看速率限制统计
show ips block rate-limits

# 重置统计
reset ips block stats
```

### 使用示例

#### 简单阻断操作
```c
/* 在检测到威胁时执行阻断 */
int ips_detection_handle_threat(ips_session_t *session,
                               ips_threat_type_t threat_type)
{
    switch (threat_type) {
        case IPS_THREAT_MALWARE:
            /* 恶意软件：发送 TCP Reset 并阻断会话 */
            ips_block_send_tcp_reset(session->thread_index, session,
                                   IPS_BLOCK_DIRECTION_TO_SOURCE,
                                   IPS_BLOCK_REASON_MALWARE);
            ips_block_session(session, create_reset_action(), 3600);
            break;

        case IPS_THREAT_PORT_SCAN:
            /* 端口扫描：发送 ICMP 不可达 */
            ips_block_send_icmp_unreachable(session->thread_index, session,
                                          ICMP_UNREACHABLE_PORT,
                                          "Port scan detected");
            break;

        case IPS_THREAT_DOS_ATTACK:
            /* DoS 攻击：静默丢弃包 */
            ips_block_drop_packet(session->thread_index, session);
            break;

        default:
            break;
    }

    return 0;
}
```

#### 策略驱动阻断
```c
/* 基于策略的阻断处理 */
int ips_block_policy_handler(ips_session_t *session,
                           vlib_buffer_t *b)
{
    ips_block_manager_t *bm = &block_manager;
    ips_block_policy_t *policy;

    /* 遍历所有启用的策略 */
    pool_foreach(policy, bm->policies) {
        if (!policy->enabled)
            continue;

        /* 应用策略 */
        if (ips_block_apply_policy(session, b, policy) == 0) {
            /* 策略匹配并执行成功 */
            return 0;
        }
    }

    /* 没有策略匹配 */
    return IPS_BLOCK_ERROR_NO_MATCH;
}
```

## 性能优化

### 内存管理优化

```c
/* 预分配缓冲区池 */
typedef struct {
    vlib_buffer_t *buffer_pool;
    u32 pool_size;
    u32 pool_index;
    clib_spinlock_t pool_lock;
} ips_block_buffer_pool_t;

/* 高效的缓冲区分配 */
vlib_buffer_t *ips_block_alloc_buffer_fast(u32 thread_index)
{
    ips_block_buffer_pool_t *pool = &block_manager.buffer_pools[thread_index];

    clib_spinlock_lock(&pool->pool_lock);

    if (pool->pool_index < pool->pool_size) {
        vlib_buffer_t *buf = pool->buffer_pool[pool->pool_index++];
        clib_spinlock_unlock(&pool->pool_lock);
        return buf;
    }

    clib_spinlock_unlock(&pool->pool_lock);

    /* 池耗尽，直接分配 */
    return vlib_buffer_alloc(vlib_get_main(), 1);
}
```

### 批量操作优化

```c
/* 批量阻断处理 */
int ips_block_batch_process(u32 thread_index,
                           ips_block_request_t *requests,
                           u32 count)
{
    ips_block_stats_t *stats = &block_manager.per_thread_stats[thread_index];
    u32 processed = 0;
    u32 batch_size = 16;
    ips_block_request_t batch[16];

    for (u32 i = 0; i < count; i += batch_size) {
        u32 current_batch_size = CLIB_MIN(batch_size, count - i);

        /* 收集批次 */
        for (u32 j = 0; j < current_batch_size; j++) {
            batch[j] = requests[i + j];
        }

        /* 批量处理 */
        ips_block_execute_batch(thread_index, batch, current_batch_size);
        processed += current_batch_size;
    }

    stats->total_blocks += processed;
    return processed;
}
```

## 监控和统计

### 实时监控

```bash
# 实时监控阻断活动
monitor ips block activity

# 监控速率限制状态
monitor ips block rate-limits

# 监控会话阻断状态
monitor ips block sessions

# 监控策略执行
monitor ips block policies
```

### 性能指标

```bash
# 显示详细统计
show ips block stats

# 输出示例：
IPS Block Statistics (thread 0):
  Total Blocks:           1,234,567
  TCP Resets Sent:        890,123
  ICMP Messages Sent:     234,567
  Packets Dropped:        109,877

  Session Management:
    Sessions Blocked:      45,678
    Sessions Unblocked:    44,999
    Active Blocked:        679

  Protocol Distribution:
    TCP Blocks:            987,654
    UDP Blocks:            123,456
    ICMP Blocks:           123,457

  Rate Limiting:
    Rate Limited Blocks:   12,345
    Rate Limit Exceeded:   23,456

  Performance:
    Blocks/Second:         5,432
    Avg Latency:           0.123ms
    Memory Usage:          2.34MB
```

## 集成接口

### 与检测引擎集成

```c
/* 检测引擎阻断接口 */
int ips_detection_block_session(ips_session_t *session,
                               ips_detection_result_t *result)
{
    ips_block_action_t action;

    /* 根据检测结果构建阻断动作 */
    switch (result->severity) {
        case IPS_SEVERITY_HIGH:
            action = create_reset_action();
            break;
        case IPS_SEVERITY_MEDIUM:
            action = create_icmp_action();
            break;
        case IPS_SEVERITY_LOW:
            action = create_drop_action();
            break;
        default:
            return -1;
    }

    /* 执行阻断 */
    return ips_block_session(session, action, result->suggested_timeout);
}
```

### 与日志系统集成

```c
/* 阻断事件日志记录 */
void ips_block_log_event(ips_block_event_type_t type,
                        ips_session_t *session,
                        ips_block_action_t *action)
{
    ips_log_entry_t log_entry;

    log_entry.timestamp = vlib_time_now(vlib_get_main());
    log_entry.event_type = IPS_LOG_EVENT_BLOCK;
    log_entry.block_type = type;
    log_entry.session_id = session->session_id;
    log_entry.action_type = action->type;
    log_entry.session_key = session->key;

    /* 添加详细信息 */
    switch (action->type) {
        case IPS_BLOCK_ACTION_TCP_RESET:
            snprintf(log_entry.details, sizeof(log_entry.details),
                    "TCP Reset sent to %s",
                    format_ip46_address(&session->key.src_ip, IP46_TYPE_ANY));
            break;
        case IPS_BLOCK_ACTION_ICMP_ERROR:
            snprintf(log_entry.details, sizeof(log_entry.details),
                    "ICMP %d/%d sent to %s",
                    action->params.icmp_error.icmp_type,
                    action->params.icmp_error.icmp_code,
                    format_ip46_address(&session->key.src_ip, IP46_TYPE_ANY));
            break;
        default:
            strcpy(log_entry.details, "Block action executed");
            break;
    }

    ips_log_write(&log_entry);
}
```

## 故障排除

### 常见问题

1. **TCP Reset 不生效**
   - 检查网络路径和路由
   - 验证防火墙规则
   - 确认包构造正确

2. **速率限制过于严格**
   - 调整令牌桶参数
   - 监控实际使用率
   - 考虑动态调整策略

3. **会话阻断泄漏**
   - 检查超时机制
   - 验证清理逻辑
   - 监控内存使用

### 调试命令

```bash
# 启用阻断调试
debug ips block all
debug ips block reset
debug ips block icmp
debug ips block session

# 显示内部状态
show ips block internals
show ips block session-table
show ips block rate-limiters

# 转储配置
dump ips block configuration
```

## API 参考

### 核心函数
- `ips_block_init()` - 初始化阻断模块
- `ips_block_send_tcp_reset()` - 发送 TCP Reset
- `ips_block_send_icmp_unreachable()` - 发送 ICMP 错误
- `ips_block_session()` - 阻断会话
- `ips_block_drop_packet()` - 丢弃包
- `ips_block_apply_policy()` - 应用策略

### 数据结构
- `ips_block_manager_t` - 阻断管理器
- `ips_block_action_t` - 阻断动作
- `ips_block_policy_t` - 阻断策略
- `ips_block_stats_t` - 统计信息

### 回调函数
- `ips_block_action_callback()` - 动作执行回调
- `ips_block_policy_callback()` - 策略匹配回调
- `ips_block_stats_callback()` - 统计更新回调

## 版本历史

- **v1.0.0** - 基础阻断功能
- **v1.1.0** - 会话级阻断
- **v1.2.0** - 速率限制支持
- **v1.3.0** - 策略管理系统
- **v2.0.0** - 性能优化和批量处理

## 许可证

Copyright (c) 2024 VPP IPS Project
Licensed under the Apache License, Version 2.0