# IPS ACL Module - VPP IPS Plugin Access Control List

## 概述

IPS ACL 模块是基于 VPP ACL 插件的会话级访问控制系统，提供高性能的包过滤和会话管理功能。该模块深度集成了 VPP 原生 ACL 引擎，支持 TCP 状态感知、SYN/SYN-ACK 阻断和会话级控制。

## 架构设计

### 核心组件

```
IPS ACL 架构
├── ACL 规则管理器 (ips_acl_manager_t)
│   ├── VPP ACL 插件接口
│   ├── 会话级 ACL 规则池
│   ├── TCP 状态跟踪表
│   └── 性能统计信息
├── TCP 状态跟踪引擎
│   ├── 状态机管理
│   ├── 会话键值哈希表
│   └── 状态转换逻辑
└── 高性能处理节点
    ├── 批量处理优化
    ├── 向量化操作
    └── 缓存友好设计
```

### 数据结构

#### 扩展的 ACL 规则结构
```c
typedef struct {
    u32 rule_id;                       /* 规则 ID */
    ips_acl_action_t action;           /* 动作类型 */

    /* 基本匹配条件 */
    u8 is_ipv6;                        /* IPv6 标志 */
    ip46_address_t src_ip;             /* 源 IP 地址 */
    ip46_address_t dst_ip;             /* 目标 IP 地址 */
    u8 src_prefixlen;                  /* 源 IP 前缀长度 */
    u8 dst_prefixlen;                  /* 目标 IP 前缀长度 */
    u16 src_port_start;                /* 源端口范围开始 */
    u16 src_port_end;                  /* 源端口范围结束 */
    u16 dst_port_start;                /* 目标端口范围开始 */
    u16 dst_port_end;                  /* 目标端口范围结束 */
    u8 protocol;                       /* 协议类型 */

    /* TCP 状态匹配扩展 */
    u8 match_tcp_state;                /* TCP 状态匹配标志 */
    ips_tcp_state_t tcp_state;         /* 要求的 TCP 状态 */
    u8 tcp_flags_mask;                 /* TCP 标志掩码 */
    u8 tcp_flags_value;                /* TCP 标志值 */

    /* 会话级控制 */
    u8 session_control;                /* 会话控制级别 */
    u8 match_direction;                /* 匹配方向 */

    /* SYN/SYN-ACK 阻断标志 */
    u8 block_syn;                      /* 阻断 SYN 包 */
    u8 block_synack;                   /* 阻断 SYN-ACK 包 */

    /* 统计和管理 */
    u64 hit_count;                     /* 命中计数 */
    u64 session_hit_count;             /* 会话命中计数 */
    f64 last_hit_time;                 /* 最后命中时间 */
    char description[64];              /* 规则描述 */
} ips_acl_rule_t;
```

#### TCP 状态跟踪结构
```c
typedef struct {
    ips_session_key_t key;             /* 会话键值 */
    ips_tcp_state_t state;             /* TCP 状态 */
    u32 seq_number;                    /* 序列号 */
    u32 ack_number;                    /* 确认号 */
    f64 last_update;                   /* 最后更新时间 */
    u8 direction;                      /* 流量方向 */
} ips_tcp_state_entry_t;
```

## 核心功能

### 1. VPP ACL 集成

模块使用 VPP 原生 ACL 插件实现高性能包分类：

```c
/* 创建 VPP ACL 规则 */
static u32 ips_acl_create_vpp_rule(ips_acl_rule_t *ips_rule)
{
    /* 构建 VPP ACL 命令 */
    u8 *cmd = format(cmd, "acl add %s ipv4 %U/%u %U/%u %u %u-%u %u-%u %u %u",
                     action_str,
                     format_ip4_address, &ips_rule->src_ip.ip4, ips_rule->src_prefixlen,
                     format_ip4_address, &ips_rule->dst_ip.ip4, ips_rule->dst_prefixlen,
                     ips_rule->protocol,
                     ips_rule->src_port_start, ips_rule->src_port_end,
                     ips_rule->dst_port_start, ips_rule->dst_port_end,
                     ips_rule->tcp_flags_value, ips_rule->tcp_flags_mask);

    /* 执行 VPP CLI 命令 */
    ret = vlib_cli_execute(vm, (char *)cmd);
    return acl_index;
}
```

### 2. TCP 状态跟踪引擎

实现完整的 TCP 状态机，支持精确的连接状态跟踪：

```c
/* TCP 状态更新 */
ips_tcp_state_t ips_acl_update_tcp_state(ips_session_key_t *key,
                                        tcp_header_t *tcp,
                                        u8 direction)
{
    /* 状态转换逻辑 */
    switch (old_state) {
        case IPS_TCP_STATE_NONE:
            if ((flags & IPS_TCP_FLAG_SYN) && !(flags & IPS_TCP_FLAG_ACK))
                new_state = IPS_TCP_STATE_SYN_SENT;
            break;
        case IPS_TCP_STATE_SYN_SENT:
            if ((flags & IPS_TCP_FLAG_SYN) && (flags & IPS_TCP_FLAG_ACK))
                new_state = IPS_TCP_STATE_ESTABLISHED;
            break;
        // ... 其他状态转换
    }
    return new_state;
}
```

### 3. SYN/SYN-ACK 阻断

提供精确的连接建立阻断能力：

```c
/* SYN 包阻断检查 */
int ips_acl_check_syn_block(ips_session_key_t *key, vlib_buffer_t *b)
{
    /* 检查 SYN 标志 */
    u8 tcp_flags = tcp->flags;
    if (!((tcp_flags & IPS_TCP_FLAG_SYN) && !(tcp_flags & IPS_TCP_FLAG_ACK)))
        return 0;

    /* 匹配阻断规则 */
    pool_foreach(rule, am->ips_rules) {
        if (rule->block_syn && match_rule(rule, key, b)) {
            clib_warning("Blocking TCP SYN packet: %U -> %U",
                        format_ip46_address, &key->src_ip, IP46_TYPE_ANY,
                        format_ip46_address, &key->dst_ip, IP46_TYPE_ANY);
            return 1;
        }
    }
    return 0;
}
```

### 4. 高性能批量处理

优化包处理性能，使用批量操作：

```c
/* 批量处理函数 */
void ips_acl_process_batch(vlib_main_t *vm,
                          vlib_node_runtime_t *node,
                          vlib_frame_t *frame,
                          u32 *buffers,
                          u32 count)
{
    /* 4 包批量处理 */
    for (u32 i = 0; i < count; i += 4) {
        u32 batch_size = (i + 4 <= count) ? 4 : (count - i);

        /* 批量提取会话键 */
        for (u32 j = 0; j < batch_size; j++) {
            ips_acl_extract_session_key(bufs[j], &keys[j], &directions[j]);
        }

        /* 批量处理决策 */
        for (u32 j = 0; j < batch_size; j++) {
            /* SYN/SYN-ACK 检查 */
            /* TCP 状态更新 */
            /* ACL 规则匹配 */
            /* 动作决策 */
        }

        /* 批量提交到下一节点 */
        for (u32 j = 0; j < batch_size; j++) {
            vlib_validate_buffer_enqueue_x1(vm, node, next_indices[j],
                                          frame, buffers[i + j], next_indices[j]);
        }
    }
}
```

## 配置和使用

### CLI 命令

#### 基本规则管理
```bash
# 添加阻断规则（默认阻断）
ips acl add rule src 1.1.1.1 dst-port 80

# 添加 SYN 阻断规则
ips acl add rule src 2.2.2.2 dst-port 443 block-syn

# 添加 SYN-ACK 阻断规则
ips acl add rule src 3.3.3.3 dst-port 22 block-synack

# 添加会话级规则
ips acl add rule src 4.4.4.4 dst-port 8080 session-level

# 添加放行规则
ips acl add rule src 5.5.5.5 dst-port 53 action permit

# 添加带描述的规则
ips acl add rule src 6.6.6.6 dst-port 25 description "Block SMTP"
```

#### 高级功能配置
```bash
# 启用 TCP 状态跟踪
ips acl tcp-state enable

# 禁用 TCP 状态跟踪
ips acl tcp-state disable

# 查看 TCP 状态跟踪信息
ips acl tcp-state show

# 查看统计信息
ips acl show stats

# 查看特定线程统计
ips acl show stats thread 1

# 重置统计信息
ips acl reset stats
```

#### 规则管理
```bash
# 启用/禁用规则
ips acl set rule 1 enable
ips acl set rule 2 disable

# 删除规则
ips acl remove rule 1
```

### 使用示例

#### 防止恶意连接
```bash
# 阻止来自恶意 IP 的所有连接尝试
ips acl add rule src 192.168.1.100 block-syn

# 阻止对外部特定服务的连接
ips acl add rule dst 10.0.0.50 dst-port 3389 block-syn
```

#### 服务器保护
```bash
# 保护 Web 服务器，只允许特定 IP 访问
ips acl add rule src 192.168.1.0/24 dst-port 80 action permit
ips acl add rule dst-port 80 block-syn

# 保护 SSH 服务，限制连接源
ips acl add rule src 10.0.0.0/8 dst-port 22 action permit
ips acl add rule dst-port 22 block-syn
```

#### 防止数据泄露
```bash
# 阻止内部网络向外的敏感端口连接
ips acl add rule src 192.168.0.0/16 dst-port 445 block-syn
ips acl add rule src 192.168.0.0/16 dst-port 1433 block-syn
```

## 性能优化

### 内存管理
- 使用 VPP bihash 数据结构实现高效查找
- 内存池管理减少动态分配开销
- 批量操作减少系统调用

### 缓存优化
- 会话级决策缓存避免重复匹配
- TCP 状态缓存减少状态机计算
- 批量处理提高缓存局部性

### 算法优化
- 4 包批量处理提高吞吐量
- 向量化操作减少分支预测失败
- 零拷贝操作降低内存带宽

## 监控和统计

### 性能指标
```bash
# 查看详细统计信息
ips acl show stats

# 输出示例：
IPS ACL Statistics (thread 0):
  Total packets checked: 1,234,567
  Packets permitted:    1,200,000
  Packets denied:       30,000
  Packets reset:        4,567
  Sessions blocked:     2,345
  ACL errors:           0

  VPP ACL rule hits:    45,678
  TCP state hits:       23,456
  Session cache hits:   89,012
  SYN packets blocked:  12,345
  SYN-ACK packets blocked: 1,234

  ACL hit rate:         3.70%
  Cache hit rate:       7.21%
  TCP state hit rate:   1.90%
```

### 调试功能
- 详细的日志记录
- 实时状态监控
- 错误追踪和报告

## 集成接口

### 与会话模块集成
```c
/* 在会话查找中集成 ACL 检查 */
int ips_session_lookup_with_acl(ips_session_t **session,
                               u32 thread_index,
                               ips_session_key_t *key,
                               vlib_buffer_t *b)
{
    /* 会话查找 */
    int rv = ips_session_lookup(session, thread_index, key);

    /* ACL 检查 */
    if (rv == 0) {
        ips_acl_action_t action;
        ips_acl_check_packet(thread_index, *session, ip4, ip6, tcp, &action);

        if (action == IPS_ACL_ACTION_DENY) {
            /* 触发阻断逻辑 */
            ips_block_session(*session, BLOCK_REASON_ACL);
        }
    }

    return rv;
}
```

### 与阻断模块集成
```c
/* ACL 触发的阻断动作 */
void ips_acl_execute_block_action(ips_session_t *session,
                                 ips_acl_action_t action)
{
    switch (action) {
        case IPS_ACL_ACTION_DENY:
            ips_block_session(session, BLOCK_REASON_ACL_DENY);
            break;
        case IPS_ACL_ACTION_RESET:
            ips_block_session(session, BLOCK_REASON_ACL_RESET);
            ips_acl_send_tcp_reset(session->thread_index, session, 0);
            break;
        default:
            break;
    }
}
```

## 配置参数

### 默认配置
```c
/* 可配置参数 */
#define IPS_ACL_DEFAULT_MAX_SESSIONS     65536    /* 最大会话数 */
#define IPS_ACL_DEFAULT_STATE_TIMEOUT    300      /* 状态超时时间（秒） */
#define IPS_ACL_DEFAULT_BATCH_SIZE       4        /* 批量处理大小 */
#define IPS_ACL_DEFAULT_CACHE_TIMEOUT    60       /* 缓存超时时间（秒） */
```

### 运行时配置
```bash
# 配置最大会话数
set ips acl max-sessions 100000

# 配置 TCP 状态超时
set ips acl tcp-timeout 600

# 配置批量处理大小
set ips acl batch-size 8
```

## 故障排除

### 常见问题

1. **ACL 规则不生效**
   - 检查规则优先级和顺序
   - 确认 VPP ACL 插件已加载
   - 验证规则语法正确性

2. **性能问题**
   - 监控缓存命中率
   - 检查批量处理效率
   - 优化规则复杂度

3. **状态跟踪异常**
   - 验证 TCP 标志识别
   - 检查会话键值生成
   - 确认状态转换逻辑

### 调试命令
```bash
# 显示当前规则
show ips acl rules

# 显示 TCP 状态表
show ips acl tcp-state table

# 显示性能统计
show ips acl performance

# 启用调试模式
set ips acl debug on
```

## API 参考

### 核心函数
- `ips_acl_init()` - 初始化 ACL 模块
- `ips_acl_check_packet()` - 包 ACL 检查
- `ips_acl_add_rule()` - 添加 ACL 规则
- `ips_acl_update_tcp_state()` - 更新 TCP 状态
- `ips_acl_process_batch()` - 批量处理包

### 数据结构
- `ips_acl_manager_t` - ACL 管理器
- `ips_acl_rule_t` - ACL 规则
- `ips_tcp_state_entry_t` - TCP 状态条目
- `ips_acl_stats_t` - 统计信息

## 版本历史

- **v1.0.0** - 基础 ACL 功能
- **v1.1.0** - TCP 状态跟踪
- **v1.2.0** - SYN/SYN-ACK 阻断
- **v1.3.0** - 高性能批量处理
- **v2.0.0** - 会话级控制集成

## 许可证

Copyright (c) 2024 VPP IPS Project
Licensed under the Apache License, Version 2.0