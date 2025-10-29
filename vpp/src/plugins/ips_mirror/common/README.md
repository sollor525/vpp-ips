# IPS Mirror Common Module

## 📋 模块概述

IPS Mirror Common模块提供整个IPS插件的核心共享组件和通用功能。该模块包含流管理、协议解析、PCRE/Hyperscan集成、多内容检测等基础功能，为其他模块提供统一的底层支持。

## 🏗️ 架构设计

### 核心组件

- **流管理** (`ips_flow.c/.h`) - 网络流的状态管理
- **PCRE/Hyperscan集成** (`ips_pcre_hyperscan.c`) - 正则表达式高性能匹配
- **多内容检测** (`ips_multi_content_detection.c`) - 复杂内容匹配逻辑
- **通用工具** - 字符串处理、内存管理等

### 设计原则

本模块遵循KISS和DRY原则：

- **KISS (Keep It Simple, Stupid)** - 保持设计简洁，避免过度工程化
- **DRY (Don't Repeat Yourself)** - 消除重复代码，提供统一的抽象接口
- **单一职责** - 每个组件专注于特定的功能领域
- **高内聚低耦合** - 组件内部紧密相关，组件之间松散耦合

## 📁 文件结构

```
common/
├── README.md                          # 本文档
├── ips_flow.c                         # 流状态管理实现
├── ips_flow.h                         # 流状态管理接口
├── ips_pcre_hyperscan.c              # PCRE到Hyperscan转换
├── ips_multi_content_detection.c     # 多内容检测实现
└── ips_multi_content.c               # 多内容匹配核心逻辑
```

## 🔧 核心功能

### 1. 流管理 (ips_flow.c/.h)

提供网络流的完整生命周期管理，支持TCP、UDP、ICMP等多种协议。

#### 主要功能

- **流创建和销毁**: 自动管理流的创建、更新和销毁
- **协议检测**: 智能识别流的应用层协议
- **状态跟踪**: 跟踪流的连接状态和方向性
- **超时管理**: 基于Timer Wheel的高效超时处理

#### 核心数据结构

```c
typedef struct {
    /* 流标识符 */
    ips_flow_key_t key;

    /* 协议信息 */
    u8 protocol;
    u8 is_tcp;
    u8 is_udp;

    /* 状态信息 */
    u8 state;
    u8 direction;

    /* 统计信息 */
    u64 packets_seen;
    u64 bytes_seen;
    f64 last_seen;

    /* TCP重排序 */
    u8 tcp_reorder_enabled;
    // ... TCP重排序相关字段

    /* Hyperscan支持 */
    hs_stream_t *hs_stream;

    /* 性能优化 */
    u32 last_processed_packet_hash;
} ips_flow_t;
```

#### 主要API

```c
// 创建和管理流
ips_flow_t *ips_flow_create(ips_flow_key_t *key, u32 thread_index);
void ips_flow_destroy(ips_flow_t *flow, u32 thread_index);
ips_flow_t *ips_flow_lookup(ips_flow_key_t *key, u32 thread_index);

// 更新流状态
int ips_flow_update(ips_flow_t *flow, vlib_buffer_t *buffer);
int ips_flow_set_protocol(ips_flow_t *flow, ips_alproto_t protocol);

// 超时管理
void ips_flow_process_timeouts(u32 thread_index, f64 now);
```

### 2. PCRE/Hyperscan集成 (ips_pcre_hyperscan.c)

提供PCRE正则表达式到Hyperscan高性能模式转换的功能。

#### 功能特性

- **自动转换**: 将PCRE模式转换为Hyperscan兼容格式
- **标志映射**: 正确处理PCRE和Hyperscan之间的标志差异
- **错误处理**: 提供详细的转换错误信息和恢复机制
- **性能优化**: 支持流式和非流式匹配模式

#### 转换API

```c
// 转换PCRE到Hyperscan
int ips_convert_pcre_to_hyperscan(const char *pcre_pattern,
                                 u8 **hs_pattern,
                                 unsigned int *hs_flags,
                                 u8 **error_msg);

// 验证Hyperscan兼容性
int ips_validate_pcre_for_hyperscan(const char *pcre_pattern,
                                    u8 **error_msg);

// 释放转换资源
void ips_free_converted_pattern(char *pattern);
```

#### 支持的PCRE特性

- **基础模式**: 字符匹配、字符类、量词
- **高级特性**: 分组、选择、锚点
- **标志支持**: i(忽略大小写)、m(多行)、s(单行)、x(扩展)
- **限制说明**: 不支持回溯引用和复杂断言

### 3. 多内容检测 (ips_multi_content_detection.c)

实现复杂的多内容匹配逻辑，支持顺序、距离、相对位置等约束。

#### 匹配算法

- **顺序匹配**: 按指定顺序匹配多个内容模式
- **距离约束**: 支持内容之间的距离限制
- **相对匹配**: 支持相对于前一个匹配的位置
- **优化策略**: 基于启发式的匹配顺序优化

#### 核心API

```c
// 多内容匹配
int ips_match_multi_content_rule(ips_rule_t *rule,
                                 const u8 *data,
                                 u32 data_len);

// 增强匹配
int ips_match_enhanced_rule(ips_rule_t *rule,
                           ips_flow_t *flow,
                           vlib_buffer_t *buffer);

// 内容匹配辅助
int ips_match_content_with_modifiers(const ips_content_match_t *content,
                                     const u8 *payload,
                                     u32 payload_len,
                                     u32 *match_offset);
```

## ⚡ 性能优化

### 1. 内存管理优化

- **内存池**: 使用VPP内存池减少分配开销
- **预分配**: 提前分配常用大小的内存块
- **缓存友好**: 数据结构考虑CPU缓存局部性
- **零拷贝**: 避免不必要的数据拷贝

### 2. 查找优化

- **哈希表**: 流查找使用高效的哈希表实现
- **LRU缓存**: 缓存最近使用的流信息
- **批量操作**: 支持批量的流更新操作
- **无锁设计**: 尽可能使用无锁数据结构

### 3. 算法优化

- **早期退出**: 不满足条件时尽早退出匹配
- **预过滤**: 基于简单条件进行快速预过滤
- **并行匹配**: 支持多个匹配条件的并行处理
- **自适应优化**: 根据运行时性能调整算法参数

## 🔍 监控和统计

### 1. 流统计

```c
typedef struct {
    u64 total_flows_created;     // 总创建流数
    u64 total_flows_destroyed;   // 总销毁流数
    u64 active_flows;            // 当前活跃流数
    u64 flows_timeout;           // 超时流数
    u64 max_concurrent_flows;    // 最大并发流数
    f64 avg_flow_lifetime;       // 平均流生存时间
} ips_flow_stats_t;
```

### 2. 匹配统计

```c
typedef struct {
    u64 total_matches;           // 总匹配次数
    u64 successful_matches;      // 成功匹配次数
    u64 failed_matches;          // 失败匹配次数
    f64 avg_match_time;          // 平均匹配时间
    u64 cache_hits;              // 缓存命中次数
    u64 cache_misses;            // 缓存未命中次数
} ips_match_stats_t;
```

### 3. 监控API

```c
// 获取流统计
void ips_flow_get_stats(ips_flow_stats_t *stats);

// 获取匹配统计
void ips_match_get_stats(ips_match_stats_t *stats);

// 重置统计计数器
void ips_common_reset_stats(void);
```

## 🛠️ 配置选项

### 1. 流管理配置

```c
typedef struct {
    u32 max_flows_per_thread;     // 每线程最大流数
    f64 flow_timeout_default;     // 默认流超时时间
    f64 tcp_timeout;              // TCP流超时时间
    f64 udp_timeout;              // UDP流超时时间
    u8 enable_tcp_reorder;        // 启用TCP重排序
    u32 reorder_window_size;      // 重排序窗口大小
} ips_flow_config_t;
```

### 2. 匹配配置

```c
typedef struct {
    u8 enable_hyperscan;          // 启用Hyperscan加速
    u32 max_pattern_length;       // 最大模式长度
    u32 max_patterns_per_rule;    // 每规则最大模式数
    u8 enable_parallel_matching;  // 启用并行匹配
    u32 match_cache_size;         // 匹配缓存大小
} ips_match_config_t;
```

## 🚀 使用指南

### 1. 基本使用

```c
// 创建和查找流
ips_flow_key_t flow_key = {
    .src_addr = src_ip,
    .dst_addr = dst_ip,
    .src_port = src_port,
    .dst_port = dst_port,
    .protocol = IP_PROTOCOL_TCP
};

ips_flow_t *flow = ips_flow_lookup_or_create(&flow_key, thread_index);
if (flow) {
    // 更新流状态
    ips_flow_update(flow, buffer);

    // 进行协议检测
    ips_alproto_t protocol = ips_flow_detect_protocol(flow, buffer);
}
```

### 2. 内容匹配

```c
// 多内容匹配
ips_rule_t rule = {
    .content_count = 2,
    .contents = {
        {.pattern = "GET", .length = 3},
        {.pattern = "admin", .length = 5, .distance = 10}
    }
};

int result = ips_match_multi_content_rule(&rule, data, data_len);
if (result > 0) {
    // 匹配成功
}
```

### 3. PCRE转换

```c
// 转换PCRE模式
const char *pcre_pattern = "/user=(.*?);/i";
u8 *hs_pattern = NULL;
unsigned int hs_flags = 0;
u8 *error_msg = NULL;

int result = ips_convert_pcre_to_hyperscan(pcre_pattern,
                                          &hs_pattern,
                                          &hs_flags,
                                          &error_msg);
if (result == 0) {
    // 转换成功，使用hs_pattern
    ips_free_converted_pattern((char*)hs_pattern);
} else {
    // 转换失败，处理error_msg
}
```

## 🔧 故障排除

### 1. 常见问题

**Q: 流创建失败**
A: 检查内存是否充足，确认流配置参数合理

**Q: 匹配性能差**
A: 考虑启用Hyperscan，优化匹配顺序，增加缓存大小

**Q: PCRE转换失败**
A: 检查PCRE语法，确认使用的特性受到支持

**Q: 内存泄漏**
A: 确保正确调用销毁函数，检查异步处理逻辑

### 2. 调试工具

```bash
# 显示流统计
vpp# ips flow stats

# 显示匹配统计
vpp# ips match stats

# 显示流详情
vpp# ips flow show <flow-key>

# 清除统计计数器
vpp# ips common clear-stats
```

### 3. 性能调优

- **流数量优化**: 调整`max_flows_per_thread`参数
- **超时设置**: 根据网络环境调整超时参数
- **缓存大小**: 根据内存容量调整缓存配置
- **并行度**: 增加匹配并行度以提高吞吐量

## 📈 未来发展

### 1. 计划功能
- **机器学习**: 基于流量模式优化匹配策略
- **硬件加速**: 支持FPGA/GPU加速匹配
- **协议扩展**: 支持更多应用层协议检测
- **压缩存储**: 压缩流状态以减少内存使用

### 2. 性能提升
- **NUMA优化**: 考虑NUMA架构的内存分配
- **DPDK集成**: 支持DPDK高性能数据平面
- **eBPF支持**: 使用eBPF进行内核级别处理
- **分布式扩展**: 支持分布式流管理

## 🔗 相关模块

- [Session模块](../session/README.md) - 会话和定时器管理
- [Detection模块](../detection/README.md) - 入侵检测引擎
- [Rules模块](../rules/README.md) - 规则解析和管理

---

## 📞 技术支持

如有问题或建议，请查看：
- [主项目文档](../README.md)
- [API文档](../docs/api.md)
- [开发指南](../docs/development.md)

---

*本文档最后更新时间：2024-10-29*