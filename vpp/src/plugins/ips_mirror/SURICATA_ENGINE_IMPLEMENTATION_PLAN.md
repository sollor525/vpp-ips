# VPP IPS Suricata规则引擎实现计划

## 概述

本文档详细描述了VPP IPS插件的增强Suricata规则引擎的实现方案，重点在于高性能、多阶段匹配和完整的语法支持。

## 核心架构设计

### 1. 多阶段匹配引擎

#### 1.1 匹配阶段定义
```c
typedef enum {
    IPS_MATCH_STAGE_PROTOCOL = 0,    // 协议匹配 (TCP/UDP/ICMP)
    IPS_MATCH_STAGE_IP_HEADER,       // IP头部匹配
    IPS_MATCH_STAGE_TRANSPORT,       // 传输层匹配 (端口、TCP标志)
    IPS_MATCH_STAGE_APPLICATION,     // 应用层匹配 (协议识别)
    IPS_MATCH_STAGE_CONTENT,         // 内容匹配
    IPS_MATCH_STAGE_OPTIONS,         // 选项匹配 (byte_test, pcre等)
    IPS_MATCH_STAGE_COMPLETE
} ips_match_stage_t;
```

#### 1.2 早期退出机制
- **协议过滤**：首先进行协议匹配，快速排除不匹配的规则
- **端口过滤**：基于源/目标端口进行预过滤
- **IP地址过滤**：使用IP网络掩码快速过滤
- **内容哈希**：使用内容哈希进行快速预过滤

### 2. 高性能内容匹配

#### 2.1 内容匹配算法
```c
// Boyer-Moore-Horspool算法实现
static inline const u8 *
bmh_search(const u8 *pattern, u32 pattern_len,
           const u8 *text, u32 text_len, u8 nocase)
{
    // 预处理坏字符表
    u8 bad_char[256];
    for (int i = 0; i < 256; i++)
        bad_char[i] = pattern_len;

    for (int i = 0; i < pattern_len - 1; i++)
        bad_char[tolower(pattern[i])] = pattern_len - 1 - i;

    // 搜索
    u32 skip = 0;
    while (text_len - skip >= pattern_len) {
        const u8 *haystack = text + skip;
        int i = pattern_len - 1;

        while (i >= 0 &&
               (nocase ? tolower(haystack[i]) : haystack[i]) == pattern[i])
            i--;

        if (i < 0) return haystack;  // 匹配成功

        skip += bad_char[tolower(haystack[pattern_len - 1])];
    }

    return NULL;
}
```

#### 2.2 多内容匹配优化
- **并行匹配**：同时搜索多个content模式
- **最短内容优先**：优先匹配最短的内容模式
- **快速模式**：使用最快的模式进行预过滤

### 3. 高级匹配选项实现

#### 3.1 offset/depth/distance/within支持
```c
int ips_match_content_with_modifiers(
    const ips_content_match_t *content,
    const u8 *data, u32 data_len,
    ips_content_match_context_t *ctx)
{
    u32 search_start = ctx->relative_offset;
    u32 search_end = data_len;

    // 应用offset修饰符
    if (content->modifiers & IPS_CONTENT_MOD_OFFSET) {
        search_start = content->offset;
    }

    // 应用depth修饰符
    if (content->modifiers & IPS_CONTENT_MOD_DEPTH) {
        search_end = clib_min(search_start + content->depth, data_len);
    }

    // 应用distance修饰符
    if (content->modifiers & IPS_CONTENT_MOD_DISTANCE &&
        ctx->distance_offset > 0) {
        search_start = ctx->distance_offset + content->distance;
    }

    // 应用within修饰符
    if (content->modifiers & IPS_CONTENT_MOD_WITHIN) {
        search_end = search_start + content->within;
    }

    // 执行匹配
    const u8 *match = ips_find_content_pattern(
        content->pattern, content->pattern_len,
        data + search_start, search_end - search_start,
        content->modifiers & IPS_CONTENT_MOD_NOCASE);

    if (match) {
        ctx->relative_offset = (match - data) + content->pattern_len;
        return 1;
    }

    return 0;
}
```

#### 3.2 byte_test实现
```c
int ips_match_byte_test(const ips_byte_test_t *byte_test,
                       const u8 *data, u32 data_len,
                       ips_content_match_context_t *ctx)
{
    u32 offset = byte_test->offset;
    if (byte_test->relative) {
        offset += ctx->relative_offset;
    }

    if (offset + byte_test->bytes > data_len)
        return 0;  // 超出数据范围

    u32 value = 0;
    for (int i = 0; i < byte_test->bytes; i++) {
        value = (value << 8) | data[offset + i];
    }

    if (byte_test->mask) {
        value &= byte_test->mask;
    }

    switch (byte_test->op) {
    case IPS_BYTE_TEST_EQ: return value == byte_test->value;
    case IPS_BYTE_TEST_LT: return value < byte_test->value;
    case IPS_BYTE_TEST_GT: return value > byte_test->value;
    case IPS_BYTE_TEST_LE: return value <= byte_test->value;
    case IPS_BYTE_TEST_GE: return value >= byte_test->value;
    case IPS_BYTE_TEST_AND: return (value & byte_test->value) != 0;
    case IPS_BYTE_TEST_OR:  return (value | byte_test->value) != 0;
    case IPS_BYTE_TEST_XOR: return (value ^ byte_test->value) != 0;
    default: return 0;
    }
}
```

### 4. 流状态机制 (flowbits)

#### 4.1 流位存储结构
```c
typedef struct {
    u32 flowbit_hash;        // 流位名称的哈希值
    u8 is_set:1;            // 是否已设置
    u8 is_persistent:1;      // 是否持久化
    f64 set_time;           // 设置时间
    u32 packet_count;       // 设置时的包计数
} ips_flowbit_entry_t;

typedef struct {
    ips_flowbit_entry_t *entries;
    u32 entry_count;
    u32 capacity;
    f64 last_access_time;
} ips_session_flowbits_t;
```

#### 4.2 流位操作实现
```c
int ips_flowbit_operation(ips_session_t *session,
                         const ips_flowbit_t *flowbit,
                         u32 thread_index)
{
    ips_session_flowbits_t *flowbits =
        ips_get_session_flowbits(session, thread_index);

    u32 hash = clib_hash_string(flowbit->name);
    ips_flowbit_entry_t *entry =
        ips_find_flowbit_entry(flowbits, hash);

    switch (flowbit->operation) {
    case IPS_FLOWBIT_SET:
        if (!entry) {
            entry = ips_create_flowbit_entry(flowbits, hash);
            if (!entry) return -1;
        }
        entry->is_set = 1;
        entry->set_time = vlib_time_now(vlib_get_main());
        entry->packet_count = session->packet_count;
        break;

    case IPS_FLOWBIT_UNSET:
        if (entry) {
            entry->is_set = 0;
        }
        break;

    case IPS_FLOWBIT_ISSET:
        return entry ? entry->is_set : 0;

    case IPS_FLOWBIT_ISNOTSET:
        return entry ? !entry->is_set : 1;
    }

    return 0;
}
```

### 5. 规则索引和优化

#### 5.1 多级索引结构
```c
typedef struct {
    // 第一级：协议索引
    ips_suricata_rule_t *protocol_rules[256];

    // 第二级：端口索引
    struct {
        ips_suricata_rule_t *rules;
        u32 count;
    } port_rules[65536];

    // 第三级：内容哈希索引
    hash_t *content_hash;

    // 第四级：SID哈希索引
    hash_t *sid_hash;
} ips_rule_index_t;
```

#### 5.2 规则预过滤
```c
static inline ips_suricata_rule_t **
ips_prefilter_rules(ips_packet_context_t *ctx, u32 *rule_count)
{
    ips_rule_index_t *index = &global_rule_index;
    ips_suricata_rule_t **candidates = NULL;
    *rule_count = 0;

    // 第一级：协议过滤
    if (index->protocol_rules[ctx->protocol]) {
        vec_add(candidates, index->protocol_rules[ctx->protocol]);
    }

    // 第二级：端口过滤
    u16 src_port = ctx->src_port;
    u16 dst_port = ctx->dst_port;

    if (index->port_rules[src_port].count > 0) {
        vec_add(candidates, index->port_rules[src_port].rules,
                index->port_rules[src_port].count);
    }

    if (index->port_rules[dst_port].count > 0) {
        vec_add(candidates, index->port_rules[dst_port].rules,
                index->port_rules[dst_port].count);
    }

    // 去重
    ips_deduplicate_rules(&candidates, rule_count);

    return candidates;
}
```

### 6. 性能优化策略

#### 6.1 缓存机制
- **规则缓存**：缓存最近匹配的规则
- **内容缓存**：缓存内容匹配结果
- **会话缓存**：缓存会话级别的匹配状态

#### 6.2 并行处理
```c
// 多线程并行匹配
int ips_parallel_match_rules(ips_suricata_rule_t **rules,
                            u32 rule_count,
                            ips_packet_context_t *ctx)
{
    u32 num_threads = vlib_get_thread_main()->n_vlib_mains;
    u32 rules_per_thread = rule_count / num_threads;

    // 分配工作给各个线程
    for (u32 i = 0; i < num_threads; i++) {
        u32 start = i * rules_per_thread;
        u32 end = (i == num_threads - 1) ? rule_count :
                  (i + 1) * rules_per_thread;

        // 提交匹配任务到线程
        ips_submit_match_task(rules + start, end - start, ctx, i);
    }

    // 等待所有线程完成
    ips_wait_match_completion();

    return ctx->matches_found;
}
```

## 实现优先级

### 第一阶段（核心功能）
1. **基础解析器**：完善规则解析器，支持完整语法
2. **多阶段匹配**：实现基本的多阶段匹配框架
3. **内容匹配**：实现高效的内容匹配算法
4. **规则索引**：建立基本的规则索引系统

### 第二阶段（高级功能）
1. **高级修饰符**：实现offset/depth/distance/within
2. **byte操作**：实现byte_test和byte_jump
3. **流状态**：实现flowbits机制
4. **性能优化**：添加缓存和预取机制

### 第三阶段（优化完善）
1. **PCRE支持**：集成正则表达式引擎
2. **并行处理**：实现多线程并行匹配
3. **监控调试**：完善性能监控和调试功能
4. **压力测试**：进行全面的性能测试

## 预期性能指标

### 吞吐量目标
- **小包（64字节）**：> 10Mpps
- **中等包（1500字节）**：> 5Mpps
- **大包（9000字节）**：> 1Mpps

### 延迟目标
- **平均匹配延迟**：< 100ns
- **最大匹配延迟**：< 1μs
- **规则加载时间**：< 1秒（10万规则）

### 内存使用目标
- **每规则内存开销**：< 200字节
- **每会话流位开销**：< 100字节
- **缓存内存开销**：< 100MB

## 测试策略

### 功能测试
1. **语法兼容性**：与标准Suricata规则100%兼容
2. **匹配准确性**：确保所有匹配选项正确工作
3. **边界条件**：测试各种边界和异常情况

### 性能测试
1. **吞吐量测试**：在不同包大小下的吞吐量
2. **延迟测试**：匹配延迟的分布和峰值
3. **扩展性测试**：规则数量对性能的影响

### 压力测试
1. **高负载测试**：持续高负载下的稳定性
2. **内存泄漏测试**：长时间运行的内存稳定性
3. **多线程测试**：并发处理的正确性

这个实现方案将为VPP IPS插件提供一个完整、高性能的Suricata兼容规则引擎，满足企业级入侵防御系统的需求。