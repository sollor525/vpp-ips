# IPS Detection Module

## 概述

Detection模块是IPS Mirror插件的检测引擎核心，负责基于Suricata规则进行高效的网络流量检测和威胁识别。

## 目录结构

```
detection/
├── README.md                          # 本文档
├── ips_detection.c                    # 检测引擎主实现
├── ips_detection_module.c             # 检测模块初始化和管理
├── ips_hyperscan_engine.c             # Hyperscan高性能模式匹配引擎
├── ips_hyperscan_engine.h             # Hyperscan引擎头文件
├── ips_pcre_engine.c                  # PCRE正则表达式引擎
├── ips_suricata_engine.c              # Suricata检测引擎核心
├── ips_suricata_engine_core.c         # Suricata引擎核心实现
├── ips_suricata_engine.h              # Suricata引擎头文件
├── ips_suricata_integration.c         # Suricata规则集成接口
├── ips_suricata_integration.h         # Suricata集成头文件
├── ips_suricata_parser.c              # Suricata规则解析器
├── ips_suricata_parser.h              # Suricata解析器头文件
├── ips_suricata_cli.c                 # Suricata命令行接口
├── ips_flowbits.c                     # 流标记管理
├── ips_byte_operations.c              # 字节操作函数
├── ips_rule_index.c                   # 规则索引管理
├── ips_rule_index.h                   # 规则索引头文件
└── ips_suricata_inspect_node.c        # 检测节点实现
```

## 核心组件

### 1. 检测引擎 (ips_detection.c)

**功能概述**:
- 主检测流程控制
- 多引擎协调管理
- 检测结果聚合
- 性能统计收集

**关键特性**:
- 支持Hyperscan和PCRE双引擎模式
- 多阶段检测优化
- 线程安全的检测上下文管理
- 实时性能监控

**主要接口**:
```c
int ips_detection_engine_init(ips_detection_engine_t *engine);
int ips_detection_process_packet(ips_detection_engine_t *engine,
                                ips_packet_context_t *packet_ctx,
                                ips_detection_result_t *result);
void ips_detection_engine_cleanup(ips_detection_engine_t *engine);
```

### 2. Hyperscan高性能引擎 (ips_hyperscan_engine.c)

**功能概述**:
- 基于Intel Hyperscan的高性能模式匹配
- 支持大规模规则集并行匹配
- 内存优化的数据库管理
- 线程本地化执行

**性能优势**:
- **5-10倍性能提升**: 相比传统PCRE匹配
- **并行处理**: 支持多模式同时匹配
- **内存效率**: 优化的数据结构设计
- **扩展性**: 支持动态规则更新

**核心数据结构**:
```c
typedef struct ips_hs_database_t {
    hs_database_t *hs_db;           /* 编译的Hyperscan数据库 */
    hs_scratch_t *hs_scratch;       /* 匹配工作空间 */
    u32 *rule_ids;                  /* 规则ID映射 */
    u32 pattern_count;              /* 模式数量 */
    u8 is_valid;                    /* 数据库有效性标志 */
} ips_hs_database_t;
```

### 3. Suricata引擎核心 (ips_suricata_engine_core.c)

**功能概述**:
- 完整的Suricata规则语义支持
- 多协议检测能力
- 复杂规则条件处理
- 状态检测支持

**支持的规则选项**:
- **内容匹配**: content, nocase, depth, offset
- **协议检测**: ip, tcp, udp, icmp
- **流量检测**: flow, flowbits
- **字节操作**: byte_test, byte_jump, byte_extract
- **距离检测**: distance, within, offset

**检测流程**:
1. 协议过滤和验证
2. IP/传输层条件匹配
3. 应用层协议检测
4. 内容模式匹配
5. 规则选项处理

### 4. 规则解析器 (ips_suricata_parser.c)

**功能概述**:
- Suricata规则语法解析
- 规则结构化存储
- 语法验证和错误处理
- 规则优化预处理

**支持的规则格式**:
```
alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"WEB-MISC /cgi-bin/phf access"; content:"/cgi-bin/phf"; nocase; classtype:attempted-recon; sid:1002; rev:1;)
```

**解析能力**:
- 42种高级规则选项支持
- 完整的Suricata 6.x语法兼容
- 自动错误恢复和报告
- 规则分类和标记

### 5. 规则索引系统 (ips_rule_index.c)

**功能概述**:
- 高效的规则检索和过滤
- 多维度规则索引
- 动态规则更新支持
- 查询性能优化

**索引类型**:
- **协议索引**: 按IP/TCP/UDP/ICMP分类
- **端口索引**: 源/目的端口快速查找
- **内容索引**: 基于模式哈希的快速定位
- **SID索引**: 规则ID的唯一索引

## 检测流程

### 1. 数据包接收
```
数据包 → 协议解析 → 检测上下文构建 → 检测引擎调度
```

### 2. 规则匹配
```
规则过滤 → 协议匹配 → 内容匹配 → 选项处理 → 结果聚合
```

### 3. 结果处理
```
匹配验证 → 告警生成 → 动作执行 → 统计更新
```

## 性能优化

### 1. 多阶段过滤
- **协议过滤**: 快速排除不相关协议
- **端口过滤**: 基于端口的预筛选
- **内容过滤**: 高效的模式匹配
- **选项过滤**: 复杂条件验证

### 2. 内存管理
- **对象池**: 预分配检测上下文
- **缓存友好**: 优化的数据结构布局
- **零拷贝**: 最小化内存复制
- **异步清理**: 延迟内存回收

### 3. 并行处理
- **线程本地**: 每线程独立工作空间
- **无锁设计**: 最小化线程同步
- **批量处理**: 批量数据包处理
- **流水线**: 检测阶段并行化

## 配置选项

### 1. 引擎配置
```c
typedef struct ips_detection_config_t {
    u32 max_rules;                    /* 最大规则数量 */
    u32 max_pattern_length;           /* 最大模式长度 */
    u32 hyperscan_thread_limit;       /* Hyperscan线程限制 */
    u8 enable_pcre_fallback;          /* PCRE回退启用 */
    u8 enable_flowbits;               /* 流标记启用 */
} ips_detection_config_t;
```

### 2. 性能调优
- **内存限制**: 控制检测引擎内存使用
- **批处理大小**: 优化吞吐量
- **缓存策略**: 提升命中率
- **并发度**: 调整并行处理能力

## 监控和统计

### 1. 检测统计
```c
typedef struct ips_detection_stats_t {
    u64 total_packets;               /* 总处理包数 */
    u64 matched_packets;             /* 匹配包数 */
    u64 alerts_generated;            /* 生成告警数 */
    u64 false_positives;             /* 误报数量 */
    f64 avg_processing_time;         /* 平均处理时间 */
} ips_detection_stats_t;
```

### 2. 性能指标
- **吞吐量**: 包/秒处理能力
- **延迟**: 单包检测延迟
- **准确率**: 检测准确率统计
- **资源使用**: CPU和内存使用率

## 集成接口

### 1. 初始化接口
```c
int ips_detection_module_init(vlib_main_t *vm);
void ips_detection_module_exit(vlib_main_t *vm);
```

### 2. 运行时接口
```c
int ips_detection_process_node(vlib_main_t *vm,
                               vlib_node_runtime_t *node,
                               vlib_frame_t *frame);
```

### 3. 配置接口
```c
int ips_detection_set_config(ips_detection_config_t *config);
int ips_detection_get_stats(ips_detection_stats_t *stats);
```

## 错误处理

### 1. 解析错误
- **语法错误**: 规则格式问题
- **语义错误**: 规则逻辑问题
- **资源错误**: 内存不足等
- **配置错误**: 参数无效

### 2. 运行时错误
- **匹配错误**: 引擎执行问题
- **内存错误**: 分配失败
- **系统错误**: 外部依赖问题

## 最佳实践

### 1. 规则管理
- **分类组织**: 按威胁类型分类
- **优先级设置**: 重要规则优先
- **定期更新**: 保持规则库时效性
- **性能监控**: 关注规则性能影响

### 2. 性能优化
- **规则精简**: 移除冗余规则
- **模式优化**: 优化正则表达式
- **索引策略**: 合理使用索引
- **资源规划**: 预估资源需求

## 故障排除

### 1. 常见问题
- **编译失败**: 检查依赖库
- **性能下降**: 检查规则复杂度
- **内存泄漏**: 监控内存使用
- **误报率高**: 调整规则精度

### 2. 调试工具
- **规则验证**: 语法和逻辑检查
- **性能分析**: CPU和内存分析
- **日志分析**: 详细运行日志
- **统计监控**: 实时性能指标

## 版本兼容性

- **Suricata**: 6.x版本兼容
- **Hyperscan**: 5.4+版本
- **PCRE**: 8.x版本
- **VPP**: 23.10+版本

## 参考资料

- [Suricata规则语法](https://suricata.io/docs/rules/syntax/)
- [Hyperscan开发者指南](https://intel.github.io/hyperscan/dev-reference/)
- [VPP插件开发指南](https://docs.fd.io/vpp/23.10/gettingstarted/developers/plugindoc.html)

---

*最后更新: 2024年10月29日*