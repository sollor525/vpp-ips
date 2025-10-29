# VPP IPS Mirror Plugin

一个基于 VPP (Vector Packet Processing) 的高性能入侵防御系统插件，专门设计用于分析镜像流量并执行威胁检测和响应操作。

## 目录

- [核心特性](#核心特性)
- [架构设计](#架构设计)
- [模块详解](#模块详解)
- [构建和安装](#构建和安装)
- [使用指南](#使用指南)
- [性能优化](#性能优化)
- [开发指南](#开发指南)
- [故障排查](#故障排查)

---

## 核心特性

### ✅ 已实现功能

- **高性能包处理**
  - 基于 VPP 数据平面的零拷贝处理
  - 多线程并行处理，无锁设计
  - Cache 优化的数据结构（128字节会话结构体对齐到2个cacheline）

- **完整的会话管理**
  - TCP 会话状态跟踪（完整的TCP状态机）
  - Timer Wheel 老化机制（高效的超时管理）
  - Per-thread 会话池（避免锁竞争）
  - IPv4/IPv6 双栈支持

- **增强的检测引擎**
  - 基于Suricata规则的完整检测引擎
  - Hyperscan高性能模式匹配（5-10倍性能提升）
  - PCRE正则表达式支持
  - 多阶段检测优化（协议→IP→传输→应用→内容→选项）
  - Flowbits流状态管理
  - 字节操作支持（byte_test, byte_jump）

- **深度协议解析**
  - HTTP协议解析（请求/响应分析、头部提取）
  - TLS/SSL协议解析（握手跟踪、SNI提取、版本识别）
  - DNS协议解析（查询/响应分析、多记录类型支持）
  - 协议异常检测和安全特征识别

- **灵活的规则引擎**
  - 完整的Suricata规则语法支持（42种高级选项）
  - 规则索引系统（协议、端口、内容、SID索引）
  - 动态规则加载和热更新
  - 规则分类和优先级管理

- **高级访问控制**
  - TCP-based ACL（基于TCP状态的访问控制）
  - 会话级策略执行
  - 多种阻断响应机制
  - 实时策略更新

- **多样的阻断能力**
  - TCP Reset - 发送 RST 包终止连接
  - TCP FIN - 优雅关闭连接
  - ICMP Unreachable - ICMP 不可达消息
  - ICMP Admin Prohibited - ICMP 管理禁止
  - Silent Drop - 静默丢弃
  - 双向阻断支持

- **丰富的日志系统**
  - 统一的日志框架（IPS_LOG宏）
  - 多级别日志（ERROR, WARNING, INFO, DEBUG, TRACE）
  - 结构化告警日志
  - 可配置日志输出

- **丰富的 API 和 CLI**
  - VPP 二进制 API（支持远程调用）
  - 完整的 CLI 命令集
  - 详细的统计信息和调试支持

### 🚧 正在开发的功能

- **TCP流重组** - 基于VPP缓冲区链的高效重排序
- **机器学习增强** - 协议识别准确率提升
- **威胁情报集成** - 外部威胁情报源支持

---

## 架构设计

### 整体架构

```
┌─────────────────────────────────────────────────────────────────┐
│                     VPP IPS Mirror Plugin                        │
├─────────────────────────────────────────────────────────────────┤
│  输入节点 (ips-input-node)                                      │
│  ├── 数据包接收和预处理                                          │
│  ├── 会话查找/创建                                              │
│  └── 基础协议解析                                                │
├─────────────────────────────────────────────────────────────────┤
│  TCP处理节点 (tcp-processing-node) [建议优化]                    │
│  ├── TCP会话管理 (tcp-session-node)                            │
│  ├── TCP流重组 (tcp-reorder-node)                              │
│  └── TCP ACL检查 (tcp-acl-node)                                │
├─────────────────────────────────────────────────────────────────┤
│  检测引擎 (detection-module)                                    │
│  ├── Suricata规则引擎                                          │
│  ├── Hyperscan模式匹配                                          │
│  ├── 规则解析和索引                                              │
│  └── 多阶段检测处理                                              │
├─────────────────────────────────────────────────────────────────┤
│  协议解析 (protocols-module)                                    │
│  ├── HTTP协议解析器                                             │
│  ├── TLS/SSL协议解析器                                          │
│  ├── DNS协议解析器                                              │
│  └── 协议检测框架                                                │
├─────────────────────────────────────────────────────────────────┤
│  会话管理 (session-module)                                      │
│  ├── 会话生命周期管理                                            │
│  ├── Timer Wheel超时处理                                        │
│  ├── 会话状态跟踪                                                │
│  └── 内存池管理                                                  │
├─────────────────────────────────────────────────────────────────┤
│  响应处理 (block-module)                                        │
│  ├── 多种阻断响应                                                │
│  ├── 告警生成                                                    │
│  └── 日志记录                                                    │
└─────────────────────────────────────────────────────────────────┘
```

### 节点架构优化建议

基于VPP最佳实践，建议将处理流程细分为以下节点：

```
ips-input → tcp-session → tcp-reorder → tcp-acl → detection → block/permit
```

**节点功能划分**:
1. **ips-input-node**: 基础包处理和会话查找
2. **tcp-session-node**: TCP会话管理和状态跟踪
3. **tcp-reorder-node**: TCP流重排序和乱序处理
4. **tcp-acl-node**: TCP-based ACL检查和策略执行
5. **detection-node**: 入侵检测和规则匹配
6. **block-node**: 阻断处理和响应执行

**架构优势**:
- **单一职责**: 每个节点专注特定功能
- **模块化设计**: 便于测试、维护和扩展
- **性能优化**: 针对特定功能的专门优化
- **缓存友好**: 减少节点间的上下文切换
- **并行处理**: 支持节点级别的并行处理

---

## 模块详解

### 📋 Detection Module - 检测引擎核心

**文件**: `detection/` 目录

**核心功能**:
- 基于Suricata规则的完整检测引擎
- Hyperscan高性能模式匹配
- 多阶段检测优化
- 规则解析和索引系统

**关键组件**:
- `ips_suricata_engine_core.c` - Suricata检测引擎核心
- `ips_hyperscan_engine.c` - Hyperscan高性能匹配
- `ips_suricata_parser.c` - 规则解析器
- `ips_rule_index.c` - 规则索引系统

**性能指标**:
- 支持100万+规则
- 5-10倍性能提升（相比传统PCRE）
- 多线程并行处理

### 🔐 Session Module - 会话管理

**文件**: `session/` 目录

**核心功能**:
- TCP会话状态跟踪
- Timer Wheel超时管理
- 高效会话查找和更新
- 内存池管理

**关键组件**:
- `ips_session.c/.h` - 会话管理核心
- `ips_session_timer.c/.h` - 定时器管理
- `ips_tcp_reorder.c` - TCP重排序（将独立为节点）

**性能特性**:
- O(1)复杂度的会话操作
- 支持数百万并发会话
- 线程本地化设计

### 🌐 Protocols Module - 协议解析

**文件**: `protocols/` 目录

**核心功能**:
- HTTP协议深度解析
- TLS/SSL协议分析
- DNS协议解析
- 协议异常检测

**关键组件**:
- `ips_http_parser.c/.h` - HTTP协议解析器
- `ips_tls_parser.c/.h` - TLS/SSL协议解析器
- `ips_dns_parser.c/.h` - DNS协议解析器

**检测能力**:
- 完整的应用层协议支持
- 安全特征识别
- 异常流量检测

### 🛡️ Block Module - 响应处理

**文件**: `block/` 目录

**核心功能**:
- 多种阻断响应机制
- 告警生成和记录
- 流量拦截

**响应类型**:
- TCP Reset/FIN
- ICMP消息
- 静默丢弃
- 双向阻断

### 🔧 ACL Module - 访问控制

**文件**: `acl/` 目录

**核心功能**:
- TCP-based ACL
- 会话级策略
- 动态规则更新

**特性**:
- 基于连接状态的ACL
- 实时策略更新
- 高性能匹配

### 📚 Common Module - 公共组件

**文件**: `common/` 目录

**核心功能**:
- 通用数据结构
- 协议解析基础
- 响应处理
- 日志系统

**关键组件**:
- `ips_flow.c` - 流管理
- `ips_proto.c` - 协议基础
- `ips_response.c` - 响应处理
- `ips_logging.c` - 日志系统

---

## 构建和安装

### 依赖要求

- **VPP**: 23.10+版本
- **Hyperscan**: 5.4+版本（可选，用于高性能模式匹配）
- **PCRE**: 8.x版本（可选，用于正则表达式支持）
- **CMake**: 3.12+
- **GCC/Clang**: 支持C11标准

### 编译步骤

```bash
# 1. 进入VPP源码目录
cd /path/to/vpp

# 2. 配置编译环境
make build

# 3. 编译IPS插件
cd build-root/build-vpp_debug-native
make -j$(nproc) ips_plugin

# 4. 安装插件
make install
```

### 配置Hyperscan（可选）

```bash
# 1. 克隆Hyperscan源码
git clone https://github.com/intel/hyperscan.git
cd hyperscan

# 2. 编译安装
cmake -DBUILD_SHARED_LIBS=ON .
make -j$(nproc)
sudo make install

# 3. 更新动态库缓存
sudo ldconfig
```

---

## 使用指南

### 基本配置

```bash
# 1. 启用IPS插件
vpp# set ips interface <interface-name> enable

# 2. 配置镜像流量
vpp# set interface state <interface-name> up
vpp# set interface promiscuous <interface-name> on

# 3. 加载检测规则
vpp# ips rules load /path/to/rules.rules

# 4. 启用检测
vpp# ips detection enable
```

### 规则管理

```bash
# 加载Suricata规则
vpp# ips rules load suricata /path/to/suricata.rules

# 添加单个规则
vpp# ips rule add "alert tcp any any -> any 80 (msg:\"Web Attack\"; content:\"GET\"; sid:1;)"

# 启用/禁用规则
vpp# ips rule enable <sid>
vpp# ips rule disable <sid>

# 显示规则状态
vpp# show ips rules
```

### 会话管理

```bash
# 显示会话统计
vpp# show ips sessions stats

# 显示活跃会话
vpp# show ips sessions active

# 清理过期会话
vpp# clear ips sessions expired
```

### 检测引擎配置

```bash
# 启用Hyperscan
vpp# set ips detection hyperscan enable

# 配置检测参数
vpp# set ips detection max-rules 100000
vpp# set ips detection timeout 30

# 显示检测统计
vpp# show ips detection stats
```

### 日志配置

```bash
# 配置日志级别
vpp# set ips log level debug

# 启用文件日志
vpp# set ips log file /var/log/ips.log

# 显示日志统计
vpp# show ips log stats
```

---

## 性能优化

### 编译优化

```bash
# 使用优化编译选项
export CFLAGS="-O3 -march=native"
export CXXFLAGS="-O3 -march=native"

# 启用链接时优化
export LDFLAGS="-flto"

# 编译
make build-release
```

### 运行时优化

```bash
# 1. CPU亲和性设置
vpp# set ips cpu affinity <cpu-list>

# 2. 内存预分配
vpp# set ips memory prealloc 1G

# 3. 批处理大小调整
vpp# set ips batch-size 256

# 4. 工作线程配置
vpp# set ips workers <num-workers>
```

### 规则优化

```bash
# 1. 规则分组优化
vpp# ips rules optimize

# 2. 启用规则缓存
vpp# set ips detection rule-cache enable

# 3. 配置规则索引
vpp# set ips detection index-size 1000000
```

### 监控和调优

```bash
# 性能监控
vpp# show ips performance

# 内存使用
vpp# show ips memory

# 规则性能
vpp# show ips rules performance

# 协议统计
vpp# show ips protocols stats
```

---

## 开发指南

### 代码结构

```
ips_mirror/
├── README.md                    # 主文档
├── CMakeLists.txt              # 构建配置
├── ips.c                       # 插件入口
├── ips.h                       # 主要头文件
├── ips_node.c                  # 主处理节点
├── ips_cli.c                   # CLI命令
├── ips_timer_api.c             # 定时器API
├── detection/                  # 检测引擎模块
├── session/                    # 会话管理模块
├── protocols/                  # 协议解析模块
├── block/                      # 阻断处理模块
├── acl/                        # 访问控制模块
├── rules/                      # 规则管理模块
├── common/                     # 公共组件模块
├── ips/                        # VPP API定义
└── docs/                       # 文档目录
```

### 添加新协议解析器

1. **创建解析器文件**
```bash
# 在protocols/目录下创建新解析器
touch protocols/ips_<protocol>_parser.c
touch protocols/ips_<protocol>_parser.h
```

2. **实现解析器接口**
```c
// 实现标准解析器接口
int ips_<protocol>_parse(vlib_buffer_t *b,
                         ips_<protocol>_context_t *ctx);

int ips_<protocol>_detect_anomalies(ips_<protocol>_context_t *ctx);
```

3. **注册解析器**
```c
// 在协议检测框架中注册
ips_protocol_parser_t <protocol>_parser = {
    .parse = ips_<protocol>_parse,
    .detect_anomalies = ips_<protocol>_detect_anomalies,
    .cleanup = ips_<protocol>_cleanup
};
```

### 添加新节点

1. **创建节点文件**
```bash
# 创建新的VPP节点
touch ips_<node_name>_node.c
touch ips_<node_name>_node.h
```

2. **实现节点函数**
```c
// 实现VPP节点函数
VLIB_NODE_FN (ips_<node_name>_node_fn)
{
    // 节点处理逻辑
    return frame->n_vectors;
}
```

3. **注册节点**
```c
// 注册节点到VPP
VLIB_REGISTER_NODE (ips_<node_name>_node) = {
    .name = "ips-<node-name>",
    .function = ips_<node_name>_node_fn,
    .vector_size = sizeof (u32),
};
```

### 调试技巧

```bash
# 1. 启用详细日志
vpp# set ips log level trace

# 2. 启用调试模式
vpp# set ips debug enable

# 3. 跟踪特定会话
vpp# trace ips session <session-id>

# 4. 转储内部状态
vpp# dump ips internals
```

---

## 故障排查

### 常见问题

#### 1. 插件加载失败
```bash
# 检查插件文件
ls -la /usr/lib/vpp_plugins/ips_plugin.so

# 检查VPP日志
journalctl -u vpp -f

# 检查依赖库
ldd /usr/lib/vpp_plugins/ips_plugin.so
```

#### 2. 规则加载失败
```bash
# 检查规则语法
vpp# ips rules validate /path/to/rules.rules

# 显示详细错误
vpp# ips rules load /path/to/rules.rules verbose

# 检查规则数量
vpp# show ips rules count
```

#### 3. 性能问题
```bash
# 检查CPU使用
vpp# show ips cpu

# 检查内存使用
vpp# show ips memory

# 检查包处理统计
vpp# show ips performance
```

#### 4. 会话问题
```bash
# 检查会话统计
vpp# show ips sessions stats

# 检查会话表状态
vpp# show ips sessions table

# 清理会话表
vpp# clear ips sessions all
```

### 调试命令

```bash
# 启用调试模式
vpp# debug ips enable

# 跟踪数据包
vpp# trace ips packet <packet-id>

# 显示内部状态
vpp# show ips internals

# 生成核心转储
vpp# ips dump core

# 重置统计信息
vpp# clear ips stats
```

### 日志分析

```bash
# 查看IPS日志
tail -f /var/log/ips.log

# 过滤错误日志
grep "ERROR" /var/log/ips.log

# 分析告警日志
grep "ALERT" /var/log/ips.log

# 统计日志条目
wc -l /var/log/ips.log
```

---

## 贡献指南

### 代码提交

1. **遵循代码风格**
   - 使用4空格缩进
   - 遵循Linux内核代码风格
   - 添加适当的注释

2. **编写测试**
   - 为新功能编写单元测试
   - 添加性能测试
   - 验证内存泄漏

3. **更新文档**
   - 更新相关文档
   - 添加使用示例
   - 更新变更日志

### 问题报告

使用GitHub Issues报告问题，包含：
- 详细的问题描述
- 复现步骤
- 环境信息
- 相关日志

---

## 许可证

本项目采用Apache License 2.0许可证。详见LICENSE文件。

---

## 联系方式

- **项目主页**: https://github.com/your-org/vpp-ips-mirror
- **问题反馈**: https://github.com/your-org/vpp-ips-mirror/issues
- **文档**: https://vpp-ips-mirror.readthedocs.io

---

*最后更新: 2024年10月29日*