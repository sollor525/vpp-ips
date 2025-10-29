# VPP IPS Mirror Plugin - API接口文档

## 概述

VPP IPS Mirror Plugin提供了丰富的API接口，包括VPP二进制API、CLI命令和编程接口。本文档详细描述了这些API的使用方法和参数说明。

---

## 目录

- [VPP二进制API](#vpp二进制api)
- [CLI命令接口](#cli命令接口)
- [编程接口](#编程接口)
- [节点接口](#节点接口)
- [会话管理API](#会话管理api)
- [检测引擎API](#检测引擎api)
- [统计和监控API](#统计和监控api)
- [配置API](#配置api)
- [错误处理](#错误处理)
- [使用示例](#使用示例)

---

## VPP二进制API

VPP IPS Mirror Plugin支持以下二进制API消息：

### 1. 会话管理API

#### ips_session_get_stats
获取会话统计信息

**请求格式**:
```c
typedef struct {
    u32 client_index;
    u32 context;
    u32 thread_index;
} vl_api_ips_session_get_stats_t;

#define vl_msg_id(n, h) n,
typedef enum {
    VL_API_IPS_SESSION_GET_STATS,
} vl_api_message_id_t;
```

**响应格式**:
```c
typedef struct {
    u32 context;
    u32 retval;
    u32 active_sessions;
    u32 total_created;
    u32 total_deleted;
} vl_api_ips_session_get_stats_reply_t;
```

**使用示例**:
```python
# Python示例
import vpp_papi

# 创建VPP连接
vpp = vpp_papi.VPP()

# 获取会话统计
stats = vpp.api.ips_session_get_stats(thread_index=0)
print(f"活跃会话数: {stats.active_sessions}")
```

### 2. 规则管理API

#### ips_rules_load
加载检测规则

**请求格式**:
```c
typedef struct {
    u32 client_index;
    u32 context;
    u8 rule_file[256];
    u32 rule_type;  // 0=基础格式, 1=Suricata格式
} vl_api_ips_rules_load_t;
```

**响应格式**:
```c
typedef struct {
    u32 context;
    u32 retval;
    u32 rules_loaded;
    u32 rules_failed;
    u32 total_rules;
} vl_api_ips_rules_load_reply_t;
```

#### ips_rule_add
动态添加单个规则

**请求格式**:
```c
typedef struct {
    u32 client_index;
    u32 context;
    u8 rule[1024];
} vl_api_ips_rule_add_t;
```

#### ips_rule_enable / ips_rule_disable
启用/禁用规则

**请求格式**:
```c
typedef struct {
    u32 client_index;
    u32 context;
    u32 sid;  // 规则ID
} vl_api_ips_rule_enable_t;
```

### 3. 检测引擎API

#### ips_detection_enable
启用/禁用检测引擎

**请求格式**:
```c
typedef struct {
    u32 client_index;
    u32 context;
    u8 enable;  // 1=启用, 0=禁用
} vl_api_ips_detection_enable_t;
```

#### ips_detection_set_config
配置检测引擎参数

**请求格式**:
```c
typedef struct {
    u32 client_index;
    u32 context;
    u32 max_rules;
    u32 max_pattern_length;
    u32 hyperscan_thread_limit;
    u8 enable_pcre_fallback;
    u8 enable_flowbits;
} vl_api_ips_detection_set_config_t;
```

---

## CLI命令接口

### 1. 基础配置命令

#### ips enable
启用IPS功能
```bash
vpp# ips enable
```

#### ips disable
禁用IPS功能
```bash
vpp# ips disable
```

#### ips interface <interface> enable
在指定接口启用IPS
```bash
vpp# ips interface GigabitEthernet0/0/0 enable
```

### 2. 规则管理命令

#### ips rules load <file>
加载规则文件
```bash
vpp# ips rules load /path/to/rules.rules
vpp# ips rules load suricata /path/to/suricata.rules
```

#### ips rule add "<rule>"
添加单个规则
```bash
vpp# ips rule add "alert tcp any any -> any 80 (msg:\"Web Attack\"; content:\"GET\"; sid:1;)"
```

#### ips rule enable/disable <sid>
启用/禁用规则
```bash
vpp# ips rule enable 1001
vpp# ips rule disable 1002
```

#### show ips rules
显示规则状态
```bash
vpp# show ips rules
vpp# show ips rules sid 1001
vpp# show ips rules enabled
```

### 3. 会话管理命令

#### show ips sessions
显示会话信息
```bash
vpp# show ips sessions
vpp# show ips sessions active
vpp# show ips sessions stats
vpp# show ips sessions table
```

#### clear ips sessions
清理会话
```bash
vpp# clear ips sessions expired
vpp# clear ips sessions all
```

### 4. 检测引擎命令

#### ips detection enable
启用检测引擎
```bash
vpp# ips detection enable
```

#### ips detection disable
禁用检测引擎
```bash
vpp# ips detection disable
```

#### ips detection config <parameter> <value>
配置检测参数
```bash
vpp# ips detection config max-rules 100000
vpp# ips detection config hyperscan enable
vpp# ips detection config timeout 30
```

#### show ips detection
显示检测引擎状态
```bash
vpp# show ips detection
vpp# show ips detection stats
vpp# show ips detection config
```

### 5. ACL管理命令

#### ips acl add <rule>
添加ACL规则
```bash
vpp# ips acl add "permit tcp any any -> any 80"
vpp# ips acl add "deny tcp any any -> any 22"
```

#### ips acl enable/disable <id>
启用/禁用ACL规则
```bash
vpp# ips acl enable 1
vpp# ips acl disable 2
```

#### show ips acl
显示ACL规则
```bash
vpp# show ips acl
vpp# show ips acl rules
vpp# show ips acl stats
```

### 6. 统计和监控命令

#### show ips stats
显示整体统计
```bash
vpp# show ips stats
vpp# show ips stats detailed
vpp# show ips performance
```

#### show ips memory
显示内存使用
```bash
vpp# show ips memory
vpp# show ips memory threads
```

#### show ips logs
显示日志信息
```bash
vpp# show ips logs
vpp# show ips logs error
vpp# show ips logs debug
```

---

## 编程接口

### 1. 核心数据结构

#### ips_main_t
主控制结构
```c
typedef struct {
    /* 配置参数 */
    ips_config_t config;

    /* 线程数据 */
    ips_per_thread_data_t *per_thread_data;

    /* VPP API */
    u32 vl_api_rx;

    /* 统计信息 */
    ips_global_stats_t stats;
} ips_main_t;
```

#### ips_session_t
会话结构
```c
typedef struct {
    /* 会话标识 */
    ips_session_key4_t key4;    // IPv4会话键
    ips_session_key6_t key6;    // IPv6会话键

    /* 协议信息 */
    u8 protocol;
    u8 is_ipv6;

    /* TCP状态 */
    u8 tcp_state_src;
    u8 tcp_state_dst;
    u32 tcp_seq_src;
    u32 tcp_seq_dst;

    /* 会话标志 */
    u32 flags;
    u32 session_index;

    /* 统计信息 */
    u64 packet_count;
    u64 byte_count;
    f64 start_time;
    f64 last_activity;
} ips_session_t;
```

#### ips_rule_t
规则结构
```c
typedef struct {
    /* 基本信息 */
    u32 sid;                    // 规则ID
    u32 gid;                    // 规则组ID
    u32 rev;                    // 规则版本
    u8 *msg;                    // 规则消息

    /* 匹配条件 */
    u8 protocol;                // 协议类型
    ip4_address_t src_ip4;      // 源IPv4地址
    ip4_address_t dst_ip4;      // 目的IPv4地址
    u16 src_port_min;           // 源端口范围
    u16 src_port_max;
    u16 dst_port_min;           // 目的端口范围
    u16 dst_port_max;

    /* 内容匹配 */
    ips_content_t *contents;    // 内容模式数组
    u32 content_count;          // 内容数量

    /* 规则选项 */
    ips_rule_options_t options;

    /* 动作 */
    u8 action;                  // 规则动作

    /* 统计 */
    u64 match_count;
    u64 alert_count;
} ips_rule_t;
```

### 2. 会话管理API

#### 创建会话
```c
/* IPv4会话 */
ips_session_t *ips_session_lookup_or_create_ipv4(
    u32 thread_index,
    ip4_header_t *ip4h,
    tcp_header_t *tcph
);

/* IPv6会话 */
ips_session_t *ips_session_lookup_or_create_ipv6(
    u32 thread_index,
    ip6_header_t *ip6h,
    tcp_header_t *tcph
);
```

#### 查找会话
```c
ips_session_t *ips_session_lookup_ipv4(
    u32 thread_index,
    ips_session_key4_t *key
);

ips_session_t *ips_session_lookup_ipv6(
    u32 thread_index,
    ips_session_key6_t *key
);
```

#### 删除会话
```c
void ips_session_delete(
    u32 thread_index,
    ips_session_t *session
);
```

### 3. 检测引擎API

#### 初始化检测引擎
```c
int ips_detection_engine_init(
    ips_detection_engine_t *engine
);
```

#### 处理数据包
```c
int ips_detection_process_packet(
    ips_detection_engine_t *engine,
    ips_packet_context_t *packet_ctx,
    ips_detection_result_t *result
);
```

#### 加载规则
```c
int ips_detection_load_rules(
    ips_detection_engine_t *engine,
    const char *rule_file,
    u32 rule_type
);
```

### 4. 规则管理API

#### 解析规则
```c
int ips_suricata_parse_rule(
    const char *rule_string,
    ips_rule_t *rule
);
```

#### 添加规则
```c
int ips_detection_add_rule(
    ips_detection_engine_t *engine,
    ips_rule_t *rule
);
```

#### 删除规则
```c
int ips_detection_remove_rule(
    ips_detection_engine_t *engine,
    u32 sid
);
```

---

## 节点接口

### 1. 节点注册

新的架构包含以下处理节点：

#### ips-input-node
主输入节点，负责包的初步处理和路由
```c
VLIB_REGISTER_NODE (ips_input_node) = {
    .name = "ips-input",
    .function = ips_input_node_fn,
    .vector_size = sizeof (u32),
    .type = VLIB_NODE_TYPE_INTERNAL,
};
```

#### ips-tcp-session-node
TCP会话管理节点
```c
VLIB_REGISTER_NODE (ips_tcp_session_node) = {
    .name = "ips-tcp-session",
    .function = ips_tcp_session_node_fn,
    .vector_size = sizeof (u32),
    .type = VLIB_NODE_TYPE_INTERNAL,
};
```

#### ips-tcp-reorder-node
TCP流重排序节点
```c
VLIB_REGISTER_NODE (ips_tcp_reorder_node) = {
    .name = "ips-tcp-reorder",
    .function = ips_tcp_reorder_node_fn,
    .vector_size = sizeof (u32),
    .type = VLIB_NODE_TYPE_INTERNAL,
};
```

#### ips-tcp-acl-node
TCP ACL检查节点
```c
VLIB_REGISTER_NODE (ips_tcp_acl_node) = {
    .name = "ips-tcp-acl",
    .function = ips_tcp_acl_node_fn,
    .vector_size = sizeof (u32),
    .type = VLIB_NODE_TYPE_INTERNAL,
};
```

### 2. 节点间通信

节点间通过VPP的buffer机制传递信息：
```c
/* 在节点间传递会话信息 */
vnet_buffer (b0)->unused[0] = session->session_index;
vnet_buffer (b0)->unused[1] = session->src_port;
vnet_buffer (b0)->unused[2] = session->dst_port;
```

---

## 会话管理API

### 1. 会话生命周期

#### 创建会话
```c
ips_session_t *session = ips_session_lookup_or_create_ipv4(
    thread_index, ip4h, tcph
);

if (session) {
    /* 会话创建成功 */
    IPS_LOG(IPS_LOG_LEVEL_DEBUG, "Session created: index=%u",
            session->session_index);
}
```

#### 更新会话状态
```c
/* 更新TCP状态 */
if (tcph->flags & TCP_FLAG_SYN) {
    session->tcp_state_src = IPS_SESSION_STATE_SYN_SENT;
}

if (tcph->flags & TCP_FLAG_ACK) {
    /* 处理ACK确认 */
    if (session->tcp_state_src == IPS_SESSION_STATE_SYN_SENT) {
        session->tcp_state_src = IPS_SESSION_STATE_ESTABLISHED;
    }
}
```

#### 会话超时处理
```c
/* 检查会话是否过期 */
f64 now = vlib_time_now(vm);
if (now - session->last_activity > session_timeout) {
    ips_session_delete(thread_index, session);
}
```

### 2. 会话统计

#### 获取会话统计
```c
typedef struct {
    u32 active_sessions;
    u32 total_created;
    u32 total_deleted;
    u32 sessions_per_second;
    f64 avg_session_duration;
} ips_session_global_stats_t;

void ips_session_get_global_stats(
    ips_session_global_stats_t *stats
);
```

#### 线程本地统计
```c
typedef struct {
    u64 packets_processed;
    u64 sessions_created;
    u64 sessions_deleted;
    u64 tcp_connections;
    u64 udp_sessions;
} ips_per_thread_stats_t;
```

---

## 检测引擎API

### 1. 检测引擎初始化

```c
int ips_detection_engine_init(ips_detection_engine_t *engine)
{
    /* 初始化规则索引 */
    engine->rule_index = ips_rule_index_create();

    /* 初始化Hyperscan引擎 */
    engine->hs_engine = ips_hyperscan_engine_create();

    /* 初始化PCRE引擎 */
    engine->pcre_engine = ips_pcre_engine_create();

    /* 初始化统计信息 */
    memset(&engine->stats, 0, sizeof(engine->stats));

    return 0;
}
```

### 2. 规则加载和匹配

#### 加载Suricata规则
```c
int ips_detection_load_suricata_rules(
    ips_detection_engine_t *engine,
    const char *rule_file
)
{
    FILE *fp = fopen(rule_file, "r");
    if (!fp) {
        return -1;
    }

    char line[2048];
    u32 rules_loaded = 0;
    u32 rules_failed = 0;

    while (fgets(line, sizeof(line), fp)) {
        /* 跳过注释和空行 */
        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }

        /* 解析规则 */
        ips_rule_t rule;
        if (ips_suricata_parse_rule(line, &rule) == 0) {
            /* 添加规则到引擎 */
            ips_detection_add_rule(engine, &rule);
            rules_loaded++;
        } else {
            rules_failed++;
        }
    }

    fclose(fp);

    /* 编译Hyperscan数据库 */
    ips_hyperscan_compile(engine->hs_engine);

    return rules_loaded;
}
```

#### 数据包检测
```c
int ips_detection_process_packet(
    ips_detection_engine_t *engine,
    ips_packet_context_t *packet_ctx,
    ips_detection_result_t *result
)
{
    /* 重置检测结果 */
    memset(result, 0, sizeof(*result));

    /* 获取候选规则 */
    u32 candidate_count;
    ips_rule_index_entry_t *candidates = ips_rule_index_lookup(
        engine->rule_index, packet_ctx, &candidate_count
    );

    /* 逐个匹配规则 */
    for (u32 i = 0; i < candidate_count; i++) {
        ips_rule_t *rule = candidates[i].rule;

        /* 检查协议条件 */
        if (!ips_detection_check_protocol(rule, packet_ctx)) {
            continue;
        }

        /* 检查IP条件 */
        if (!ips_detection_check_ip(rule, packet_ctx)) {
            continue;
        }

        /* 检查端口条件 */
        if (!ips_detection_check_ports(rule, packet_ctx)) {
            continue;
        }

        /* 检查内容匹配 */
        if (ips_detection_check_content(rule, packet_ctx, result)) {
            result->matched_rules[result->match_count++] = rule;
            result->action = rule->action;

            /* 如果是阻断动作，立即返回 */
            if (rule->action == IPS_ACTION_BLOCK) {
                break;
            }
        }
    }

    return result->match_count > 0 ? 0 : -1;
}
```

---

## 统计和监控API

### 1. 全局统计

```c
typedef struct {
    /* 会话统计 */
    u64 total_sessions;
    u64 active_sessions;
    u64 sessions_per_second;

    /* 检测统计 */
    u64 total_packets;
    u64 packets_per_second;
    u64 alerts_generated;
    u64 rules_matched;

    /* 性能统计 */
    f64 avg_processing_time;
    f64 max_processing_time;
    u64 memory_usage;
} ips_global_stats_t;

void ips_get_global_stats(ips_global_stats_t *stats);
```

### 2. 线程统计

```c
typedef struct {
    u64 packets_processed;
    u64 sessions_created;
    u64 sessions_deleted;
    u64 rules_matched;
    u64 alerts_generated;

    /* 性能指标 */
    f64 avg_processing_time;
    u64 cpu_time;
} ips_thread_stats_t;

void ips_get_thread_stats(u32 thread_index, ips_thread_stats_t *stats);
```

### 3. 规则统计

```c
typedef struct {
    u32 sid;
    u64 match_count;
    u64 alert_count;
    f64 last_match_time;
    f64 avg_match_interval;
} ips_rule_stats_t;

void ips_get_rule_stats(u32 sid, ips_rule_stats_t *stats);
```

---

## 配置API

### 1. 基础配置

```c
typedef struct {
    /* 全局设置 */
    u8 enabled;
    u8 debug_enabled;
    u32 max_sessions;
    u32 session_timeout;

    /* 检测设置 */
    u8 detection_enabled;
    u8 hyperscan_enabled;
    u32 max_rules;
    u32 rule_update_interval;

    /* 性能设置 */
    u32 thread_count;
    u32 batch_size;
    u32 buffer_size;
} ips_config_t;

int ips_set_config(const ips_config_t *config);
int ips_get_config(ips_config_t *config);
```

### 2. 检测引擎配置

```c
typedef struct {
    /* Hyperscan配置 */
    u32 hs_thread_limit;
    u32 hs_scan_mode;
    u32 hs_database_size;

    /* PCRE配置 */
    u32 pcre_match_limit;
    u32 pcre_recursion_limit;

    /* 规则配置 */
    u32 max_content_length;
    u32 max_rule_depth;
    u32 max_offset_value;
} ips_detection_config_t;

int ips_detection_set_config(const ips_detection_config_t *config);
```

### 3. 日志配置

```c
typedef struct {
    u32 log_level;        // IPS_LOG_LEVEL_*
    u32 max_log_size;     // 最大日志文件大小
    u32 log_rotation;     // 日志轮转设置
    u8 file_logging;      // 是否启用文件日志
    u8 console_logging;   // 是否启用控制台日志
    char log_file[256];   // 日志文件路径
} ips_log_config_t;

int ips_log_set_config(const ips_log_config_t *config);
```

---

## 错误处理

### 1. 错误代码

```c
typedef enum {
    IPS_ERROR_NONE = 0,
    IPS_ERROR_INVALID_PARAM = -1,
    IPS_ERROR_MEMORY_ALLOC = -2,
    IPS_ERROR_RULE_PARSE = -3,
    IPS_ERROR_SESSION_CREATE = -4,
    IPS_ERROR_DETECTION_FAILED = -5,
    IPS_ERROR_CONFIG_INVALID = -6,
    IPS_ERROR_THREAD_LIMIT = -7,
    IPS_ERROR_TIMEOUT = -8,
    IPS_ERROR_PERMISSION_DENIED = -9,
    IPS_ERROR_SYSTEM = -10
} ips_error_t;
```

### 2. 错误处理示例

```c
int ips_detection_load_rules(const char *rule_file)
{
    if (!rule_file) {
        IPS_LOG(IPS_LOG_LEVEL_ERROR, "Rule file path is NULL");
        return IPS_ERROR_INVALID_PARAM;
    }

    FILE *fp = fopen(rule_file, "r");
    if (!fp) {
        IPS_LOG(IPS_LOG_LEVEL_ERROR, "Cannot open rule file: %s", rule_file);
        return IPS_ERROR_FILE_NOT_FOUND;
    }

    /* 处理规则加载 */
    int result = process_rule_file(fp);
    fclose(fp);

    if (result < 0) {
        IPS_LOG(IPS_LOG_LEVEL_ERROR, "Failed to load rules: %d", result);
        return result;
    }

    IPS_LOG(IPS_LOG_LEVEL_INFO, "Successfully loaded %d rules", result);
    return result;
}
```

---

## 使用示例

### 1. Python客户端示例

```python
#!/usr/bin/env python3

import vpp_papi
import time

class IPSClient:
    def __init__(self):
        self.vpp = vpp_papi.VPP()
        self.connect()

    def connect(self):
        """连接到VPP"""
        self.vpp.connect("ips-client")

    def load_rules(self, rule_file):
        """加载规则文件"""
        try:
            result = self.vpp.api.ips_rules_load(
                rule_file=rule_file,
                rule_type=1  # Suricata格式
            )
            print(f"规则加载成功: {result.rules_loaded}/{result.total_rules}")
            return result
        except Exception as e:
            print(f"规则加载失败: {e}")
            return None

    def enable_detection(self):
        """启用检测引擎"""
        try:
            result = self.vpp.api.ips_detection_enable(enable=1)
            print("检测引擎已启用")
            return result
        except Exception as e:
            print(f"启用检测引擎失败: {e}")
            return None

    def get_session_stats(self):
        """获取会话统计"""
        try:
            stats = self.vpp.api.ips_session_get_stats(thread_index=0)
            print(f"活跃会话: {stats.active_sessions}")
            print(f"总创建: {stats.total_created}")
            print(f"总删除: {stats.total_deleted}")
            return stats
        except Exception as e:
            print(f"获取会话统计失败: {e}")
            return None

    def add_rule(self, rule_string):
        """添加单个规则"""
        try:
            result = self.vpp.api.ips_rule_add(rule=rule_string)
            print(f"规则添加成功: {result.retval}")
            return result
        except Exception as e:
            print(f"规则添加失败: {e}")
            return None

# 使用示例
if __name__ == "__main__":
    client = IPSClient()

    # 加载规则文件
    client.load_rules("/etc/ips/rules/suricata.rules")

    # 启用检测引擎
    client.enable_detection()

    # 动态添加规则
    rule = 'alert tcp any any -> any 80 (msg:"Test Rule"; content:"GET"; sid:1000001;)'
    client.add_rule(rule)

    # 监控会话统计
    while True:
        client.get_session_stats()
        time.sleep(10)
```

### 2. C客户端示例

```c
#include <stdio.h>
#include <stdlib.h>
#include <vlibapi/vlib.h>
#include "ips.api.h"

int main(int argc, char *argv[])
{
    /* 连接到VPP */
    vlib_main_t *vm = vlib_get_main();
    if (!vm) {
        printf("无法连接到VPP\n");
        return -1;
    }

    /* 加载规则 */
    vl_api_ips_rules_load_t *mp = vl_msg_api_alloc(
        sizeof(*vl_api_ips_rules_load_t)
    );

    mp->_vl_msg_id = ntohs(VL_API_IPS_RULES_LOAD);
    mp->client_index = 0;
    mp->context = 1;
    strncpy((char*)mp->rule_file, "/etc/ips/rules/suricata.rules", 255);
    mp->rule_type = 1;  // Suricata格式

    /* 发送消息 */
    vl_api_send_msg(vm->vlib_api_rx, (u8 *)mp);

    /* 等待响应 */
    vl_api_peek_msg(vm->vlib_api_rx);

    /* 启用检测引擎 */
    vl_api_ips_detection_enable_t *enable_mp = vl_msg_api_alloc(
        sizeof(*vl_api_ips_detection_enable_t)
    );

    enable_mp->_vl_msg_id = ntohs(VL_API_IPS_DETECTION_ENABLE);
    enable_mp->client_index = 0;
    enable_mp->context = 2;
    enable_mp->enable = 1;

    vl_api_send_msg(vm->vlib_api_rx, (u8 *)enable_mp);

    printf("IPS配置完成\n");
    return 0;
}
```

### 3. Node.js客户端示例

```javascript
const vpp_api = require('vpp-api-client');

class IPSManager {
    constructor() {
        this.client = new vpp_api.VPPClient();
        this.connected = false;
    }

    async connect() {
        try {
            await this.client.connect();
            this.connected = true;
            console.log('连接到VPP成功');
        } catch (error) {
            console.error('连接失败:', error);
            throw error;
        }
    }

    async loadRules(ruleFile, ruleType = 'suricata') {
        if (!this.connected) {
            throw new Error('未连接到VPP');
        }

        try {
            const result = await this.client.call('ips_rules_load', {
                rule_file: ruleFile,
                rule_type: ruleType === 'suricata' ? 1 : 0
            });

            console.log(`规则加载完成: ${result.rules_loaded}/${result.total_rules}`);
            return result;
        } catch (error) {
            console.error('规则加载失败:', error);
            throw error;
        }
    }

    async enableDetection() {
        try {
            const result = await this.client.call('ips_detection_enable', {
                enable: true
            });
            console.log('检测引擎已启用');
            return result;
        } catch (error) {
            console.error('启用检测引擎失败:', error);
            throw error;
        }
    }

    async getSessionStats(threadIndex = 0) {
        try {
            const stats = await this.client.call('ips_session_get_stats', {
                thread_index: threadIndex
            });

            console.log(`活跃会话: ${stats.active_sessions}`);
            console.log(`总创建: ${stats.total_created}`);
            console.log(`总删除: ${stats.total_deleted}`);

            return stats;
        } catch (error) {
            console.error('获取会话统计失败:', error);
            throw error;
        }
    }

    async addRule(ruleString) {
        try {
            const result = await this.client.call('ips_rule_add', {
                rule: ruleString
            });

            console.log(`规则添加成功: ${result.retval}`);
            return result;
        } catch (error) {
            console.error('规则添加失败:', error);
            throw error;
        }
    }
}

// 使用示例
async function main() {
    const ips = new IPSManager();

    try {
        // 连接到VPP
        await ips.connect();

        // 加载规则
        await ips.loadRules('/etc/ips/rules/suricata.rules');

        // 启用检测引擎
        await ips.enableDetection();

        // 动态添加规则
        const rule = 'alert tcp any any -> any 80 (msg:"Test Rule"; content:"GET"; sid:1000001;)';
        await ips.addRule(rule);

        // 定期获取统计信息
        setInterval(async () => {
            await ips.getSessionStats();
        }, 10000);

    } catch (error) {
        console.error('IPS管理器错误:', error);
    }
}

if (require.main === module) {
    main();
}

module.exports = IPSManager;
```

---

## 注意事项

### 1. 性能考虑

- **批量操作**: 尽量使用批量API调用减少开销
- **异步调用**: 使用异步API避免阻塞
- **内存管理**: 注意及时释放分配的内存
- **线程安全**: 在多线程环境下注意数据竞争

### 2. 安全考虑

- **参数验证**: 验证所有输入参数
- **权限检查**: 确保API调用者有足够权限
- **资源限制**: 设置合理的资源使用限制
- **错误信息**: 避免在错误信息中泄露敏感信息

### 3. 兼容性

- **版本兼容**: 注意VPP和IPS插件版本兼容性
- **API变更**: 关注API变更通知
- **向后兼容**: 保持向后兼容性

### 4. 调试建议

- **日志级别**: 使用适当的日志级别
- **统计监控**: 定期检查性能统计
- **错误处理**: 完善的错误处理机制
- **测试覆盖**: 充分的测试覆盖

---

*最后更新: 2024年10月29日*