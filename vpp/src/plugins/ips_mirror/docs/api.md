# IPS Mirror API Reference

## 📋 API概述

IPS Mirror插件提供完整的REST API和VPP Binary API接口，支持配置管理、规则操作、会话管理、统计查询等功能。API设计遵循RESTful原则，提供统一的错误处理和响应格式。

## 🏗️ API架构

### API类型

1. **VPP Binary API** - 高性能的二进制协议接口
2. **CLI API** - 命令行接口，通过VPP CLI访问
3. **REST API** - HTTP/JSON接口（计划中）

### 核心模块

- **接口管理API** (`ips_interface_enable_disable`) - 启用/禁用接口
- **规则管理API** (`ips_rule_*`) - 规则的增删改查
- **会话管理API** (`ips_session_*`) - 会话操作和查询
- **统计API** (`ips_*_stats`) - 各种统计信息获取
- **定时器API** (`ips_timer_*`) - 定时器配置和管理

## 📁 API文件结构

```
docs/
├── api.md                        # 本文档
├── binary-api.md                 # Binary API详细说明
├── cli-api.md                    # CLI API详细说明
└── rest-api.md                   # REST API详细说明（计划中）

../ips.api                         # VPP API定义文件
../ips_api.c                       # API实现文件
../ips_timer_api.c                 # 定时器API实现
```

## 🔧 VPP Binary API

### API消息定义

IPS Mirror插件的API消息定义在`ips.api`文件中，使用VPP的API定义语言。

#### 核心API消息

```c
/** \brief Enable/disable IPS on interface
    @param client_index - opaque cookie to identify the sender
    @param context - sender context, to match reply w/ request
    @param sw_if_index - interface index
    @param enable_disable - 1 to enable, 0 to disable
*/
autoreply define ips_interface_enable_disable
{
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    bool enable_disable;
};

/** \brief Add IPS rule
    @param client_index - opaque cookie to identify the sender
    @param context - sender context, to match reply w/ request
    @param rule_id - unique rule identifier
    @param gid - group identifier
    @param sid - signature identifier
    @param priority - rule priority (lower number = higher priority)
    @param action - action to take (0=pass, 1=drop, 2=alert, 3=reject, 4=log)
    @param protocol - IP protocol (0=any, 6=TCP, 17=UDP, etc.)
    @param direction - flow direction (0=to_server, 1=to_client, 2=both)
    @param flags - rule flags
    @param is_ipv6 - 1 for IPv6, 0 for IPv4
    @param src_address - source IP address
    @param dst_address - destination IP address
    @param src_port - source port (0=any)
    @param dst_port - destination port (0=any)
    @param rule_content - rule content string
*/
autoreply define ips_rule_add
{
    u32 client_index;
    u32 context;
    u32 rule_id;
    u32 gid;
    u32 sid;
    u32 priority;
    u8 action;
    u8 protocol;
    u8 direction;
    u32 flags;
    u8 is_ipv6;
    u8 src_address[16];
    u8 dst_address[16];
    u16 src_port;
    u16 dst_port;
    u8 rule_content[1024];
};

/** \brief Delete IPS rule
    @param client_index - opaque cookie to identify the sender
    @param context - sender context, to match reply w/ request
    @param rule_id - rule identifier to delete
*/
autoreply define ips_rule_delete
{
    u32 client_index;
    u32 context;
    u32 rule_id;
};

/** \brief Get session statistics
    @param client_index - opaque cookie to identify the sender
    @param context - sender context, to match reply w/ request
    @param thread_index - thread index (0xFFFFFFFF for all threads)
*/
define ips_session_get_stats
{
    u32 client_index;
    u32 context;
    u32 thread_index;
};

/** \brief Reply for ips_session_get_stats
    @param context - sender context, to match reply w/ request
    @param retval - return value
    @param total_sessions - total sessions
    @param active_sessions - active sessions
    @param tcp_sessions - TCP sessions
    @param udp_sessions - UDP sessions
    @param icmp_sessions - ICMP sessions
    @param sessions_created - sessions created
    @param sessions_destroyed - sessions destroyed
    @param sessions_timeout - sessions timed out
*/
define ips_session_get_stats_reply
{
    u32 context;
    i32 retval;
    u32 total_sessions;
    u32 active_sessions;
    u32 tcp_sessions;
    u32 udp_sessions;
    u32 icmp_sessions;
    u64 sessions_created;
    u64 sessions_destroyed;
    u64 sessions_timeout;
};
```

### 定时器API

```c
/** \brief Set timer configuration
    @param client_index - opaque cookie to identify the sender
    @param context - sender context, to match reply w/ request
    @param timer_wheel_ticks_per_second - timer wheel granularity
    @param max_timer_interval - maximum timer interval
    @param backup_scan_interval - backup scan interval
    @param emergency_scan_threshold - emergency scan threshold
    @param force_cleanup_target - force cleanup target
    @param max_timer_wheel_check_interval - max time without timer wheel check
*/
autoreply define ips_timer_set_config
{
    u32 client_index;
    u32 context;
    u32 timer_wheel_ticks_per_second;
    u32 max_timer_interval;
    f64 backup_scan_interval;
    u32 emergency_scan_threshold;
    u32 force_cleanup_target;
    f64 max_timer_wheel_check_interval;
};

/** \brief Get timer statistics
    @param client_index - opaque cookie to identify the sender
    @param context - sender context, to match reply w/ request
    @param thread_index - thread index
*/
define ips_timer_get_stats
{
    u32 client_index;
    u32 context;
    u32 thread_index;
};

/** \brief Reply for ips_timer_get_stats
    @param context - sender context, to match reply w/ request
    @param retval - return value
    @param timers_started - total timers started
    @param timers_expired - total timers expired
    @param timers_stopped - total timers stopped
    @param timers_updated - total timers updated
    @param backup_scans - backup scans performed
    @param emergency_scans - emergency scans performed
    @param timer_wheel_checks - timer wheel checks performed
*/
define ips_timer_get_stats_reply
{
    u32 context;
    i32 retval;
    u64 timers_started;
    u64 timers_expired;
    u64 timers_stopped;
    u64 timers_updated;
    u64 backup_scans;
    u64 emergency_scans;
    u64 timer_wheel_checks;
};
```

## 💻 CLI API

### CLI命令结构

IPS Mirror插件提供丰富的CLI命令，支持配置管理、规则操作、状态查询等功能。

#### 接口管理命令

```bash
# 启用IPS接口
vpp# ips enable interface <interface-name>

# 禁用IPS接口
vpp# ips disable interface <interface-name>

# 查看接口状态
vpp# ips show interfaces

# 显示接口详细信息
vpp# ips show interface <interface-name> [detailed]
```

#### 规则管理命令

```bash
# 添加规则
vpp# ips rule add <rule-string>

# 删除规则
vpp# ips rule delete <rule-id>

# 启用/禁用规则
vpp# ips rule enable <rule-id>
vpp# ips rule disable <rule-id>

# 查看规则
vpp# ips rule show [<rule-id>]

# 显示规则统计
vpp# ips rule stats

# 从文件加载规则
vpp# ips rule load <filename>

# 验证规则语法
vpp# ips rule validate <rule-string>
```

#### 会话管理命令

```bash
# 显示会话统计
vpp# ips session stats

# 显示活跃会话
vpp# ips session show [active|all] [limit]

# 显示特定会话
vpp# ips session show <session-key>

# 清理过期会话
vpp# ips session cleanup

# 设置会话超时
vpp# ips session set timeout <seconds>

# 显示会话详细信息
vpp# ips session show <src-ip>:<src-port> <dst-ip>:<dst-port> <protocol>
```

#### 定时器管理命令

```bash
# 显示定时器统计
vpp# ips timer stats

# 设置定时器配置
vpp# ips timer set ticks-per-second <value>
vpp# ips timer set max-interval <seconds>
vpp# ips timer set backup-scan-interval <seconds>

# 显示定时器状态
vpp# ips timer show status

# 手动处理过期定时器
vpp# ips timer process-expired

# 重置定时器统计
vpp# ips timer clear-stats
```

#### 检测引擎命令

```bash
# 显示检测统计
vpp# ips detection stats

# 显示引擎状态
vpp# ips detection engines

# 显示性能指标
vpp# ips detection performance

# 显示Hyperscan统计
vpp# ips hyperscan stats

# 显示PCRE统计
vpp# ips pcre stats
```

## 📊 统计API

### 会话统计

```c
typedef struct {
    u64 total_sessions_created;     // 总创建会话数
    u64 total_sessions_destroyed;   // 总销毁会话数
    u64 active_sessions;            // 当前活跃会话数
    u64 sessions_timeout;           // 超时会话数
    u64 max_concurrent_sessions;    // 最大并发会话数
    f64 avg_session_lifetime;       // 平均会话生存时间
    u64 tcp_sessions;               // TCP会话数
    u64 udp_sessions;               // UDP会话数
    u64 icmp_sessions;              // ICMP会话数
} ips_session_stats_t;
```

### 规则统计

```c
typedef struct {
    u64 total_rules;                // 总规则数
    u64 enabled_rules;              // 启用规则数
    u64 disabled_rules;             // 禁用规则数
    u64 rule_matches;               // 规则匹配次数
    u64 rule_additions;             // 规则添加次数
    u64 rule_deletions;             // 规则删除次数
    f64 avg_rule_compile_time;      // 平均规则编译时间
    u64 hyperscan_patterns;         // Hyperscan模式数
    u64 pcre_patterns;              // PCRE模式数
} ips_rule_stats_t;
```

### 检测统计

```c
typedef struct {
    u64 total_packets_scanned;      // 总扫描数据包数
    u64 total_rules_evaluated;      // 总评估规则数
    u64 total_matches_found;        // 总匹配次数
    u64 false_positives;            // 误报次数
    u64 false_negatives;            // 漏报次数
    f64 avg_scan_time;              // 平均扫描时间
    f64 avg_rules_per_packet;       // 每包平均规则数
    u64 hyperscan_matches;          // Hyperscan匹配次数
    u64 pcre_matches;               // PCRE匹配次数
} ips_detection_stats_t;
```

### 性能指标

```c
typedef struct {
    f64 detection_rate;             // 检测速率 (packets/sec)
    f64 match_rate;                 // 匹配速率 (matches/sec)
    f64 throughput;                 // 吞吐量 (Mbps)
    u64 cpu_usage;                  // CPU使用率
    u64 memory_usage;               // 内存使用量
    f64 latency;                    // 平均延迟
    u64 dropped_packets;            // 丢弃数据包数
} ips_performance_metrics_t;
```

## 🚀 API使用示例

### Python客户端示例

```python
import socket
import struct
from vpp_papi import VPPApiClient

class IPSMirrorAPI:
    def __init__(self, socket_path='/run/vpp/api.sock'):
        self.client = VPPApiClient(socket_path)

    def enable_interface(self, interface_name):
        """启用IPS接口"""
        sw_if_index = self.client.get_interface_index(interface_name)
        return self.client.api('ips_interface_enable_disable',
                              sw_if_index=sw_if_index,
                              enable_disable=True)

    def add_rule(self, rule_string):
        """添加规则"""
        # 解析规则字符串
        rule = self.parse_rule(rule_string)
        return self.client.api('ips_rule_add', **rule)

    def get_session_stats(self, thread_index=0xFFFFFFFF):
        """获取会话统计"""
        return self.client.api('ips_session_get_stats',
                              thread_index=thread_index)

    def get_timer_stats(self, thread_index=0):
        """获取定时器统计"""
        return self.client.api('ips_timer_get_stats',
                              thread_index=thread_index)

# 使用示例
api = IPSMirrorAPI()

# 启用接口
result = api.enable_interface('GigabitEthernet0/0/0')
print(f"Interface enable result: {result}")

# 添加规则
rule = 'alert tcp any any -> any 80 (msg:"HTTP Attack"; content:"<script>"; sid:1000001;)'
result = api.add_rule(rule)
print(f"Rule add result: {result}")

# 获取统计
stats = api.get_session_stats()
print(f"Session stats: {stats}")

timer_stats = api.get_timer_stats()
print(f"Timer stats: {timer_stats}")
```

### C++客户端示例

```cpp
#include <vpp-api/client.h>
#include <ips.api_types.h>

class IPSMirrorAPI {
private:
    vppapi_client *client;

public:
    IPSMirrorAPI(const char* socket_path) {
        client = vppapi_client_connect(socket_path);
    }

    ~IPSMirrorAPI() {
        vppapi_client_disconnect(client);
    }

    int enable_interface(const char* interface_name) {
        u32 sw_if_index = vppapi_get_sw_if_index(client, interface_name);

        vl_api_ips_interface_enable_disable_t *mp =
            vl_msg_api_alloc(sizeof(*mp));
        mp->_vl_msg_id = ntohs(VL_API_IPS_INTERFACE_ENABLE_DISABLE);
        mp->client_index = client->client_index;
        mp->context = client->context++;
        mp->sw_if_index = sw_if_index;
        mp->enable_disable = 1;

        return vppapi_send_msg(client, (u8*)mp);
    }

    int add_rule(const char* rule_string) {
        // 解析规则字符串
        ips_rule_t rule;
        if (parse_rule_string(rule_string, &rule) != 0) {
            return -1;
        }

        vl_api_ips_rule_add_t *mp =
            vl_msg_api_alloc(sizeof(*mp));
        mp->_vl_msg_id = ntohs(VL_API_IPS_RULE_ADD);
        mp->client_index = client->client_index;
        mp->context = client->context++;
        mp->rule_id = rule.rule_id;
        mp->gid = rule.gid;
        mp->sid = rule.sid;
        mp->priority = rule.priority;
        mp->action = rule.action;
        mp->protocol = rule.protocol;
        mp->direction = rule.direction;
        mp->flags = rule.flags;
        mp->is_ipv6 = rule.is_ipv6;
        memcpy(mp->src_address, rule.src_address, 16);
        memcpy(mp->dst_address, rule.dst_address, 16);
        mp->src_port = rule.src_port;
        mp->dst_port = rule.dst_port;
        strncpy((char*)mp->rule_content, rule.rule_content, sizeof(mp->rule_content)-1);

        return vppapi_send_msg(client, (u8*)mp);
    }

    int get_session_stats(u32 thread_index, ips_session_stats_t *stats) {
        vl_api_ips_session_get_stats_t *mp =
            vl_msg_api_alloc(sizeof(*mp));
        mp->_vl_msg_id = ntohs(VL_API_IPS_SESSION_GET_STATS);
        mp->client_index = client->client_index;
        mp->context = client->context++;
        mp->thread_index = thread_index;

        return vppapi_send_msg_with_reply(client, (u8*)mp,
            (vl_api_reply_handler_fn*)session_stats_reply_handler, stats);
    }
};

// 使用示例
int main() {
    IPSMirrorAPI api("/run/vpp/api.sock");

    // 启用接口
    int result = api.enable_interface("GigabitEthernet0/0/0");
    printf("Interface enable result: %d\n", result);

    // 添加规则
    const char* rule = "alert tcp any any -> any 80 (msg:\"HTTP Attack\"; content:\"<script>\"; sid:1000001;)";
    result = api.add_rule(rule);
    printf("Rule add result: %d\n", result);

    // 获取统计
    ips_session_stats_t stats;
    result = api.get_session_stats(0xFFFFFFFF, &stats);
    if (result == 0) {
        printf("Total sessions: %lu\n", stats.total_sessions_created);
        printf("Active sessions: %lu\n", stats.active_sessions);
    }

    return 0;
}
```

## 🔧 错误处理

### 错误代码

API使用标准的VPP错误码：

- **0** - 成功
- **-1** - 一般错误
- **-2** - 参数错误
- **-3** - 资源不足
- **-4** - 权限不足
- **-5** - 状态错误
- **-6** - 协议错误

### 错误响应格式

```c
typedef struct {
    u32 context;     // 请求上下文
    i32 retval;      // 返回值（错误码）
    u32 error_code;  // 详细错误代码
    char error_msg[256]; // 错误消息
} ips_error_reply_t;
```

### 常见错误处理

```python
def handle_api_error(response):
    if response.retval != 0:
        error_code = response.error_code
        error_msg = response.error_msg
        print(f"API Error {error_code}: {error_msg}")

        # 根据错误类型进行处理
        if error_code == 2:  # 参数错误
            raise ValueError(f"Invalid parameters: {error_msg}")
        elif error_code == 3:  # 资源不足
            raise RuntimeError(f"Resource exhaustion: {error_msg}")
        elif error_code == 4:  # 权限不足
            raise PermissionError(f"Permission denied: {error_msg}")
        else:
            raise Exception(f"API Error: {error_msg}")

    return response
```

## 📈 性能优化

### API调用优化

1. **批量操作** - 使用批量API减少网络往返
2. **异步调用** - 对于非关键操作使用异步API
3. **缓存结果** - 缓存频繁查询的结果
4. **连接复用** - 复用API连接减少开销

### 批量API示例

```c
/** \brief Batch add multiple rules
    @param client_index - opaque cookie to identify the sender
    @param context - sender context, to match reply w/ request
    @param rules - array of rules to add
    @param rule_count - number of rules in array
*/
autoreply define ips_rule_batch_add
{
    u32 client_index;
    u32 context;
    u8 rule_count;
    vl_api_ips_rule_add_t rules[64];
};
```

## 🔍 监控和调试

### API监控

```bash
# 显示API调用统计
vpp# ips api stats

# 显示API错误日志
vpp# ips api errors

# 显示API调用历史
vpp# ips api history

# 清除API统计
vpp# ips api clear-stats
```

### 调试工具

```c
// 启用API调试
#define IPS_API_DEBUG 1

// API调用日志
void ips_api_log_call(const char* api_name, void* request, void* response);

// 性能分析
void ips_api_profile_start(const char* api_name);
void ips_api_profile_end(const char* api_name);
```

## 🔗 相关文档

- [主项目文档](../README.md)
- [开发指南](development.md)
- [配置指南](configuration.md)
- [测试指南](testing.md)

---

## 📞 技术支持

如有API相关问题，请查看：
- [API问题排查](api-troubleshooting.md)
- [最佳实践指南](api-best-practices.md)
- [性能调优指南](api-performance.md)

---

*本文档最后更新时间：2024-10-29*