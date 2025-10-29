# IPS Mirror Testing Guide

## 📋 测试概述

本文档提供了IPS Mirror插件的全面测试指南，包括单元测试、集成测试、性能测试和安全测试等内容。测试框架遵循VPP测试标准，支持自动化测试和持续集成。

## 🏗️ 测试架构

### 测试层次

1. **单元测试** - 测试单个函数和模块
2. **集成测试** - 测试模块间的交互
3. **系统测试** - 测试完整的IPS功能
4. **性能测试** - 测试系统性能指标
5. **安全测试** - 测试安全相关功能

### 测试环境

```bash
# 测试环境要求
- VPP 23.01+ 版本
- Hyperscan 5.4+ 库
- PCRE 8.0+ 库
- 足过4核CPU
- 8GB+ 内存
- Ubuntu 20.04+ 或 CentOS 8+
```

## 📁 测试文件结构

```
tests/
├── unit/                           # 单元测试
│   ├── test_session.c            # 会话管理测试
│   ├── test_timer.c              # 定时器测试
│   ├── test_rules.c              # 规则管理测试
│   ├── test_detection.c          # 检测引擎测试
│   ├── test_hyperscan.c          # Hyperscan测试
│   └── test_tcp_reorder.c        # TCP重排序测试
├── integration/                   # 集成测试
│   ├── test_flow_integration.c   # 流集成测试
│   ├── test_session_integration.c # 会话集成测试
│   └── test_detection_integration.c # 检测集成测试
├── system/                        # 系统测试
│   ├── test_full_pipeline.c      # 完整流水线测试
│   ├── test_rule_processing.c    # 规则处理测试
│   └── test_session_management.c  # 会话管理测试
├── performance/                   # 性能测试
│   ├── test_throughput.c         # 吞吐量测试
│   ├── test_latency.c            # 延迟测试
│   └── test_scalability.c        # 可扩展性测试
├── security/                      # 安全测试
│   ├── test_rule_validation.c    # 规则验证测试
│   ├── test_buffer_overflow.c     # 缓冲区溢出测试
│   └── test_memory_safety.c       # 内存安全测试
├── data/                          # 测试数据
│   ├── rules/                    # 测试规则文件
│   ├── packets/                  # 测试数据包
│   └── traffic/                  # 测试流量文件
└── scripts/                       # 测试脚本
    ├── run_tests.sh              # 运行测试脚本
    ├── generate_test_data.py     # 生成测试数据
    └── performance_benchmark.sh  # 性能基准测试
```

## 🔧 单元测试

### 测试框架

使用VPP的测试框架，基于`vlib/test/test.h`：

```c
#include <vlib/test/test.h>

/* 测试宏 */
#define TEST_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            test_fail(__FILE__, __LINE__, message); \
            return -1; \
        } \
    } while(0)

#define TEST_ASSERT_EQ(expected, actual, message) \
    do { \
        if ((expected) != (actual)) { \
            test_fail(__FILE__, __LINE__, message); \
            return -1; \
        } \
    } while(0)

#define TEST_ASSERT_NE(expected, actual, message) \
    do { \
        if ((expected) == (actual)) { \
            test_fail(__FILE__, __LINE__, message); \
            return -1; \
        } \
    } while(0)
```

### 会话管理测试

```c
#include <vlib/test/test.h>
#include "../session/ips_session.h"

static int test_session_creation(void)
{
    vlib_main_t *vm = vlib_get_main();
    ips_session_t *session;
    ip4_header_t ip4h;
    tcp_header_t tcph;

    /* 准备测试数据 */
    setup_test_ip4_header(&ip4h, "192.168.1.1", "192.168.1.2", 6);
    setup_test_tcp_header(&tcph, 12345, 80);

    /* 测试会话创建 */
    session = ips_session_create_ipv4(0, &ip4h, &tcph);
    TEST_ASSERT(session != NULL, "Failed to create IPv4 session");

    /* 验证会话属性 */
    TEST_ASSERT_EQ(IP_PROTOCOL_TCP, session->protocol, "Wrong protocol");
    TEST_ASSERT_EQ(12345, session->client_flow.key.src_port, "Wrong source port");
    TEST_ASSERT_EQ(80, session->server_flow.key.dst_port, "Wrong destination port");

    /* 清理 */
    ips_session_destroy(session, 0);

    return 0;
}

static int test_session_lookup(void)
{
    vlib_main_t *vm = vlib_get_main();
    ips_session_t *session1, *session2;
    ip4_header_t ip4h;
    tcp_header_t tcph;

    /* 准备测试数据 */
    setup_test_ip4_header(&ip4h, "192.168.1.1", "192.168.1.2", 6);
    setup_test_tcp_header(&tcph, 12345, 80);

    /* 创建第一个会话 */
    session1 = ips_session_create_ipv4(0, &ip4h, &tcph);
    TEST_ASSERT(session1 != NULL, "Failed to create first session");

    /* 查找相同会话 */
    session2 = ips_session_lookup_ipv4(0, &ip4h, &tcph);
    TEST_ASSERT(session2 != NULL, "Failed to lookup session");
    TEST_ASSERT_EQ(session1, session2, "Lookup returned different session");

    /* 清理 */
    ips_session_destroy(session1, 0);

    return 0;
}

/* 测试套件 */
static int test_session_suite(void)
{
    int rv;

    rv = test_session_creation();
    if (rv != 0) return rv;

    rv = test_session_lookup();
    if (rv != 0) return rv;

    /* 添加更多测试... */

    return 0;
}

VLIB_TEST_MODULE_REGISTER(test_session_suite);
```

### 定时器测试

```c
#include <vlib/test/test.h>
#include "../session/ips_session_timer.h"

static int test_timer_creation(void)
{
    clib_error_t *error;
    ips_session_timer_config_t config = {
        .ticks_per_second = 100.0,
        .max_timer_interval = 3600.0,
        .backup_scan_interval = 10.0,
        .emergency_scan_threshold = 1000
    };

    /* 初始化定时器系统 */
    error = ips_session_timer_init(config.ticks_per_second,
                                   config.max_timer_interval);
    TEST_ASSERT(error == NULL, "Timer initialization failed");

    /* 清理 */
    ips_session_timer_cleanup();

    return 0;
}

static int test_timer_operations(void)
{
    ips_session_t session;
    f64 now = vlib_time_now(vlib_get_main());

    /* 初始化会话 */
    memset(&session, 0, sizeof(session));
    session.expiration_time = now + 300.0;

    /* 启动定时器 */
    ips_session_timer_start(&session, 300.0);
    TEST_ASSERT(session.timer_index != 0, "Timer start failed");

    /* 更新定时器 */
    ips_session_timer_update(&session, 600.0);
    TEST_ASSERT(session.expiration_time > now + 300.0, "Timer update failed");

    /* 停止定时器 */
    ips_session_timer_stop(&session);
    TEST_ASSERT(session.timer_index == 0, "Timer stop failed");

    return 0;
}

static int test_timer_suite(void)
{
    int rv;

    rv = test_timer_creation();
    if (rv != 0) return rv;

    rv = test_timer_operations();
    if (rv != 0) return rv;

    return 0;
}

VLIB_TEST_MODULE_REGISTER(test_timer_suite);
```

### 规则管理测试

```c
#include <vlib/test/test.h>
#include "../rules/ips_rule_parser.h"

static int test_rule_parsing(void)
{
    ips_suricata_rule_t rule;
    const char *rule_string = "alert tcp any any -> any 80 "
                            "(msg:\"HTTP Attack Test\"; "
                            "content:\"<script>\"; "
                            "sid:1000001; rev:1;)";

    /* 解析规则 */
    int result = ips_parse_suricata_rule(rule_string, &rule);
    TEST_ASSERT_EQ(0, result, "Rule parsing failed");

    /* 验证规则属性 */
    TEST_ASSERT_EQ(IPS_ACTION_ALERT, rule.action, "Wrong action");
    TEST_ASSERT_EQ(IP_PROTOCOL_TCP, rule.protocol, "Wrong protocol");
    TEST_ASSERT_EQ(1000001, rule.sid, "Wrong SID");
    TEST_ASSERT_EQ(1, rule.rev, "Wrong revision");
    TEST_ASSERT_STR_EQ("HTTP Attack Test", rule.msg, "Wrong message");

    /* 验证内容匹配 */
    TEST_ASSERT_EQ(1, rule.content_count, "Wrong content count");
    TEST_ASSERT_STR_EQ("<script>", rule.contents[0].pattern, "Wrong content pattern");

    return 0;
}

static int test_rule_validation(void)
{
    ips_suricata_rule_t rule;
    const char *invalid_rule = "alert tcp any any -> any 80 "
                             "(msg:\"Invalid Rule\"; "
                             "content:\"test\"; "
                             "sid:1000001;)";

    /* 测试有效规则 */
    const char *valid_rule = "alert tcp any any -> any 80 "
                           "(msg:\"Valid Rule\"; "
                           "content:\"test\"; "
                           "sid:1000001; rev:1;)";

    /* 解析有效规则 */
    int result = ips_parse_suricata_rule(valid_rule, &rule);
    TEST_ASSERT_EQ(0, result, "Valid rule parsing failed");

    /* 验证规则有效性 */
    result = ips_validate_rule(&rule);
    TEST_ASSERT_EQ(0, result, "Valid rule validation failed");

    return 0;
}

static int test_rule_suite(void)
{
    int rv;

    rv = test_rule_parsing();
    if (rv != 0) return rv;

    rv = test_rule_validation();
    if (rv != 0) return rv;

    return 0;
}

VLIB_TEST_MODULE_REGISTER(test_rule_suite);
```

## 🔧 集成测试

### 流集成测试

```c
#include <vlib/test/test.h>
#include "../common/ips_flow.h"
#include "../session/ips_session.h"

static int test_flow_session_integration(void)
{
    vlib_main_t *vm = vlib_get_main();
    ips_session_t *session;
    ips_flow_t *flow;
    ip4_header_t ip4h;
    tcp_header_t tcph;
    vlib_buffer_t *buffer;

    /* 准备测试数据 */
    setup_test_ip4_header(&ip4h, "192.168.1.1", "192.168.1.2", 6);
    setup_test_tcp_header(&tcph, 12345, 80);
    buffer = create_test_buffer("GET /test HTTP/1.1\r\n\r\n");

    /* 创建会话 */
    session = ips_session_create_ipv4(0, &ip4h, &tcph);
    TEST_ASSERT(session != NULL, "Failed to create session");

    /* 更新会话（应该自动创建和更新流） */
    int result = ips_session_update(session, buffer, 1);
    TEST_ASSERT_EQ(0, result, "Failed to update session");

    /* 验证流状态 */
    flow = &session->client_flow;
    TEST_ASSERT(flow != NULL, "Client flow not created");
    TEST_ASSERT_EQ(IPS_FLOW_STATE_ESTABLISHED, flow->state, "Wrong flow state");

    /* 清理 */
    ips_session_destroy(session, 0);
    vlib_buffer_free(buffer);

    return 0;
}

static int test_integration_suite(void)
{
    int rv;

    rv = test_flow_session_integration();
    if (rv != 0) return rv;

    return 0;
}

VLIB_TEST_MODULE_REGISTER(test_integration_suite);
```

## 🔧 系统测试

### 完整流水线测试

```c
#include <vlib/test/test.h>
#include "../detection/ips_detection.h"
#include "../rules/ips_rules_module.h"

static int test_full_detection_pipeline(void)
{
    vlib_main_t *vm = vlib_get_main();
    ips_session_t *session;
    vlib_buffer_t *buffer;
    ips_detection_result_t result;

    /* 初始化检测引擎 */
    clib_error_t *error = ips_suricata_engine_init_vpp(vm);
    TEST_ASSERT(error == NULL, "Detection engine initialization failed");

    /* 加载测试规则 */
    load_test_rules();

    /* 创建测试数据包 */
    session = create_test_session();
    buffer = create_http_packet("GET /admin/login.php HTTP/1.1\r\nHost: example.com\r\n\r\n");
    TEST_ASSERT(session != NULL, "Failed to create test session");
    TEST_ASSERT(buffer != NULL, "Failed to create test packet");

    /* 执行检测 */
    int matches = ips_suricata_engine_match_packet(session, buffer, &result);
    TEST_ASSERT(matches > 0, "No rules matched expected attack packet");
    TEST_ASSERT_EQ(IPS_ACTION_ALERT, result.action, "Wrong action for attack packet");

    /* 清理 */
    ips_session_destroy(session, 0);
    vlib_buffer_free(buffer);
    ips_suricata_engine_cleanup();

    return 0;
}

static int test_system_suite(void)
{
    int rv;

    rv = test_full_detection_pipeline();
    if (rv != 0) return rv;

    return 0;
}

VLIB_TEST_MODULE_REGISTER(test_system_suite);
```

## 🚀 性能测试

### 吞吐量测试

```c
#include <vlib/test/test.h>
#include <vppinfra/perfmon.h>

static int test_throughput_measurement(void)
{
    vlib_main_t *vm = vlib_get_main();
    perfmon_cpu_usage_t cpu_usage;
    f64 start_time, end_time;
    u64 packets_processed = 0;
    u32 packet_count = 1000000; // 1M packets

    /* 初始化性能监控 */
    perfmon_cpu_usage_init(&cpu_usage);

    /* 开始计时 */
    start_time = vlib_time_now(vm);

    /* 处理数据包 */
    for (u32 i = 0; i < packet_count; i++) {
        vlib_buffer_t *buffer = create_test_packet();
        ips_session_t *session = create_test_session();

        int result = process_test_packet(session, buffer);
        if (result == 0) {
            packets_processed++;
        }

        vlib_buffer_free(buffer);
        ips_session_destroy(session, 0);

        /* 每1000个包检查一次CPU使用率 */
        if (i % 1000 == 0) {
            perfmon_cpu_usage(&cpu_usage);
            if (cpu_usage.os_cpu > 80.0) {
                break; // 避免过载
            }
        }
    }

    /* 结束计时 */
    end_time = vlib_time_now(vm);
    f64 duration = end_time - start_time;

    /* 计算性能指标 */
    f64 pps = packets_processed / duration;
    f64 gbps = (packets_processed * 1500 * 8) / (duration * 1e9);

    test_log("Throughput Test Results:");
    test_log("  Packets processed: %lu", packets_processed);
    test_log("  Duration: %.2f seconds", duration);
    test_log("  Packets per second: %.2f", pps);
    test_log("  Throughput: %.2f Gbps", gbps);

    /* 性能要求验证 */
    TEST_ASSERT(pps >= 1000000, "Throughput below 1M PPS requirement");
    TEST_ASSERT(gbps >= 1.0, "Throughput below 1 Gbps requirement");

    return 0;
}

static int test_performance_suite(void)
{
    int rv;

    rv = test_throughput_measurement();
    if (rv != 0) return rv;

    return 0;
}

VLIB_TEST_MODULE_REGISTER(test_performance_suite);
```

## 🔧 安全测试

### 规则验证测试

```c
#include <vlib/test/test.h>
#include "../rules/ips_rule_parser.h"

static int test_rule_injection_prevention(void)
{
    const char *malicious_rules[] = {
        // SQL注入尝试
        "alert tcp any any -> any 3306 (content:\"' OR 1=1 --\"; sid:1;)",

        // 命令注入尝试
        "alert tcp any any -> any 22 (content:\"; rm -rf /\"; sid:2;)",

        // 路径遍历尝试
        "alert tcp any any -> any 80 (content:\"../../../etc/passwd\"; sid:3;)",

        // 缓冲区溢出尝试
        "alert tcp any any -> any 80 (content:\"AAAAAAAAAAAAAAAAAAAAAAAA\"; depth:1000; sid:4;)"
    };

    for (int i = 0; i < ARRAY_LEN(malicious_rules); i++) {
        ips_suricata_rule_t rule;

        /* 尝试解析恶意规则 */
        int result = ips_parse_suricata_rule(malicious_rules[i], &rule);

        /* 规则应该被拒绝或安全化 */
        TEST_ASSERT(result != 0 || !is_rule_safe(&rule),
                   "Malicious rule should be rejected or sanitized");
    }

    return 0;
}

static int test_buffer_overflow_prevention(void)
{
    u8 oversized_buffer[100000];
    vlib_buffer_t *buffer;
    ips_session_t *session;

    /* 创建超大数据包 */
    buffer = create_buffer_with_data(oversized_buffer, sizeof(oversized_buffer));
    session = create_test_session();

    /* 测试处理超大数据包 */
    int result = process_packet(session, buffer);

    /* 应该安全处理或拒绝 */
    TEST_ASSERT(result != 0, "Oversized packet should be rejected");

    /* 清理 */
    vlib_buffer_free(buffer);
    ips_session_destroy(session, 0);

    return 0;
}

static int test_security_suite(void)
{
    int rv;

    rv = test_rule_injection_prevention();
    if (rv != 0) return rv;

    rv = test_buffer_overflow_prevention();
    if (rv != 0) return rv;

    return 0;
}

VLIB_TEST_MODULE_REGISTER(test_security_suite);
```

## 📋 测试脚本

### 运行所有测试

```bash
#!/bin/bash
# run_tests.sh

echo "Running IPS Mirror Test Suite..."

# 设置测试环境
export VPP_TEST_DIR=$(dirname "$0")
export VPP_BUILD_DIR="/root/workspace/IPS/vpp/build-root"

# 单元测试
echo "Running unit tests..."
./test_runner unit/ || exit 1

# 集成测试
echo "Running integration tests..."
./test_runner integration/ || exit 1

# 系统测试
echo "Running system tests..."
./test_runner system/ || exit 1

# 性能测试
echo "Running performance tests..."
./test_runner performance/ || exit 1

# 安全测试
echo "Running security tests..."
./test_runner security/ || exit 1

echo "All tests passed!"
```

### 性能基准测试

```bash
#!/bin/bash
# performance_benchmark.sh

echo "Running Performance Benchmark Tests..."

# 设置测试参数
PACKET_SIZES=(64 128 256 512 1024 1500)
RULE_COUNTS=(100 1000 10000 100000)

for size in "${PACKET_SIZES[@]}"; do
    echo "Testing packet size: $size bytes"

    for count in "${RULE_COUNTS[@]}"; do
        echo "  Rule count: $count"

        # 生成测试规则
        python generate_test_rules.py $count > test_rules.rules

        # 加载规则
        vpp_api ips_rule_load test_rules.rules

        # 运行基准测试
        ./benchmark_test --packet-size $size --duration 60

        # 收集结果
        ./collect_results --packet-size $size --rule-count $count
    done
done

# 生成性能报告
./generate_performance_report.sh
```

## 📊 测试数据生成

### 规则生成器

```python
#!/usr/bin/env python3
# generate_test_rules.py

import random
import sys

def generate_http_rules(count):
    """生成HTTP测试规则"""
    rules = []

    for i in range(count):
        sid = 1000000 + i

        # 随机选择HTTP方法
        methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]
        method = random.choice(methods)

        # 随机选择路径
        paths = ["/admin", "/login", "/api", "/upload", "/download"]
        path = random.choice(paths)

        # 随机选择攻击类型
        attacks = ["<script>", "javascript:", "eval(", "document.cookie",
                  "exec(", "system(", "union select", "drop table"]
        attack = random.choice(attacks)

        rule = f"alert tcp any any -> any 80 ("
        rule += f"msg:\"HTTP {method} {path} Attack\"; "
        rule += f"content:\"{method}\"; http.method; "
        rule += f"content:\"{path}\"; http.uri; "
        rule += f"content:\"{attack}\"; http.body; "
        rule += f"sid:{sid}; rev:1;)"

        rules.append(rule)

    return rules

def generate_dns_rules(count):
    """生成DNS测试规则"""
    rules = []

    for i in range(count):
        sid = 2000000 + i

        # 随机选择域名
        domains = ["malware.com", "phishing.net", "botnet.org", "c2server.info"]
        domain = random.choice(domains)

        rule = f"alert udp any 53 -> any any ("
        rule += f"msg:\"DNS Tunneling to {domain}\"; "
        rule += f"dns.query; content:\"{domain}\"; "
        rule += f"sid:{sid}; rev:1;)"

        rules.append(rule)

    return rules

def main():
    if len(sys.argv) < 3:
        print("Usage: python generate_test_rules.py <count> <type>")
        print("Types: http, dns, all")
        sys.exit(1)

    count = int(sys.argv[1])
    rule_type = sys.argv[2]

    rules = []

    if rule_type == "http" or rule_type == "all":
        rules.extend(generate_http_rules(count // 2))

    if rule_type == "dns" or rule_type == "all":
        rules.extend(generate_dns_rules(count // 2))

    # 输出规则
    for rule in rules:
        print(rule)

if __name__ == "__main__":
    main()
```

## 📈 测试报告

### 测试结果收集

```bash
#!/bin/bash
# collect_results.sh

REPORT_DIR="test_reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="$REPORT_DIR/test_report_$TIMESTAMP.txt"

mkdir -p $REPORT_DIR

echo "IPS Mirror Test Report" > $REPORT_FILE
echo "Generated: $(date)" >> $REPORT_FILE
echo "================================" >> $REPORT_FILE

# 收集单元测试结果
echo -e "\n## Unit Tests\n" >> $REPORT_FILE
./test_runner unit/ >> $REPORT_FILE

# 收集集成测试结果
echo -e "\n## Integration Tests\n" >> $REPORT_FILE
./test_runner integration/ >> $REPORT_FILE

# 收集系统测试结果
echo -e "\n## System Tests\n" >> $REPORT_FILE
./test_runner system/ >> $REPORT_FILE

# 收集性能测试结果
echo -e "\n## Performance Tests\n" >> $REPORT_FILE
./test_runner performance/ >> $REPORT_FILE

# 收集安全测试结果
echo -e "\n## Security Tests\n" >> $REPORT_FILE
./test_runner security/ >> $REPORT_FILE

echo "Test report saved to: $REPORT_FILE"
```

## 🔧 测试自动化

### CI/CD集成

```yaml
# .gitlab-ci.yml

stages:
  - build
  - test
  - security
  - deploy

variables:
  VPP_BUILD_DIR: "/root/workspace/IPS/vpp/build-root"

before_script:
  - echo "Setting up test environment..."
  - source /etc/profile
  - export VPP_TEST_DIR=$(pwd)

build:
  stage: build
  script:
    - echo "Building IPS Mirror..."
    - make clean
    - make build
  artifacts:
    paths:
      - build-root/
    expire_in: 1 week

test:
  stage: test
  script:
    - echo "Running tests..."
    - cd tests
    - ./run_tests.sh
  artifacts:
    reports:
      junit: test_reports/*.xml
    paths:
      - test_reports/
    expire_in: 1 week
  dependencies:
    - build

security:
  stage: security
  script:
    - echo "Running security tests..."
    - cd tests
    - ./run_security_tests.sh
  artifacts:
    reports:
      junit: security_reports/*.xml
    paths:
      - security_reports/
    expire_in: 1 week
  dependencies:
    - test
```

## 🔍 故障排除

### 常见测试问题

**Q: 测试套件编译失败**
A: 检查VPP版本兼容性，确认所有依赖库已安装

**Q: 单元测试通过但集成测试失败**
A: 检查模块间接口一致性，验证配置参数

**Q: 性能测试结果不稳定**
A: 固定测试环境，禁用其他进程，多次运行取平均值

**Q: 内存泄漏检测失败**
A: 使用valgrind或AddressSanitizer详细检查内存使用

### 调试工具

```bash
# 使用GDB调试测试
gdb --args ./test_runner unit/test_session
(gdb) break test_session_creation
(gdb) run

# 内存泄漏检测
valgrind --leak-check=full ./test_runner unit/

# AddressSanitizer检测
export ASAN_OPTIONS=detect_leaks=1
./test_runner unit/
```

## 📈 持续改进

### 测试覆盖率

```bash
# 生成测试覆盖率报告
gcov -r ../src/
lcov --capture --directory ../src --output-file coverage.info
genhtml coverage.info --output-directory coverage_report
```

### 性能回归检测

```bash
# 设置性能基准
./performance_benchmark.sh --baseline

# 运行回归测试
./performance_regression_test.sh

# 生成回归报告
./generate_regression_report.sh
```

---

## 🔗 相关文档

- [主项目文档](../README.md)
- [API文档](api.md)
- [开发指南](development.md)

---

*本文档最后更新时间：2024-10-29*