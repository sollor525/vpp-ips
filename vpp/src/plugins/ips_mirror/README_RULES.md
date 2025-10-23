# VPP IPS Plugin - Rules Loading and Management

## 概述

VPP IPS插件支持在系统启动时自动加载规则文件，并提供CLI命令进行规则的动态重新加载和管理。

## 功能特性

### 1. 系统启动时自动加载规则
- 插件初始化时自动检查默认规则文件路径
- 如果文件存在，自动加载并编译规则
- 默认规则文件路径：`/etc/vpp/ips/suricata.rules`

### 2. CLI命令支持
提供完整的CLI命令集合用于规则管理：

#### 规则加载命令
```bash
# 从默认文件加载规则
ips rules load default

# 从指定文件加载规则
ips rules load file /path/to/rules.txt

# 重新加载规则（清除现有规则后重新加载）
ips rules load reload default
ips rules load reload file /path/to/rules.txt
```

#### 配置管理命令
```bash
# 设置默认规则文件路径
ips config rules-file /path/to/custom/rules.txt

# 设置会话超时时间（秒）
ips config session-timeout 600

# 设置清理间隔时间（秒）
ips config cleanup-interval 120

# 启用/禁用混杂模式
ips config promiscuous-mode enable
ips config promiscuous-mode disable
```

#### 查看命令
```bash
# 查看IPS配置
show ips config

# 查看已加载的规则
show ips rules

# 查看IPS统计信息
show ips stats

# 清除统计信息
clear ips stats
```

#### 接口管理命令
```bash
# 在接口上启用IPS
ips interface GigabitEthernet0/8/0

# 在接口上禁用IPS
ips interface GigabitEthernet0/8/0 disable
```

## 规则文件格式

IPS插件支持Suricata兼容的规则格式：

### 基本语法
```
action protocol src_ip src_port direction dst_ip dst_port (options)
```

### 支持的动作
- `alert` - 生成告警
- `drop` - 丢弃数据包
- `reject` - 拒绝连接
- `pass` - 允许通过
- `log` - 记录日志

### 支持的协议
- `tcp` - TCP协议
- `udp` - UDP协议
- `icmp` - ICMP协议
- `ip` - 任意IP协议

### 地址和端口格式
- `any` - 任意地址/端口
- `192.168.1.1` - 特定IP地址
- `192.168.1.0/24` - CIDR网络
- `80` - 特定端口
- `1000:2000` - 端口范围

### 方向
- `->` - 单向（源到目标）
- `<-` - 单向（目标到源）
- `<>` - 双向

### 规则选项
- `msg:"描述信息"` - 规则描述
- `content:"匹配内容"` - 内容匹配
- `sid:数字` - 规则ID
- `gid:数字` - 组ID
- `priority:数字` - 优先级（1=高，3=低）
- `nocase` - 忽略大小写
- `classtype:"分类"` - 规则分类
- `reference:"参考"` - 参考信息

### 示例规则
```bash
# HTTP GET请求检测
alert tcp any any -> any 80 (msg:"HTTP GET Request"; content:"GET"; sid:1000001; gid:1; priority:3;)

# SQL注入检测
alert tcp any any -> any 80 (msg:"SQL Injection Attack"; content:"union select"; nocase; sid:1000002; gid:1; priority:1;)

# XSS攻击检测
alert tcp any any -> any 80 (msg:"XSS Attack"; content:"<script"; nocase; sid:1000003; gid:1; priority:2;)

# 恶意软件检测
drop tcp any any -> any any (msg:"Malware Pattern"; content:"malware_signature"; sid:1000004; gid:1; priority:1;)
```

## 使用流程

### 1. 准备规则文件
```bash
# 创建规则目录
sudo mkdir -p /etc/vpp/ips

# 创建规则文件
sudo vim /etc/vpp/ips/suricata.rules
```

### 2. 启动VPP
```bash
# VPP将自动加载默认规则文件
sudo vpp unix {cli-listen /tmp/vpp-cli.sock}
```

### 3. 配置IPS
```bash
# 连接到VPP CLI
sudo vppctl

# 查看配置
vpp# show ips config

# 在接口上启用IPS
vpp# ips interface GigabitEthernet0/8/0

# 查看规则
vpp# show ips rules
```

### 4. 动态重新加载规则
```bash
# 修改规则文件后重新加载
vpp# ips rules load reload default

# 查看更新后的规则
vpp# show ips rules
```

## 配置文件示例

### /etc/vpp/ips/suricata.rules
```bash
# IPS Rules for VPP - Example Configuration
# Based on Suricata rule format

# Basic HTTP detection rules
alert tcp any any -> any 80 (msg:"HTTP GET Request"; content:"GET"; sid:1000001; gid:1; priority:3;)
alert tcp any any -> any 80 (msg:"HTTP POST Request"; content:"POST"; sid:1000002; gid:1; priority:3;)

# SQL Injection detection
alert tcp any any -> any 80 (msg:"Possible SQL Injection Attack"; content:"union select"; nocase; sid:1000003; gid:1; priority:1;)
alert tcp any any -> any 80 (msg:"SQL Injection - DROP TABLE"; content:"drop table"; nocase; sid:1000004; gid:1; priority:1;)

# XSS detection
alert tcp any any -> any 80 (msg:"Cross Site Scripting Attack"; content:"<script"; nocase; sid:1000005; gid:1; priority:2;)
alert tcp any any -> any 80 (msg:"XSS - JavaScript Alert"; content:"javascript:alert"; nocase; sid:1000006; gid:1; priority:2;)

# SSH Brute Force detection
alert tcp any any -> any 22 (msg:"SSH Connection Attempt"; content:"SSH"; sid:1000007; gid:1; priority:3;)

# FTP detection
alert tcp any any -> any 21 (msg:"FTP Login Attempt"; content:"USER"; sid:1000008; gid:1; priority:3;)

# DNS detection
alert udp any any -> any 53 (msg:"DNS Query"; sid:1000009; gid:1; priority:3;)

# ICMP detection
alert icmp any any -> any any (msg:"ICMP Ping"; sid:1000010; gid:1; priority:3;)

# Malware detection patterns
drop tcp any any -> any any (msg:"Known Malware Pattern"; content:"malware_signature"; sid:1000011; gid:1; priority:1;)

# Port scanning detection
alert tcp any any -> any any (msg:"Port Scan Detected"; sid:1000012; gid:1; priority:2;)
```

## 故障排除

### 1. 规则加载失败
```bash
# 检查规则文件是否存在
ls -la /etc/vpp/ips/suricata.rules

# 检查文件权限
sudo chmod 644 /etc/vpp/ips/suricata.rules

# 查看VPP日志
sudo journalctl -u vpp -f
```

### 2. 规则编译失败
```bash
# 检查规则语法
# 确保每行规则格式正确
# 检查括号匹配
# 验证选项格式
```

### 3. 性能问题
```bash
# 查看统计信息
vpp# show ips stats

# 调整配置参数
vpp# ips config session-timeout 300
vpp# ips config cleanup-interval 60
```

## 技术实现

### 1. 启动时加载
- 在`ips_init()`函数中实现
- 检查默认规则文件是否存在
- 自动调用`ips_load_rules_from_file()`
- 自动编译规则

### 2. CLI命令实现
- 使用VPP的CLI框架
- 支持参数解析和验证
- 提供详细的帮助信息

### 3. 规则解析
- 实现Suricata兼容的规则解析器
- 支持C99标准，无外部依赖
- 使用VPP内存管理

### 4. 规则编译
- 集成Hyperscan模式匹配引擎
- 支持多模式并行匹配
- 优化的内存使用

## 扩展功能

### 未来计划
1. 支持更多Suricata规则选项
2. 实现规则组管理
3. 添加规则性能分析
4. 支持规则热更新
5. 集成外部威胁情报

### 自定义规则开发
可以通过修改`ips_rule_parser.c`来添加新的规则选项和功能。

## 参考资料

- [Suricata Rule Format](https://suricata.readthedocs.io/en/latest/rules/index.html)
- [VPP Plugin Development Guide](https://wiki.fd.io/view/VPP/Writing_a_Plugin)
- [Hyperscan Documentation](https://intel.github.io/hyperscan/dev-reference/)
