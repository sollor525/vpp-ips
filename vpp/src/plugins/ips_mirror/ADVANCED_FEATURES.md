# IPS插件高级特性支持

## 🚀 概述

VPP IPS插件现在支持大量Suricata兼容的高级特性，能够处理复杂的入侵检测规则。

## 📋 支持的高级特性

### 1. Flow状态检测
```
flow:to_client,established
flow:from_server,not_established
flow:stateless
```

**支持的Flow选项：**
- `to_client` - 流向客户端的数据包
- `to_server` - 流向服务器的数据包
- `from_client` - 来自客户端的数据包
- `from_server` - 来自服务器的数据包
- `established` - 已建立的连接
- `not_established` - 未建立的连接
- `stateless` - 无状态检测

### 2. 内容匹配增强
```
content:"stdapi_fs_file_expand_path"; depth:60; nocase;
content:"|ff 53 4d 42|"; offset:4;
content:"SELECT"; distance:0; within:50;
```

**支持的内容选项：**
- `depth:N` - 在数据包前N字节内搜索
- `offset:N` - 从第N字节开始搜索
- `distance:N` - 距离上次匹配N字节后搜索
- `within:N` - 在N字节范围内搜索
- `nocase` - 忽略大小写
- `rawbytes` - 在原始数据中搜索
- 十六进制内容：`|ff 53 4d 42|`

### 3. 数据包大小检测
```
dsize:5
dsize:>100
dsize:<1000
```

**支持的操作符：**
- `dsize:N` - 数据包大小等于N
- `dsize:>N` - 数据包大小大于N
- `dsize:<N` - 数据包大小小于N

### 4. 字节测试
```
byte_test:1,>,0,5
byte_test:2,&,40,2
byte_test:4,=,0x12345678,0,relative
```

**支持的字节测试：**
- `byte_test:bytes,operator,value,offset`
- 操作符：`>`, `<`, `=`, `&` (AND), `|` (OR)
- `relative` - 相对于上次匹配位置

### 5. 阈值控制
```
threshold: type limit, track by_src, count 30, seconds 60
threshold: type threshold, track by_dst, count 100, seconds 10
threshold: type both, track by_rule, count 5, seconds 30
```

**支持的阈值类型：**
- `limit` - 限制触发次数
- `threshold` - 达到阈值才触发
- `both` - 仅在达到精确次数时触发

**跟踪方式：**
- `by_src` - 按源IP跟踪
- `by_dst` - 按目标IP跟踪
- `by_rule` - 按规则跟踪

### 6. Flow Bits（流位）
```
flowbits:set,is_proto_irc
flowbits:isset,ET.teamviewerkeepaliveout
flowbits:isnotset,malware.detected
flowbits:toggle,suspicious_activity
flowbits:unset,temp_flag
flowbits:noalert
```

**支持的Flow Bits操作：**
- `set` - 设置流位
- `isset` - 检查流位是否已设置
- `isnotset` - 检查流位是否未设置
- `toggle` - 切换流位状态
- `unset` - 清除流位
- `noalert` - 不产生告警但设置流位

### 7. 数据可用性检查
```
isdataat:400,relative
isdataat:1000
isdataat:50,rawbytes
```

**支持的选项：**
- `isdataat:size` - 检查是否有足够数据
- `relative` - 相对于上次匹配位置
- `rawbytes` - 检查原始数据

### 8. 协议特定检测
```
window:0
id:0
```

**支持的协议选项：**
- `window:N` - TCP窗口大小检测
- `id:N` - IP分片ID检测

### 9. 元数据支持
```
metadata:created_at 2010_07_30, confidence High, signature_severity Critical
```

支持任意元数据标签用于规则分类和管理。

## 🔧 规则示例

### 基础规则
```
alert tcp any any -> any 80 (msg:"HTTP GET Request"; content:"GET"; depth:10; sid:1001;)
```

### 高级规则
```
alert tcp $EXTERNAL_NET any -> $HOME_NET any (
    msg:"ET ATTACK_RESPONSE Metasploit Meterpreter File/Memory Interaction Detected";
    flow:to_client,established;
    content:"stdapi_fs_file_expand_path";
    depth:60;
    reference:url,www.nologin.org/Downloads/Papers/meterpreter.pdf;
    classtype:successful-user;
    sid:2009578;
    rev:2;
    metadata:affected_product Any, attack_target Client_and_Server, created_at 2010_07_30;
)
```

### 阈值规则
```
alert tcp $EXTERNAL_NET any -> $SMTP_SERVERS 25 (
    msg:"ET DOS Excessive SMTP MAIL-FROM DDoS";
    flow:to_server,established;
    content:"MAIL FROM:";
    nocase;
    threshold: type limit, track by_src, count 30, seconds 60;
    classtype:denial-of-service;
    sid:2001795;
)
```

### 字节测试规则
```
alert udp any any -> any 53 (
    msg:"ET DOS DNS BIND 9 Dynamic Update DoS attempt";
    byte_test:1,&,40,2;
    byte_test:1,>,0,5;
    content:"|00 00 06|";
    offset:8;
    reference:cve,2009-0696;
    classtype:attempted-dos;
    sid:2009701;
)
```

## 🔄 兼容性

### 完全支持的Suricata特性
- ✅ Flow状态检测
- ✅ 内容匹配（包括十六进制）
- ✅ 数据包大小检测
- ✅ 字节测试
- ✅ 阈值控制
- ✅ Flow bits
- ✅ 基本协议检测

### 部分支持的特性
- 🔶 PCRE正则表达式（解析支持，执行需要扩展）
- 🔶 HTTP协议解析（基础支持）
- 🔶 TLS/SSL检测（基础支持）

### 计划支持的特性
- 🔲 完整的PCRE支持
- 🔲 HTTP URI/Header解析
- 🔲 TLS指纹识别
- 🔲 DNS协议解析
- 🔲 文件提取和检测

## 🎯 性能优化

### 1. 规则优化
- 使用`depth`和`offset`限制搜索范围
- 优先使用字节测试而非复杂正则表达式
- 合理设置阈值避免误报

### 2. Flow管理
- Flow bits按线程隔离，避免锁竞争
- 阈值跟踪使用高效哈希表
- 自动清理过期的Flow状态

### 3. 内存管理
- 规则编译时预分配内存
- 使用VPP的内存池管理
- 零拷贝的数据包处理

## 📊 使用统计

### 规则匹配统计
```bash
vppctl show ips stats
```

### Flow状态查看
```bash
vppctl show ips flows
```

### 阈值状态查看
```bash
vppctl show ips thresholds
```

## 🐛 调试和故障排除

### 1. 规则解析错误
```bash
vppctl ips rules load file /path/to/rules.rules
# 查看日志中的解析错误信息
```

### 2. 性能问题
```bash
vppctl show ips config
vppctl show runtime
# 检查CPU使用率和内存使用情况
```

### 3. 误报问题
- 调整阈值设置
- 使用Flow bits进行更精确的状态跟踪
- 优化规则的匹配条件

## 🔗 相关文档

- [基础配置指南](README.md)
- [架构修复文档](ARCHITECTURE_FIX.md)
- [启动故障排除](VPP_STARTUP_TROUBLESHOOTING.md)
- [Suricata官方文档](https://suricata.readthedocs.io/)

---

**注意：** 这个实现专注于高性能和VPP集成，某些高级特性可能与原始Suricata实现有细微差异，但保持了核心功能的兼容性。
