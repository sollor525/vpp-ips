# IPS Mirror Plugin 命名映射表

## 文件重命名映射

### Enhanced/Advanced 文件重命名
```
原文件名 -> 新文件名
-----------------------------------
ips_pcre_hyperscan_enhanced.c -> ips_pcre_hyperscan.c
ips_rule_parser_advanced.c -> ips_rule_parser.c (替换基础版本)
ips_suricata_enhanced_parser.c -> ips_suricata_parser.c
ips_suricata_enhanced_parser.h -> ips_suricata_parser.h
ips_suricata_enhanced_engine.h -> ips_suricata_engine.h
```

### 需要删除的文件
```
基础版本将被增强版本替换：
ips_rule_parser.c (将被 ips_rule_parser_advanced.c 替换并重命名)
```

## 函数重命名映射

### Enhanced 函数重命名
```
原函数名 -> 新函数名
-----------------------------------
ips_convert_pcre_to_hyperscan_enhanced() -> ips_convert_pcre_to_hyperscan()
ips_validate_pcre_for_hyperscan_enhanced() -> ips_validate_pcre_for_hyperscan()
```

### 需要删除的重复函数
```
基础版本将被删除（保留增强版本）：
ips_convert_pcre_to_hyperscan() (保留增强版本)
ips_validate_pcre_for_hyperscan() (保留增强版本)
```

## 数据结构重命名映射

### 结构体重命名
```
原结构体 -> 新结构体
-----------------------------------
ips_enhanced_detection_config_t -> ips_detection_config_t
```

## 头文件包含更新

### 需要更新头文件引用的文件
```
需要更新的文件列表：
- 所有包含 ips_suricata_enhanced_parser.h 的文件
- 所有包含 ips_suricata_enhanced_engine.h 的文件
- 所有调用增强函数的文件
```

## CMakeLists.txt 更新

### 需要更新的源文件列表
```
源文件路径更新：
common/ips_pcre_hyperscan_enhanced.c -> common/ips_pcre_hyperscan.c
rules/ips_rule_parser_advanced.c -> rules/ips_rule_parser.c
detection/ips_suricata_enhanced_parser.c -> detection/ips_suricata_parser.c
```

### 需要更新的头文件列表
```
头文件路径更新：
detection/ips_suricata_enhanced_parser.h -> detection/ips_suricata_parser.h
detection/ips_suricata_enhanced_engine.h -> detection/ips_suricata_engine.h
```

## 实施顺序

1. 重命名文件
2. 更新头文件引用
3. 更新函数名
4. 更新CMakeLists.txt
5. 删除重复代码
6. 测试编译