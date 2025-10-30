#!/bin/bash

# 系统检查所有IPS节点的枚举和数组长度匹配

echo "=== IPS节点枚举和数组长度检查 ==="
echo

# 检查所有包含节点枚举的文件
files=$(find /root/workspace/IPS/vpp/src/plugins/ips_mirror -name "*.c" -exec grep -l "N_NEXT" {} \;)

for file in $files; do
    echo "检查文件: $file"

    # 查找枚举定义
    echo "--- 枚举定义 ---"
    grep -A 20 "typedef enum" "$file" | grep -A 20 "_NEXT" | head -25

    # 查找next_nodes数组
    echo "--- next_nodes数组 ---"
    grep -A 15 "next_nodes = {" "$file" | head -20

    echo
done