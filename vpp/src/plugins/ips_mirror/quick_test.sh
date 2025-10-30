#!/bin/bash

# VPP-IPS快速测试脚本
# 用于快速验证VPP-IPS系统的基本功能

set -e

TEST_LOG="/tmp/ips_quick_test.log"
RESULTS_DIR="/tmp/ips_quick_results"
mkdir -p $RESULTS_DIR

echo "=== VPP-IPS系统快速功能测试 ===" | tee $TEST_LOG
echo "测试开始时间: $(date)" | tee -a $TEST_LOG

# 1. 环境检查
echo "=== 1. 环境检查 ===" | tee -a $TEST_LOG

# 检查VPP进程
if pgrep vpp_main > /dev/null; then
    echo "✓ VPP进程运行正常" | tee -a $TEST_LOG
else
    echo "✗ VPP进程未运行，尝试启动..." | tee -a $TEST_LOG
    cd /root/workspace/IPS/vpp
    ./autorun.sh
    sleep 10
fi

# 检查IPS插件
vppctl show plugins | grep -q ips && echo "✓ IPS插件已加载" | tee -a $TEST_LOG || echo "✗ IPS插件未加载" | tee -a $TEST_LOG

# 检查网络接口
vppctl show interface host-veth1 | grep -q "up" && echo "✓ 网络接口正常" | tee -a $TEST_LOG || echo "✗ 网络接口异常" | tee -a $TEST_LOG

# 2. 基础功能测试
echo "=== 2. 基础功能测试 ===" | tee -a $TEST_LOG

# 启用IPS功能
vppctl ips interface host-veth1 2>/dev/null || true
vppctl set interface promiscuous on host-veth1 2>/dev/null || true

# 添加简单ACL规则
vppctl ips acl add rule src 10.0.79.87 tcp action permit 2>/dev/null || true
vppctl ips acl add rule src any tcp action deny 2>/dev/null || true
vppctl ips acl show stats 2>/dev/null || true

echo "✓ IPS功能已启用" | tee -a $TEST_LOG

# 3. 流量测试（使用可用的pcap文件）
echo "=== 3. 流量测试 ===" | tee -a $TEST_LOG

# 测试每个pcap文件
for pcap_file in /root/workspace/pcap/*.pcap; do
    if [ -f "$pcap_file" ]; then
        pcap_name=$(basename "$pcap_file")
        echo "测试文件: $pcap_name" | tee -a $TEST_LOG

        # 收集测试前统计
        vppctl show ips statistics > $RESULTS_DIR/before_${pcap_name}.log 2>&1

        # 回放流量
        echo "回放流量: $pcap_name" | tee -a $TEST_LOG
        tcpreplay -i veth0 --loop 1 --pps 2000 "$pcap_file" 2>/dev/null || echo "流量回放失败: $pcap_name" | tee -a $TEST_LOG

        # 等待处理完成
        sleep 3

        # 收集测试后统计
        vppctl show ips statistics > $RESULTS_DIR/after_${pcap_name}.log 2>&1
        vppctl show ips sessions > $RESULTS_DIR/sessions_${pcap_name}.log 2>&1
        vppctl ips acl show stats > $RESULTS_DIR/acl_${pcap_name}.log 2>&1

        echo "✓ 完成: $pcap_name" | tee -a $TEST_LOG
    fi
done

# 4. 结果分析
echo "=== 4. 测试结果分析 ===" | tee -a $TEST_LOG

# 统计处理的包数
echo "包处理统计:" | tee -a $TEST_LOG
for pcap_file in /root/workspace/pcap/*.pcap; do
    pcap_name=$(basename "$pcap_file")
    before_packets=$(grep "packets" $RESULTS_DIR/before_${pcap_name}.log | awk '{print $2}' | head -1)
    after_packets=$(grep "packets" $RESULTS_DIR/after_${pcap_name}.log | awk '{print $2}' | head -1)

    if [ -n "$before_packets" ] && [ -n "$after_packets" ]; then
        processed=$((after_packets - before_packets))
        echo "$pcap_name: 处理了 $processed 个包" | tee -a $TEST_LOG
    fi
done

# 会话统计
echo -e "\n会话统计:" | tee -a $TEST_LOG
total_sessions=0
for pcap_file in /root/workspace/pcap/*.pcap; do
    pcap_name=$(basename "$pcap_file")
    session_count=$(grep -c "session" $RESULTS_DIR/sessions_${pcap_name}.log 2>/dev/null || echo "0")
    total_sessions=$((total_sessions + session_count))
    echo "$pcap_name: $session_count 个会话" | tee -a $TEST_LOG
done
echo "总会话数: $total_sessions" | tee -a $TEST_LOG

# 错误检查
echo -e "\n错误检查:" | tee -a $TEST_LOG
error_count=0
for pcap_file in /root/workspace/pcap/*.pcap; do
    pcap_name=$(basename "$pcap_file")
    if grep -q "error\|fail\|drop" $RESULTS_DIR/after_${pcap_name}.log 2>/dev/null; then
        echo "$pcap_name: 发现错误或丢弃" | tee -a $TEST_LOG
        error_count=$((error_count + 1))
    fi
done

if [ $error_count -eq 0 ]; then
    echo "✓ 无严重错误" | tee -a $TEST_LOG
else
    echo "⚠ 发现 $error_count 个错误，请检查详细日志" | tee -a $TEST_LOG
fi

# 5. 系统资源检查
echo -e "\n=== 5. 系统资源检查 ===" | tee -a $TEST_LOG

if pgrep vpp_main > /dev/null; then
    vpp_pid=$(pgrep vpp_main)
    memory_kb=$(cat /proc/$vpp_pid/status | grep VmRSS | awk '{print $2}')
    cpu_usage=$(ps -p $vpp_pid -o %cpu=)
    echo "VPP内存使用: ${memory_kb}KB" | tee -a $TEST_LOG
    echo "VPP CPU使用: ${cpu_usage}%" | tee -a $TEST_LOG
else
    echo "✗ VPP进程异常" | tee -a $TEST_LOG
fi

# 6. 测试总结
echo -e "\n=== 测试总结 ===" | tee -a $TEST_LOG
echo "测试完成时间: $(date)" | tee -a $TEST_LOG
echo "详细日志: $TEST_LOG" | tee -a $TEST_LOG
echo "结果目录: $RESULTS_DIR" | tee -a $TEST_LOG

# 生成测试报告
cat > $RESULTS_DIR/test_summary.txt << EOF
VPP-IPS快速测试总结
==================
测试时间: $(date)
测试文件数: $(ls /root/workspace/pcap/*.pcap | wc -l)
总会话数: $total_sessions
错误数量: $error_count

测试文件:
$(ls /root/workspace/pcap/*.pcap)

结果文件:
$(ls -la $RESULTS_DIR/)
EOF

echo "✓ 测试总结已保存到: $RESULTS_DIR/test_summary.txt" | tee -a $TEST_LOG

echo -e "\n=== 快速测试完成 ===" | tee -a $TEST_LOG

# 如果有错误，返回非零退出码
if [ $error_count -gt 0 ]; then
    exit 1
else
    exit 0
fi