#!/bin/bash
#==================================================
#  VPP veth1 接管 + 2M 大页 + Core dump 一键脚本
#  自动识别本地 Debug/Release 编译路径
#==================================================
set -euo pipefail

############################
# Core dump 配置函数
############################
setup_core_dump() {
    local COREDIR="/opt/corfiles"
    local NEED_CONFIG=false

    echo "==== 配置 Core Dump 保存功能 ===="

    # 检查是否已经配置完成
    if [[ -f "/etc/sysctl.d/99-coredump.conf" ]] &&
       [[ -d "$COREDIR" ]] &&
       [[ "$(cat /proc/sys/kernel/core_pattern 2>/dev/null)" == "$COREDIR/%e.%p.%t.core" ]]; then
        echo "Core dump 已经配置完成，跳过重复配置"
        echo ""
        echo "当前配置状态:"
        echo "  保存路径: $COREDIR"
        echo "  文件格式: $(basename "$(cat /proc/sys/kernel/core_pattern)")"
        echo "  ulimit -c: $(ulimit -c)"
        echo ""
        return 0
    fi

    echo "检测到未配置或配置不完整，开始配置..."
    NEED_CONFIG=true

    # 创建 core dump 目录
    if [[ ! -d "$COREDIR" ]]; then
        echo "创建 Core dump 目录: $COREDIR"
        sudo mkdir -p "$COREDIR"
        sudo chmod 777 "$COREDIR"
    else
        echo "Core dump 目录已存在: $COREDIR"
    fi

    # 设置 core dump 文件名格式
    local CORE_PATTERN="$COREDIR/%e.%p.%t.core"
    if [[ "$(cat /proc/sys/kernel/core_pattern 2>/dev/null)" != "$CORE_PATTERN" ]]; then
        echo "配置 core pattern..."
        echo "$CORE_PATTERN" | sudo tee /proc/sys/kernel/core_pattern > /dev/null
    else
        echo "Core pattern 已正确配置"
    fi

    # 永久化配置（通过 sysctl）
    local CORE_PATTERN_CONF="/etc/sysctl.d/99-coredump.conf"
    if [[ ! -f "$CORE_PATTERN_CONF" ]] || [[ "$(grep "kernel.core_pattern" "$CORE_PATTERN_CONF" 2>/dev/null)" != "kernel.core_pattern = $CORE_PATTERN" ]]; then
        echo "配置永久化 core pattern..."
        echo "kernel.core_pattern = $CORE_PATTERN" | sudo tee "$CORE_PATTERN_CONF" > /dev/null
        sudo sysctl -p "$CORE_PATTERN_CONF" > /dev/null
    else
        echo "永久化 core pattern 配置已存在"
    fi

    # 设置 ulimit（检查 limits.conf）
    if ! grep -q "core unlimited" /etc/security/limits.conf 2>/dev/null; then
        echo "配置 ulimit 限制..."
        echo "* soft core unlimited" | sudo tee -a /etc/security/limits.conf > /dev/null
        echo "* hard core unlimited" | sudo tee -a /etc/security/limits.conf > /dev/null
    else
        echo "ulimit 限制已配置"
    fi

    # 设置当前会话的 ulimit
    ulimit -c unlimited

    # 配置 systemd 服务
    if command -v systemctl &> /dev/null; then
        local SYSTEMD_CONF="/etc/systemd/coredump.conf.d/custom.conf"
        if [[ ! -f "$SYSTEMD_CONF" ]]; then
            echo "配置 systemd-coredump..."
            sudo mkdir -p /etc/systemd/coredump.conf.d
            cat << EOF | sudo tee "$SYSTEMD_CONF" > /dev/null
[Storage]
Compress=no
ProcessSizeMax=2G
ExternalSizeMax=2G
JournalSizeMax=1G
InlineMax=2G
EOF
            sudo systemctl daemon-reload
            sudo systemctl restart systemd-coredump 2>/dev/null || true
        else
            echo "systemd-coredump 已配置"
        fi
    fi

    # 禁用 apport（如果存在）
    if command -v systemctl &> /dev/null && systemctl is-active --quiet apport; then
        echo "禁用 apport..."
        sudo systemctl disable apport 2>/dev/null || true
        sudo systemctl stop apport 2>/dev/null || true
    fi

    echo ""
    echo "Core dump 配置完成"
    echo "保存路径: $COREDIR"
    echo "文件格式: %e.%p.%t.core (程序名.PID.时间戳.core)"
    echo ""

    # 验证配置
    echo "验证配置:"
    echo "  Core pattern: $(cat /proc/sys/kernel/core_pattern)"
    echo "  ulimit -c: $(ulimit -c)"
    echo ""
}

############################
# 0. 可修改变量
############################
HUGEPAGE_SIZE=2048            # 2MB 页数
HUGEPAGE_SZ_MB=2        # 单页大小，单位 MB
IF_VETH0=veth0
IF_VETH1=veth1
IP_VETH0=192.168.123.1/24      # 修改到同一网段
IP_VETH1=192.168.123.2/24
IP_VPP_VETH1=192.168.123.3/24

############################
# 1. 定位 VPP 可执行文件
############################
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# 按优先级搜索
for flavour in debug release; do
  LOCAL_VPP="$SCRIPT_DIR/build-root/install-vpp_${flavour}-native/vpp/bin/vpp"
  if [[ -x "$LOCAL_VPP" ]]; then
    VPP_BIN="$LOCAL_VPP"
    VPP_FLAVOUR="$flavour"
    break
  fi
done
# 回退到系统路径
if [[ -z "${VPP_BIN:-}" ]]; then
  VPP_BIN=/usr/bin/vpp
  VPP_FLAVOUR="system"
fi
echo "使用 VPP 路径: $VPP_BIN  (flavour: $VPP_FLAVOUR)"

############################
# 2. 配置大页
############################
echo "==== 配置 $HUGEPAGE_SIZE 个 ${HUGEPAGE_SZ_MB}MB 大页 ===="

# 检查当前大页配置
current_hugepages=$(grep ^HugePages_Total /proc/meminfo | awk '{print $2}')

if [[ $current_hugepages -ge $HUGEPAGE_SIZE ]]; then
    echo "大页已配置充足: $current_hugepages (需要: $HUGEPAGE_SIZE)"
else
    echo "配置大页: 当前 $current_hugepages, 需要 $HUGEPAGE_SIZE"
    # 先清零，避免碎片
    sysctl -w vm.nr_hugepages=0
    for n in /sys/devices/system/node/node*; do
      echo 0 > "$n/hugepages/hugepages-2048kB/nr_hugepages"
    done
    # 再申请
    sysctl -w vm.nr_hugepages=$HUGEPAGE_SIZE
    # 若仍不足，按 NUMA 均分
    actual=$(grep ^HugePages_Total /proc/meminfo | awk '{print $2}')
    if [[ $actual -lt $HUGEPAGE_SIZE ]]; then
      need=$(( (HUGEPAGE_SIZE - actual) / $(nproc) ))
      for n in /sys/devices/system/node/node*; do
        echo $need > "$n/hugepages/hugepages-2048kB/nr_hugepages"
      done
      sysctl -w vm.nr_hugepages=$HUGEPAGE_SIZE
    fi
fi
grep HugePages /proc/meminfo

############################
# 3. 创建 veth pair
############################
echo "==== 创建 veth pair ===="

# 检查 veth 接口是否已存在且配置正确
if ip link show $IF_VETH0 &>/dev/null; then
    # 更安全的 IP 地址提取方式
    current_ip0=$(ip addr show $IF_VETH0 2>/dev/null | grep "inet $IP_VETH0" | awk '{print $2}' || echo "")
    current_ip1=$(ip addr show $IF_VETH1 2>/dev/null | grep "inet $IP_VETH1" | awk '{print $2}' || echo "")

    echo "检测到现有 veth 接口:"
    echo "  $IF_VETH0: ${current_ip0:-"未配置"}"
    echo "  $IF_VETH1: ${current_ip1:-"未配置"}"

    if [[ "$current_ip0" == "$IP_VETH0" ]] && [[ "$current_ip1" == "$IP_VETH1" ]]; then
        echo "veth 接口已存在且配置正确"
    else
        echo "veth 接口配置不完整，重新配置..."
        echo "删除现有接口..."
        ip link del $IF_VETH0 || true
        sleep 1

        echo "创建新的 veth 接口..."
        ip link add $IF_VETH0 type veth peer name $IF_VETH1
        echo "配置 IP 地址..."
        ip addr add $IP_VETH0 dev $IF_VETH0
        ip addr add $IP_VETH1 dev $IF_VETH1

        echo "启用接口..."
        ip link set $IF_VETH0 up
        ip link set $IF_VETH1 up

        echo "验证配置..."
        sleep 2

        # 再次验证配置
        verify_ip0=$(ip addr show $IF_VETH0 2>/dev/null | grep "inet $IP_VETH0" | awk '{print $2}')
        verify_ip1=$(ip addr show $IF_VETH1 2>/dev/null | grep "inet $IP_VETH1" | awk '{print $2}')

        echo "重新配置完成:"
        echo "  $IF_VETH0: ${verify_ip0:-"配置失败"}"
        echo "  $IF_VETH1: ${verify_ip1:-"配置失败"}"

        if [[ "$verify_ip0" != "$IP_VETH0" ]] || [[ "$verify_ip1" != "$IP_VETH1" ]]; then
            echo "错误：veth 接口 IP 配置失败"
            echo "调试信息:"
            ip addr show $IF_VETH0
            ip addr show $IF_VETH1
            exit 1
        fi
    fi
else
    echo "创建新的 veth 接口..."
    ip link add $IF_VETH0 type veth peer name $IF_VETH1
    echo "配置 IP 地址..."
    ip addr add $IP_VETH0 dev $IF_VETH0
    ip addr add $IP_VETH1 dev $IF_VETH1

    echo "启用接口..."
    ip link set $IF_VETH0 up
    ip link set $IF_VETH1 up

    echo "验证配置..."
    sleep 2

    # 验证配置
    verify_ip0=$(ip addr show $IF_VETH0 2>/dev/null | grep "inet $IP_VETH0" | awk '{print $2}')
    verify_ip1=$(ip addr show $IF_VETH1 2>/dev/null | grep "inet $IP_VETH1" | awk '{print $2}')

    echo "创建完成:"
    echo "  $IF_VETH0: ${verify_ip0:-"配置失败"}"
    echo "  $IF_VETH1: ${verify_ip1:-"配置失败"}"

    if [[ "$verify_ip0" != "$IP_VETH0" ]] || [[ "$verify_ip1" != "$IP_VETH1" ]]; then
        echo "错误：veth 接口 IP 配置失败"
        echo "调试信息:"
        ip addr show $IF_VETH0
        ip addr show $IF_VETH1
        exit 1
    fi
fi

# 验证接口状态
echo "接口状态:"
ip link show $IF_VETH0 | grep -E "state|mtu"
ip link show $IF_VETH1 | grep -E "state|mtu"

############################
setup_core_dump

############################
# 5. 强制重启 VPP
############################
echo "==== 启动 VPP (${VPP_FLAVOUR}) ===="

# 检查并停止现有的 VPP 进程
VPP_PID=$(pgrep -x vpp_main 2>/dev/null | head -1 || true)
if [[ -n "$VPP_PID" ]]; then
    echo "检测到 VPP 正在运行 (PID: $VPP_PID)"
    echo "命令行: $(ps -p $VPP_PID -o cmd= 2>/dev/null || echo '进程已退出')"
    echo "停止现有 VPP 进程..."
    
    # 尝试优雅停止
    kill -TERM "$VPP_PID" 2>/dev/null || true
    sleep 2
    
    # 检查是否已停止
    if kill -0 "$VPP_PID" 2>/dev/null; then
        echo "进程未响应 SIGTERM，使用 SIGKILL 强制停止..."
        kill -9 "$VPP_PID" 2>/dev/null || true
        sleep 1
    fi
    
    # 验证进程已停止
    if pgrep -x vpp_main >/dev/null 2>&1; then
        echo "❌ 警告: VPP 进程可能未完全停止"
    else
        echo "✅ VPP 进程已停止"
    fi
fi

# 停掉系统服务（避免冲突）
systemctl stop vpp 2>/dev/null || true

echo ""
echo "启动新的 VPP 进程..."

# 清空旧日志
rm -f /tmp/vpp.log

# 配置 hyperscan 动态库路径
HYPERSCAN_LIB_PATH="/root/workspace/vpp-ips/3rd-dep/hyperscan/hyperscan/build/lib"
if [[ -d "$HYPERSCAN_LIB_PATH" ]]; then
    echo "配置 hyperscan 动态库路径: $HYPERSCAN_LIB_PATH"
    export LD_LIBRARY_PATH="$HYPERSCAN_LIB_PATH${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    echo "LD_LIBRARY_PATH: $LD_LIBRARY_PATH"
else
    echo "⚠️  警告: hyperscan 库路径不存在: $HYPERSCAN_LIB_PATH"
    echo "ips_mirror plugin 可能无法正常加载"
fi

# 启动 VPP（后台运行）
"$VPP_BIN" -c /etc/vpp/startup.conf >/tmp/vpp.log 2>&1 &

# 等待 VPP 启动（检查进程和 CLI socket）
echo "等待 VPP 启动..."
vpp_started=false
for i in {1..15}; do
    sleep 1
    VPP_PID=$(pgrep -x vpp_main 2>/dev/null | head -1 || true)
    if [[ -n "$VPP_PID" ]]; then
        # 进程存在，检查 CLI socket
        if [[ -S /run/vpp/cli.sock ]] || [[ -S /var/run/vpp/cli.sock ]]; then
            vpp_started=true
            echo ""
            echo "✅ VPP 启动成功 (PID: $VPP_PID)"
            break
        fi
    fi
    echo -n "."
done
echo ""

if [[ "$vpp_started" != "true" ]]; then
    echo "❌ VPP 启动失败，查看日志:"
    echo ""
    tail -30 /tmp/vpp.log
    echo ""
    echo "完整日志: /tmp/vpp.log"
    exit 1
fi

# 等待 VPP 完全初始化
sleep 2

echo "VPP 进程信息:"
VPP_PID=$(pgrep -x vpp_main 2>/dev/null | head -1 || true)
echo "  PID: $VPP_PID"
echo "  CLI Socket: $(ls -l /run/vpp/cli.sock 2>/dev/null || echo '不存在')"
if [[ -n "$VPP_PID" ]]; then
    echo "  命令行: $(ps -p $VPP_PID -o cmd=)"
fi

############################
# 6. VPP 接管 veth1
############################
echo "==== VPP 接管 $IF_VETH1 ===="

# 检查 VPP 接口是否已经存在（更可靠的检测方法）
INTERFACE_EXISTS=false
if vppctl show interface 2>/dev/null | grep -q "host-$IF_VETH1"; then
    INTERFACE_EXISTS=true
    echo "host-$IF_VETH1 接口已存在于 VPP"
fi

if [[ "$INTERFACE_EXISTS" == "true" ]]; then
    echo "检查接口状态..."
    INTERFACE_STATUS=$(vppctl show interface host-$IF_VETH1 2>&1)
    
    if echo "$INTERFACE_STATUS" | grep -q "up"; then
        echo "接口已启用"
    else
        echo "接口未启用，重新启用..."
        vppctl set interface state host-$IF_VETH1 up
    fi

    # 检查 IP 地址（更精确的检测）
    echo "检查 IP 地址配置..."
    ADDR_OUTPUT=$(vppctl show interface addr 2>/dev/null | grep -A 5 "host-$IF_VETH1")
    
    # 检查期望的 IP 是否已配置
    if echo "$ADDR_OUTPUT" | grep -q "L3 $IP_VPP_VETH1"; then
        echo "✅ IP 地址已正确配置: $IP_VPP_VETH1"
    else
        echo "IP 地址未配置或不正确，当前配置:"
        echo "$ADDR_OUTPUT"
        echo "配置 IP 地址: $IP_VPP_VETH1"
        
        # 尝试配置 IP（如果已存在会报错，但不影响）
        SET_IP_OUTPUT=$(vppctl set interface ip address host-$IF_VETH1 $IP_VPP_VETH1 2>&1)
        if echo "$SET_IP_OUTPUT" | grep -qi "conflict"; then
            echo "⚠️  IP 地址已存在（这是正常的）"
        elif echo "$SET_IP_OUTPUT" | grep -qi "error"; then
            echo "❌ 配置 IP 失败: $SET_IP_OUTPUT"
        else
            echo "✅ IP 地址配置成功"
        fi
    fi
    
    # 启用混杂模式（关键！）
    echo "启用混杂模式（promiscuous mode）"
    vppctl set interface promiscuous on host-$IF_VETH1 2>&1
else
    echo "创建 host-$IF_VETH1 接口..."
    echo "执行: vppctl create host-interface name $IF_VETH1"
    CREATE_OUTPUT=$(vppctl create host-interface name $IF_VETH1 2>&1)
    echo "$CREATE_OUTPUT"
    
    # 检查创建是否成功
    if echo "$CREATE_OUTPUT" | grep -qi "error"; then
        echo "错误: 接口创建失败"
        echo "$CREATE_OUTPUT"
        exit 1
    fi
    
    # 提取接口名称（可能是 host-veth1 或其他格式）
    CREATED_INTERFACE=$(echo "$CREATE_OUTPUT" | grep -oP "host-\w+" | head -1)
    if [[ -z "$CREATED_INTERFACE" ]]; then
        CREATED_INTERFACE="host-$IF_VETH1"
    fi
    echo "接口名称: $CREATED_INTERFACE"
    
    echo "启用接口: $CREATED_INTERFACE"
    if ! vppctl set interface state $CREATED_INTERFACE up 2>&1; then
        echo "警告: 启用接口失败"
    fi
    
    echo "配置 IP 地址: $IP_VPP_VETH1"
    if ! vppctl set interface ip address $CREATED_INTERFACE $IP_VPP_VETH1 2>&1; then
        echo "警告: 配置 IP 地址失败"
    fi
    
    echo "启用混杂模式（promiscuous mode）"
    if ! vppctl set interface promiscuous on $CREATED_INTERFACE 2>&1; then
        echo "警告: 启用混杂模式失败"
    fi
    
    # 等待接口就绪
    sleep 1
fi

echo ""
echo "VPP 接口配置完成:"
vppctl show interface host-$IF_VETH1 2>&1 || vppctl show interface | grep -A 5 "host-"

############################
# 7. 连通性验证
############################
echo "==== 测试 Linux <-> VPP 连通性 ===="
echo "从 $IP_VETH0 ($IF_VETH0) ping VPP 接口 ${IP_VPP_VETH1%/*}"
if ping -c 3 -I $IF_VETH0 ${IP_VPP_VETH1%/*}; then
  echo "✅ 连通性测试成功！"
else
  echo "❌ Ping 失败"
  echo ""
  echo "调试信息："
  echo "1. 检查 VPP 接口状态："
  vppctl show interface host-$IF_VETH1
  echo ""
  echo "2. 检查 VPP 接口地址："
  vppctl show interface addr
  echo ""
  echo "3. 启用 VPP 跟踪查看数据包流向："
  echo "   vppctl trace add af-packet-input 10"
  echo "   ping -c 1 -I $IF_VETH0 ${IP_VPP_VETH1%/*}"
  echo "   vppctl show trace"
  echo ""
  echo "4. 查看 VPP 日志："
  echo "   tail -f /tmp/vpp.log"
  exit 1
fi

############################
# 8. 显示配置信息
############################
echo "==== 配置完成！内核<->VPP 已打通 ===="
echo ""
echo "Core dump 配置信息："
echo "保存路径: /opt/corfiles"
echo "文件格式: 程序名.PID.时间戳.core"
echo "例如: vpp.12345.1699123456.core"
echo ""
echo "VPP 进程信息:"
VPP_PID=$(pgrep -x vpp_main)
if [[ -n "$VPP_PID" ]]; then
  echo "PID: $VPP_PID"
  echo "命令行: $(ps -p $VPP_PID -o cmd=)"
  echo "Core dump 限制: $(ulimit -c)"
else
  echo "VPP 进程未找到"
fi
echo ""
echo "调试提示:"
echo "1. 使用 'gdb $VPP_BIN /opt/corfiles/vpp.\$PID.\$TIMESTAMP.core' 进行调试"
echo "2. 检查 'dmesg | grep -i segfault' 查看崩溃信息"
echo "3. 查看日志 'tail -f /tmp/vpp.log'"
echo ""
echo "Hyperscan 库配置:"
echo "路径: $HYPERSCAN_LIB_PATH"
echo "验证: ldd \$(which vpp) | grep hs || echo 'Hyperscan 库未链接到 VPP 主程序，但插件会动态加载'"

