#!/bin/bash
#==================================================
#  VPP veth1 接管 + 2M 大页 一键脚本
#  自动识别本地 Debug/Release 编译路径
#==================================================
set -euo pipefail

############################
# 0. 可修改变量
############################
HUGEPAGE_SIZE=2048            # 2MB 页数
HUGEPAGE_SZ_MB=2        # 单页大小，单位 MB
IF_VETH0=veth0
IF_VETH1=veth1
IP_VETH0=192.168.123.1/24
IP_VETH1=192.168.123.2/24

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
grep HugePages /proc/meminfo

############################
# 3. 创建 veth pair
############################
echo "==== 创建 veth pair ===="
ip link show $IF_VETH0 &>/dev/null && ip link del $IF_VETH0 || true
ip link add $IF_VETH0 type veth peer name $IF_VETH1
ip addr add $IP_VETH0 dev $IF_VETH0
ip link set $IF_VETH0 up
ip link set $IF_VETH1 up

############################
# 4. 停止系统服务 & 用本地二进制启动
############################
echo "==== 启动 VPP (${VPP_FLAVOUR}) ===="
systemctl stop vpp 2>/dev/null || true   # 停掉系统服务避免 8713 端口冲突
# 使用本地 unit 文件（若存在）或直接前台启动
if [[ -f "$SCRIPT_DIR/build-root/install-vpp_${VPP_FLAVOUR}-native/vpp/CMakeFiles/debian/vpp.service" ]]; then
  cp -f "$SCRIPT_DIR/build-root/install-vpp_${VPP_FLAVOUR}-native/vpp/CMakeFiles/debian/vpp.service" \
        /lib/systemd/system/vpp.service
  sed -i "s|ExecStart=.*|ExecStart=$VPP_BIN -c /etc/vpp/startup.conf|g" /lib/systemd/system/vpp.service
  systemctl daemon-reload
  systemctl restart vpp
  systemctl is-active -q vpp || { echo "VPP 启动失败"; exit 1; }
else
  # 简单前台启动（调试时方便看日志）
  # 如果存在 vpp 进程则优雅/强制终止
    if pgrep -x vpp_main >/dev/null; then
      echo "正在停止 VPP ..."
      pkill -9 vpp_main
      # 等待完全退出（可选）
      while pgrep -x vpp_main >/dev/null; do
        sleep 0.2
      done
      echo "VPP 已停止"
  else
    echo "VPP 未运行，跳过 kill"
  fi
  nohup "$VPP_BIN" -c /etc/vpp/startup.conf >/tmp/vpp.log 2>&1 &
  sleep 2
  pgrep -x vpp_main >/dev/null || { echo "VPP 前台启动失败，查看 /tmp/vpp.log"; exit 1; }
fi

############################
# 5. VPP 接管 veth1
############################
echo "==== VPP 接管 $IF_VETH1 ===="
vppctl create host-interface name $IF_VETH1
vppctl set interface state host-$IF_VETH1 up
vppctl set interface ip address host-$IF_VETH1 $IP_VETH1
vppctl show interface addr

############################
# 6. 连通性验证
############################
ping -c 3 -I $IF_VETH0 ${IP_VETH1%/*} || {
  echo "ping 失败，检查 iptables 或 VPP 日志"
  exit 1
}
echo "==== 全部完成！内核<->VPP 已打通 ===="
