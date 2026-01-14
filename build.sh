#!/bin/bash
#
# VPP IPS Build Script
#
# Usage:
#   ./build.sh [release|debug] [build|rebuild]
#
# Examples:
#   ./build.sh debug build      # 增量编译 debug 版本
#   ./build.sh release rebuild  # 完全重新编译 release 版本
#   ./build.sh debug            # 默认增量编译 debug 版本
#

set -e  # 遇到错误立即退出

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# 默认参数
BUILD_TYPE="debug"
BUILD_MODE="build"
WORKSPACE_DIR="/root/workspace/vpp-ips"
VPP_DIR="${WORKSPACE_DIR}/vpp"
DEP_DIR="${WORKSPACE_DIR}/3rd-dep"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# 需要保留的 VPP 插件列表（插件名不带 lib 前缀）
KEEP_PLUGINS=(
    "acl_plugin.so"
    "ips_plugin.so"
    "dpdk_plugin.so"
    "perfmon_plugin.so"
    "cnat_plugin.so"
)

# 需要复制的依赖库
DEP_LIBS=(
    "hyperscan/hyperscan/build/lib/libhs.so"
)

# 解析命令行参数
if [ -n "$1" ]; then
    case "$1" in
        debug|release)
            BUILD_TYPE="$1"
            ;;
        *)
            log_error "Invalid build type: $1 (must be 'debug' or 'release')"
            echo "Usage: $0 [debug|release] [build|rebuild]"
            exit 1
            ;;
    esac
fi

if [ -n "$2" ]; then
    case "$2" in
        build|rebuild)
            BUILD_MODE="$2"
            ;;
        *)
            log_error "Invalid build mode: $2 (must be 'build' or 'rebuild')"
            echo "Usage: $0 [debug|release] [build|rebuild]"
            exit 1
            ;;
    esac
fi

# 设置构建目录
if [ "$BUILD_TYPE" = "debug" ]; then
    BUILD_DIR="${VPP_DIR}/build-root/build-vpp_debug-native"
    INSTALL_DIR="${VPP_DIR}/build-root/install-vpp_debug-native"
    BUILD_CONFIG="build-vpp_debug-native"
else
    BUILD_DIR="${VPP_DIR}/build-root/build-vpp-native"
    INSTALL_DIR="${VPP_DIR}/build-root/install-vpp-native"
    BUILD_CONFIG="build-vpp-native"
fi

# 输出构建配置
log_step "Build Configuration"
echo "=========================================="
echo "Build Type:    ${BUILD_TYPE}"
echo "Build Mode:    ${BUILD_MODE}"
echo "VPP Directory: ${VPP_DIR}"
echo "Build Directory: ${BUILD_DIR}"
echo "Install Directory: ${INSTALL_DIR}"
echo "Timestamp:     ${TIMESTAMP}"
echo "=========================================="
echo ""

# 检查工作目录
if [ ! -d "${VPP_DIR}" ]; then
    log_error "VPP directory not found: ${VPP_DIR}"
    exit 1
fi

cd "${VPP_DIR}"

# Step 1: 清理（如果是 rebuild 模式）
if [ "$BUILD_MODE" = "rebuild" ]; then
    log_step "Cleaning previous build..."
    if [ "$BUILD_TYPE" = "release" ]; then
        make wipe-release || {
            log_error "Failed to clean build directory"
            exit 1
        }
        log_info "Clean completed (release mode)"
    else
        make wipe || {
            log_error "Failed to clean build directory"
            exit 1
        }
        log_info "Clean completed (debug mode)"
    fi
fi

# Step 2: 构建 VPP (配置+编译+安装)
log_step "Building VPP (${BUILD_TYPE} mode)..."
if [ "$BUILD_TYPE" = "release" ]; then
    make build-release || {
        log_error "Failed to build VPP"
        exit 1
    }
    log_info "VPP build completed (release mode)"
else
    make build || {
        log_error "Failed to build VPP"
        exit 1
    }
    log_info "VPP build completed (debug mode)"
fi

# Step 3: 复制 bin 和 lib 到 vpp-ips 目录
log_step "Copying VPP binaries and libraries..."

# 目标目录（创建 vpp-ips/vpp-ips/ 子目录结构）
TARGET_ROOT_DIR="${WORKSPACE_DIR}/vpp-ips"
TARGET_BIN_DIR="${TARGET_ROOT_DIR}/bin"
TARGET_LIB_DIR="${TARGET_ROOT_DIR}/lib"

# 清理旧文件
rm -rf "${TARGET_ROOT_DIR}"

# 创建目标目录结构
mkdir -p "${TARGET_BIN_DIR}"
mkdir -p "${TARGET_LIB_DIR}/vpp_plugins"

# 复制 bin 目录
if [ -d "${INSTALL_DIR}/vpp/bin" ]; then
    cp -rf "${INSTALL_DIR}/vpp/bin"/* "${TARGET_BIN_DIR}/"
    log_info "Copied bin directory: ${TARGET_BIN_DIR}"
else
    log_warn "VPP bin directory not found: ${INSTALL_DIR}/vpp/bin"
fi

# 复制 lib 目录（排除不需要的插件）
# VPP 实际安装路径：install-vpp_debug-native/vpp/lib/x86_64-linux-gnu/
VPP_LIB_ARCH_DIR="${INSTALL_DIR}/vpp/lib/x86_64-linux-gnu"
VPP_PLUGIN_DIR="${VPP_LIB_ARCH_DIR}/vpp_plugins"
VPP_PYTHON_DIR="${INSTALL_DIR}/vpp/lib/python3.8/site-packages"

if [ -d "${VPP_LIB_ARCH_DIR}" ]; then
    # 复制所有库文件（.so 文件和符号链接）
    lib_count=0
    for file in "${VPP_LIB_ARCH_DIR}"/*; do
        filename=$(basename "${file}")
        # 跳过目录（保留符号链接）
        if [ -d "${file}" ]; then
            continue
        fi
        # 复制 .so 文件（包括符号链接和实际文件）
        # 匹配所有 .so 文件，包括带版本号的（如 libxxx.so.version）
        if [[ "${filename}" =~ \.so ]]; then
            cp -af "${file}" "${TARGET_LIB_DIR}/"
            lib_count=$((lib_count + 1))
        fi
    done
    log_info "Total libraries copied: ${lib_count}"

    # 复制选定的插件
    if [ -d "${VPP_PLUGIN_DIR}" ]; then
        plugin_count=0
        for plugin in "${KEEP_PLUGINS[@]}"; do
            if [ -f "${VPP_PLUGIN_DIR}/${plugin}" ]; then
                cp -f "${VPP_PLUGIN_DIR}/${plugin}" "${TARGET_LIB_DIR}/vpp_plugins/"
                log_info "Copied plugin: ${plugin}"
                plugin_count=$((plugin_count + 1))
            else
                log_warn "Plugin not found: ${plugin}"
            fi
        done
        log_info "Total plugins copied: ${plugin_count}"
    else
        log_warn "VPP plugin directory not found: ${VPP_PLUGIN_DIR}"
    fi

    # 复制 vpp-api python 包
    if [ -d "${VPP_PYTHON_DIR}/vpp_papi" ]; then
        cp -rf "${VPP_PYTHON_DIR}/vpp_papi" "${TARGET_LIB_DIR}/"
        log_info "Copied VPP API Python package"
    fi
else
    log_warn "VPP lib arch directory not found: ${VPP_LIB_ARCH_DIR}"
fi

# Step 4: 复制依赖库（3rd-dep）
log_step "Copying 3rd-party dependencies..."

for dep_lib in "${DEP_LIBS[@]}"; do
    dep_path="${DEP_DIR}/${dep_lib}"
    if [ -f "${dep_path}" ]; then
        cp -rf "${dep_path}" "${TARGET_LIB_DIR}/"
        log_info "Copied dependency: $(basename ${dep_lib})"
    else
        log_warn "Dependency not found: ${dep_path}"
    fi
done

# 特殊处理：复制 Hyperscan 的所有相关库
if [ -d "${DEP_DIR}/hyperscan/hyperscan/build/lib" ]; then
    hs_lib_count=0
    for hs_lib in "${DEP_DIR}/hyperscan/hyperscan/build/lib"/libhs*; do
        if [ -f "${hs_lib}" ]; then
            cp -rf "${hs_lib}" "${TARGET_LIB_DIR}/"
            log_info "Copied Hyperscan library: $(basename ${hs_lib})"
            hs_lib_count=$((hs_lib_count + 1))
        fi
    done
    log_info "Total Hyperscan libraries copied: ${hs_lib_count}"
fi

# Step 5: 创建库路径配置脚本
log_step "Creating environment setup script..."
cat > "${TARGET_ROOT_DIR}/vpp-env.sh" << 'EOF'
#!/bin/bash
#
# VPP IPS Environment Setup Script
#
# 用法: source vpp-env.sh
#

# 检测是否使用 source 执行
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "错误: 必须使用 'source' 命令执行此脚本"
    echo ""
    echo "正确用法:"
    echo "  source vpp-env.sh"
    echo "  . ./vpp-env.sh"
    echo ""
    echo "原因: 此脚本设置环境变量，必须在当前 shell 中执行"
    return 1 2>/dev/null || exit 1
fi

# 获取脚本所在目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 设置环境变量
export PATH="${SCRIPT_DIR}/bin:${PATH}"
export LD_LIBRARY_PATH="${SCRIPT_DIR}/lib:${SCRIPT_DIR}/lib/vpp_plugins:${LD_LIBRARY_PATH}"

# 设置 Hyperscan 库路径（如果在 lib 中）
if [ -f "${SCRIPT_DIR}/lib/libhs.so" ]; then
    export LD_LIBRARY_PATH="${SCRIPT_DIR}/lib:${LD_LIBRARY_PATH}"
fi

ldconfig

echo "VPP IPS environment configured:"
echo "  PATH=${PATH}"
echo "  LD_LIBRARY_PATH=${LD_LIBRARY_PATH}"
echo ""
echo "You can now run:"
echo "  vppctl          # VPP CLI"
echo "  vpp -c <conf>   # Start VPP"
EOF

chmod +x "${TARGET_ROOT_DIR}/vpp-env.sh"
log_info "Created environment setup script: vpp-env.sh"

# Step 6: 打包
log_step "Creating release package..."

PACKAGE_NAME="vpp-ips-${BUILD_TYPE}-${TIMESTAMP}.tar.gz"
PACKAGE_PATH="${WORKSPACE_DIR}/${PACKAGE_NAME}"

# 在 vpp-ips 目录中创建版本信息文件
cat > "${TARGET_ROOT_DIR}/VERSION.txt" << EOF
VPP IPS Build Package
=====================
Build Type: ${BUILD_TYPE}
Build Mode: ${BUILD_MODE}
Build Time: ${TIMESTAMP}
Build Date: $(date)
Hostname: $(hostname)
User: $(whoami)
Git Branch: $(cd "${VPP_DIR}" && git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
Git Commit: $(cd "${VPP_DIR}" && git rev-parse --short HEAD 2>/dev/null || echo "unknown")

Included Components:
====================
VPP Core: Yes
IPS Plugin: Yes
ACL Plugin: Yes
DPDK Plugin: Yes
Perfmon Plugin: Yes
Hyperscan: Yes

Included Plugins:
=================
EOF

# 添加插件列表到 VERSION.txt
for plugin in "${KEEP_PLUGINS[@]}"; do
    echo "  - ${plugin}" >> "${TARGET_ROOT_DIR}/VERSION.txt"
done

# 打包 vpp-ips 目录
cd "${WORKSPACE_DIR}"
tar -czf "${PACKAGE_PATH}" vpp-ips

# 获取包大小
PACKAGE_SIZE=$(du -h "${PACKAGE_PATH}" | cut -f1)

log_info "Package created: ${PACKAGE_NAME}"
log_info "Package size: ${PACKAGE_SIZE}"

# Step 7: 创建符号链接（最新版本）
LATEST_NAME="vpp-ips-${BUILD_TYPE}-latest.tar.gz"
ln -sf "${PACKAGE_NAME}" "${LATEST_NAME}"
log_info "Latest package link: ${LATEST_NAME} -> ${PACKAGE_NAME}"

# 完成
echo ""
log_step "Build Summary"
echo "=========================================="
echo "Build Type:    ${BUILD_TYPE}"
echo "Build Mode:    ${BUILD_MODE}"
echo "Package:       ${PACKAGE_NAME}"
echo "Size:          ${PACKAGE_SIZE}"
echo "Location:      ${WORKSPACE_DIR}"
echo ""
echo "Package Contents:"
echo "  - VPP binaries (vpp, vppctl, etc.)"
echo "  - Selected VPP plugins:"
for plugin in "${KEEP_PLUGINS[@]}"; do
    echo "      ${plugin}"
done
echo "  - Hyperscan libraries"
echo "  - Environment setup script (vpp-env.sh)"
echo ""
echo "To extract and use:"
echo "  tar -xzf ${PACKAGE_NAME}"
echo "  cd vpp-ips"
echo "  source vpp-env.sh"
echo "  vppctl show version"
echo "=========================================="

log_info "Build completed successfully!"
