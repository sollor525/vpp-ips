#!/bin/bash

# Verification script for IPS plugin build and lint status

set -euo pipefail

echo "=== VPP IPS Plugin Build Verification ==="
echo

# Check if we're in the right directory
if [ ! -f "ips.api" ]; then
  echo "Error: Please run this script from src/plugins/ips_mirror directory"
  exit 1
fi

PLUGIN_NAME="ips"
BUILD_ROOT_REL="../../../build-root/build-vpp_debug-native"
INSTALL_ROOT_REL="../../../build-root/install-vpp_debug-native"

# Check source files
echo "1. Checking source files..."
SOURCE_FILES=(
  "ips.c"
  "ips.h"
  "ips_api.c"
  "ips_cli.c"
  "ips_node.c"
  "common/ips_flow.c"
  "detection/ips_detection.c"
  "common/ips_proto.c"
  "common/ips_response.c"
  "rules/ips_rule_parser.c"
  "ips.api"
  "CMakeLists.txt"
)

for file in "${SOURCE_FILES[@]}"; do
  if [ -f "$file" ]; then
    echo "  ✓ $file"
  else
    echo "  ✗ $file (missing)"
  fi
done

echo

# Check generated API files
echo "2. Checking generated API files..."
FOUND_DIR=""
if [ -d "$BUILD_ROOT_REL" ]; then
  FOUND_DIR=$(find "$BUILD_ROOT_REL" -type f -name "${PLUGIN_NAME}.api_enum.h" -printf "%h\n" -quit || true)
fi

if [ -n "$FOUND_DIR" ]; then
  echo "  ✓ Build artifacts directory found: $FOUND_DIR"
  API_FILES=(
    "${PLUGIN_NAME}.api_enum.h"
    "${PLUGIN_NAME}.api_types.h"
    "${PLUGIN_NAME}.api.h"
    "${PLUGIN_NAME}.api.c"
  )
  for file in "${API_FILES[@]}"; do
    if [ -f "$FOUND_DIR/$file" ]; then
      echo "  ✓ $FOUND_DIR/$file"
    else
      echo "  ✗ $FOUND_DIR/$file (missing)"
    fi
  done
else
  echo "  ✗ Generated API files not found under: $BUILD_ROOT_REL"
  echo "     Please run 'make build' first"
fi

echo

# Check symbolic links
echo "3. Checking symbolic links for IDE support..."
SYMLINK_FILES=(
  "${PLUGIN_NAME}.api_enum.h"
  "${PLUGIN_NAME}.api_types.h"
  "${PLUGIN_NAME}.api.h"
  "${PLUGIN_NAME}.api.c"
)

echo "  Current directory links:"
for file in "${SYMLINK_FILES[@]}"; do
  if [ -L "$file" ]; then
    if [ -e "$file" ]; then
      echo "    ✓ $file -> $(readlink "$file")"
    else
      echo "    ⚠ $file -> $(readlink "$file") (broken link)"
    fi
  else
    echo "    ✗ $file (no symbolic link)"
  fi
.done

echo "  ips/ subdirectory links (for IDE compatibility):"
for file in "${SYMLINK_FILES[@]}"; do
  if [ -L "ips/$file" ]; then
    if [ -e "ips/$file" ]; then
      echo "    ✓ ips/$file -> $(readlink "ips/$file")"
    else
      echo "    ⚠ ips/$file -> $(readlink "ips/$file") (broken link)"
    fi
  else
    echo "    ✗ ips/$file (no symbolic link)"
  fi
.done

echo

# Check plugin library
echo "4. Checking plugin library..."
PLUGIN_LIB="$INSTALL_ROOT_REL/vpp/lib/x86_64-linux-gnu/vpp_plugins/${PLUGIN_NAME}_plugin.so"

if [ -f "$PLUGIN_LIB" ]; then
  echo "  ✓ Plugin library exists: $PLUGIN_LIB"
  echo "    Size: $(ls -lh "$PLUGIN_LIB" | awk '{print $5}')"
else
  echo "  ✗ Plugin library not found: $PLUGIN_LIB"
fi

echo

# Check Hyperscan integration
echo "5. Checking Hyperscan integration..."
if [ -f "$PLUGIN_LIB" ] && ldd "$PLUGIN_LIB" 2>/dev/null | grep -q "libhs"; then
  echo "  ✓ Hyperscan library linked"
  ldd "$PLUGIN_LIB" 2>/dev/null | grep libhs | sed 's/^/    /'
else
  echo "  ⚠ Hyperscan library not linked (optional)"
fi

echo

# Summary
echo "=== Summary ==="
if [ -f "$PLUGIN_LIB" ] && [ -L "${PLUGIN_NAME}.api_enum.h" ]; then
  echo "✓ IPS plugin build successful!"
  echo "✓ Symbolic links created for IDE support"
  echo ""
  echo "To resolve any remaining lint errors in your IDE:"
  echo "1. Ensure your IDE includes the current directory in its search paths"
  echo "2. Restart your IDE/language server"
  echo "3. If issues persist, run: ./update_api_links.sh"
else
  echo "⚠ Some issues detected. Please check the output above."
  if [ ! -f "$PLUGIN_LIB" ]; then
    echo "  - Run 'make build' to build the plugin"
  fi
  if [ ! -L "${PLUGIN_NAME}.api_enum.h" ]; then
    echo "  - Run './update_api_links.sh' to create symbolic links"
  fi
fi

echo
