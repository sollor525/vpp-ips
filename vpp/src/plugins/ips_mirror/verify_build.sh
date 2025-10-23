#!/bin/bash

# Verification script for IPS plugin build and lint status

echo "=== VPP IPS Plugin Build Verification ==="
echo

# Check if we're in the right directory
if [ ! -f "ips.api" ]; then
  echo "Error: Please run this script from src/plugins/ips directory"
  exit 1
fi

# Check source files
echo "1. Checking source files..."
SOURCE_FILES=(
  "ips.c"
  "ips.h"
  "ips_api.c"
  "ips_cli.c"
  "ips_node.c"
  "ips_flow.c"
  "ips_detection.c"
  "ips_proto.c"
  "ips_response.c"
  "ips_rule_parser.c"
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
BUILD_DIR="../../../build-root/build-vpp_debug-native/vpp/CMakeFiles/plugins/ips"

if [ -d "$BUILD_DIR" ]; then
  echo "  ✓ Build directory exists"

  API_FILES=(
    "ips.api_enum.h"
    "ips.api_types.h"
    "ips.api.h"
    "ips.api.c"
  )

  for file in "${API_FILES[@]}"; do
    if [ -f "$BUILD_DIR/$file" ]; then
      echo "  ✓ $BUILD_DIR/$file"
    else
      echo "  ✗ $BUILD_DIR/$file (missing)"
    fi
  done
else
  echo "  ✗ Build directory not found: $BUILD_DIR"
  echo "     Please run 'make build' first"
fi

echo

# Check symbolic links
echo "3. Checking symbolic links for IDE support..."
echo "  Current directory links:"
SYMLINK_FILES=(
  "ips.api_enum.h"
  "ips.api_types.h"
  "ips.api.h"
  "ips.api.c"
)

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
done

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
done

echo

# Check plugin library
echo "4. Checking plugin library..."
PLUGIN_LIB="../../../build-root/install-vpp_debug-native/vpp/lib/x86_64-linux-gnu/vpp_plugins/ips_plugin.so"

if [ -f "$PLUGIN_LIB" ]; then
  echo "  ✓ Plugin library exists: $PLUGIN_LIB"
  echo "    Size: $(ls -lh "$PLUGIN_LIB" | awk '{print $5}')"
else
  echo "  ✗ Plugin library not found: $PLUGIN_LIB"
fi

echo

# Check Hyperscan integration
echo "5. Checking Hyperscan integration..."
if ldd "$PLUGIN_LIB" 2>/dev/null | grep -q "libhs"; then
  echo "  ✓ Hyperscan library linked"
  ldd "$PLUGIN_LIB" 2>/dev/null | grep libhs | sed 's/^/    /'
else
  echo "  ⚠ Hyperscan library not linked (optional)"
fi

echo

# Summary
echo "=== Summary ==="
if [ -f "$PLUGIN_LIB" ] && [ -L "ips.api_enum.h" ]; then
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
  if [ ! -L "ips.api_enum.h" ]; then
    echo "  - Run './update_api_links.sh' to create symbolic links"
  fi
fi

echo
