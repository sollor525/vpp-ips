#!/bin/bash

# Script to update API symbolic links for IPS plugin
# This helps IDEs find the generated API files

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="../../../build-root/build-vpp_debug-native/vpp/CMakeFiles/plugins/ips"

cd "$SCRIPT_DIR"

echo "Updating API symbolic links for IPS plugin..."

# Remove old links if they exist
rm -f ips.api_enum.h ips.api_types.h ips.api.c ips.api.h

# Check if build directory exists
if [ ! -d "$BUILD_DIR" ]; then
  echo "Build directory not found: $BUILD_DIR"
  echo "Please build the project first with 'make build'"
  exit 1
fi

# Create new symbolic links in current directory
ln -sf "$BUILD_DIR/ips.api_enum.h" .
ln -sf "$BUILD_DIR/ips.api_types.h" .
ln -sf "$BUILD_DIR/ips.api.c" .
ln -sf "$BUILD_DIR/ips.api.h" .

# Create ips subdirectory for IDE compatibility (handles ips/ips.api_*.h includes)
mkdir -p ips
cd ips
ln -sf "../$BUILD_DIR/ips.api_enum.h" .
ln -sf "../$BUILD_DIR/ips.api_types.h" .
ln -sf "../$BUILD_DIR/ips.api.c" .
ln -sf "../$BUILD_DIR/ips.api.h" .
cd ..

echo "API symbolic links updated successfully!"
echo "Files linked in current directory:"
ls -la *.api_enum.h *.api_types.h *.api.c *.api.h 2>/dev/null || echo "Some files may not exist yet - build the project first"
echo "Files linked in ips/ subdirectory:"
ls -la ips/*.api_enum.h ips/*.api_types.h ips/*.api.c ips/*.api.h 2>/dev/null || echo "Some files may not exist yet - build the project first"
