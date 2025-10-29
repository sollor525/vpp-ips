#!/bin/bash

# Script to update API symbolic links for IPS plugin
# This helps IDEs find the generated API files

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_ROOT_REL="../../../build-root/build-vpp_debug-native"

cd "$SCRIPT_DIR"

echo "Updating API symbolic links for IPS plugin..."

# Remove old links if they exist
rm -f ips.api_enum.h ips.api_types.h ips.api.c ips.api.h || true
rm -f ips/ips.api_enum.h ips/ips.api_types.h ips/ips.api.c ips/ips.api.h || true

# Try to locate the directory containing generated API files dynamically
FOUND_DIR=""
if [ -d "$BUILD_ROOT_REL" ]; then
  # Prefer CMake binary dir for this plugin if it exists
  # Fallback to searching for ips.api_enum.h anywhere under build-root
  FOUND_DIR=$(find "$BUILD_ROOT_REL" -type f -name "ips.api_enum.h" -printf "%h\n" -quit || true)
fi

if [ -z "$FOUND_DIR" ]; then
  echo "Build directory not found or API files not generated under: $BUILD_ROOT_REL"
  echo "Please build the project first with 'make build'"
  exit 1
fi

echo "Detected generated API dir: $FOUND_DIR"

# Create new symbolic links in current directory
ln -sf "$FOUND_DIR/ips.api_enum.h" ./ips.api_enum.h
ln -sf "$FOUND_DIR/ips.api_types.h" ./ips.api_types.h
ln -sf "$FOUND_DIR/ips.api.c" ./ips.api.c
ln -sf "$FOUND_DIR/ips.api.h" ./ips.api.h

# Create ips subdirectory for IDE compatibility (handles ips/ips.api_*.h includes)
mkdir -p ips
ln -sf "$FOUND_DIR/ips.api_enum.h" ./ips/ips.api_enum.h
ln -sf "$FOUND_DIR/ips.api_types.h" ./ips/ips.api_types.h
ln -sf "$FOUND_DIR/ips.api.c" ./ips/ips.api.c
ln -sf "$FOUND_DIR/ips.api.h" ./ips/ips.api.h

# Show status
echo "API symbolic links updated successfully!"
echo "Files linked in current directory:"
ls -la *.api_enum.h *.api_types.h *.api.c *.api.h 2>/dev/null || echo "Some files may not exist yet - build the project first"
echo "Files linked in ips/ subdirectory:"
ls -la ips/*.api_enum.h ips/*.api_types.h ips/*.api.c ips/*.api.h 2>/dev/null || echo "Some files may not exist yet - build the project first"
