# VPP IPS Plugin

This is an Intrusion Prevention System (IPS) plugin for Vector Packet Processing (VPP).

## Features

- Traffic mirroring and analysis
- Protocol parsing and session management
- Rule-based detection engine with Hyperscan support
- Multiple response actions (drop, alert, reject, log)
- Multi-threaded processing
- VPP API integration
- CLI commands for management

## Building

The plugin is built as part of the VPP build process:

```bash
make build
```

## IDE Support and Lint Errors

### Understanding API File Generation

VPP plugins use an API definition system where:
1. `ips.api` defines the API messages
2. During build, VPP generates C header files:
   - `ips.api_enum.h` - Message ID enumerations
   - `ips.api_types.h` - Message structure definitions
   - `ips.api.h` - Complete API declarations
   - `ips.api.c` - API implementation helpers

### Resolving Lint Errors

IDEs may show lint errors because the generated API files are not present in the source directory. We provide several solutions:

#### Option 1: Use the Update Script (Recommended)
```bash
# After building the project
./src/plugins/ips/update_api_links.sh
```

This script creates symbolic links in two locations:
- Current directory: `ips.api_enum.h`, `ips.api_types.h`, etc.
- `ips/` subdirectory: For includes like `#include <ips/ips.api_enum.h>`

#### Option 2: Manual Symbolic Links
```bash
cd src/plugins/ips

# Create links in current directory
ln -sf ../../../build-root/build-vpp_debug-native/vpp/CMakeFiles/plugins/ips/ips.api_enum.h .
ln -sf ../../../build-root/build-vpp_debug-native/vpp/CMakeFiles/plugins/ips/ips.api_types.h .
ln -sf ../../../build-root/build-vpp_debug-native/vpp/CMakeFiles/plugins/ips/ips.api.c .
ln -sf ../../../build-root/build-vpp_debug-native/vpp/CMakeFiles/plugins/ips/ips.api.h .

# Create ips/ subdirectory for IDE compatibility
mkdir -p ips
cd ips
ln -sf ../../../../build-root/build-vpp_debug-native/vpp/CMakeFiles/plugins/ips/ips.api_enum.h .
ln -sf ../../../../build-root/build-vpp_debug-native/vpp/CMakeFiles/plugins/ips/ips.api_types.h .
ln -sf ../../../../build-root/build-vpp_debug-native/vpp/CMakeFiles/plugins/ips/ips.api.c .
ln -sf ../../../../build-root/build-vpp_debug-native/vpp/CMakeFiles/plugins/ips/ips.api.h .
```

#### Option 3: IDE Configuration
Configure your IDE to include the build directory in its search paths:
- Add `build-root/build-vpp_debug-native/vpp/CMakeFiles/plugins/ips/` to include paths
- Add `build-root/install-vpp_debug-native/vpp/include/` to include paths

#### Option 4: Use the Verification Script
```bash
./src/plugins/ips/verify_build.sh
```

This script checks the build status and provides guidance on resolving any issues.

### Important Notes

1. **Build First**: Always build the project before trying to resolve lint errors
2. **Generated Files**: The API files are generated during build and should not be edited manually
3. **Symbolic Links**: The symbolic links are safe to commit to version control as they point to build artifacts
4. **CMake Integration**: The CMakeLists.txt now includes automatic symbolic link creation

## Usage

### CLI Commands

```bash
# Enable IPS on interface
vpp# ips interface GigabitEthernet0/8/0 enable

# Add a rule
vpp# ips rule add id 1 msg "Test Rule" content "malware"

# Compile rules
vpp# ips rules compile

# Show statistics
vpp# show ips stats
```

### API Usage

The plugin provides a VPP API for programmatic control. See the generated API documentation for details.

## Architecture

- **Traffic Collection**: Handles mirrored traffic from switches
- **Protocol Parsing**: Multi-layer protocol analysis (VLAN, MPLS, VXLAN, GRE)
- **Session Management**: TCP session tracking and reassembly
- **Detection Engine**: Pattern matching with Hyperscan
- **Response Actions**: Configurable responses to detected threats

## Dependencies

- VPP (Vector Packet Processing)
- Hyperscan (optional, for high-performance pattern matching)
- Standard C libraries

## License

Licensed under the Apache License, Version 2.0.
