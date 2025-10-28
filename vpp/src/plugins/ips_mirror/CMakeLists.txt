##############################################################################
# IPS Plugin - Modular Architecture
##############################################################################

# Set Hyperscan paths first
set(HYPERSCAN_ROOT "/root/workspace/IPS/3rd-dep/hyperscan/hyperscan")
set(HYPERSCAN_INCLUDE_DIR "${HYPERSCAN_ROOT}/build")
set(HYPERSCAN_LIB_DIR "${HYPERSCAN_ROOT}/build/lib")

# Find Hyperscan library
find_library(HYPERSCAN_LIB
  NAMES hs libhs
  PATHS ${HYPERSCAN_LIB_DIR}
  NO_DEFAULT_PATH
)

# Find PCRE library
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCRE REQUIRED libpcre)

# Collect all source files from modules
set(IPS_SOURCES
  # Core plugin files
  ips.c
  ips_cli.c
  ips_node.c
  ips_logging.c
  ips_multi_content.c

  # Session module
  session/ips_session.c
  session/ips_session_timer.c
  session/ips_session_cli.c
  # Temporarily disabled due to Hyperscan dependency:
  # session/ips_tcp_reorder.c

  # Blocking module
  block/ips_block.c
  block/ips_block_node.c
  block/ips_block_cli.c

  # ACL module
  acl/ips_acl.c
  acl/ips_acl_cli.c

  # Detection engine module
  detection/ips_detection_module.c
  detection/ips_detection_temp.c
  detection/ips_inspect_node.c
  # Temporarily disabled due to Hyperscan dependency:
  # detection/ips_detection.c
  # detection/ips_detection_advanced.c
  # detection/ips_detection_optimized.c
  # detection/ips_detection_enhanced.c
  # detection/ips_multi_content_detection.c

  # Rules module
  rules/ips_rules_module.c
  # Temporarily disabled due to dependencies:
  # rules/ips_rule_parser.c
  # rules/ips_rule_parser_advanced.c
  # rules/ips_enhanced_parser.c
  # rules/ips_enhanced_suricata_parser.c
  # rules/ips_multi_content_parser.c

  # Common utilities (exclude problematic files for now)
  common/ips_proto.c
  common/ips_response.c
  common/ips_flow.c
#  common/ips_pcre_support.c          # Temporarily disabled
#  common/ips_pcre_hyperscan.c        # Temporarily disabled
#  common/ips_pcre_hyperscan_enhanced.c # Temporarily disabled

  # Protocol detection module
  protocols/ips_protocol_detection.c
  protocols/ips_protocol_detect_node.c

  # Timer API - Temporarily disabled
  # ips_timer_api.c
)

# Collect all header files
set(IPS_HEADERS
  ips.h
  ips_logging.h
  
  # Module headers
  session/ips_session.h
  session/ips_session_timer.h

  detection/ips_detection_module.h
  detection/ips_detection.h

  rules/ips_rules_module.h
  rules/ips_rule_parser.h

  # Common headers
  common/ips_proto.h
  common/ips_response.h
)

# Add the plugin
add_vpp_plugin(ips
  SOURCES
  ${IPS_SOURCES}

  API_FILES
  ips.api

  INSTALL_HEADERS
  ${IPS_HEADERS}

  LINK_LIBRARIES
  vppinfra
  vnet
  vlibapi
  vlibmemory

  COMPONENT
  vpp-plugin-ips
)

# Configure Hyperscan support (temporarily disabled)
message(STATUS "Hyperscan support temporarily disabled for core functionality testing")
# if(EXISTS "${HYPERSCAN_INCLUDE_DIR}/hs/hs.h" AND HYPERSCAN_LIB)
#   message(STATUS "Found Hyperscan at ${HYPERSCAN_ROOT}")
#   message(STATUS "Found Hyperscan library: ${HYPERSCAN_LIB}")
#
#   # Add Hyperscan include directory and library
#   target_include_directories(ips_plugin PRIVATE ${HYPERSCAN_INCLUDE_DIR})
#   target_link_libraries(ips_plugin ${HYPERSCAN_LIB})
#   target_compile_definitions(ips_plugin PRIVATE HAVE_HYPERSCAN=1)
#
#   # Add runtime library path
#   set_target_properties(ips_plugin PROPERTIES
#     INSTALL_RPATH "${HYPERSCAN_LIB_DIR}"
#     BUILD_WITH_INSTALL_RPATH TRUE
#   )
# else()
#   if(NOT EXISTS "${HYPERSCAN_INCLUDE_DIR}/hs/hs.h")
#     message(WARNING "Hyperscan headers not found at ${HYPERSCAN_INCLUDE_DIR}")
#   endif()
#   if(NOT HYPERSCAN_LIB)
#     message(WARNING "Hyperscan library not found in ${HYPERSCAN_LIB_DIR}")
#   endif()
# endif()

# Add module include directories
target_include_directories(ips_plugin PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/session
    ${CMAKE_CURRENT_SOURCE_DIR}/detection
    ${CMAKE_CURRENT_SOURCE_DIR}/rules
    ${CMAKE_CURRENT_SOURCE_DIR}/common
    ${CMAKE_CURRENT_SOURCE_DIR}/protocols
    ${CMAKE_CURRENT_SOURCE_DIR}/block
    ${CMAKE_CURRENT_SOURCE_DIR}/acl
)

# Create symbolic links to generated API files for IDE support
add_custom_command(TARGET ips_plugin POST_BUILD
  # Create links in current directory
  COMMAND ${CMAKE_COMMAND} -E create_symlink
    ${CMAKE_CURRENT_BINARY_DIR}/ips.api_enum.h
    ${CMAKE_CURRENT_SOURCE_DIR}/ips.api_enum.h
  COMMAND ${CMAKE_COMMAND} -E create_symlink
    ${CMAKE_CURRENT_BINARY_DIR}/ips.api_types.h
    ${CMAKE_CURRENT_SOURCE_DIR}/ips.api_types.h
  COMMAND ${CMAKE_COMMAND} -E create_symlink
    ${CMAKE_CURRENT_BINARY_DIR}/ips.api.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ips.api.c
  COMMAND ${CMAKE_COMMAND} -E create_symlink
    ${CMAKE_CURRENT_BINARY_DIR}/ips.api.h
    ${CMAKE_CURRENT_SOURCE_DIR}/ips.api.h
  # Create ips subdirectory for IDE compatibility (handles ips/ips.api_*.h includes)
  COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_SOURCE_DIR}/ips
  COMMAND ${CMAKE_COMMAND} -E create_symlink
    ${CMAKE_CURRENT_BINARY_DIR}/ips.api_enum.h
    ${CMAKE_CURRENT_SOURCE_DIR}/ips/ips.api_enum.h
  COMMAND ${CMAKE_COMMAND} -E create_symlink
    ${CMAKE_CURRENT_BINARY_DIR}/ips.api_types.h
    ${CMAKE_CURRENT_SOURCE_DIR}/ips/ips.api_types.h
  COMMAND ${CMAKE_COMMAND} -E create_symlink
    ${CMAKE_CURRENT_BINARY_DIR}/ips.api.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ips/ips.api.c
  COMMAND ${CMAKE_COMMAND} -E create_symlink
    ${CMAKE_CURRENT_BINARY_DIR}/ips.api.h
    ${CMAKE_CURRENT_SOURCE_DIR}/ips/ips.api.h
  COMMENT "Creating symbolic links to generated API files for IDE support"
)