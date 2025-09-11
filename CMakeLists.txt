cmake_minimum_required(VERSION 3.16)

project(tdx_tapp VERSION 1.0.0 LANGUAGES C CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set default build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")
set(CMAKE_CXX_FLAGS_RELEASE "-O2 -DNDEBUG")
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -DDEBUG")

# Options
option(FORCE_TDX_SUPPORT "Force enable TDX support even without hardware" OFF)
option(BUILD_TESTING "Build tests" OFF)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/rpc)

# Add custom module path for FindTDX
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

# ============================================================================
# TDX Hardware Detection and Support Configuration
# ============================================================================

message(STATUS "=== TDX Configuration ===")

# Set TDX options before calling find_package
if(FORCE_TDX_SUPPORT)
    set(TDX_FORCE_SUPPORT ON)
endif()

# Use the proper FindTDX module
find_package(TDX)

if(TDX_FOUND)
    add_definitions(-DHAVE_TDX_ATTEST)
    if(TDX_USE_LOCAL_IMPLEMENTATION)
        message(STATUS "TDX support: ENABLED (Local implementation from deps/)")
    else()
        message(STATUS "TDX support: ENABLED (System library)")
    endif()
    message(STATUS "  Libraries: ${TDX_ATTEST_LIBRARIES}")
    message(STATUS "  Include: ${TDX_ATTEST_INCLUDE_DIRS}")
else()
    if(TDX_HARDWARE_SUPPORTED)
        message(STATUS "TDX support: DISABLED (No library/sources available)")
    else()
        message(STATUS "TDX support: DISABLED (No hardware support)")
    endif()
endif()

message(STATUS "=========================")

# ============================================================================
# Find Required Packages
# ============================================================================

find_package(PkgConfig REQUIRED)
if(NOT TARGET protobuf::libprotobuf)
    find_package(Protobuf REQUIRED)
endif()
find_package(gRPC REQUIRED)
find_package(OpenSSL REQUIRED)

# Find gRPC C++ plugin
find_program(gRPC_CPP_PLUGIN_EXECUTABLE grpc_cpp_plugin)
if(NOT gRPC_CPP_PLUGIN_EXECUTABLE)
    set(gRPC_CPP_PLUGIN_EXECUTABLE "/usr/local/bin/grpc_cpp_plugin")
    if(NOT EXISTS ${gRPC_CPP_PLUGIN_EXECUTABLE})
        message(FATAL_ERROR "grpc_cpp_plugin not found")
    endif()
endif()

# ============================================================================
# Generate Protobuf and gRPC Files
# ============================================================================

set(PROTO_FILES ${CMAKE_SOURCE_DIR}/rpc/tapp_service.proto)
set(PROTO_OUT_DIR ${CMAKE_BINARY_DIR}/generated)

file(MAKE_DIRECTORY ${PROTO_OUT_DIR})

# Custom command to generate protobuf files
add_custom_command(
    OUTPUT 
        ${PROTO_OUT_DIR}/tapp_service.pb.cc
        ${PROTO_OUT_DIR}/tapp_service.pb.h
        ${PROTO_OUT_DIR}/tapp_service.grpc.pb.cc
        ${PROTO_OUT_DIR}/tapp_service.grpc.pb.h
    COMMAND ${Protobuf_PROTOC_EXECUTABLE}
    ARGS 
        --cpp_out=${PROTO_OUT_DIR}
        --grpc_out=${PROTO_OUT_DIR}
        --plugin=protoc-gen-grpc=${gRPC_CPP_PLUGIN_EXECUTABLE}
        --proto_path=${CMAKE_SOURCE_DIR}/rpc
        ${PROTO_FILES}
    DEPENDS ${PROTO_FILES}
    COMMENT "Generating protobuf and gRPC files"
)

# Create a library for generated protobuf files
add_library(tapp_proto
    ${PROTO_OUT_DIR}/tapp_service.pb.cc
    ${PROTO_OUT_DIR}/tapp_service.grpc.pb.cc
)

target_link_libraries(tapp_proto
    ${Protobuf_LIBRARIES}
    gRPC::grpc++
)

target_include_directories(tapp_proto PUBLIC ${PROTO_OUT_DIR})

# ============================================================================
# Build Libraries
# ============================================================================

# Boost library
add_library(boost_lib
    src/boost.cpp
)

target_include_directories(boost_lib PUBLIC include)
target_link_libraries(boost_lib 
    OpenSSL::SSL 
    OpenSSL::Crypto
)

# Add TDX support to boost_lib if available
if(TDX_FOUND)
    target_link_libraries(boost_lib ${TDX_ATTEST_LIBRARIES})
    target_include_directories(boost_lib PRIVATE ${TDX_ATTEST_INCLUDE_DIRS})
    # Or use the imported target if you prefer:
    # target_link_libraries(boost_lib TDX::tdx_attest)
endif()

# Key tool library
add_library(key_tool_lib
    src/key_tool.cpp
)

target_include_directories(key_tool_lib PUBLIC include)
target_link_libraries(key_tool_lib 
    OpenSSL::SSL 
    OpenSSL::Crypto
)

# Add TDX support to key_tool_lib if available
if(TDX_FOUND)
    target_link_libraries(key_tool_lib ${TDX_ATTEST_LIBRARIES})
    target_include_directories(key_tool_lib PRIVATE ${TDX_ATTEST_INCLUDE_DIRS})
    # Or use the imported target if you prefer:
    # target_link_libraries(key_tool_lib TDX::tdx_attest)
endif()

# ============================================================================
# Build Executables
# ============================================================================

# CLI executable
add_executable(tapp_cli
    src/cli.cpp
)

target_link_libraries(tapp_cli
    boost_lib
    key_tool_lib
)

# gRPC server executable
add_executable(tapp_server
    src/tapp.cpp
)

target_link_libraries(tapp_server
    boost_lib
    key_tool_lib
    tapp_proto
    gRPC::grpc++
    gRPC::grpc++_reflection
)

target_include_directories(tapp_server PRIVATE ${PROTO_OUT_DIR})

# ============================================================================
# Testing Support
# ============================================================================

enable_testing()

if(BUILD_TESTING)
    find_package(GTest)
    if(GTest_FOUND)
        add_executable(tapp_tests
            tests/test_boost.cpp
            tests/test_key_tool.cpp
            tests/test_grpc_service.cpp
        )
        
        target_link_libraries(tapp_tests
            boost_lib
            key_tool_lib
            tapp_proto
            GTest::GTest
            GTest::Main
            gRPC::grpc++
            gRPC::grpc++_reflection
        )
        
        target_include_directories(tapp_tests PRIVATE ${PROTO_OUT_DIR})
        add_test(NAME TappTests COMMAND tapp_tests)
        
        message(STATUS "Testing: ENABLED")
    else()
        message(STATUS "Testing: DISABLED (GTest not found)")
    endif()
else()
    message(STATUS "Testing: DISABLED")
endif()

# ============================================================================
# Installation
# ============================================================================

# Install executables
install(TARGETS tapp_cli tapp_server
    RUNTIME DESTINATION bin
)

# Install headers
install(FILES 
    include/boost.hpp
    include/key_tool.hpp
    DESTINATION include/tdx_tapp
)

# Install libraries
install(TARGETS boost_lib key_tool_lib
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

# Install local TDX library if built
if(TDX_USE_LOCAL_IMPLEMENTATION AND TARGET tdx_attest_local)
    install(TARGETS tdx_attest_local
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
    )
    install(FILES 
        deps/tdx_attest.h
        deps/qgs_msg_lib.h
        DESTINATION include/tdx_tapp
    )
endif()

# Create and install pkg-config file
configure_file(
    ${CMAKE_SOURCE_DIR}/cmake/tdx_tapp.pc.in
    ${CMAKE_BINARY_DIR}/tdx_tapp.pc
    @ONLY
)

install(FILES ${CMAKE_BINARY_DIR}/tdx_tapp.pc
    DESTINATION lib/pkgconfig
)

# ============================================================================
# Development Helpers
# ============================================================================

# Code formatting
find_program(CLANG_FORMAT_EXECUTABLE clang-format)
if(CLANG_FORMAT_EXECUTABLE)
    add_custom_target(format
        COMMAND find ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/include -name "*.cpp" -o -name "*.hpp" | xargs ${CLANG_FORMAT_EXECUTABLE} -i
        COMMENT "Formatting source code with clang-format"
    )
endif()

# Clean all build artifacts
add_custom_target(clean-all
    COMMAND ${CMAKE_BUILD_TOOL} clean
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_BINARY_DIR}/generated
    COMMENT "Cleaning all build artifacts"
)

# TDX hardware check target
add_custom_target(check-tdx
    COMMAND echo "=== TDX Hardware Check ==="
    COMMAND echo "Checking CPU flags:" && lscpu | grep -i tdx || echo "No TDX flags found"
    COMMAND echo "Checking /dev/tdx_guest:" && ls -la /dev/tdx_guest 2>/dev/null || echo "/dev/tdx_guest not found"
    COMMAND echo "Checking kernel modules:" && lsmod | grep -E 'tdx|intel_tdx' || echo "No TDX modules loaded"
    COMMENT "Manual TDX hardware support check"
)

# ============================================================================
# Build Summary
# ============================================================================

message(STATUS "")
message(STATUS "=== Build Configuration Summary ===")
message(STATUS "  Project: ${PROJECT_NAME} ${PROJECT_VERSION}")
message(STATUS "  C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  Install Prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "  OpenSSL Version: ${OPENSSL_VERSION}")
message(STATUS "  Protobuf Version: ${Protobuf_VERSION}")

if(TDX_FOUND)
    if(TDX_USE_LOCAL_IMPLEMENTATION)
        message(STATUS "  TDX Support: ENABLED (Local Implementation)")
    else()
        message(STATUS "  TDX Support: ENABLED (System Library)")
    endif()
else()
    if(TDX_HARDWARE_SUPPORTED)
        message(STATUS "  TDX Support: DISABLED (No library/sources)")
    else()
        message(STATUS "  TDX Support: DISABLED (No hardware support)")
    endif()
endif()

if(BUILD_TESTING AND GTest_FOUND)
    message(STATUS "  Testing: ENABLED")
else()
    message(STATUS "  Testing: DISABLED")
endif()

message(STATUS "=====================================")
message(STATUS "")