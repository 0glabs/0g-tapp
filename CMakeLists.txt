cmake_minimum_required(VERSION 3.16)

project(tdx_tapp VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(PkgConfig REQUIRED)
find_package(Protobuf REQUIRED)
find_package(gRPC REQUIRED)
find_program(gRPC_CPP_PLUGIN_EXECUTABLE grpc_cpp_plugin)
if(NOT gRPC_CPP_PLUGIN_EXECUTABLE)
    set(gRPC_CPP_PLUGIN_EXECUTABLE "/usr/local/bin/grpc_cpp_plugin")
    if(NOT EXISTS ${gRPC_CPP_PLUGIN_EXECUTABLE})
        message(FATAL_ERROR "grpc_cpp_plugin not found")
    endif()
endif()

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Check for TDX attestation library (optional)
find_library(TDX_ATTEST_LIBRARY
    NAMES tdx_attest libtdx_attest
    PATHS /usr/lib64 /usr/lib /usr/local/lib64 /usr/local/lib
    DOC "TDX attestation library"
)

find_path(TDX_ATTEST_INCLUDE_DIR
    NAMES tdx_attest.h
    PATHS /usr/include /usr/local/include
    DOC "TDX attestation include directory"
)

if(TDX_ATTEST_LIBRARY AND TDX_ATTEST_INCLUDE_DIR)
    set(TDX_ATTEST_FOUND TRUE)
    set(TDX_ATTEST_LIBRARIES ${TDX_ATTEST_LIBRARY})
    set(TDX_ATTEST_INCLUDE_DIRS ${TDX_ATTEST_INCLUDE_DIR})
    message(STATUS "Found TDX attestation: ${TDX_ATTEST_LIBRARY}")
else()
    set(TDX_ATTEST_FOUND FALSE)
    message(STATUS "TDX attestation library not found")
endif()

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/rpc)

# Compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -O2")

# Add debug flags in debug mode
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -DDEBUG")

# TDX support
if(TDX_ATTEST_FOUND)
    add_definitions(-DHAVE_TDX_ATTEST)
    message(STATUS "TDX attestation library found - enabling TDX support")
    message(STATUS "  Library: ${TDX_ATTEST_LIBRARIES}")
    message(STATUS "  Include: ${TDX_ATTEST_INCLUDE_DIRS}")
else()
    message(STATUS "TDX attestation library not found - using mock implementation")
endif()

# Generate protobuf and gRPC files
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

# Boost library
add_library(boost_lib
    src/boost.cpp
)

target_include_directories(boost_lib PUBLIC include)
target_link_libraries(boost_lib 
    OpenSSL::SSL 
    OpenSSL::Crypto
)

if(TDX_ATTEST_FOUND)
    target_link_libraries(boost_lib ${TDX_ATTEST_LIBRARIES})
    target_include_directories(boost_lib PRIVATE ${TDX_ATTEST_INCLUDE_DIRS})
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

if(TDX_ATTEST_FOUND)
    target_link_libraries(key_tool_lib ${TDX_ATTEST_LIBRARIES})
    target_include_directories(key_tool_lib PRIVATE ${TDX_ATTEST_INCLUDE_DIRS})
endif()

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

# Install targets
install(TARGETS tapp_cli tapp_server
    RUNTIME DESTINATION bin
)

install(FILES 
    include/boost.hpp
    include/key_tool.hpp
    DESTINATION include/tdx_tapp
)

install(TARGETS boost_lib key_tool_lib
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

# Create pkg-config files
configure_file(
    ${CMAKE_SOURCE_DIR}/cmake/tdx_tapp.pc.in
    ${CMAKE_BINARY_DIR}/tdx_tapp.pc
    @ONLY
)

install(FILES ${CMAKE_BINARY_DIR}/tdx_tapp.pc
    DESTINATION lib/pkgconfig
)

# Print build information
message(STATUS "Build configuration:")
message(STATUS "  C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  Install Prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "  OpenSSL Version: ${OPENSSL_VERSION}")
message(STATUS "  Protobuf Version: ${Protobuf_VERSION}")
if(TDX_ATTEST_FOUND)
    message(STATUS "  TDX Support: Enabled")
else()
    message(STATUS "  TDX Support: Mock Implementation")
endif()

# Add custom target for documentation
find_program(DOXYGEN_EXECUTABLE doxygen)
if(DOXYGEN_EXECUTABLE)
    add_custom_target(docs
        COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_SOURCE_DIR}/Doxyfile
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Generating documentation with Doxygen"
    )
endif()

# Add testing support
enable_testing()

# Test executable (optional)
if(BUILD_TESTING)
    find_package(GTest)
    if(GTest_FOUND)
        add_executable(tapp_tests
            tests/test_boost.cpp
            tests/test_key_tool.cpp
        )
        
        target_link_libraries(tapp_tests
            boost_lib
            key_tool_lib
            GTest::GTest
            GTest::Main
        )
        
        add_test(NAME TappTests COMMAND tapp_tests)
    endif()
endif()

# gRPC Service Tests (optional)
if(BUILD_TESTING AND BUILD_GRPC_SERVER)
    add_executable(tapp_grpc_tests
        tests/test_grpc_service.cpp
    )
    
    target_link_libraries(tapp_grpc_tests
        tapp_proto
        gRPC::grpc++
        GTest::GTest
        GTest::Main
    )
    
    target_include_directories(tapp_grpc_tests PRIVATE ${PROTO_OUT_DIR})
    
    add_test(NAME TappGrpcTests COMMAND tapp_grpc_tests)
endif()

# Development helpers
add_custom_target(format
    COMMAND find ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/include -name "*.cpp" -o -name "*.hpp" | xargs clang-format -i
    COMMENT "Formatting source code"
)

add_custom_target(clean-all
    COMMAND ${CMAKE_BUILD_TOOL} clean
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_BINARY_DIR}/generated
    COMMENT "Cleaning all build artifacts"
)