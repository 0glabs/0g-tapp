# FindTDX.cmake - Find TDX (Trust Domain Extensions) support
#
# This module defines:
#  TDX_FOUND - True if TDX hardware and software support is available
#  TDX_HARDWARE_SUPPORTED - True if TDX hardware is detected
#  TDX_ATTEST_FOUND - True if TDX attestation library is available
#  TDX_ATTEST_LIBRARIES - Libraries to link against
#  TDX_ATTEST_INCLUDE_DIRS - Include directories
#  TDX_USE_LOCAL_IMPLEMENTATION - True if using local deps/ sources
#
# Usage:
#  find_package(TDX)
#  if(TDX_FOUND)
#    target_link_libraries(mytarget ${TDX_ATTEST_LIBRARIES})
#    target_include_directories(mytarget PRIVATE ${TDX_ATTEST_INCLUDE_DIRS})
#  endif()

include(FindPackageHandleStandardArgs)

# Initialize variables
set(TDX_FOUND FALSE)
set(TDX_HARDWARE_SUPPORTED FALSE)
set(TDX_ATTEST_FOUND FALSE)
set(TDX_USE_LOCAL_IMPLEMENTATION FALSE)

# Function to check TDX hardware support using various methods
function(_check_tdx_hardware_support)
    set(TDX_HARDWARE_SUPPORTED FALSE PARENT_SCOPE)
    
    # Skip hardware check on non-Linux systems
    if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
        message(VERBOSE "TDX check: Skipping hardware check on non-Linux system")
        return()
    endif()
    
    # Method 1: Check lscpu output for tdx_guest flag
    execute_process(
        COMMAND lscpu
        OUTPUT_VARIABLE LSCPU_OUTPUT
        ERROR_QUIET
        OUTPUT_STRIP_TRAILING_WHITESPACE
        RESULT_VARIABLE LSCPU_RESULT
    )
    
    if(LSCPU_RESULT EQUAL 0 AND LSCPU_OUTPUT MATCHES "tdx_guest")
        message(VERBOSE "TDX check: tdx_guest flag found in lscpu output")
        set(TDX_HARDWARE_SUPPORTED TRUE PARENT_SCOPE)
        return()
    endif()
    
    # Method 2: Check for /dev/tdx_guest device
    if(EXISTS "/dev/tdx_guest")
        message(VERBOSE "TDX check: /dev/tdx_guest device file exists")
        set(TDX_HARDWARE_SUPPORTED TRUE PARENT_SCOPE)
        return()
    endif()
    
    # Method 3: Check /proc/cpuinfo for TDX flags
    if(EXISTS "/proc/cpuinfo")
        file(READ "/proc/cpuinfo" CPUINFO_CONTENT)
        if(CPUINFO_CONTENT MATCHES "tdx_guest")
            message(VERBOSE "TDX check: tdx_guest flag found in /proc/cpuinfo")
            set(TDX_HARDWARE_SUPPORTED TRUE PARENT_SCOPE)
            return()
        endif()
    endif()
    
    # Method 4: Check for TDX kernel modules
    execute_process(
        COMMAND sh -c "lsmod 2>/dev/null | grep -E 'tdx|intel_tdx' || true"
        OUTPUT_VARIABLE LSMOD_OUTPUT
        ERROR_QUIET
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    
    if(NOT LSMOD_OUTPUT STREQUAL "")
        message(VERBOSE "TDX check: TDX-related kernel modules detected")
        set(TDX_HARDWARE_SUPPORTED TRUE PARENT_SCOPE)
        return()
    endif()
    
    # Method 5: Check dmesg for TDX messages (requires root or specific permissions)
    execute_process(
        COMMAND sh -c "dmesg 2>/dev/null | grep -i tdx | head -1 || true"
        OUTPUT_VARIABLE DMESG_OUTPUT
        ERROR_QUIET
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    
    if(NOT DMESG_OUTPUT STREQUAL "")
        message(VERBOSE "TDX check: TDX-related messages found in dmesg")
        set(TDX_HARDWARE_SUPPORTED TRUE PARENT_SCOPE)
        return()
    endif()
    
    message(VERBOSE "TDX check: No TDX hardware support detected")
endfunction()

# Function to find system TDX attestation library
function(_find_system_tdx_library)
    set(TDX_ATTEST_FOUND FALSE PARENT_SCOPE)
    
    # Find TDX attestation library
    find_library(TDX_ATTEST_LIBRARY
        NAMES tdx_attest libtdx_attest
        PATHS 
            /usr/lib64
            /usr/lib
            /usr/local/lib64
            /usr/local/lib
            /opt/intel/tdx/lib64
            /opt/intel/tdx/lib
        PATH_SUFFIXES
            tdx
        DOC "TDX attestation library"
    )
    
    # Find TDX attestation headers
    find_path(TDX_ATTEST_INCLUDE_DIR
        NAMES tdx_attest.h
        PATHS 
            /usr/include
            /usr/local/include
            /opt/intel/tdx/include
        PATH_SUFFIXES
            tdx
        DOC "TDX attestation include directory"
    )
    
    if(TDX_ATTEST_LIBRARY AND TDX_ATTEST_INCLUDE_DIR)
        set(TDX_ATTEST_FOUND TRUE PARENT_SCOPE)
        set(TDX_ATTEST_LIBRARIES ${TDX_ATTEST_LIBRARY} PARENT_SCOPE)
        set(TDX_ATTEST_INCLUDE_DIRS ${TDX_ATTEST_INCLUDE_DIR} PARENT_SCOPE)
        message(VERBOSE "TDX check: Found system TDX library: ${TDX_ATTEST_LIBRARY}")
        message(VERBOSE "TDX check: Found system TDX headers: ${TDX_ATTEST_INCLUDE_DIR}")
    else()
        message(VERBOSE "TDX check: System TDX library not found")
        if(TDX_ATTEST_LIBRARY AND NOT TDX_ATTEST_INCLUDE_DIR)
            message(VERBOSE "TDX check: Library found but headers missing")
        elseif(TDX_ATTEST_INCLUDE_DIR AND NOT TDX_ATTEST_LIBRARY)
            message(VERBOSE "TDX check: Headers found but library missing")
        endif()
    endif()
endfunction()

# Function to check and potentially build local TDX library
function(_check_local_tdx_sources)
    set(TDX_ATTEST_FOUND FALSE PARENT_SCOPE)
    set(TDX_USE_LOCAL_IMPLEMENTATION FALSE PARENT_SCOPE)
    
    # Check if we have a deps directory
    if(NOT DEFINED TDX_DEPS_DIR)
        set(TDX_DEPS_DIR "${CMAKE_SOURCE_DIR}/deps")
    endif()
    
    if(NOT EXISTS "${TDX_DEPS_DIR}")
        message(VERBOSE "TDX check: deps directory not found: ${TDX_DEPS_DIR}")
        return()
    endif()
    
    # Check for required source files
    set(REQUIRED_FILES
        "${TDX_DEPS_DIR}/tdx_attest.h"
        "${TDX_DEPS_DIR}/tdx_attest.c"
        "${TDX_DEPS_DIR}/qgs_msg_lib.h"
        "${TDX_DEPS_DIR}/qgs_msg_lib.c"
    )
    
    set(MISSING_FILES "")
    foreach(FILE ${REQUIRED_FILES})
        if(NOT EXISTS "${FILE}")
            list(APPEND MISSING_FILES "${FILE}")
        endif()
    endforeach()
    
    if(MISSING_FILES)
        message(VERBOSE "TDX check: Missing local TDX source files:")
        foreach(FILE ${MISSING_FILES})
            message(VERBOSE "  - ${FILE}")
        endforeach()
        return()
    endif()
    
    message(VERBOSE "TDX check: All required local TDX source files found")
    
    # Create local TDX library target
    if(NOT TARGET tdx_attest_local)
        add_library(tdx_attest_local STATIC
            "${TDX_DEPS_DIR}/tdx_attest.c"
            "${TDX_DEPS_DIR}/qgs_msg_lib.c"
        )
        
        target_include_directories(tdx_attest_local 
            PUBLIC "${TDX_DEPS_DIR}"
        )
        
        # Set some basic compile flags
        target_compile_options(tdx_attest_local PRIVATE
            -Wall -Wextra
        )
        
        # Add position independent code for potential shared library use
        set_target_properties(tdx_attest_local PROPERTIES
            POSITION_INDEPENDENT_CODE ON
        )
    endif()
    
    set(TDX_ATTEST_FOUND TRUE PARENT_SCOPE)
    set(TDX_ATTEST_LIBRARIES tdx_attest_local PARENT_SCOPE)
    set(TDX_ATTEST_INCLUDE_DIRS "${TDX_DEPS_DIR}" PARENT_SCOPE)
    set(TDX_USE_LOCAL_IMPLEMENTATION TRUE PARENT_SCOPE)
    set(TDX_LOCAL_TARGET tdx_attest_local PARENT_SCOPE)
endfunction()

# Main TDX detection logic
if(TDX_FIND_REQUIRED OR NOT DEFINED TDX_FIND_QUIETLY)
    message(STATUS "Checking for TDX support...")
endif()

# Check hardware support first
_check_tdx_hardware_support()

if(TDX_HARDWARE_SUPPORTED)
    if(TDX_FIND_REQUIRED OR NOT DEFINED TDX_FIND_QUIETLY)
        message(STATUS "TDX hardware support detected")
    endif()
    
    # Try to find system library first
    _find_system_tdx_library()
    
    # If system library not found, check for local sources
    if(NOT TDX_ATTEST_FOUND)
        _check_local_tdx_sources()
    endif()
    
    # Set overall TDX found status
    if(TDX_ATTEST_FOUND)
        set(TDX_FOUND TRUE)
    endif()
else()
    if(TDX_FIND_REQUIRED OR NOT DEFINED TDX_FIND_QUIETLY)
        message(STATUS "TDX hardware support not detected")
    endif()
endif()

# Handle the standard find_package arguments
find_package_handle_standard_args(TDX
    FOUND_VAR TDX_FOUND
    REQUIRED_VARS TDX_HARDWARE_SUPPORTED TDX_ATTEST_FOUND
    REASON_FAILURE_MESSAGE "TDX support requires both hardware support and attestation library"
)

# Create imported target if TDX is found
if(TDX_FOUND AND NOT TARGET TDX::tdx_attest)
    if(TDX_USE_LOCAL_IMPLEMENTATION)
        # For local implementation, create an alias
        add_library(TDX::tdx_attest ALIAS tdx_attest_local)
    else()
        # For system library, create imported target
        add_library(TDX::tdx_attest UNKNOWN IMPORTED)
        set_target_properties(TDX::tdx_attest PROPERTIES
            IMPORTED_LOCATION "${TDX_ATTEST_LIBRARIES}"
            INTERFACE_INCLUDE_DIRECTORIES "${TDX_ATTEST_INCLUDE_DIRS}"
        )
    endif()
endif()

# Mark variables as advanced
mark_as_advanced(
    TDX_ATTEST_LIBRARY
    TDX_ATTEST_INCLUDE_DIR
)

# Debug output
if(TDX_FIND_DEBUG OR CMAKE_FIND_DEBUG_MODE)
    message(STATUS "TDX Debug Info:")
    message(STATUS "  TDX_FOUND: ${TDX_FOUND}")
    message(STATUS "  TDX_HARDWARE_SUPPORTED: ${TDX_HARDWARE_SUPPORTED}")
    message(STATUS "  TDX_ATTEST_FOUND: ${TDX_ATTEST_FOUND}")
    message(STATUS "  TDX_USE_LOCAL_IMPLEMENTATION: ${TDX_USE_LOCAL_IMPLEMENTATION}")
    if(TDX_ATTEST_FOUND)
        message(STATUS "  TDX_ATTEST_LIBRARIES: ${TDX_ATTEST_LIBRARIES}")
        message(STATUS "  TDX_ATTEST_INCLUDE_DIRS: ${TDX_ATTEST_INCLUDE_DIRS}")
    endif()
endif()