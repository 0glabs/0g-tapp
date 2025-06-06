# TDX TAPP Build Guide

## Build Methods Overview

TDX TAPP project provides two build methods:
1. **Automated Build**: Using `build.sh` script (Recommended)
2. **Manual Build**: Using CMake commands

## Method 1: Automated Build (Recommended)

### Script Syntax
```bash
./build.sh [OPTIONS] [TARGETS]
```

### Options
```bash
--build-type TYPE         # Build type: Release|Debug (default: Release)
--install-prefix DIR      # Installation path (default: /usr/local)
--enable-testing         # Enable testing
--disable-testing        # Disable testing (default)
--force-tdx             # Force enable TDX support
--grpc-version VER      # gRPC version (default: v1.50.0)
--help                  # Show help
```

### Build Targets
```bash
deps                    # Install system dependencies
grpc                   # Compile and install gRPC
tdx-check              # Check TDX support
configure              # Configure build
build                  # Compile project
test                   # Run tests
format                 # Format code
install                # Install to system
examples               # Run examples
package                # Create packages
all                    # Full build pipeline (default)
clean                  # Clean build directory
```

### Common Commands
```bash
# Full automated build
./build.sh

# Compile gRPC only
./build.sh grpc

# Debug build
./build.sh --build-type Debug configure build

# Enable testing
./build.sh --enable-testing build test

# Force TDX support
./build.sh --force-tdx configure build

# Check TDX support
./build.sh tdx-check

# Clean and rebuild
./build.sh clean configure build

# Custom install path
./build.sh --install-prefix /opt/tdx install
```

## Method 2: Manual CMake Build

### System Dependencies Installation

#### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential cmake pkg-config libssl-dev \
    libprotobuf-dev protobuf-compiler \
    autoconf libtool zlib1g-dev
```

#### CentOS/RHEL
```bash
sudo yum groupinstall -y "Development Tools"
sudo yum install -y \
    cmake pkgconfig openssl-devel \
    protobuf-devel protobuf-compiler \
    autoconf libtool zlib-devel
```

### gRPC Source Compilation
```bash
# Clone gRPC source
git clone --recurse-submodules -b v1.50.0 \
    https://github.com/grpc/grpc
cd grpc && mkdir build && cd build

# Configure and compile
cmake -DgRPC_INSTALL=ON -DgRPC_BUILD_TESTS=OFF ..
make -j4 && sudo make install

# Update library cache (Linux)
sudo ldconfig
```

### CMake Build Parameters

#### Basic Parameters
```bash
cmake -DCMAKE_BUILD_TYPE=Release ..        # Build type: Release/Debug
cmake -DCMAKE_INSTALL_PREFIX=/usr/local .. # Installation path
cmake -DCMAKE_C_COMPILER=gcc ..            # C compiler
cmake -DCMAKE_CXX_COMPILER=g++ ..          # C++ compiler
```

#### Project Parameters
```bash
cmake -DFORCE_TDX_SUPPORT=ON ..     # Force enable TDX support (default OFF)
cmake -DBUILD_TESTING=ON ..         # Enable test build (default OFF)
cmake -DTDX_DEPS_DIR=/path/to/deps  # TDX dependency source directory (default ./deps)
```

### Build Targets

#### Main Targets
```bash
make                    # Build all targets
make tapp_cli          # CLI executable
make tapp_server       # gRPC server
make tapp_tests        # Test program (requires BUILD_TESTING=ON)
```

#### Library Targets
```bash
make boost_lib          # Boost functionality library
make key_tool_lib       # Key tool library
make tapp_proto         # Protocol Buffers generated code
make tdx_attest_local   # Local TDX attestation library (if using local sources)
```

#### Utility Targets
```bash
make format            # Code formatting (requires clang-format)
make clean-all         # Clean all build artifacts
make check-tdx         # Check TDX hardware support
make install           # Install to system
make test              # Run tests
```

### Manual Build Examples

#### Standard Build
```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
```

#### Debug Build
```bash
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Debug ..
make -j$(nproc)
```

#### Build with Tests
```bash
mkdir build && cd build
cmake -DBUILD_TESTING=ON ..
make -j$(nproc)
make test
```

#### Force TDX Support Build
```bash
mkdir build && cd build
cmake -DFORCE_TDX_SUPPORT=ON ..
make -j$(nproc)
```

#### Custom Installation Path
```bash
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/opt/tdx_tapp ..
make -j$(nproc)
sudo make install
```

## TDX Support Status

During build, one of the following status will be displayed:
- `TDX Support: ENABLED (System Library)` - Using system TDX library
- `TDX Support: ENABLED (Local Implementation)` - Using deps/ directory sources
- `TDX Support: DISABLED (No hardware support)` - No hardware support
- `TDX Support: DISABLED (No library/sources)` - No library or sources available

## Dependency Check

The project automatically detects the following dependencies:
- CMake 3.16+
- C++17 compatible compiler
- OpenSSL
- Protocol Buffers
- gRPC
- TDX hardware support (detected through multiple methods)
- TDX attestation library (system library or deps/ sources)