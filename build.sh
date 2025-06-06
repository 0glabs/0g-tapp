#!/bin/bash

# TDX TAPP Build Script
# Automated build, test, and deployment script with gRPC source compilation

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
PROJECT_NAME="tdx_tapp"
BUILD_DIR="build"
INSTALL_PREFIX="/usr/local"
CMAKE_BUILD_TYPE="Release"
ENABLE_TESTING="OFF"
FORCE_TDX_SUPPORT="OFF"  # OFF, ON
GRPC_VERSION="v1.50.0"
GRPC_SOURCE_DIR="grpc"

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${PURPLE}========================================${NC}"
    echo -e "${PURPLE} $1${NC}"
    echo -e "${PURPLE}========================================${NC}"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to detect OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command_exists apt-get; then
            echo "ubuntu"
        elif command_exists yum; then
            echo "centos"
        elif command_exists pacman; then
            echo "arch"
        else
            echo "linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    else
        echo "unknown"
    fi
}

# Function to install basic dependencies (excluding gRPC)
install_dependencies() {
    local os=$(detect_os)
    print_header "Installing Basic Dependencies"
    
    case $os in
        ubuntu)
            print_info "Installing dependencies for Ubuntu/Debian..."
            sudo apt-get update
            sudo apt-get install -y \
                build-essential \
                cmake \
                pkg-config \
                libssl-dev \
                libprotobuf-dev \
                protobuf-compiler \
                libgtest-dev \
                clang-format \
                git \
                curl \
                wget \
                autoconf \
                libtool \
                zlib1g-dev
            ;;
        centos)
            print_info "Installing dependencies for CentOS/RHEL..."
            sudo yum groupinstall -y "Development Tools"
            sudo yum install -y \
                cmake \
                pkgconfig \
                openssl-devel \
                protobuf-devel \
                protobuf-compiler \
                gtest-devel \
                git \
                curl \
                wget \
                autoconf \
                libtool \
                zlib-devel
            ;;
        macos)
            print_info "Installing dependencies for macOS..."
            if command_exists brew; then
                brew install cmake pkg-config openssl protobuf googletest autoconf libtool
            else
                print_error "Homebrew not found. Please install Homebrew first."
                exit 1
            fi
            ;;
        *)
            print_warning "Unknown OS. Please install dependencies manually."
            ;;
    esac
    
    print_success "Basic dependencies installed successfully"
}

# Function to compile and install gRPC from source
install_grpc_from_source() {
    print_header "Installing gRPC from Source"
    
    # Check if gRPC is already installed
    if pkg-config --exists grpc++ && pkg-config --exists grpc; then
        local grpc_version=$(pkg-config --modversion grpc++)
        print_info "gRPC already installed (version: $grpc_version)"
        read -p "Do you want to reinstall gRPC from source? [y/N]: " -r
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_info "Skipping gRPC installation"
            return 0
        fi
    fi
    
    # Clone gRPC repository
    if [[ -d "$GRPC_SOURCE_DIR" ]]; then
        print_info "gRPC source directory exists, pulling latest changes..."
        cd "$GRPC_SOURCE_DIR"
        git fetch --all
        git checkout "$GRPC_VERSION"
        git submodule update --init --recursive
        cd ..
    else
        print_info "Cloning gRPC repository (version: $GRPC_VERSION)..."
        git clone --recurse-submodules -b "$GRPC_VERSION" https://github.com/grpc/grpc "$GRPC_SOURCE_DIR"
    fi
    
    # Build and install gRPC
    cd "$GRPC_SOURCE_DIR"
    mkdir -p build
    cd build
    
    print_info "Configuring gRPC build..."
    cmake \
        -DgRPC_INSTALL=ON \
        -DgRPC_BUILD_TESTS=OFF \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX" \
        ..
    
    local nproc_cmd
    if command_exists nproc; then
        nproc_cmd="nproc"
    else
        nproc_cmd="sysctl -n hw.ncpu"  # macOS
    fi
    
    local jobs
    jobs=$($nproc_cmd 2>/dev/null || echo "4")
    
    print_info "Building gRPC with $jobs parallel jobs (this may take a while)..."
    make -j"$jobs"
    
    print_info "Installing gRPC..."
    sudo make install
    
    # Update library cache on Linux
    if [[ "$(detect_os)" != "macos" ]]; then
        sudo ldconfig
    fi
    
    cd ../..
    print_success "gRPC installed successfully"
}

# Function to check TDX hardware support
check_tdx_hardware() {
    print_info "Checking TDX hardware support..."
    
    local tdx_supported=false
    
    # Method 1: Check lscpu for tdx_guest flag
    if command_exists lscpu; then
        if lscpu | grep -q "tdx_guest"; then
            print_success "TDX guest support detected in CPU flags"
            tdx_supported=true
        fi
    fi
    
    # Method 2: Check /dev/tdx_guest device
    if [[ -e "/dev/tdx_guest" ]]; then
        print_success "TDX guest device found: /dev/tdx_guest"
        tdx_supported=true
    fi
    
    # Method 3: Check kernel modules
    if lsmod 2>/dev/null | grep -qE 'tdx|intel_tdx'; then
        print_success "TDX kernel modules detected"
        tdx_supported=true
    fi
    
    if [[ "$tdx_supported" == true ]]; then
        print_success "TDX hardware support detected"
        return 0
    else
        print_warning "No TDX hardware support detected"
        return 1
    fi
}

# Function to check TDX attestation library
check_tdx_library() {
    print_info "Checking TDX attestation library..."
    
    # Check for system TDX library
    if pkg-config --exists tdx_attest 2>/dev/null; then
        print_success "System TDX attestation library found"
        return 0
    fi
    
    # Check for library files manually
    local lib_paths=("/usr/lib64" "/usr/lib" "/usr/local/lib64" "/usr/local/lib")
    for path in "${lib_paths[@]}"; do
        if [[ -f "$path/libtdx_attest.so" || -f "$path/libtdx_attest.a" ]]; then
            print_success "TDX attestation library found in $path"
            return 0
        fi
    done
    
    # Check for local deps directory
    if [[ -d "deps" && -f "deps/tdx_attest.h" && -f "deps/tdx_attest.c" ]]; then
        print_success "Local TDX attestation sources found in deps/"
        return 0
    fi
    
    print_warning "TDX attestation library not found"
    return 1
}

# Function to run TDX hardware check target
run_tdx_check() {
    print_header "TDX Hardware Check"
    
    if [[ -d "$BUILD_DIR" ]]; then
        cd "$BUILD_DIR"
        if make check-tdx 2>/dev/null; then
            print_success "TDX check completed"
        else
            print_warning "TDX check target not available"
        fi
        cd ..
    else
        # Manual check if build directory doesn't exist
        check_tdx_hardware
    fi
}

# Function to configure build
configure_build() {
    print_header "Configuring Build"
    
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"
    
    local cmake_args=(
        -DCMAKE_BUILD_TYPE="$CMAKE_BUILD_TYPE"
        -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX"
        -DBUILD_TESTING="$ENABLE_TESTING"
    )
    
    # Add TDX support flag if specified
    if [[ "$FORCE_TDX_SUPPORT" == "ON" ]]; then
        cmake_args+=(-DFORCE_TDX_SUPPORT=ON)
        print_info "Forcing TDX support"
    fi
    
    print_info "Running cmake with arguments: ${cmake_args[*]}"
    cmake "${cmake_args[@]}" ..
    
    cd - > /dev/null
    print_success "Build configured successfully"
}

# Function to build project
build_project() {
    print_header "Building Project"
    
    cd "$BUILD_DIR"
    
    local nproc_cmd
    if command_exists nproc; then
        nproc_cmd="nproc"
    else
        nproc_cmd="sysctl -n hw.ncpu"  # macOS
    fi
    
    local jobs
    jobs=$($nproc_cmd 2>/dev/null || echo "4")
    
    print_info "Building with $jobs parallel jobs..."
    make -j"$jobs"
    
    cd - > /dev/null
    print_success "Build completed successfully"
}

# Function to run tests
run_tests() {
    print_header "Running Tests"
    
    cd "$BUILD_DIR"
    
    if [[ "$ENABLE_TESTING" == "ON" ]]; then
        print_info "Running unit tests..."
        if make test; then
            print_success "All tests passed"
        else
            print_warning "Some tests failed"
        fi
    else
        print_info "Testing disabled"
    fi
    
    cd - > /dev/null
}

# Function to format code
format_code() {
    print_header "Formatting Code"
    
    if [[ -d "$BUILD_DIR" ]]; then
        cd "$BUILD_DIR"
        if make format 2>/dev/null; then
            print_success "Code formatting completed"
        else
            print_warning "Code formatting not available (clang-format not found)"
        fi
        cd - > /dev/null
    else
        print_warning "Build directory not found, cannot format code"
    fi
}

# Function to install project
install_project() {
    print_header "Installing Project"
    
    cd "$BUILD_DIR"
    print_info "Installing to $INSTALL_PREFIX..."
    sudo make install
    
    # Update library cache on Linux
    if [[ "$(detect_os)" != "macos" ]]; then
        sudo ldconfig
    fi
    
    cd - > /dev/null
    
    print_success "Installation completed"
    print_info "Installed files:"
    echo "  - $INSTALL_PREFIX/bin/tapp_cli"
    echo "  - $INSTALL_PREFIX/bin/tapp_server"
    echo "  - $INSTALL_PREFIX/lib/libboost_lib.*"
    echo "  - $INSTALL_PREFIX/lib/libkey_tool_lib.*"
    echo "  - $INSTALL_PREFIX/include/tdx_tapp/"
    echo "  - $INSTALL_PREFIX/lib/pkgconfig/tdx_tapp.pc"
}

# Function to run examples
run_examples() {
    print_header "Running Examples"
    
    cd "$BUILD_DIR"
    
    if [[ -f "tapp_cli" ]]; then
        print_info "Testing CLI tool..."
        if ./tapp_cli --help 2>/dev/null; then
            print_success "CLI tool help displayed successfully"
        else
            print_warning "CLI help failed (may be expected in some configurations)"
        fi
        
        print_info "Testing basic CLI functionality..."
        if ./tapp_cli --version 2>/dev/null; then
            print_success "CLI version check passed"
        else
            print_warning "CLI version check failed"
        fi
    else
        print_warning "tapp_cli not found in build directory"
    fi
    
    if [[ -f "tapp_server" ]]; then
        print_info "Testing server binary..."
        if ./tapp_server --help 2>/dev/null; then
            print_success "Server help displayed successfully"
        else
            print_warning "Server help failed"
        fi
    else
        print_warning "tapp_server not found in build directory"
    fi
    
    cd - > /dev/null
}

# Function to create distribution package
create_package() {
    print_header "Creating Distribution Package"
    
    cd "$BUILD_DIR"
    
    if command_exists cpack; then
        print_info "Creating distribution packages..."
        cpack
        print_success "Packages created in $BUILD_DIR"
        ls -la *.deb *.rpm *.tar.gz 2>/dev/null || print_info "No packages found"
    else
        print_warning "CPack not found - skipping package creation"
    fi
    
    cd - > /dev/null
}

# Function to print build summary
print_summary() {
    print_header "Build Summary"
    
    echo -e "${CYAN}Project:${NC} $PROJECT_NAME"
    echo -e "${CYAN}Build Type:${NC} $CMAKE_BUILD_TYPE"
    echo -e "${CYAN}Install Prefix:${NC} $INSTALL_PREFIX"
    echo -e "${CYAN}Testing:${NC} $ENABLE_TESTING"
    echo -e "${CYAN}Force TDX Support:${NC} $FORCE_TDX_SUPPORT"
    
    # Check TDX status
    echo -e "${CYAN}TDX Hardware:${NC} $(check_tdx_hardware && echo "Supported" || echo "Not detected")"
    echo -e "${CYAN}TDX Library:${NC} $(check_tdx_library && echo "Available" || echo "Not found")"
    
    if [[ -d "$BUILD_DIR" ]]; then
        echo -e "${CYAN}Build Directory:${NC} $BUILD_DIR"
        echo -e "${CYAN}Build Files:${NC}"
        ls -la "$BUILD_DIR"/{tapp_cli,tapp_server,lib*.so,lib*.a} 2>/dev/null | sed 's/^/  /' || echo "  No build files found"
    fi
    
    print_success "Build completed successfully!"
    
    echo ""
    echo -e "${GREEN}Next steps:${NC}"
    echo "  1. Run CLI tool: ./$BUILD_DIR/tapp_cli --help"
    echo "  2. Start server: ./$BUILD_DIR/tapp_server --help"
    echo "  3. Install system-wide: sudo make install (from build directory)"
    echo "  4. Check TDX support: make check-tdx (from build directory)"
}

# Function to show usage
show_usage() {
    echo "TDX TAPP Build Script"
    echo ""
    echo "Usage: $0 [OPTIONS] [TARGETS]"
    echo ""
    echo "Options:"
    echo "  --build-type TYPE     Set build type (Release|Debug|RelWithDebInfo)"
    echo "  --install-prefix DIR  Set installation prefix (default: /usr/local)"
    echo "  --enable-testing      Enable unit testing"
    echo "  --disable-testing     Disable unit testing (default)"
    echo "  --force-tdx           Force enable TDX support"
    echo "  --grpc-version VER    gRPC version to compile (default: $GRPC_VERSION)"
    echo "  --help               Show this help message"
    echo ""
    echo "Targets:"
    echo "  deps                 Install basic dependencies"
    echo "  grpc                 Compile and install gRPC from source"
    echo "  tdx-check            Check TDX hardware and library support"
    echo "  configure            Configure build"
    echo "  build                Build project"
    echo "  test                 Run tests"
    echo "  format               Format source code"
    echo "  install              Install project"
    echo "  examples             Run examples"
    echo "  package              Create distribution package"
    echo "  all                  Run all targets (default)"
    echo "  clean                Clean build directory"
    echo ""
    echo "Examples:"
    echo "  $0                               # Full build with defaults"
    echo "  $0 grpc configure build          # Install gRPC and build"
    echo "  $0 --force-tdx build             # Force TDX support and build"
    echo "  $0 --build-type Debug test       # Debug build with tests"
    echo "  $0 clean                         # Clean build directory"
    echo "  $0 tdx-check                     # Check TDX support only"
}

# Function to clean build directory
clean_build() {
    print_header "Cleaning Build Directory"
    
    if [[ -d "$BUILD_DIR" ]]; then
        cd "$BUILD_DIR"
        if make clean-all 2>/dev/null; then
            print_info "Cleaned using make clean-all"
        fi
        cd - > /dev/null
        
        print_info "Removing $BUILD_DIR..."
        rm -rf "$BUILD_DIR"
        print_success "Build directory cleaned"
    else
        print_info "Build directory doesn't exist"
    fi
}

# Main execution
main() {
    local targets=()
    local run_all=true
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --build-type)
                CMAKE_BUILD_TYPE="$2"
                shift 2
                ;;
            --install-prefix)
                INSTALL_PREFIX="$2"
                shift 2
                ;;
            --enable-testing)
                ENABLE_TESTING="ON"
                shift
                ;;
            --disable-testing)
                ENABLE_TESTING="OFF"
                shift
                ;;
            --force-tdx)
                FORCE_TDX_SUPPORT="ON"
                shift
                ;;
            --grpc-version)
                GRPC_VERSION="$2"
                shift 2
                ;;
            --help)
                show_usage
                exit 0
                ;;
            deps|grpc|tdx-check|configure|build|test|format|install|examples|package|all|clean)
                targets+=("$1")
                run_all=false
                shift
                ;;
            *)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # If no targets specified, run all
    if [[ $run_all == true ]]; then
        targets=("deps" "grpc" "tdx-check" "configure" "build" "test" "examples")
    fi
    
    print_header "TDX TAPP Build Script"
    print_info "OS: $(detect_os)"
    print_info "Build Type: $CMAKE_BUILD_TYPE"
    print_info "gRPC Version: $GRPC_VERSION"
    print_info "Targets: ${targets[*]}"
    
    # Execute targets
    for target in "${targets[@]}"; do
        case $target in
            deps)
                install_dependencies
                ;;
            grpc)
                install_grpc_from_source
                ;;
            tdx-check)
                run_tdx_check
                ;;
            configure)
                configure_build
                ;;
            build)
                build_project
                ;;
            test)
                run_tests
                ;;
            format)
                format_code
                ;;
            install)
                install_project
                ;;
            examples)
                run_examples
                ;;
            package)
                create_package
                ;;
            all)
                install_dependencies
                install_grpc_from_source
                run_tdx_check
                configure_build
                build_project
                run_tests
                run_examples
                ;;
            clean)
                clean_build
                ;;
            *)
                print_error "Unknown target: $target"
                exit 1
                ;;
        esac
    done
    
    # Print summary unless cleaning
    if [[ ! " ${targets[*]} " =~ " clean " ]]; then
        print_summary
    fi
}

# Run main function with all arguments
main "$@"