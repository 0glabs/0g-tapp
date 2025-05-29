#!/bin/bash

# TDX TAPP Build Script
# Automated build, test, and deployment script

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
ENABLE_TESTING="ON"
ENABLE_TDX="AUTO"  # AUTO, ON, OFF
ENABLE_GRPC_SERVER="ON"

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

# Function to install dependencies
install_dependencies() {
    local os=$(detect_os)
    print_header "Installing Dependencies"
    
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
                libgrpc++-dev \
                protobuf-compiler-grpc \
                libgtest-dev \
                doxygen \
                clang-format \
                clang-tidy \
                git \
                curl \
                wget
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
                doxygen \
                git \
                curl \
                wget
            ;;
        macos)
            print_info "Installing dependencies for macOS..."
            if command_exists brew; then
                brew install cmake pkg-config openssl protobuf grpc googletest doxygen
            else
                print_error "Homebrew not found. Please install Homebrew first."
                exit 1
            fi
            ;;
        *)
            print_warning "Unknown OS. Please install dependencies manually."
            ;;
    esac
    
    print_success "Dependencies installed successfully"
}

# Function to check TDX support
check_tdx_support() {
    print_info "Checking TDX support..."
    
    if [[ "$ENABLE_TDX" == "OFF" ]]; then
        print_info "TDX support disabled by configuration"
        return 1
    fi
    
    if pkg-config --exists tdx_attest; then
        print_success "TDX attestation library found"
        return 0
    else
        if [[ "$ENABLE_TDX" == "ON" ]]; then
            print_error "TDX attestation library required but not found"
            exit 1
        else
            print_warning "TDX attestation library not found - using mock implementation"
            return 1
        fi
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
        -DBUILD_GRPC_SERVER="$ENABLE_GRPC_SERVER"
    )
    
    # Add TDX support if available
    if check_tdx_support; then
        cmake_args+=(-DHAVE_TDX_ATTEST=ON)
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
        ctest --output-on-failure --verbose
        print_success "All tests passed"
    else
        print_info "Testing disabled"
    fi
    
    cd - > /dev/null
}

# Function to generate documentation
generate_docs() {
    print_header "Generating Documentation"
    
    if command_exists doxygen; then
        print_info "Generating API documentation..."
        doxygen Doxyfile 2>/dev/null || true
        print_success "Documentation generated"
    else
        print_warning "Doxygen not found - skipping documentation generation"
    fi
}

# Function to install project
install_project() {
    print_header "Installing Project"
    
    cd "$BUILD_DIR"
    print_info "Installing to $INSTALL_PREFIX..."
    sudo make install
    cd - > /dev/null
    
    print_success "Installation completed"
    print_info "Installed files:"
    echo "  - $INSTALL_PREFIX/bin/tapp_cli"
    echo "  - $INSTALL_PREFIX/bin/tapp_server"
    echo "  - $INSTALL_PREFIX/lib/libboost_lib.so"
    echo "  - $INSTALL_PREFIX/lib/libkey_tool_lib.so"
    echo "  - $INSTALL_PREFIX/include/tdx_tapp/"
}

# Function to run examples
run_examples() {
    print_header "Running Examples"
    
    cd "$BUILD_DIR"
    
    if [[ -f "tapp_cli" ]]; then
        print_info "Testing CLI tool..."
        ./tapp_cli key all || print_warning "CLI test failed (expected in mock mode)"
        
        print_info "Testing quote generation..."
        ./tapp_cli boost quote test_quote.dat || print_warning "Quote test failed"
        
        if [[ -f "test_quote.dat" ]]; then
            print_success "Quote generated successfully ($(wc -c < test_quote.dat) bytes)"
            rm -f test_quote.dat
        fi
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
        ls -la *.deb *.rpm *.tar.gz 2>/dev/null || true
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
    echo -e "${CYAN}TDX Support:${NC} $(check_tdx_support && echo "Enabled" || echo "Mock")"
    
    if [[ -d "$BUILD_DIR" ]]; then
        echo -e "${CYAN}Build Directory:${NC} $BUILD_DIR"
        echo -e "${CYAN}Build Files:${NC}"
        ls -la "$BUILD_DIR"/{tapp_cli,tapp_server,lib*.so} 2>/dev/null | sed 's/^/  /' || echo "  No build files found"
    fi
    
    print_success "Build completed successfully!"
    
    echo ""
    echo -e "${GREEN}Next steps:${NC}"
    echo "  1. Run CLI tool: ./$BUILD_DIR/tapp_cli key all"
    echo "  2. Start server: ./$BUILD_DIR/tapp_server"
    echo "  3. Install system-wide: sudo make install (from build directory)"
    echo "  4. Run with Docker: docker-compose up"
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
    echo "  --enable-testing      Enable unit testing (default: ON)"
    echo "  --disable-testing     Disable unit testing"
    echo "  --enable-tdx          Force enable TDX support"
    echo "  --disable-tdx         Force disable TDX support"
    echo "  --help               Show this help message"
    echo ""
    echo "Targets:"
    echo "  deps                 Install dependencies"
    echo "  configure            Configure build"
    echo "  build                Build project"
    echo "  test                 Run tests"
    echo "  docs                 Generate documentation"
    echo "  install              Install project"
    echo "  examples             Run examples"
    echo "  package              Create distribution package"
    echo "  all                  Run all targets (default)"
    echo "  clean                Clean build directory"
    echo ""
    echo "Examples:"
    echo "  $0                               # Full build with defaults"
    echo "  $0 --build-type Debug build test # Debug build and test only"
    echo "  $0 --disable-tdx configure build # Build without TDX support"
    echo "  $0 clean                         # Clean build directory"
}

# Function to clean build directory
clean_build() {
    print_header "Cleaning Build Directory"
    
    if [[ -d "$BUILD_DIR" ]]; then
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
                ENABLE_TESTING="OFF"
                shift
                ;;
            --disable-testing)
                ENABLE_TESTING="OFF"
                shift
                ;;
            --enable-tdx)
                ENABLE_TDX="ON"
                shift
                ;;
            --disable-tdx)
                ENABLE_TDX="OFF"
                shift
                ;;
            --help)
                show_usage
                exit 0
                ;;
            deps|configure|build|test|docs|install|examples|package|all|clean)
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
        targets=("deps" "configure" "build" "test" "docs" "examples")
    fi
    
    print_header "TDX TAPP Build Script"
    print_info "OS: $(detect_os)"
    print_info "Build Type: $CMAKE_BUILD_TYPE"
    print_info "Targets: ${targets[*]}"
    
    # Execute targets
    for target in "${targets[@]}"; do
        case $target in
            deps)
                install_dependencies
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
            docs)
                generate_docs
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
                configure_build
                build_project
                run_tests
                generate_docs
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