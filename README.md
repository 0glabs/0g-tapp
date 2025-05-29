# 0G TAPP - Trusted Application (C++)

A comprehensive C++ implementation of a Trusted Domain Extensions (TDX) application platform that provides secure Docker Compose measurement, TDX attestation, and Ethereum key derivation capabilities.

## 🏗️ Project Structure

```
tdx_tapp/
├── include/
│   ├── boost.hpp           # Boost library interface
│   └── key_tool.hpp        # Key tool library interface
├── rpc/
│   └── tapp_service.proto          # gRPC protocol definition
├── src/
│   ├── boost.cpp           # Boost library implementation
│   ├── key_tool.cpp        # Key tool library implementation
│   ├── cli.cpp             # CLI application
│   └── tapp.cpp            # gRPC server implementation
├── tests/                  # Unit tests (optional)
├── CMakeLists.txt          # Build configuration
└── README.md               # This file
```

## 🚀 Features

### 📦 Boost Library
- **Docker Compose Measurement**: Calculate cryptographic hashes of Docker volumes
- **TDX RTMR Extension**: Extend Runtime Measurement Registers with compose file hash and volumes hash
- **TDX Quote Generation**: Generate and export TDX attestation quotes
- **Secure Volume Tracking**: Recursively hash directories and files

### 🔐 Key Tool Library
- **Ethereum Key Derivation**: Generate Ethereum keypairs from TDX reports
- **Secure Memory Management**: Automatic cleanup of sensitive data
- **Address Generation**: Derive Ethereum addresses using Keccak-256
- **Mock TDX Support**: Development-friendly mock implementation

### 🖥️ CLI Interface
- **Unified Commands**: Single binary for all operations
- **REST API Server**: HTTP endpoint for remote operations
- **File I/O**: Read/write compose files and quotes
- **Real-time Feedback**: Progress indicators and colored output

### 🌐 gRPC Service
- **StartApp**: Deploy applications with measurement
- **GetQuote**: Generate TDX attestation quotes
- **GetPubkey**: Retrieve Ethereum keys and addresses
- **Reflection Support**: Service discovery capabilities

## 🛠️ Dependencies

### Required
- **C++17 or later**
- **CMake 3.16+**
- **OpenSSL 1.1.0+** (for cryptographic operations)
- **Protobuf 3.x** (for gRPC)
- **gRPC 1.x** (for remote procedure calls)

### Optional
- **TDX Attestation Library** (`tdx_attest`) - For real TDX hardware
- **Google Test** (for unit testing)
- **Doxygen** (for documentation generation)
- **clang-format** (for code formatting)

## 🔧 Building & 🧪 Testing

```bash
./build.sh help

TDX TAPP Build Script

Usage: build.sh [OPTIONS] [TARGETS]

Options:
  --build-type TYPE     Set build type (Release|Debug|RelWithDebInfo)
  --install-prefix DIR  Set installation prefix (default: /usr/local)
  --enable-testing      Enable unit testing (default: ON)
  --disable-testing     Disable unit testing
  --enable-tdx          Force enable TDX support
  --disable-tdx         Force disable TDX support
  --help               Show this help message

Targets:
  deps                 Install dependencies
  configure            Configure build
  build                Build project
  test                 Run tests
  docs                 Generate documentation
  install              Install project
  examples             Run examples
  package              Create distribution package
  all                  Run all targets (default)
  clean                Clean build directory

Examples:
  build.sh                               # Full build with defaults
  build.sh --build-type Debug build test # Debug build and test only
  build.sh --disable-tdx configure build # Build without TDX support
  build.sh clean                         
```

## 📖 Usage

### CLI Tool

#### Boost Commands
```bash
# Measure and start application
./tapp_cli boost measure docker-compose.yml 3

# Start an business application
./tapp_cli boost start_app docker-compose.yml 3

# Generate TDX quote
./tapp_cli boost quote output.dat
```

#### Key Commands
```bash
# Show public key only
./tapp_cli key pubkey

# Show Ethereum address only
./tapp_cli key address

# Show both keys and address
./tapp_cli key all
```

### gRPC Server
```bash
# Start server on default port (50051)
./tapp_server

# Start server on custom address
./tapp_server 0.0.0.0:8080
```

### Library Usage

#### Boost Library
```cpp
#include "boost.hpp"

boost_lib::BoostLib boost;

// Measure Docker Compose volumes
auto result = boost.start_app(compose_content, 3);
if (result.status == boost_lib::ErrorCode::SUCCESS) {
    boost_lib::BoostLib::print_hex("Hash", result.volumes_hash);
}

// Generate TDX quote
auto quote = boost.generate_quote();
if (quote.status == boost_lib::ErrorCode::SUCCESS) {
    // Save quote.quote_data to file
}
```

#### Key Tool Library
```cpp
#include "key_tool.hpp"

key_tool::KeyToolLib key_tool;

// Get Ethereum keys
auto result = key_tool.get_pubkey_from_report();
if (result.status == key_tool::ErrorCode::SUCCESS) {
    std::cout << "Address: " << result.eth_address_hex << std::endl;
}
```

## 🔒 Security Features

### 🛡️ Memory Protection
- **Secure Buffers**: RAII wrappers for sensitive data
- **Automatic Cleanup**: Private keys cleared from memory immediately
- **No Persistent Storage**: Keys exist only transiently in TDX environment

### 🔐 Cryptographic Operations
- **HKDF Key Derivation**: RFC 5869 compliant key derivation
- **secp256k1 Curve**: Ethereum-compatible elliptic curve cryptography
- **SHA-256/Keccak-256**: Industry-standard hash algorithms

### 🏗️ TDX Integration
- **RTMR Extension**: Secure measurement of application state
- **Quote Generation**: Hardware-backed attestation proofs
- **Mock Support**: Development without TDX hardware

## 📚 API Reference

### Boost Library

```cpp
namespace boost_lib {
    class BoostLib {
        StartAppResult start_app(const std::string& compose_content, int rtmr_index);
        QuoteResult generate_quote(const std::vector<uint8_t>& report_data = {});
        std::vector<uint8_t> calculate_compose_volumes_hash(const std::string& compose_content);
        std::vector<uint8_t> calculate_directory_hash(const std::string& dir_path);
    };
}
```

### Key Tool Library

```cpp
namespace key_tool {
    class KeyToolLib {
        PubkeyResult get_pubkey_from_report();
        std::vector<uint8_t> get_public_key_only();
        std::vector<uint8_t> get_address_only();
        static std::string format_address_hex(const std::vector<uint8_t>& address);
    };
}
```

### gRPC Services

```protobuf
service TappService {
    rpc StartApp(StartAppRequest) returns (StartAppResponse);
    rpc GetQuote(GetQuoteRequest) returns (GetQuoteResponse);
    rpc GetPubkey(GetPubkeyRequest) returns (GetPubkeyResponse);
}
```

## ⚠️ Important Notes

1. **Private Key Security**: Private keys are never stored persistently and only exist temporarily in memory within the TDX environment.

2. **TDX Hardware**: This implementation includes mock TDX support for development. For production use with real TDX hardware, install the TDX attestation library.

3. **Ethereum Compatibility**: Generated keys and addresses are fully compatible with Ethereum mainnet and testnets.

4. **Memory Safety**: All sensitive cryptographic material is automatically cleared from memory using secure cleanup functions.

## 📄 License

This project is provided as-is for educational and development purposes.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run the test suite
6. Submit a pull request

## 📞 Support

For questions, issues, or contributions, please refer to the project's issue tracker or documentation.