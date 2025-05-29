/**
 * @file key_tool.hpp
 * @brief TDX Ethereum Key Generation Library Interface (C++)
 */

#ifndef KEY_TOOL_LIB_HPP
#define KEY_TOOL_LIB_HPP

#include <string>
#include <vector>
#include <memory>
#include <cstdint>

namespace key_tool {

// Constants
constexpr size_t ETH_PRIVKEY_LEN = 32;     // Private key length in bytes
constexpr size_t ETH_PUBKEY_LEN = 64;      // Public key length in bytes (uncompressed, without prefix)
constexpr size_t ETH_ADDR_LEN = 20;        // Ethereum address length in bytes
constexpr size_t ETH_ADDR_HEX_LEN = 42;    // Ethereum address hex string length (with 0x prefix)

// Error codes
enum class ErrorCode {
    SUCCESS = 0,
    TDX_REPORT = -1,
    KEY_DERIVATION = -2,
    INVALID_PARAM = -3,
    CRYPTO = -4
};

/**
 * @brief Result structure for public key operations
 */
struct PubkeyResult {
    ErrorCode status;
    std::string message;
    std::vector<uint8_t> public_key;      // 64-byte uncompressed public key
    std::vector<uint8_t> eth_address;     // 20-byte Ethereum address  
    std::string eth_address_hex;          // Hex string with 0x prefix
    
    PubkeyResult() : status(ErrorCode::SUCCESS), 
                     public_key(ETH_PUBKEY_LEN, 0), 
                     eth_address(ETH_ADDR_LEN, 0) {}
};

/**
 * @brief Secure memory cleaner for sensitive data
 */
class SecureMemory {
public:
    /**
     * @brief Securely clear memory
     * @param data Pointer to data
     * @param size Size of data
     */
    static void clear(void* data, size_t size);
    
    /**
     * @brief Securely clear vector
     * @param vec Vector to clear
     */
    static void clear(std::vector<uint8_t>& vec);
};

/**
 * @brief RAII wrapper for secure memory
 */
template<size_t Size>
class SecureBuffer {
public:
    SecureBuffer() { data_.fill(0); }
    ~SecureBuffer() { SecureMemory::clear(data_.data(), Size); }
    
    uint8_t* data() { return data_.data(); }
    const uint8_t* data() const { return data_.data(); }
    constexpr size_t size() const { return Size; }
    
    // Delete copy operations for security
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;
    
    // Allow move operations
    SecureBuffer(SecureBuffer&& other) noexcept {
        data_ = std::move(other.data_);
        SecureMemory::clear(other.data_.data(), Size);
    }
    
    SecureBuffer& operator=(SecureBuffer&& other) noexcept {
        if (this != &other) {
            SecureMemory::clear(data_.data(), Size);
            data_ = std::move(other.data_);
            SecureMemory::clear(other.data_.data(), Size);
        }
        return *this;
    }

private:
    std::array<uint8_t, Size> data_;
};

/**
 * @brief Main Key Tool Library class
 */
class KeyToolLib {
public:
    /**
     * @brief Constructor - initializes the library
     * @throws std::runtime_error if initialization fails
     */
    KeyToolLib();
    
    /**
     * @brief Destructor - cleans up resources
     */
    ~KeyToolLib();
    
    /**
     * @brief Get public key and Ethereum address from TDX report
     * @return PubkeyResult with keys and address
     */
    PubkeyResult get_pubkey_from_report();
    
    /**
     * @brief Get only public key from TDX report (64 bytes uncompressed)
     * @return Public key or empty vector on error
     */
    std::vector<uint8_t> get_public_key_only();
    
    /**
     * @brief Get only Ethereum address from TDX report (20 bytes)
     * @return Ethereum address or empty vector on error
     */
    std::vector<uint8_t> get_address_only();
    
    /**
     * @brief Format Ethereum address as hex string with 0x prefix
     * @param address 20-byte Ethereum address
     * @return Hex string with 0x prefix or empty string on error
     */
    static std::string format_address_hex(const std::vector<uint8_t>& address);
    
    /**
     * @brief Print hex data for debugging (ONLY for public values)
     * @param label Label for the data
     * @param data Data to print
     */
    static void print_hex(const std::string& label, const std::vector<uint8_t>& data);

private:
    /**
     * @brief Get private key from TDX report (NEVER expose this!)
     * @param private_key Buffer to store private key (will be cleared after use)
     * @return true on success, false otherwise
     */
    bool get_private_key_from_tdx_report(SecureBuffer<ETH_PRIVKEY_LEN>& private_key);
    
    /**
     * @brief Derive public key from private key
     * @param private_key Private key (32 bytes)
     * @return Public key (64 bytes) or empty vector on error
     */
    std::vector<uint8_t> derive_public_key_from_private(const SecureBuffer<ETH_PRIVKEY_LEN>& private_key);
    
    /**
     * @brief Derive Ethereum address from public key
     * @param public_key Public key (64 bytes)
     * @return Ethereum address (20 bytes) or empty vector on error
     */
    std::vector<uint8_t> derive_address_from_public_key(const std::vector<uint8_t>& public_key);
    
    bool initialized_;
};

} // namespace key_tool

#endif // KEY_TOOL_LIB_HPP