/**
 * @file key_tool.cpp
 * @brief TDX Ethereum Key Generation Library Implementation (C++)
 * 
 * SECURITY DESIGN: Private keys are never stored persistently and 
 * only derived temporarily from TDX report when needed, then cleared.
 */

#include "key_tool.hpp"
#include <iostream>
#include <iomanip>
#include <cstring>
#include <ctime>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/kdf.h>
#include <openssl/err.h>

#ifdef HAVE_TDX_ATTEST
#include <tdx_attest.h>
#else
// Mock implementation for testing without TDX hardware
#define TDX_REPORT_DATA_SIZE 64
#define TDX_ATTEST_SUCCESS 0

typedef struct {
    uint8_t d[TDX_REPORT_DATA_SIZE];
} tdx_report_data_t;

typedef struct {
    uint8_t d[1024]; 
} tdx_report_t;

namespace {
    int tdx_att_get_report(const tdx_report_data_t *report_data, tdx_report_t *report) {
        const uint8_t mock_report_data[32] = {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
            0xA5, 0xB7, 0xC9, 0xD1, 0xE3, 0xF5, 0x17, 0x29,
            0x3B, 0x4D, 0x5F, 0x71, 0x83, 0x95, 0xA7, 0xB9
        };
        
        std::memset(report->d, 0, sizeof(report->d));
        std::memcpy(report->d, mock_report_data, sizeof(mock_report_data));
        
        if (report_data) {
            for (int i = 0; i < TDX_REPORT_DATA_SIZE && i + 32 < sizeof(report->d); i++) {
                report->d[32 + i] ^= report_data->d[i];
            }
        }
        
        for (int i = 32 + TDX_REPORT_DATA_SIZE; i < sizeof(report->d); i++) {
            report->d[i] = (i * 0x53) & 0xFF;
        }
        
        std::cout << "[MOCK] Generated TDX report" << std::endl;
        return TDX_ATTEST_SUCCESS;
    }
}
#endif

namespace key_tool {

// SecureMemory implementation
void SecureMemory::clear(void* data, size_t size) {
    if (data && size > 0) {
        OPENSSL_cleanse(data, size);
    }
}

void SecureMemory::clear(std::vector<uint8_t>& vec) {
    if (!vec.empty()) {
        OPENSSL_cleanse(vec.data(), vec.size());
        vec.clear();
    }
}

// KeyToolLib implementation
KeyToolLib::KeyToolLib() : initialized_(false) {
    // Initialize OpenSSL if needed
    // OpenSSL_add_all_digests(); // Not needed in OpenSSL 1.1.0+
    initialized_ = true;
}

KeyToolLib::~KeyToolLib() {
    // Cleanup OpenSSL if needed
    // EVP_cleanup(); // Not needed in OpenSSL 1.1.0+
}

PubkeyResult KeyToolLib::get_pubkey_from_report() {
    PubkeyResult result;
    
    SecureBuffer<ETH_PRIVKEY_LEN> private_key;
    
    // Get private key from TDX report
    if (!get_private_key_from_tdx_report(private_key)) {
        result.status = ErrorCode::TDX_REPORT;
        result.message = "Failed to get private key from TDX report";
        return result;
    }
    
    // Derive public key from private key
    result.public_key = derive_public_key_from_private(private_key);
    if (result.public_key.empty()) {
        result.status = ErrorCode::KEY_DERIVATION;
        result.message = "Failed to derive public key";
        return result;
    }
    
    // Derive Ethereum address from public key
    result.eth_address = derive_address_from_public_key(result.public_key);
    if (result.eth_address.empty()) {
        result.status = ErrorCode::KEY_DERIVATION;
        result.message = "Failed to derive Ethereum address";
        return result;
    }

    // Format address as hex string
    result.eth_address_hex = format_address_hex(result.eth_address);
    if (result.eth_address_hex.empty()) {
        result.status = ErrorCode::KEY_DERIVATION;
        result.message = "Failed to format address as hex";
        return result;
    }
    
    result.status = ErrorCode::SUCCESS;
    result.message = "Successfully derived keys from TDX environment";
    
    return result;
}

std::vector<uint8_t> KeyToolLib::get_public_key_only() {
    SecureBuffer<ETH_PRIVKEY_LEN> private_key;
    
    // Get private key from TDX report
    if (!get_private_key_from_tdx_report(private_key)) {
        std::cerr << "Failed to get private key from TDX report" << std::endl;
        return {};
    }
    
    // Derive public key from private key
    return derive_public_key_from_private(private_key);
}

std::vector<uint8_t> KeyToolLib::get_address_only() {
    SecureBuffer<ETH_PRIVKEY_LEN> private_key;
    
    // Get private key from TDX report
    if (!get_private_key_from_tdx_report(private_key)) {
        std::cerr << "Failed to get private key from TDX report" << std::endl;
        return {};
    }
    
    // Derive public key from private key
    auto public_key = derive_public_key_from_private(private_key);
    if (public_key.empty()) {
        std::cerr << "Failed to derive public key" << std::endl;
        return {};
    }
    
    // Derive Ethereum address from public key
    auto address = derive_address_from_public_key(public_key);
    
    // Clear public key from memory
    SecureMemory::clear(public_key);
    
    return address;
}

std::string KeyToolLib::format_address_hex(const std::vector<uint8_t>& address) {
    if (address.size() != ETH_ADDR_LEN) {
        return "";
    }

    std::ostringstream oss;
    oss << "0x";
    for (const auto& byte : address) {
        oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(byte);
    }

    return oss.str();
}

void KeyToolLib::print_hex(const std::string& label, const std::vector<uint8_t>& data) {
    std::cout << label << " (" << data.size() << " bytes):" << std::endl;
    for (size_t i = 0; i < data.size(); i++) {
        std::cout << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(data[i]);
        if ((i + 1) % 32 == 0 && i < data.size() - 1) {
            std::cout << std::endl;
        }
    }
    std::cout << std::dec << std::endl;
}

bool KeyToolLib::get_private_key_from_tdx_report(SecureBuffer<ETH_PRIVKEY_LEN>& private_key) {
    tdx_report_data_t report_data = {{0}};
    tdx_report_t tdx_report = {{0}};
    
    // Get TDX report
    if (tdx_att_get_report(&report_data, &tdx_report) != TDX_ATTEST_SUCCESS) {
        std::cerr << "Failed to get TDX report" << std::endl;
        return false;
    }
    
    std::cout << "TDX report obtained successfully" << std::endl;
    
    // Use HKDF to derive key material from TDX report
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx) {
        std::cerr << "Failed to create HKDF context: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        return false;
    }
    
    bool success = false;
    
    do {
        if (EVP_PKEY_derive_init(pctx) <= 0) {
            std::cerr << "Failed to initialize HKDF: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
            break;
        }
        
        if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) {
            std::cerr << "Failed to set HKDF digest: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
            break;
        }
        
        const unsigned char salt[] = "TDX-Ethereum-Key-Derivation";
        if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, sizeof(salt) - 1) <= 0) {
            std::cerr << "Failed to set HKDF salt: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
            break;
        }
        
        if (EVP_PKEY_CTX_set1_hkdf_key(pctx, tdx_report.d, sizeof(tdx_report.d)) <= 0) {
            std::cerr << "Failed to set HKDF key material: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
            break;
        }
        
        const unsigned char info[] = "TDX-0G-TAPP-KEY";
        if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, sizeof(info) - 1) <= 0) {
            std::cerr << "Failed to set HKDF info: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
            break;
        }
        
        size_t outlen = ETH_PRIVKEY_LEN;
        if (EVP_PKEY_derive(pctx, private_key.data(), &outlen) <= 0) {
            std::cerr << "Failed to derive key material: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
            break;
        }
        
        if (outlen != ETH_PRIVKEY_LEN) {
            std::cerr << "Derived key length mismatch: expected " << ETH_PRIVKEY_LEN 
                      << ", got " << outlen << std::endl;
            break;
        }
        
        std::cout << "HKDF key derivation successful" << std::endl;
        success = true;
    } while (false);
    
    EVP_PKEY_CTX_free(pctx);
    return success;
}

std::vector<uint8_t> KeyToolLib::derive_public_key_from_private(const SecureBuffer<ETH_PRIVKEY_LEN>& private_key) {
    std::vector<uint8_t> public_key;
    
    EC_KEY *key = nullptr;
    const EC_POINT *pub_point = nullptr;
    BIGNUM *priv_bn = nullptr;
    BN_CTX *bn_ctx = nullptr;
    
    do {
        // Create key context
        key = EC_KEY_new_by_curve_name(NID_secp256k1);
        if (!key) {
            std::cerr << "Failed to create EC key" << std::endl;
            break;
        }
        
        // Convert private key to BIGNUM
        priv_bn = BN_bin2bn(private_key.data(), ETH_PRIVKEY_LEN, nullptr);
        if (!priv_bn) {
            std::cerr << "Failed to convert private key to BIGNUM" << std::endl;
            break;
        }
        
        // Get the curve group
        const EC_GROUP *group = EC_KEY_get0_group(key);
        if (!group) {
            std::cerr << "Failed to get curve group" << std::endl;
            break;
        }
        
        // Set private key
        if (EC_KEY_set_private_key(key, priv_bn) != 1) {
            std::cerr << "Failed to set private key" << std::endl;
            break;
        }
        
        // Create point for public key
        EC_POINT *pub_point_new = EC_POINT_new(group);
        if (!pub_point_new) {
            std::cerr << "Failed to create EC point" << std::endl;
            break;
        }
        
        // Create BN context
        bn_ctx = BN_CTX_new();
        if (!bn_ctx) {
            std::cerr << "Failed to create BN context" << std::endl;
            EC_POINT_free(pub_point_new);
            break;
        }
        
        // Calculate public key
        if (EC_POINT_mul(group, pub_point_new, priv_bn, nullptr, nullptr, bn_ctx) != 1) {
            std::cerr << "Failed to compute public key" << std::endl;
            EC_POINT_free(pub_point_new);
            break;
        }
        
        // Set public key
        if (EC_KEY_set_public_key(key, pub_point_new) != 1) {
            std::cerr << "Failed to set public key" << std::endl;
            EC_POINT_free(pub_point_new);
            break;
        }
        
        // Get public key in uncompressed format
        pub_point = EC_KEY_get0_public_key(key);
        if (!pub_point) {
            std::cerr << "Failed to get public key" << std::endl;
            break;
        }
        
        uint8_t pub_key_raw[65] = {0}; // Includes 0x04 prefix
        size_t pub_len = EC_POINT_point2oct(group, pub_point, POINT_CONVERSION_UNCOMPRESSED, 
                                           pub_key_raw, sizeof(pub_key_raw), bn_ctx);
        
        if (pub_len != 65) {
            std::cerr << "Invalid public key length: " << pub_len << std::endl;
            break;
        }
        
        // Copy public key without 0x04 prefix
        public_key.assign(pub_key_raw + 1, pub_key_raw + 1 + ETH_PUBKEY_LEN);
        
    } while (false);
    
    // Cleanup
    if (priv_bn) BN_clear_free(priv_bn);
    if (key) EC_KEY_free(key);
    if (bn_ctx) BN_CTX_free(bn_ctx);
    
    return public_key;
}

std::vector<uint8_t> KeyToolLib::derive_address_from_public_key(const std::vector<uint8_t>& public_key) {
    if (public_key.size() != ETH_PUBKEY_LEN) {
        std::cerr << "Invalid public key size: " << public_key.size() << std::endl;
        return {};
    }
    
    std::vector<uint8_t> address;
    uint8_t hash[32];
    std::vector<uint8_t> pub_with_prefix(65); // Add the 0x04 prefix back
    
    // Reconstruct full public key with prefix
    pub_with_prefix[0] = 0x04;
    std::memcpy(pub_with_prefix.data() + 1, public_key.data(), ETH_PUBKEY_LEN);
    
    // Hash public key with SHA3-256 (Keccak-256)
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        std::cerr << "Failed to create digest context" << std::endl;
        return {};
    }
    
    bool success = false;
    
    do {
        // Use SHA3-256 (Keccak-256) for Ethereum address
        if (EVP_DigestInit_ex(ctx, EVP_sha3_256(), nullptr) != 1) {
            std::cerr << "Failed to initialize SHA3-256 digest" << std::endl;
            break;
        }
        
        if (EVP_DigestUpdate(ctx, pub_with_prefix.data(), pub_with_prefix.size()) != 1) {
            std::cerr << "Failed to update digest" << std::endl;
            break;
        }
        
        unsigned int md_len;
        if (EVP_DigestFinal_ex(ctx, hash, &md_len) != 1 || md_len != 32) {
            std::cerr << "Failed to finalize digest" << std::endl;
            break;
        }
        
        success = true;
    } while (false);
    
    EVP_MD_CTX_free(ctx);
    
    if (!success) {
        return {};
    }
    
    // Take last 20 bytes as Ethereum address
    address.assign(hash + 12, hash + 12 + ETH_ADDR_LEN);
    
    return address;
}

} // namespace key_tool