/**
 * @file test_key_tool.cpp
 * @brief Simplified Unit tests for Key Tool Library
 */

#include <gtest/gtest.h>
#include <vector>
#include <string>
#include <algorithm>

#include "key_tool.hpp"

class KeyToolLibTest : public ::testing::Test {
protected:
    // Helper function to check if vector contains only zeros
    bool is_all_zeros(const std::vector<uint8_t>& data) {
        return std::all_of(data.begin(), data.end(), [](uint8_t b) { return b == 0; });
    }
    
    // Helper function to check if string is valid hex
    bool is_valid_hex_address(const std::string& hex_str) {
        if (hex_str.length() != key_tool::ETH_ADDR_HEX_LEN) return false;
        if (hex_str.substr(0, 2) != "0x") return false;
        
        return std::all_of(hex_str.begin() + 2, hex_str.end(), [](char c) {
            return std::isxdigit(c);
        });
    }
};

TEST_F(KeyToolLibTest, ConstructorDestructor) {
    EXPECT_NO_THROW({
        key_tool::KeyToolLib key_tool;
    });
}

TEST_F(KeyToolLibTest, GetPublicKeyOnly) {
    key_tool::KeyToolLib key_tool;
    
    auto public_key = key_tool.get_public_key_only();
    
    EXPECT_FALSE(public_key.empty());
    EXPECT_EQ(public_key.size(), key_tool::ETH_PUBKEY_LEN);
    EXPECT_FALSE(is_all_zeros(public_key));
}

TEST_F(KeyToolLibTest, GetAddressOnly) {
    key_tool::KeyToolLib key_tool;
    
    auto address = key_tool.get_address_only();
    
    EXPECT_FALSE(address.empty());
    EXPECT_EQ(address.size(), key_tool::ETH_ADDR_LEN);
    EXPECT_FALSE(is_all_zeros(address));
}

TEST_F(KeyToolLibTest, GetPubkeyFromReport) {
    key_tool::KeyToolLib key_tool;
    
    auto result = key_tool.get_pubkey_from_report();
    
    EXPECT_EQ(result.status, key_tool::ErrorCode::SUCCESS);
    EXPECT_FALSE(result.message.empty());
    
    // Check public key
    EXPECT_EQ(result.public_key.size(), key_tool::ETH_PUBKEY_LEN);
    EXPECT_FALSE(is_all_zeros(result.public_key));
    
    // Check Ethereum address
    EXPECT_EQ(result.eth_address.size(), key_tool::ETH_ADDR_LEN);
    EXPECT_FALSE(is_all_zeros(result.eth_address));
    
    // Check hex address
    EXPECT_TRUE(is_valid_hex_address(result.eth_address_hex));
}

TEST_F(KeyToolLibTest, FormatAddressHex) {
    // Test with valid address
    std::vector<uint8_t> address = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC,
        0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0xA5, 0xB7, 0xC9, 0xD1
    };
    
    std::string hex_addr = key_tool::KeyToolLib::format_address_hex(address);
    
    EXPECT_FALSE(hex_addr.empty());
    EXPECT_EQ(hex_addr.length(), key_tool::ETH_ADDR_HEX_LEN);
    EXPECT_TRUE(is_valid_hex_address(hex_addr));
    EXPECT_EQ(hex_addr, "0x0123456789abcdeffedcba9876543210a5b7c9d1");
}

TEST_F(KeyToolLibTest, ConsistentKeyGeneration) {
    key_tool::KeyToolLib key_tool;
    
    // Keys should be consistent in mock mode
    auto result1 = key_tool.get_pubkey_from_report();
    auto result2 = key_tool.get_pubkey_from_report();
    
    EXPECT_EQ(result1.status, key_tool::ErrorCode::SUCCESS);
    EXPECT_EQ(result2.status, key_tool::ErrorCode::SUCCESS);
    
    EXPECT_EQ(result1.public_key, result2.public_key);
    EXPECT_EQ(result1.eth_address, result2.eth_address);
    EXPECT_EQ(result1.eth_address_hex, result2.eth_address_hex);
}