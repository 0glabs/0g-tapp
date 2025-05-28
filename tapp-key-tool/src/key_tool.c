/**
 * @file key_tool.c
 * @brief Implementation of TDX Ethereum Key Generation Tool
 * 
 * SECURITY DESIGN: Private keys are never stored persistently and 
 * only derived temporarily from TDX report when needed, then cleared.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/kdf.h>

#include "key_tool.h"

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

int tdx_att_get_report(const tdx_report_data_t *report_data, tdx_report_t *report) {
    const uint8_t mock_report_data[32] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        0xA5, 0xB7, 0xC9, 0xD1, 0xE3, 0xF5, 0x17, 0x29,
        0x3B, 0x4D, 0x5F, 0x71, 0x83, 0x95, 0xA7, 0xB9
    };
    
    memset(report->d, 0, sizeof(report->d));
    memcpy(report->d, mock_report_data, sizeof(mock_report_data));
    
    if (report_data) {
        for (int i = 0; i < TDX_REPORT_DATA_SIZE && i + 32 < sizeof(report->d); i++) {
            report->d[32 + i] ^= report_data->d[i];
        }
    }
    
    for (int i = 32 + TDX_REPORT_DATA_SIZE; i < sizeof(report->d); i++) {
        report->d[i] = (i * 0x53) & 0xFF;
    }
    
    printf("[MOCK] Generated TDX report\n");
    return TDX_ATTEST_SUCCESS;
}
#endif

/**
 * Utility function to print hex data (ONLY for public values)
 */
void tdx_eth_print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s (%zu bytes):\n", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 32 == 0 && i < len - 1) printf("\n");
    }
    printf("\n");
}

// Get TDX report and extract key material
static int get_private_key_from_tdx_report(uint8_t *private_key) {
    tdx_report_data_t report_data = {{0}};
    tdx_report_t tdx_report = {{0}};
    
    // Get TDX report (already includes measurements from init)
    if (tdx_att_get_report(&report_data, &tdx_report) != TDX_ATTEST_SUCCESS) {
        fprintf(stderr, "Failed to get TDX report\n");
        return -1;
    }
    
    // Use HKDF to derive key material from TDX report
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) {
        fprintf(stderr, "Failed to create HKDF context\n");
        return -1;
    }
    
    if (EVP_PKEY_derive_init(pctx) <= 0) {
        fprintf(stderr, "Failed to initialize HKDF\n");
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) {
        fprintf(stderr, "Failed to set HKDF digest\n");
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    
    const unsigned char salt[] = "TDX-Ethereum-Key-Derivation";
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, sizeof(salt) - 1) <= 0) {
        fprintf(stderr, "Failed to set HKDF salt\n");
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    
    const unsigned char info[] = "TDX-0G-TAPP-KEY";
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, tdx_report.d, sizeof(tdx_report.d)) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(pctx, info, sizeof(info) - 1) <= 0) {
        fprintf(stderr, "Failed to set HKDF parameters\n");
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    
    size_t outlen = ETH_PRIVKEY_LEN;
    if (EVP_PKEY_derive(pctx, private_key, &outlen) <= 0 || outlen != ETH_PRIVKEY_LEN) {
        fprintf(stderr, "Failed to derive key material\n");
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    
    EVP_PKEY_CTX_free(pctx);
    return 0;
}

// Derive public key from private key
static int derive_public_key_from_private(const uint8_t *private_key, uint8_t *public_key) {
    int ret = -1;
    EC_KEY *key = NULL;
    const EC_POINT *pub_point = NULL;
    BIGNUM *priv_bn = NULL;
    BN_CTX *bn_ctx = NULL;
    const EC_GROUP *group = NULL;
    uint8_t pub_key_raw[65] = {0}; // Includes 0x04 prefix
    
    // Create key context
    key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!key) {
        fprintf(stderr, "Failed to create EC key\n");
        goto cleanup;
    }
    
    // Convert private key to BIGNUM
    priv_bn = BN_bin2bn(private_key, ETH_PRIVKEY_LEN, NULL);
    if (!priv_bn) {
        fprintf(stderr, "Failed to convert private key to BIGNUM\n");
        goto cleanup;
    }
    
    // Get the curve group
    group = EC_KEY_get0_group(key);
    if (!group) {
        fprintf(stderr, "Failed to get curve group\n");
        goto cleanup;
    }
    
    // Set private key
    if (EC_KEY_set_private_key(key, priv_bn) != 1) {
        fprintf(stderr, "Failed to set private key\n");
        goto cleanup;
    }
    
    // Create point for public key
    EC_POINT *pub_point_new = EC_POINT_new(group);
    if (!pub_point_new) {
        fprintf(stderr, "Failed to create EC point\n");
        goto cleanup;
    }
    
    // Create BN context
    bn_ctx = BN_CTX_new();
    if (!bn_ctx) {
        fprintf(stderr, "Failed to create BN context\n");
        EC_POINT_free(pub_point_new);
        goto cleanup;
    }
    
    // Calculate public key
    if (EC_POINT_mul(group, pub_point_new, priv_bn, NULL, NULL, bn_ctx) != 1) {
        fprintf(stderr, "Failed to compute public key\n");
        EC_POINT_free(pub_point_new);
        goto cleanup;
    }
    
    // Set public key
    if (EC_KEY_set_public_key(key, pub_point_new) != 1) {
        fprintf(stderr, "Failed to set public key\n");
        EC_POINT_free(pub_point_new);
        goto cleanup;
    }
    
    // Get public key in uncompressed format
    pub_point = EC_KEY_get0_public_key(key);
    if (!pub_point) {
        fprintf(stderr, "Failed to get public key\n");
        goto cleanup;
    }
    
    size_t pub_len = EC_POINT_point2oct(group, pub_point, POINT_CONVERSION_UNCOMPRESSED, 
                                       pub_key_raw, sizeof(pub_key_raw), bn_ctx);
    
    if (pub_len != 65) {
        fprintf(stderr, "Invalid public key length: %zu\n", pub_len);
        goto cleanup;
    }
    
    // Copy public key without 0x04 prefix
    memcpy(public_key, pub_key_raw + 1, ETH_PUBKEY_LEN);
    
    ret = 0;
    
cleanup:
    if (priv_bn) BN_clear_free(priv_bn);
    if (key) EC_KEY_free(key);
    if (bn_ctx) BN_CTX_free(bn_ctx);
    
    return ret;
}

// Derive Ethereum address from public key
static int derive_address_from_public_key(const uint8_t *public_key, uint8_t *address) {
    uint8_t hash[32];
    uint8_t pub_with_prefix[65] = {0x04}; // Add the 0x04 prefix back
    
    // Reconstruct full public key with prefix
    memcpy(pub_with_prefix + 1, public_key, ETH_PUBKEY_LEN);
    
    // Hash public key with Keccak-256
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create digest context\n");
        return -1;
    }
    
    // Use SHA3-256 (Keccak-256) for Ethereum address
    if (EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL) != 1) {
        fprintf(stderr, "Failed to initialize SHA3-256 digest\n");
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    
    if (EVP_DigestUpdate(ctx, pub_with_prefix, sizeof(pub_with_prefix)) != 1) {
        fprintf(stderr, "Failed to update digest\n");
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    
    unsigned int md_len;
    if (EVP_DigestFinal_ex(ctx, hash, &md_len) != 1 || md_len != 32) {
        fprintf(stderr, "Failed to finalize digest\n");
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    
    EVP_MD_CTX_free(ctx);
    
    // Take last 20 bytes as Ethereum address
    memcpy(address, hash + 12, ETH_ADDR_LEN);
    
    return 0;
}

// Public API: Get public key directly from TDX report
int tdx_eth_get_public_key_from_report(uint8_t *public_key) {
    uint8_t private_key[ETH_PRIVKEY_LEN] = {0};
    int result = -1;
    
    // Get private key from TDX report
    if (get_private_key_from_tdx_report(private_key) != 0) {
        fprintf(stderr, "Failed to get private key from TDX report\n");
        goto cleanup;
    }
    
    // Derive public key from private key
    if (derive_public_key_from_private(private_key, public_key) != 0) {
        fprintf(stderr, "Failed to derive public key\n");
        goto cleanup;
    }
    
    result = 0;
    
cleanup:
    // Always clear private key from memory
    OPENSSL_cleanse(private_key, ETH_PRIVKEY_LEN);
    return result;
}

// Public API: Get Ethereum address directly from TDX report
int tdx_eth_get_address_from_report(uint8_t *address) {
    uint8_t private_key[ETH_PRIVKEY_LEN] = {0};
    uint8_t public_key[ETH_PUBKEY_LEN] = {0};
    int result = -1;
    
    // Get private key from TDX report
    if (get_private_key_from_tdx_report(private_key) != 0) {
        fprintf(stderr, "Failed to get private key from TDX report\n");
        goto cleanup;
    }
    
    // Derive public key from private key
    if (derive_public_key_from_private(private_key, public_key) != 0) {
        fprintf(stderr, "Failed to derive public key\n");
        goto cleanup;
    }
    
    // Derive Ethereum address from public key
    if (derive_address_from_public_key(public_key, address) != 0) {
        fprintf(stderr, "Failed to derive Ethereum address\n");
        goto cleanup;
    }
    
    result = 0;
    
cleanup:
    // Always clear sensitive data from memory
    OPENSSL_cleanse(private_key, ETH_PRIVKEY_LEN);
    OPENSSL_cleanse(public_key, ETH_PUBKEY_LEN);
    return result;
}

// Format an Ethereum address with 0x prefix
static void print_eth_address(const uint8_t *address) {
    printf("Ethereum Address (0x format): 0x");
    for (int i = 0; i < ETH_ADDR_LEN; i++) {
        printf("%02x", address[i]);
    }
    printf("\n");
}

// Command-line tool implementation
static void print_usage(const char *prog_name) {
    printf("Usage: %s <command>\n\n", prog_name);
    printf("Commands:\n");
    printf("  pubkey     Display public key derived from TDX report\n");
    printf("  address    Display Ethereum address derived from TDX report\n");
    printf("\n");
    printf("Note: Private keys are never stored and only exist transiently\n");
    printf("      in memory within the TDX environment.\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    const char *command = argv[1];
    
    if (strcmp(command, "pubkey") == 0) {
        uint8_t public_key[ETH_PUBKEY_LEN] = {0};
        
        printf("Deriving public key from TDX report...\n");
        
        if (tdx_eth_get_public_key_from_report(public_key) != 0) {
            fprintf(stderr, "Failed to get public key from TDX report\n");
            return 1;
        }
        
        tdx_eth_print_hex("Public Key (uncompressed, without 0x04 prefix)", public_key, ETH_PUBKEY_LEN);
        printf("\n✅ Public key successfully derived from TDX environment\n");
        
    } else if (strcmp(command, "address") == 0) {
        uint8_t address[ETH_ADDR_LEN] = {0};
        
        printf("Deriving Ethereum address from TDX report...\n");
        
        if (tdx_eth_get_address_from_report(address) != 0) {
            fprintf(stderr, "Failed to get Ethereum address from TDX report\n");
            return 1;
        }
        
        // Print address in different formats
        tdx_eth_print_hex("Ethereum Address (raw bytes)", address, ETH_ADDR_LEN);
        print_eth_address(address);
        
        printf("\n✅ Ethereum address successfully derived from TDX environment\n");
        
    } else {
        fprintf(stderr, "Unknown command: %s\n", command);
        print_usage(argv[0]);
        return 1;
    }
    
    return 0;
}