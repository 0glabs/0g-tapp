/**
 * @file key_tool.h
 * @brief TDX Ethereum Key Generation Tool API
 *
 * This header provides functions for generating Ethereum keys and addresses
 * directly from TDX reports. Private keys are never stored persistently.
 */

#ifndef TDX_ETH_KEY_TOOL_H
#define TDX_ETH_KEY_TOOL_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ETH_PRIVKEY_LEN 32
#define ETH_PUBKEY_LEN 64
#define ETH_ADDR_LEN 20

/**
 * @brief Get Ethereum public key directly from TDX report
 *
 * This function retrieves a TDX report, derives a private key, 
 * computes the public key, and clears the private key from memory.
 *
 * @param public_key Output buffer for the public key (64 bytes, without 0x04 prefix)
 * @return 0 on success, -1 on failure
 */
int tdx_eth_get_public_key_from_report(uint8_t *public_key);

/**
 * @brief Get Ethereum address directly from TDX report
 *
 * This function retrieves a TDX report, derives a private key,
 * computes the public key, derives the address, and clears private data.
 *
 * @param address Output buffer for Ethereum address (20 bytes)
 * @return 0 on success, -1 on failure
 */
int tdx_eth_get_address_from_report(uint8_t *address);

/**
 * @brief Print human-readable hex representation
 *
 * Helper function to print hex data for debugging
 *
 * @param label Description label
 * @param data Binary data to print
 * @param len Length of data in bytes
 */
void tdx_eth_print_hex(const char *label, const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* TDX_ETH_KEY_TOOL_H */