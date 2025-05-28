/**
 * @file boost.h
 * @brief Boost API
 *
 * This header provides functions for Boosting a TDX environment.
 */

#ifndef BOOST_H
#define BOOST_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Measure a file or directory and extend a TDX RTMR register
 *
 * Calculates a hash of the specified path (file or directory) and extends
 * the specified RTMR register with the resulting hash.
 *
 * @param path Path to the file or directory to measure
 * @param rtmr_index Index of the RTMR register to extend (0-3)
 * @return 0 on success, -1 on failure
 */
int tdx_measure_and_extend(const char *path, int rtmr_index);

/**
 * @brief Generate a TDX Quote and save it to a file
 *
 * Generates a TDX Quote that includes the current values of the RTMR registers,
 * which can be used for remote attestation to verify the integrity of the TDX environment.
 * The generated quote is saved to the specified file.
 *
 * @param report_data Optional user data to include in the quote (can be NULL)
 * @param report_data_size Size of report_data in bytes (can be 0 if report_data is NULL)
 * @param filename Path to output file to save the quote (default: "quote.dat" if NULL)
 * @return 0 on success, -1 on failure
 */
int tdx_generate_and_save_quote(const uint8_t *report_data, size_t report_data_size, 
                               const char *filename);

#ifdef __cplusplus
}
#endif

#endif /* BOOST_H */