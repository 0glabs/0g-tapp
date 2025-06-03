/**
 * @file boost.hpp
 * @brief Boost Library Interface for TDX Docker Compose measurement (C++)
 */

#ifndef BOOST_LIB_HPP
#define BOOST_LIB_HPP

#include <string>
#include <vector>
#include <memory>
#include <cstdint>
#include <mutex>
#include <chrono>

namespace boost_lib {

// Constants
constexpr size_t HASH_LEN = 32;  // SHA-256 hash length
constexpr size_t MAX_PATH = 4096;

// Error codes
enum class ErrorCode {
    SUCCESS = 0,
    INVALID_PARAM = -1,
    FILE_NOT_FOUND = -2,
    MEMORY_ALLOC = -3,
    TDX_EXTEND = -4,
    DOCKER_START = -5
};

// Attestation mode selection
enum class AttestationMode {
    REPORT_DATA = 0,  // Use report data for attestation (default)
    RTMR = 1         // Use RTMR extension for attestation
};

/**
 * @brief Result structure for start_app operation
 */
struct StartAppResult {
    ErrorCode status;
    std::string message;
    std::vector<uint8_t> volumes_hash;
    AttestationMode mode;                   // Attestation mode used
    std::string app_identifier;            // App identifier for reference
    
    StartAppResult() : status(ErrorCode::SUCCESS), volumes_hash(HASH_LEN, 0), 
                      mode(AttestationMode::REPORT_DATA) {}
};

/**
 * @brief Result structure for quote generation
 */
struct QuoteResult {
    ErrorCode status;
    std::string message;
    std::vector<uint8_t> quote_data;
    
    QuoteResult() : status(ErrorCode::SUCCESS) {}
};

/**
 * @brief Main Boost Library class
 */
class BoostLib {
public:
    /**
     * @brief Constructor - initializes the library
     * @throws std::runtime_error if initialization fails
     */
    BoostLib();
    
    /**
     * @brief Destructor - cleans up resources
     */
    ~BoostLib();
    
    /**
     * @brief Start application from Docker Compose content
     * @param compose_content Docker Compose YAML content
     * @param rtmr_index RTMR index to extend (0-3)
     * @return StartAppResult with status and hash
     */
    StartAppResult start_app(const std::string& compose_content, int rtmr_index);
    
    /**
     * @brief Start application from Docker Compose content with attestation mode
     * @param compose_content Docker Compose YAML content
     * @param mode Attestation mode (REPORT_DATA or RTMR)
     * @param rtmr_index RTMR index to extend (0-3, only used in RTMR mode)
     * @return StartAppResult with status and hash
     */
    StartAppResult start_app(const std::string& compose_content, 
                            AttestationMode mode, int rtmr_index = 0);
    
    /**
     * @brief Generate TDX quote
     * @param report_data Custom report data (optional)
     * @return QuoteResult with quote data
     */
    QuoteResult generate_quote(const std::vector<uint8_t>& report_data = {});
    
    /**
     * @brief Calculate hash of Docker Compose volumes
     * @param compose_content Docker Compose YAML content
     * @return Volume hash or empty vector on error
     */
    std::vector<uint8_t> calculate_compose_volumes_hash(const std::string& compose_content);
    
    /**
     * @brief Calculate hash of a directory recursively
     * @param dir_path Path to directory
     * @return Directory hash or empty vector on error
     */
    std::vector<uint8_t> calculate_directory_hash(const std::string& dir_path);
    
    /**
     * @brief Print hex data for debugging
     * @param label Label for the data
     * @param data Data to print
     */
    static void print_hex(const std::string& label, const std::vector<uint8_t>& data);

    /**
     * @brief Check if measurement data is available for attestation
     * @return true if measurement is ready, false otherwise
     */
    bool has_valid_measurement() const;

    /**
     * @brief Get the timestamp when measurement was created
     * @return timestamp of measurement creation
     */
    std::chrono::system_clock::time_point get_measurement_timestamp() const;

    /**
     * @brief Clear cached measurement data
     */
    void clear_measurement();

    /**
     * @brief Get current attestation mode
     * @return current attestation mode
     */
    AttestationMode get_attestation_mode() const;

    /**
     * @brief Get app identifier for current measurement
     * @return app identifier string
     */
    std::string get_app_identifier() const;

private:
    /**
     * @brief Calculate hash of a single file
     * @param file_path Path to file
     * @return File hash or empty vector on error
     */
    std::vector<uint8_t> calculate_file_hash(const std::string& file_path);
    
    /**
     * @brief Extract volume paths from compose content
     * @param compose_content Docker Compose YAML content
     * @return Vector of volume paths
     */
    std::vector<std::string> extract_volume_paths(const std::string& compose_content);
    
    /**
     * @brief Start docker compose from file
     * @param compose_file Path to compose file
     * @return true on success, false otherwise
     */
    bool start_docker_compose_from_file(const std::string& compose_file);
    
    /**
     * @brief Store measurement data securely in memory
     * @param measurement_data The measurement hash to store
     * @param mode Attestation mode used
     * @param app_id Application identifier
     * @param rtmr_index RTMR index used (if applicable)
     */
    void store_measurement_data(const std::vector<uint8_t>& measurement_data,
                               AttestationMode mode,
                               const std::string& app_id,
                               int rtmr_index = -1);

    /**
     * @brief Combine app root measurement with additional data for quote generation
     * @param additional_data Additional data from caller
     * @return Combined report data for TDX quote
     */
    std::vector<uint8_t> prepare_report_data(const std::vector<uint8_t>& additional_data);
    
    // Original member
    bool initialized_;
    
    // New members for measurement storage (secure memory)
    mutable std::mutex measurement_mutex_;
    std::vector<uint8_t> app_root_measurement_;     // App root measurement (max 32 bytes)
    bool measurement_ready_;
    AttestationMode current_mode_;
    std::string app_identifier_;
    std::chrono::system_clock::time_point measurement_timestamp_;
    int used_rtmr_index_;  // Store which RTMR was used (for reference)
};

} // namespace boost_lib

#endif // BOOST_LIB_HPP