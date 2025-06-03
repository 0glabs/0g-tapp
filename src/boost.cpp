/**
 * @file boost.cpp
 * @brief Boost Library Implementation (C++)
 */

#include "boost.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <filesystem>
#include <regex>
#include <ctime>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/limits.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <errno.h>

#define TDX_EXTEND_RTMR_DATA_LEN 48
#ifdef HAVE_TDX_ATTEST
#include <tdx_attest.h>
#else
// Mock implementation for non-TDX environments
#define TDX_REPORT_DATA_SIZE 64
#define TDX_ATTEST_SUCCESS 0
#define TDX_ATTEST_ERROR_INVALID_PARAMETER -1
#define TDX_UUID_SIZE 16

typedef struct _tdx_uuid_t {
    uint8_t d[TDX_UUID_SIZE];
} tdx_uuid_t;

typedef struct {
    uint8_t d[TDX_REPORT_DATA_SIZE];
} tdx_report_data_t;

typedef struct {
    uint8_t d[1024];
} tdx_report_t;

typedef struct {
    uint32_t version;
    uint32_t rtmr_index;
    uint8_t extend_data[TDX_EXTEND_RTMR_DATA_LEN];
    uint32_t event_data_size;
} tdx_rtmr_event_t;

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

    int tdx_att_extend(const tdx_rtmr_event_t *p_rtmr_event) {
        if (!p_rtmr_event || p_rtmr_event->version != 1 || p_rtmr_event->rtmr_index > 3) {
            return TDX_ATTEST_ERROR_INVALID_PARAMETER;
        }
        std::cout << "[MOCK] Extended RTMR[" << p_rtmr_event->rtmr_index << "] with data" << std::endl;
        return TDX_ATTEST_SUCCESS;
    }

    int tdx_att_get_quote(const tdx_report_data_t *report_data,
                          void *p_qe_target_info, uint32_t qe_target_info_size,
                          tdx_uuid_t *p_att_key_id,
                          uint8_t **pp_quote, uint32_t *p_quote_size,
                          uint32_t flags) {
        tdx_report_t report;
        if (tdx_att_get_report(report_data, &report) != TDX_ATTEST_SUCCESS) {
            return -1;
        }

        *p_quote_size = sizeof(report) + 128;
        *pp_quote = (uint8_t *)std::malloc(*p_quote_size);
        if (!*pp_quote) {
            return -1;
        }

        std::memset(*pp_quote, 0, *p_quote_size);
        std::memcpy(*pp_quote, &report, sizeof(report));
        std::memcpy(*pp_quote + sizeof(report), "MOCK_QUOTE_SIGNATURE", 20);

        std::cout << "[MOCK] Generated TDX quote (" << *p_quote_size << " bytes)" << std::endl;

        (void)p_qe_target_info;
        (void)qe_target_info_size;
        (void)p_att_key_id;
        (void)flags;

        return TDX_ATTEST_SUCCESS;
    }

    void tdx_att_free_quote(uint8_t *p_quote) {
        if (p_quote) {
            std::free(p_quote);
            std::cout << "[MOCK] Freed TDX quote" << std::endl;
        }
    }
}
#endif

namespace boost_lib {

BoostLib::BoostLib() 
    : initialized_(false), measurement_ready_(false), 
      current_mode_(AttestationMode::REPORT_DATA), used_rtmr_index_(-1) {
    // Initialize OpenSSL if needed
    // OpenSSL_add_all_digests(); // Not needed in OpenSSL 1.1.0+
    initialized_ = true;
}

BoostLib::~BoostLib() {
    // Clear sensitive data from memory
    clear_measurement();
    // Cleanup OpenSSL if needed
    // EVP_cleanup(); // Not needed in OpenSSL 1.1.0+
}

// Original interface for backward compatibility
StartAppResult BoostLib::start_app(const std::string& compose_content, int rtmr_index) {
    // Default to RTMR mode to maintain backward compatibility
    return start_app(compose_content, AttestationMode::RTMR, rtmr_index);
}

// New interface with attestation mode selection
StartAppResult BoostLib::start_app(const std::string& compose_content, 
                                  AttestationMode mode, int rtmr_index) {
    StartAppResult result;
    result.mode = mode;

    if (compose_content.empty()) {
        result.status = ErrorCode::INVALID_PARAM;
        result.message = "Empty compose content";
        return result;
    }

    // Validate RTMR index only for RTMR mode
    if (mode == AttestationMode::RTMR && (rtmr_index < 0 || rtmr_index > 3)) {
        result.status = ErrorCode::INVALID_PARAM;
        result.message = "Invalid RTMR index: " + std::to_string(rtmr_index);
        return result;
    }

    // Create temporary file for compose content
    std::string temp_file = "/tmp/docker-compose-" + std::to_string(std::time(nullptr)) + ".yml";
    
    std::ofstream file(temp_file);
    if (!file.is_open()) {
        result.status = ErrorCode::FILE_NOT_FOUND;
        result.message = "Failed to create temporary compose file";
        return result;
    }
    
    file << compose_content;
    file.close();
    
    std::cout << "=== Starting Application ===\n";
    std::cout << "Attestation Mode: " << (mode == AttestationMode::RTMR ? "RTMR" : "REPORT_DATA") << std::endl;
    if (mode == AttestationMode::RTMR) {
        std::cout << "RTMR Index: " << rtmr_index << std::endl;
    }
    std::cout << "Saved compose content to: " << temp_file << std::endl;

    std::cout << "\nComputing combined hash (compose + volumes)..." << std::endl;
    
    // 1. Calculate hash of compose content itself
    SHA256_CTX compose_sha256;
    SHA256_Init(&compose_sha256);
    SHA256_Update(&compose_sha256, 
                  reinterpret_cast<const unsigned char*>(compose_content.c_str()), 
                  compose_content.length());
    
    std::vector<uint8_t> compose_hash(HASH_LEN);
    SHA256_Final(compose_hash.data(), &compose_sha256);
    
    print_hex("Docker Compose file hash", compose_hash);

    // 2. Calculate volumes hash
    auto volumes_hash = calculate_compose_volumes_hash(compose_content);
    if (volumes_hash.empty()) {
        result.status = ErrorCode::TDX_EXTEND;
        result.message = "Failed to calculate volumes hash";
        return result;
    }
    
    print_hex("Volumes content hash", volumes_hash);

    // 3. Combine both hashes for final measurement
    SHA256_CTX combined_sha256;
    SHA256_Init(&combined_sha256);
    SHA256_Update(&combined_sha256, compose_hash.data(), compose_hash.size());
    SHA256_Update(&combined_sha256, volumes_hash.data(), volumes_hash.size());
    SHA256_Final(result.volumes_hash.data(), &combined_sha256);

    print_hex("Combined measurement hash", result.volumes_hash);

    // Generate app identifier
    result.app_identifier = "app-" + std::to_string(std::time(nullptr));

    // Process based on attestation mode
    if (mode == AttestationMode::RTMR) {
        std::cout << "\n--- RTMR Mode: Extending RTMR ---" << std::endl;
        
        // 4. Extend RTMR with combined hash
        tdx_rtmr_event_t rtmr_event = {0};
        rtmr_event.version = 1;
        rtmr_event.rtmr_index = rtmr_index;
        rtmr_event.event_data_size = 0;

        std::memset(rtmr_event.extend_data, 0, TDX_EXTEND_RTMR_DATA_LEN);
        size_t copy_len = std::min(result.volumes_hash.size(), static_cast<size_t>(TDX_EXTEND_RTMR_DATA_LEN));
        std::memcpy(rtmr_event.extend_data, result.volumes_hash.data(), copy_len);

        if (tdx_att_extend(&rtmr_event) != TDX_ATTEST_SUCCESS) {
            result.status = ErrorCode::TDX_EXTEND;
            result.message = "Failed to extend RTMR" + std::to_string(rtmr_index);
            return result;
        }

        std::cout << "✅ Successfully extended RTMR" << rtmr_index << " with combined hash" << std::endl;
        
        // Store measurement data for potential future use
        store_measurement_data(result.volumes_hash, mode, result.app_identifier, rtmr_index);
        
    } else {
        std::cout << "\n--- Report Data Mode: Storing App Root ---" << std::endl;
        
        // Store measurement data as app_root in memory
        store_measurement_data(result.volumes_hash, mode, result.app_identifier);
        
        std::cout << "✅ App root measurement stored in secure memory" << std::endl;
    }

    // Start docker compose services
    std::cout << "\nStarting Docker Compose services..." << std::endl;
    if (!start_docker_compose_from_file(temp_file)) {
        result.status = ErrorCode::TDX_EXTEND;
        result.message = "Failed to start Docker Compose services";
        std::filesystem::remove(temp_file);
        return result;
    } else {
        result.message = "Successfully started application and prepared attestation";
    }

    // Cleanup temp file
    std::filesystem::remove(temp_file);

    result.status = ErrorCode::SUCCESS;
    std::cout << "\n✅ Application startup completed successfully!" << std::endl;
    return result;
}

QuoteResult BoostLib::generate_quote(const std::vector<uint8_t>& additional_report_data) {
    QuoteResult result;

    // Check if we have valid measurement data
    // if (!has_valid_measurement()) {
    //     result.status = ErrorCode::INVALID_PARAM;
    //     result.message = "No valid measurement data available. Please start an application first.";
    //     return result;
    // }

    // Validate additional report data size (max 32 bytes to leave room for app_root)
    if (additional_report_data.size() > 32) {
        result.status = ErrorCode::INVALID_PARAM;
        result.message = "Additional report data size (" + std::to_string(additional_report_data.size()) + 
                        ") exceeds maximum (32 bytes)";
        return result;
    }

    std::cout << "\n=== Generating TDX Quote ===" << std::endl;
    
    AttestationMode mode;
    std::string app_id;
    {
        std::lock_guard<std::mutex> lock(measurement_mutex_);
        mode = current_mode_;
        app_id = app_identifier_;
    }
    
    std::cout << "Attestation Mode: " << (mode == AttestationMode::RTMR ? "RTMR" : "REPORT_DATA") << std::endl;
    std::cout << "App Identifier: " << app_id << std::endl;

    if (mode == AttestationMode::RTMR) {
        // In RTMR mode, measurement is already in RTMR, use additional data as report data
        std::cout << "Using RTMR measurement + additional data as report data" << std::endl;
        
        tdx_report_data_t tdx_report_data = {{0}};
        
        if (!additional_report_data.empty()) {
            std::memcpy(tdx_report_data.d, additional_report_data.data(), 
                       std::min(additional_report_data.size(), static_cast<size_t>(TDX_REPORT_DATA_SIZE)));
            print_hex("Additional report data", additional_report_data);
        } else {
            // Generate random nonce if no additional data provided
            std::srand(std::time(nullptr));
            for (int i = 0; i < TDX_REPORT_DATA_SIZE; i++) {
                tdx_report_data.d[i] = std::rand() & 0xFF;
            }
            std::cout << "Generated random nonce for report data" << std::endl;
        }

        // Generate quote (RTMR values will be included automatically by TDX module)
        uint8_t *p_quote_buf = nullptr;
        uint32_t quote_size = 0;
        
        if (tdx_att_get_quote(&tdx_report_data, nullptr, 0, nullptr,
                              &p_quote_buf, &quote_size, 0) != TDX_ATTEST_SUCCESS) {
            result.status = ErrorCode::TDX_EXTEND;
            result.message = "Failed to get TDX quote";
            return result;
        }

        result.quote_data.assign(p_quote_buf, p_quote_buf + quote_size);
        tdx_att_free_quote(p_quote_buf);
        
    } else {
        // In Report Data mode, combine app_root with additional data
        std::cout << "Combining app root measurement with additional data" << std::endl;
        
        auto combined_report_data = prepare_report_data(additional_report_data);
        print_hex("Combined report data (app_root + additional)", combined_report_data);

        tdx_report_data_t tdx_report_data = {{0}};
        std::memcpy(tdx_report_data.d, combined_report_data.data(), 
                   std::min(combined_report_data.size(), static_cast<size_t>(TDX_REPORT_DATA_SIZE)));

        // Generate quote with combined report data
        uint8_t *p_quote_buf = nullptr;
        uint32_t quote_size = 0;
        
        if (tdx_att_get_quote(&tdx_report_data, nullptr, 0, nullptr,
                              &p_quote_buf, &quote_size, 0) != TDX_ATTEST_SUCCESS) {
            result.status = ErrorCode::TDX_EXTEND;
            result.message = "Failed to get TDX quote";
            return result;
        }

        result.quote_data.assign(p_quote_buf, p_quote_buf + quote_size);
        tdx_att_free_quote(p_quote_buf);
    }

    std::cout << "✅ TDX quote generated successfully (" << result.quote_data.size() << " bytes)" << std::endl;
    
    result.status = ErrorCode::SUCCESS;
    result.message = "TDX quote generated successfully";
    return result;
}

bool BoostLib::has_valid_measurement() const {
    std::lock_guard<std::mutex> lock(measurement_mutex_);
    return current_mode_ == AttestationMode::REPORT_DATA && measurement_ready_ && !app_root_measurement_.empty();
}

std::chrono::system_clock::time_point BoostLib::get_measurement_timestamp() const {
    std::lock_guard<std::mutex> lock(measurement_mutex_);
    return measurement_timestamp_;
}

void BoostLib::clear_measurement() {
    std::lock_guard<std::mutex> lock(measurement_mutex_);
    
    // Securely clear measurement data
    if (!app_root_measurement_.empty()) {
        std::fill(app_root_measurement_.begin(), app_root_measurement_.end(), 0);
        app_root_measurement_.clear();
    }
    
    measurement_ready_ = false;
    app_identifier_.clear();
    current_mode_ = AttestationMode::REPORT_DATA;
    used_rtmr_index_ = -1;
    
    std::cout << "🧹 Measurement data cleared from secure memory" << std::endl;
}

AttestationMode BoostLib::get_attestation_mode() const {
    std::lock_guard<std::mutex> lock(measurement_mutex_);
    return current_mode_;
}

std::string BoostLib::get_app_identifier() const {
    std::lock_guard<std::mutex> lock(measurement_mutex_);
    return app_identifier_;
}

void BoostLib::store_measurement_data(const std::vector<uint8_t>& measurement_data,
                                     AttestationMode mode,
                                     const std::string& app_id,
                                     int rtmr_index) {
    std::lock_guard<std::mutex> lock(measurement_mutex_);
    
    // Clear previous data
    if (!app_root_measurement_.empty()) {
        std::fill(app_root_measurement_.begin(), app_root_measurement_.end(), 0);
    }
    
    // Store new measurement data (first 32 bytes for app_root)
    app_root_measurement_.resize(32, 0);
    size_t copy_len = std::min(measurement_data.size(), static_cast<size_t>(32));
    std::memcpy(app_root_measurement_.data(), measurement_data.data(), copy_len);
    
    measurement_ready_ = true;
    current_mode_ = mode;
    app_identifier_ = app_id;
    used_rtmr_index_ = rtmr_index;
    measurement_timestamp_ = std::chrono::system_clock::now();
    
    std::cout << "💾 Stored measurement data securely in memory:" << std::endl;
    std::cout << "   Mode: " << (mode == AttestationMode::RTMR ? "RTMR" : "REPORT_DATA") << std::endl;
    std::cout << "   App ID: " << app_id << std::endl;
    if (rtmr_index >= 0) {
        std::cout << "   RTMR Index: " << rtmr_index << std::endl;
    }
}

std::vector<uint8_t> BoostLib::prepare_report_data(const std::vector<uint8_t>& additional_data) {
    std::vector<uint8_t> report_data(TDX_REPORT_DATA_SIZE, 0);
    
    std::lock_guard<std::mutex> lock(measurement_mutex_);
    
    if (!measurement_ready_ || app_root_measurement_.empty()) {
        return report_data;  // Return zeros if no measurement available
    }
    
    // First 32 bytes: app_root measurement
    size_t app_root_len = std::min(app_root_measurement_.size(), static_cast<size_t>(32));
    std::memcpy(report_data.data(), app_root_measurement_.data(), app_root_len);
    
    // Next 32 bytes: additional data from caller
    if (!additional_data.empty()) {
        size_t additional_len = std::min(additional_data.size(), static_cast<size_t>(32));
        std::memcpy(report_data.data() + 32, additional_data.data(), additional_len);
    }
    
    return report_data;
}

// Keep all the existing helper methods unchanged...
std::vector<uint8_t> BoostLib::calculate_compose_volumes_hash(const std::string& compose_content) {
    std::vector<std::string> volume_paths = extract_volume_paths(compose_content);
    std::vector<uint8_t> hash(HASH_LEN, 0);
    
    if (volume_paths.empty()) {
        std::cout << "No host volumes found in compose content, using empty hash" << std::endl;
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Final(hash.data(), &sha256);
        return hash;
    }
    
    std::cout << "Found " << volume_paths.size() << " volume path(s) to measure:" << std::endl;
    
    // Initialize SHA-256 context for combined hash
    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);
    
    // Calculate hash for each volume path and combine them
    for (size_t i = 0; i < volume_paths.size(); i++) {
        std::cout << "  [" << (i + 1) << "] Processing volume: " << volume_paths[i] << std::endl;
        
        struct stat path_stat;
        if (stat(volume_paths[i].c_str(), &path_stat) != 0) {
            std::cerr << "Warning: Cannot access volume path " << volume_paths[i] 
                      << ": " << std::strerror(errno) << std::endl;
            // Use path string as hash input for missing paths
            SHA256_Update(&sha256_ctx, 
                         reinterpret_cast<const unsigned char*>(volume_paths[i].c_str()), 
                         volume_paths[i].length());
            continue;
        }
        
        std::vector<uint8_t> volume_hash;
        if (S_ISDIR(path_stat.st_mode)) {
            volume_hash = calculate_directory_hash(volume_paths[i]);
            if (!volume_hash.empty()) {
                SHA256_Update(&sha256_ctx, volume_hash.data(), volume_hash.size());
                std::cout << "    ✅ Directory hash calculated" << std::endl;
            } else {
                std::cerr << "Warning: Failed to hash directory " << volume_paths[i] << std::endl;
                SHA256_Update(&sha256_ctx, 
                             reinterpret_cast<const unsigned char*>(volume_paths[i].c_str()), 
                             volume_paths[i].length());
            }
        } else if (S_ISREG(path_stat.st_mode)) {
            volume_hash = calculate_file_hash(volume_paths[i]);
            if (!volume_hash.empty()) {
                SHA256_Update(&sha256_ctx, volume_hash.data(), volume_hash.size());
                std::cout << "    ✅ File hash calculated" << std::endl;
            } else {
                std::cerr << "Warning: Failed to hash file " << volume_paths[i] << std::endl;
                SHA256_Update(&sha256_ctx, 
                             reinterpret_cast<const unsigned char*>(volume_paths[i].c_str()), 
                             volume_paths[i].length());
            }
        } else {
            std::cerr << "Warning: " << volume_paths[i] << " is neither file nor directory" << std::endl;
            SHA256_Update(&sha256_ctx, 
                         reinterpret_cast<const unsigned char*>(volume_paths[i].c_str()), 
                         volume_paths[i].length());
        }
    }
    
    // Finalize combined hash
    SHA256_Final(hash.data(), &sha256_ctx);
    
    return hash;
}

std::vector<uint8_t> BoostLib::calculate_directory_hash(const std::string& dir_path) {
    std::vector<uint8_t> hash(HASH_LEN, 0);
    
    try {
        std::vector<std::filesystem::directory_entry> entries;
        
        // Collect all entries
        for (const auto& entry : std::filesystem::directory_iterator(dir_path)) {
            entries.push_back(entry);
        }
        
        if (entries.empty()) {
            SHA256_CTX sha256_ctx;
            SHA256_Init(&sha256_ctx);
            SHA256_Final(hash.data(), &sha256_ctx);
            return hash;
        }
        
        // Sort entries by name for consistent ordering
        std::sort(entries.begin(), entries.end(), 
                  [](const auto& a, const auto& b) {
                      return a.path().filename() < b.path().filename();
                  });
        
        SHA256_CTX sha256_ctx;
        SHA256_Init(&sha256_ctx);
        
        for (const auto& entry : entries) {
            std::string filename = entry.path().filename().string();
            SHA256_Update(&sha256_ctx, 
                         reinterpret_cast<const unsigned char*>(filename.c_str()), 
                         filename.length());
            
            if (entry.is_directory()) {
                auto subdir_hash = calculate_directory_hash(entry.path().string());
                if (!subdir_hash.empty()) {
                    SHA256_Update(&sha256_ctx, subdir_hash.data(), subdir_hash.size());
                    std::cout << "  Added directory: " << filename << std::endl;
                }
            } else if (entry.is_regular_file()) {
                auto file_hash = calculate_file_hash(entry.path().string());
                if (!file_hash.empty()) {
                    SHA256_Update(&sha256_ctx, file_hash.data(), file_hash.size());
                    std::cout << "  Added file: " << filename << std::endl;
                }
            }
        }
        
        SHA256_Final(hash.data(), &sha256_ctx);
        
    } catch (const std::filesystem::filesystem_error& ex) {
        std::cerr << "Failed to process directory " << dir_path << ": " << ex.what() << std::endl;
        return {};
    }
    
    return hash;
}

void BoostLib::print_hex(const std::string& label, const std::vector<uint8_t>& data) {
    std::cout << label << " (" << data.size() << " bytes):" << std::endl;
    for (size_t i = 0; i < data.size(); i++) {
        std::cout << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(data[i]);
    }
    std::cout << std::dec << std::endl;
}

std::vector<uint8_t> BoostLib::calculate_file_hash(const std::string& file_path) {
    std::vector<uint8_t> hash(HASH_LEN, 0);
    
    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Failed to open file " << file_path << ": " << std::strerror(errno) << std::endl;
        return {};
    }
    
    // Get file size
    file.seekg(0, std::ios::end);
    std::streamsize file_size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    if (file_size <= 0) {
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Final(hash.data(), &sha256);
        return hash;
    }
    
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    
    // Read and hash file in chunks
    constexpr size_t BUFFER_SIZE = 8192;
    std::vector<char> buffer(BUFFER_SIZE);
    
    while (file.read(buffer.data(), BUFFER_SIZE) || file.gcount() > 0) {
        SHA256_Update(&sha256, 
                     reinterpret_cast<const unsigned char*>(buffer.data()), 
                     file.gcount());
    }
    
    SHA256_Final(hash.data(), &sha256);
    
    return hash;
}

std::vector<std::string> BoostLib::extract_volume_paths(const std::string& compose_content) {
    std::vector<std::string> volume_paths;
    std::istringstream stream(compose_content);
    std::string line;
    bool in_volumes_section = false;
    
    while (std::getline(stream, line)) {
        // Trim whitespace
        line.erase(0, line.find_first_not_of(" \t"));
        line.erase(line.find_last_not_of(" \t") + 1);
        
        // Check if we're entering volumes section
        if (line.find("volumes:") != std::string::npos) {
            in_volumes_section = true;
            continue;
        }
        
        // Check if we're leaving volumes section (new top-level section)
        if (in_volumes_section && !line.empty() && line[0] != '-' && 
            line[0] != ' ' && line[0] != '\t' && line.find(':') != std::string::npos) {
            in_volumes_section = false;
        }
        
        // Extract volume paths when in volumes section
        if (in_volumes_section && line.find('-') == 0) {
            // Look for patterns like "- /host/path:/container/path" or "- ./local/path:/container/path"
            size_t dash_pos = line.find('-');
            if (dash_pos != std::string::npos) {
                std::string volume_def = line.substr(dash_pos + 1);
                
                // Trim whitespace
                volume_def.erase(0, volume_def.find_first_not_of(" \t"));
                
                // Find the colon separator
                size_t colon_pos = volume_def.find(':');
                if (colon_pos != std::string::npos) {
                    // Extract host path (before colon)
                    std::string host_path = volume_def.substr(0, colon_pos);
                    
                    // Skip named volumes (don't start with / or .)
                    if (!host_path.empty() && (host_path[0] == '/' || host_path[0] == '.')) {
                        std::cout << "Found volume path: " << host_path << std::endl;
                        volume_paths.push_back(host_path);
                    }
                }
            }
        }
    }
    
    return volume_paths;
}

bool BoostLib::start_docker_compose_from_file(const std::string& compose_file) {
    // Skip actual docker startup in test mode
    if (std::getenv("BOOST_TEST_MODE")) {
        std::cout << "✅ Docker Compose services started successfully (test mode)" << std::endl;
        return true;
    }

    // Helper function to check if command exists
    auto command_exists = [](const std::string& cmd) -> bool {
        std::string check_cmd = "command -v " + cmd + " >/dev/null 2>&1";
        return std::system(check_cmd.c_str()) == 0;
    };
    
    // Try modern docker compose first, then fallback to legacy docker-compose
    std::vector<std::pair<std::string, std::string>> commands = {
        {"docker compose", "docker compose -f " + compose_file + " up -d"},
        {"docker-compose", "docker-compose -f " + compose_file + " up -d"}
    };
    
    for (const auto& [cmd_name, full_command] : commands) {
        if (!command_exists(cmd_name.substr(0, cmd_name.find(' ')))) {
            std::cout << "ℹ️  " << cmd_name << " not found, skipping..." << std::endl;
            continue;
        }
        
        std::cout << "🚀 Executing: " << full_command << std::endl;
        
        int ret = std::system(full_command.c_str());
        if (ret == 0) {
            std::cout << "✅ Docker Compose services started successfully using " << cmd_name << std::endl;
            return true;
        } else {
            std::cerr << "⚠️  " << cmd_name << " failed (exit code: " << ret << ")" << std::endl;
        }
    }
    
    std::cerr << "❌ Failed to start Docker Compose services with any available command" << std::endl;
    std::cerr << "💡 Install Docker Compose:" << std::endl;
    std::cerr << "   - Modern: Docker Desktop or 'docker compose' plugin" << std::endl;
    std::cerr << "   - Legacy: 'sudo dnf install docker-compose' or download from GitHub" << std::endl;
    return false;
}

} // namespace boost_lib