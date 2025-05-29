/**
 * @file cli.cpp
 * @brief Unified TDX TAPP CLI Tool (Boost + Key Tool) - C++ Version
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <memory>
#include <cstring>
#include <iomanip> 

#include "boost.hpp"
#include "key_tool.hpp"

namespace {
    // Helper function to read compose file content
    std::string read_compose_file(const std::string& file_path) {
        std::ifstream file(file_path);
        if (!file.is_open()) {
            std::cerr << "Failed to open file " << file_path << ": " << std::strerror(errno) << std::endl;
            return "";
        }
        
        std::ostringstream content;
        content << file.rdbuf();
        return content.str();
    }
    
    // Format an Ethereum address with 0x prefix
    void print_eth_address(const std::vector<uint8_t>& address) {
        std::cout << "Ethereum Address (0x format): 0x";
        for (const auto& byte : address) {
            std::cout << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(byte);
        }
        std::cout << std::dec << std::endl;
    }
    
    // Print usage information
    void print_usage(const std::string& prog_name) {
        std::cout << "TDX TAPP CLI Tool - Unified Boost & Key Management (C++)" << std::endl;
        std::cout << "Usage: " << prog_name << " <category> <command> [options]" << std::endl << std::endl;
        
        std::cout << "BOOST COMMANDS:" << std::endl;
        std::cout << "  boost start_app <compose.yml> <rtmr> Start application from Docker Compose file" << std::endl;
        std::cout << "  boost measure <compose.yml> <rtmr>   Measure docker compose volumes only" << std::endl;
        std::cout << "  boost quote [output_file]            Generate TDX quote" << std::endl;
        std::cout << std::endl;
        
        std::cout << "KEY COMMANDS:" << std::endl;
        std::cout << "  key pubkey                           Display public key derived from TDX report" << std::endl;
        std::cout << "  key address                          Display Ethereum address derived from TDX report" << std::endl;
        std::cout << "  key all                              Display both public key and address" << std::endl;
        std::cout << std::endl;
        
        std::cout << "EXAMPLES:" << std::endl;
        std::cout << "  " << prog_name << " boost start_app docker-compose.yml 3" << std::endl;
        std::cout << "  " << prog_name << " boost measure docker-compose.yml 3" << std::endl;
        std::cout << "  " << prog_name << " boost quote my_quote.dat" << std::endl;
        std::cout << "  " << prog_name << " key all" << std::endl;
        std::cout << std::endl;
        
        std::cout << "For server functionality, use: tapp_server" << std::endl;
        std::cout << std::endl;
        
        std::cout << "Note: Private keys are never stored and only exist transiently" << std::endl;
        std::cout << "      in memory within the TDX environment." << std::endl;
    }
    
    // Handle boost commands
    int handle_boost_commands(const std::vector<std::string>& args) {
        if (args.size() < 3) {
            std::cerr << "Boost command requires subcommand" << std::endl;
            return 1;
        }
        
        const std::string& command = args[2];
        
        try {
            boost_lib::BoostLib boost_lib;
            
            if (command == "start_app") {
                if (args.size() < 5) {
                    std::cerr << "Error: 'boost start_app' requires <compose.yml> and <rtmr> arguments" << std::endl;
                    return 1;
                }

                const std::string& compose_path = args[3];
                int rtmr_index = std::stoi(args[4]);

                if (rtmr_index < 0 || rtmr_index > 3) {
                    std::cerr << "Error: RTMR index must be 0-3" << std::endl;
                    return 1;
                }

                // Read compose file content
                std::string compose_content = read_compose_file(compose_path);
                if (compose_content.empty()) {
                    std::cerr << "Failed to read compose file" << std::endl;
                    return 1;
                }

                std::cout << "🚀 Starting application from: " << compose_path << std::endl;
                std::cout << "📊 Using RTMR index: " << rtmr_index << std::endl;

                auto result = boost_lib.start_app(compose_content, rtmr_index);
                if (result.status != boost_lib::ErrorCode::SUCCESS) {
                    std::cerr << "❌ Failed to start application: " << result.message << std::endl;
                    return 1;
                }

                std::cout << "✅ Successfully measured and started application" << std::endl;
                boost_lib::BoostLib::print_hex("Volume Measurement Hash", result.volumes_hash);
                std::cout << "📦 Docker Compose services are now running" << std::endl;
            }
            else if (command == "measure") {
                if (args.size() < 5) {
                    std::cerr << "Error: 'boost measure' requires <compose.yml> and <rtmr> arguments" << std::endl;
                    return 1;
                }

                const std::string& compose_path = args[3];
                int rtmr_index = std::stoi(args[4]);

                if (rtmr_index < 0 || rtmr_index > 3) {
                    std::cerr << "Error: RTMR index must be 0-3" << std::endl;
                    return 1;
                }

                // Read compose file content
                std::string compose_content = read_compose_file(compose_path);
                if (compose_content.empty()) {
                    std::cerr << "Failed to read compose file" << std::endl;
                    return 1;
                }

                std::cout << "📏 Measuring volumes from: " << compose_path << std::endl;
                std::cout << "📊 Using RTMR index: " << rtmr_index << std::endl;

                // Only calculate hash without starting services
                auto hash = boost_lib.calculate_compose_volumes_hash(compose_content);
                if (hash.empty()) {
                    std::cerr << "❌ Failed to calculate volume hash" << std::endl;
                    return 1;
                }

                std::cout << "✅ Successfully measured Docker Compose volumes" << std::endl;
                boost_lib::BoostLib::print_hex("Volume Measurement Hash", hash);
            }
            else if (command == "quote") {
                std::string output_file = "quote.dat";
                if (args.size() > 3) {
                    output_file = args[3];
                }

                std::cout << "🔐 Generating TDX quote..." << std::endl;

                auto result = boost_lib.generate_quote();
                if (result.status != boost_lib::ErrorCode::SUCCESS) {
                    std::cerr << "Failed to generate quote: " << result.message << std::endl;
                    return 1;
                }

                // Save quote to file
                std::ofstream file(output_file, std::ios::binary);
                if (!file.is_open()) {
                    std::cerr << "Error: Failed to open file for writing: " << output_file << std::endl;
                    return 1;
                }

                file.write(reinterpret_cast<const char*>(result.quote_data.data()), result.quote_data.size());
                if (!file.good()) {
                    std::cerr << "Error: Failed to write quote to file" << std::endl;
                    return 1;
                }

                std::cout << "✅ TDX quote successfully saved to " << output_file 
                         << " (" << result.quote_data.size() << " bytes)" << std::endl;
            }
            else {
                std::cerr << "Unknown boost command: " << command << std::endl;
                print_usage(args[0]);
                return 1;
            }
        } catch (const std::exception& e) {
            std::cerr << "Boost library error: " << e.what() << std::endl;
            return 1;
        }
        
        return 0;
    }
    
    // Handle key commands
    int handle_key_commands(const std::vector<std::string>& args) {
        if (args.size() < 3) {
            std::cerr << "Key command requires subcommand" << std::endl;
            return 1;
        }
        
        const std::string& command = args[2];
        
        try {
            key_tool::KeyToolLib key_tool;
            
            if (command == "pubkey") {
                std::cout << "🔑 Deriving public key from TDX report..." << std::endl;
                
                auto public_key = key_tool.get_public_key_only();
                if (public_key.empty()) {
                    std::cerr << "Failed to get public key from TDX report" << std::endl;
                    return 1;
                }
                
                key_tool::KeyToolLib::print_hex("Public Key (uncompressed, without 0x04 prefix)", public_key);
                std::cout << std::endl << "✅ Public key successfully derived from TDX environment" << std::endl;
                
            } else if (command == "address") {
                std::cout << "🏠 Deriving Ethereum address from TDX report..." << std::endl;
                
                auto address = key_tool.get_address_only();
                if (address.empty()) {
                    std::cerr << "Failed to get Ethereum address from TDX report" << std::endl;
                    return 1;
                }

                std::string address_hex = key_tool::KeyToolLib::format_address_hex(address);
                if (address_hex.empty()) {
                    std::cerr << "Failed to format address as hex" << std::endl;
                    return 1;
                }
                
                // Print address in different formats
                key_tool::KeyToolLib::print_hex("Ethereum Address (raw bytes)", address);
                print_eth_address(address);
                
                std::cout << std::endl << "✅ Ethereum address successfully derived from TDX environment" << std::endl;
                
            } else if (command == "all") {
                std::cout << "🔐 Deriving public key and Ethereum address from TDX report..." << std::endl;
                
                auto result = key_tool.get_pubkey_from_report();
                if (result.status != key_tool::ErrorCode::SUCCESS) {
                    std::cerr << "Failed to get keys from TDX report: " << result.message << std::endl;
                    return 1;
                }
                
                // Print public key
                key_tool::KeyToolLib::print_hex("Public Key (uncompressed, without 0x04 prefix)", 
                                               result.public_key);
                
                // Print address in different formats
                key_tool::KeyToolLib::print_hex("Ethereum Address (raw bytes)", 
                                               result.eth_address);
                std::cout << "Ethereum Address (hex): " << result.eth_address_hex << std::endl;
                
                std::cout << std::endl << "✅ Keys successfully derived from TDX environment" << std::endl;
                
            } else {
                std::cerr << "Unknown key command: " << command << std::endl;
                print_usage(args[0]);
                return 1;
            }
        } catch (const std::exception& e) {
            std::cerr << "Key tool library error: " << e.what() << std::endl;
            return 1;
        }
        
        return 0;
    }
}

// Main function
int main(int argc, char *argv[]) {
    // Convert args to vector for easier handling
    std::vector<std::string> args;
    for (int i = 0; i < argc; i++) {
        args.emplace_back(argv[i]);
    }
    
    if (args.size() < 3) {
        print_usage(args[0]);
        return 1;
    }

    const std::string& category = args[1];

    if (category == "boost") {
        return handle_boost_commands(args);
    }
    else if (category == "key") {
        return handle_key_commands(args);
    }
    else {
        std::cerr << "Unknown category: " << category << std::endl;
        print_usage(args[0]);
        return 1;
    }
}