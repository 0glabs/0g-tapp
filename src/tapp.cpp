/**
 * @file tapp_grpc_server.cpp
 * @brief gRPC Server Implementation for TAPP Services (Modern C++)
 */

#include <iostream>
#include <memory>
#include <string>
#include <thread>

#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>
#include <grpcpp/ext/proto_server_reflection_plugin.h>

#include "tapp_service.grpc.pb.h"
#include "boost.hpp"
#include "key_tool.hpp"
#include "system_monitor.hpp"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;

using tapp_service::TappService;
using tapp_service::StartAppRequest;
using tapp_service::StartAppResponse;
using tapp_service::GetQuoteRequest;
using tapp_service::GetQuoteResponse;
using tapp_service::GetPubkeyRequest;
using tapp_service::GetPubkeyResponse;
using tapp_service::GetServiceStatusRequest;
using tapp_service::GetServiceStatusResponse;
using tapp_service::GetServiceLogsRequest;
using tapp_service::GetServiceLogsResponse;
using tapp_service::StreamServiceLogsRequest;
using tapp_service::StreamServiceLogsResponse;
using tapp_service::AttestationMode;
using tapp_service::LogLevel;
using tapp_service::ServiceHealthStatus;
class TappServiceImpl final : public TappService::Service {
private:
    std::unique_ptr<boost_lib::BoostLib> boost_lib_;
    std::unique_ptr<key_tool::KeyToolLib> key_tool_lib_;
    std::unique_ptr<system_monitor::SystemMonitor> system_monitor_;

public:
    TappServiceImpl() {
        try {
            boost_lib_ = std::make_unique<boost_lib::BoostLib>();
            key_tool_lib_ = std::make_unique<key_tool::KeyToolLib>();
            system_monitor_ = std::make_unique<system_monitor::SystemMonitor>();
            std::cout << "✅ TAPP gRPC Service initialized successfully" << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "❌ Failed to initialize TAPP service: " << e.what() << std::endl;
            throw;
        }
    }

    Status StartApp(ServerContext* context, const StartAppRequest* request,
                   StartAppResponse* response) override {
        (void)context; // Suppress unused parameter warning
        
        std::cout << "📦 StartApp request received" << std::endl;
        
        if (request->compose_content().empty()) {
            response->set_success(false);
            response->set_message("Empty compose content provided");
            std::cerr << "❌ StartApp failed: Empty compose content" << std::endl;
            return Status::OK;
        }
        
        // Default RTMR index to 3 if not specified or invalid
        int rtmr_index = request->rtmr_index();
        if (rtmr_index < 0 || rtmr_index > 3) {
            rtmr_index = 3;
            std::cout << "ℹ️  Using default RTMR index: " << rtmr_index << std::endl;
        }
        
        boost_lib::AttestationMode mode = boost_lib::AttestationMode::REPORT_DATA;
        if (request->mode() == AttestationMode::RTMR) {
            mode = boost_lib::AttestationMode::RTMR;
        }
        
        try {
            auto result = boost_lib_->start_app(request->compose_content(), mode, rtmr_index);
            
            if (result.status == boost_lib::ErrorCode::SUCCESS) {
                response->set_success(true);
                response->set_message(result.message);
                response->set_volumes_hash(result.volumes_hash.data(), result.volumes_hash.size());
                
                std::cout << "✅ StartApp completed successfully" << std::endl;
                std::cout << "📊 Volumes hash size: " << result.volumes_hash.size() << " bytes" << std::endl;
            } else {
                response->set_success(false);
                response->set_message(result.message);
                std::cerr << "❌ StartApp failed: " << result.message << std::endl;
            }
        } catch (const std::exception& e) {
            response->set_success(false);
            response->set_message("Internal error: " + std::string(e.what()));
            std::cerr << "❌ StartApp exception: " << e.what() << std::endl;
        }
        
        return Status::OK;
    }

    Status GetQuote(ServerContext* context, const GetQuoteRequest* request,
                   GetQuoteResponse* response) override {
        (void)context; // Suppress unused parameter warning
        
        std::cout << "🔐 GetQuote request received" << std::endl;
        
        try {
            std::vector<uint8_t> report_data;
            
            // Use custom report data if provided
            if (!request->report_data().empty()) {
                const std::string& data = request->report_data();
                report_data.assign(data.begin(), data.end());
                std::cout << "ℹ️  Using custom report data (" << report_data.size() << " bytes)" << std::endl;
            }
            
            auto result = boost_lib_->generate_quote(report_data);
            
            if (result.status == boost_lib::ErrorCode::SUCCESS) {
                response->set_success(true);
                response->set_message(result.message);
                response->set_quote_data(result.quote_data.data(), result.quote_data.size());
                response->set_quote_size(static_cast<uint32_t>(result.quote_data.size()));
                
                std::cout << "✅ GetQuote completed successfully" << std::endl;
                std::cout << "📊 Quote size: " << result.quote_data.size() << " bytes" << std::endl;
            } else {
                response->set_success(false);
                response->set_message(result.message);
                response->set_quote_size(0);
                std::cerr << "❌ GetQuote failed: " << result.message << std::endl;
            }
        } catch (const std::exception& e) {
            response->set_success(false);
            response->set_message("Internal error: " + std::string(e.what()));
            response->set_quote_size(0);
            std::cerr << "❌ GetQuote exception: " << e.what() << std::endl;
        }
        
        return Status::OK;
    }

    Status GetPubkey(ServerContext* context, const GetPubkeyRequest* request,
                    GetPubkeyResponse* response) override {
        (void)context; // Suppress unused parameter warning
        (void)request; // No parameters needed for this service
        
        std::cout << "🔑 GetPubkey request received" << std::endl;
        
        try {
            auto result = key_tool_lib_->get_pubkey_from_report();
            
            if (result.status == key_tool::ErrorCode::SUCCESS) {
                response->set_success(true);
                response->set_message(result.message);
                response->set_public_key(result.public_key.data(), result.public_key.size());
                response->set_eth_address(result.eth_address.data(), result.eth_address.size());
                response->set_eth_address_hex(result.eth_address_hex);
                
                std::cout << "✅ GetPubkey completed successfully" << std::endl;
                std::cout << "📍 Ethereum Address: " << result.eth_address_hex << std::endl;
            } else {
                response->set_success(false);
                response->set_message(result.message);
                std::cerr << "❌ GetPubkey failed: " << result.message << std::endl;
            }
        } catch (const std::exception& e) {
            response->set_success(false);
            response->set_message("Internal error: " + std::string(e.what()));
            std::cerr << "❌ GetPubkey exception: " << e.what() << std::endl;
        }
        
        return Status::OK;
    }

    Status GetServiceStatus(ServerContext* context, const GetServiceStatusRequest* request,
                           GetServiceStatusResponse* response) override {
        (void)context; // Suppress unused parameter warning
        
        std::cout << "🔍 GetServiceStatus request received" << std::endl;
        
        try {
            auto result = system_monitor_->get_service_status(request->service_name());
            
            if (result.status == system_monitor::ErrorCode::SUCCESS) {
                response->set_success(true);
                response->set_message(result.message);
                response->set_timestamp(std::chrono::duration_cast<std::chrono::seconds>(
                    result.timestamp.time_since_epoch()).count());
                
                // Convert system_monitor ServiceInfo to protobuf ServiceInfo
                for (const auto& service : result.services) {
                    auto* service_info = response->add_services();
                    service_info->set_name(service.name);
                    
                    // Convert health status
                    switch (service.status) {
                        case system_monitor::ServiceHealthStatus::HEALTHY:
                            service_info->set_status(ServiceHealthStatus::HEALTHY);
                            break;
                        case system_monitor::ServiceHealthStatus::UNHEALTHY:
                            service_info->set_status(ServiceHealthStatus::UNHEALTHY);
                            break;
                        default:
                            service_info->set_status(ServiceHealthStatus::UNKNOWN);
                            break;
                    }
                    
                    service_info->set_status_message(service.status_message);
                    service_info->set_uptime_seconds(service.uptime.count());
                    service_info->set_memory_usage_mb(service.memory_usage_mb);
                    service_info->set_cpu_usage_percent(service.cpu_usage_percent);
                    service_info->set_pid(service.pid);
                    service_info->set_version(service.version);
                }
                
                std::cout << "✅ GetServiceStatus completed successfully for " 
                         << result.services.size() << " service(s)" << std::endl;
            } else {
                response->set_success(false);
                response->set_message(result.message);
                std::cerr << "❌ GetServiceStatus failed: " << result.message << std::endl;
            }
        } catch (const std::exception& e) {
            response->set_success(false);
            response->set_message("Internal error: " + std::string(e.what()));
            std::cerr << "❌ GetServiceStatus exception: " << e.what() << std::endl;
        }
        
        return Status::OK;
    }

    Status GetServiceLogs(ServerContext* context, const GetServiceLogsRequest* request,
                         GetServiceLogsResponse* response) override {
        (void)context; // Suppress unused parameter warning
        
        std::cout << "📋 GetServiceLogs request received for service: " 
                 << (request->service_name().empty() ? "tapp-server" : request->service_name()) << std::endl;
        
        try {
            // Convert protobuf LogLevel to system_monitor LogLevel
            system_monitor::LogLevel min_level = system_monitor::LogLevel::DEBUG;
            switch (request->min_level()) {
                case LogLevel::ERROR:
                    min_level = system_monitor::LogLevel::ERROR;
                    break;
                case LogLevel::WARNING:
                    min_level = system_monitor::LogLevel::WARNING;
                    break;
                case LogLevel::INFO:
                    min_level = system_monitor::LogLevel::INFO;
                    break;
                case LogLevel::DEBUG:
                    min_level = system_monitor::LogLevel::DEBUG;
                    break;
            }
            
            auto result = system_monitor_->get_service_logs(
                request->service_name().empty() ? "tapp-server" : request->service_name(),
                request->lines() > 0 ? request->lines() : 100,
                request->since(),
                request->until(),
                min_level,
                request->grep_pattern(),
                request->json_format()
            );
            
            if (result.status == system_monitor::ErrorCode::SUCCESS) {
                response->set_success(true);
                response->set_message(result.message);
                response->set_total_lines(result.total_lines);
                response->set_truncated(result.truncated);
                
                // Convert system_monitor LogEntry to protobuf LogEntry
                for (const auto& log : result.logs) {
                    auto* log_entry = response->add_logs();
                    
                    log_entry->set_timestamp(log.timestamp);
                    
                    // Convert log level
                    switch (log.level) {
                        case system_monitor::LogLevel::ERROR:
                            log_entry->set_level(LogLevel::ERROR);
                            break;
                        case system_monitor::LogLevel::WARNING:
                            log_entry->set_level(LogLevel::WARNING);
                            break;
                        case system_monitor::LogLevel::INFO:
                            log_entry->set_level(LogLevel::INFO);
                            break;
                        case system_monitor::LogLevel::DEBUG:
                            log_entry->set_level(LogLevel::DEBUG);
                            break;
                    }
                    
                    log_entry->set_message(log.message);
                    log_entry->set_service_name(log.service_name);
                    
                    // Copy metadata
                    for (const auto& meta : log.metadata) {
                        (*log_entry->mutable_metadata())[meta.first] = meta.second;
                    }
                }
                
                std::cout << "✅ GetServiceLogs completed successfully, returned " 
                         << result.logs.size() << " log entries" << std::endl;
            } else {
                response->set_success(false);
                response->set_message(result.message);
                response->set_total_lines(0);
                response->set_truncated(false);
                std::cerr << "❌ GetServiceLogs failed: " << result.message << std::endl;
            }
        } catch (const std::exception& e) {
            response->set_success(false);
            response->set_message("Internal error: " + std::string(e.what()));
            std::cerr << "❌ GetServiceLogs exception: " << e.what() << std::endl;
        }
        
        return Status::OK;
    }

    Status StreamServiceLogs(ServerContext* context, const StreamServiceLogsRequest* request,
                            grpc::ServerWriter<StreamServiceLogsResponse>* writer) override {
        std::cout << "📡 StreamServiceLogs request received for service: " 
                 << (request->service_name().empty() ? "tapp-server" : request->service_name()) << std::endl;
        
        try {
            // Convert protobuf LogLevel to system_monitor LogLevel
            system_monitor::LogLevel min_level = system_monitor::LogLevel::DEBUG;
            switch (request->min_level()) {
                case LogLevel::ERROR:
                    min_level = system_monitor::LogLevel::ERROR;
                    break;
                case LogLevel::WARNING:
                    min_level = system_monitor::LogLevel::WARNING;
                    break;
                case LogLevel::INFO:
                    min_level = system_monitor::LogLevel::INFO;
                    break;
                case LogLevel::DEBUG:
                    min_level = system_monitor::LogLevel::DEBUG;
                    break;
            }
            
            std::atomic<bool> stream_active(true);
            
            // Set up callback for log stream
            auto callback = [&](const system_monitor::LogEntry& log, bool is_initial) {
                if (!stream_active || context->IsCancelled()) {
                    return;
                }
                
                StreamServiceLogsResponse response;
                auto* log_entry = response.mutable_log_entry();
                
                log_entry->set_timestamp(log.timestamp);
                
                // Convert log level
                switch (log.level) {
                    case system_monitor::LogLevel::ERROR:
                        log_entry->set_level(LogLevel::ERROR);
                        break;
                    case system_monitor::LogLevel::WARNING:
                        log_entry->set_level(LogLevel::WARNING);
                        break;
                    case system_monitor::LogLevel::INFO:
                        log_entry->set_level(LogLevel::INFO);
                        break;
                    case system_monitor::LogLevel::DEBUG:
                        log_entry->set_level(LogLevel::DEBUG);
                        break;
                }
                
                log_entry->set_message(log.message);
                log_entry->set_service_name(log.service_name);
                
                // Copy metadata
                for (const auto& meta : log.metadata) {
                    (*log_entry->mutable_metadata())[meta.first] = meta.second;
                }
                
                response.set_is_initial(is_initial);
                
                if (!writer->Write(response)) {
                    stream_active = false;
                }
            };
            
            // Start log streaming
            auto result = system_monitor_->start_log_stream(
                request->service_name().empty() ? "tapp-server" : request->service_name(),
                min_level,
                request->grep_pattern(),
                request->tail_lines() > 0 ? request->tail_lines() : 50,
                callback
            );
            
            if (result == system_monitor::ErrorCode::SUCCESS) {
                // Keep streaming until client disconnects or context is cancelled
                while (stream_active && !context->IsCancelled()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
                
                std::cout << "✅ StreamServiceLogs completed" << std::endl;
            } else {
                std::cerr << "❌ Failed to start log stream: " 
                         << system_monitor::error_code_to_string(result) << std::endl;
                return Status(grpc::StatusCode::INTERNAL, "Failed to start log stream");
            }
            
            // Stop the log stream
            system_monitor_->stop_log_stream();
            
        } catch (const std::exception& e) {
            std::cerr << "❌ StreamServiceLogs exception: " << e.what() << std::endl;
            return Status(grpc::StatusCode::INTERNAL, "Internal error: " + std::string(e.what()));
        }
        
        return Status::OK;
    }
};

void RunServer(const std::string& server_address) {
    std::cout << "🚀 Initializing TAPP gRPC Service..." << std::endl;
    
    TappServiceImpl service;

    grpc::EnableDefaultHealthCheckService(true);
    grpc::reflection::InitProtoReflectionServerBuilderPlugin();
    
    ServerBuilder builder;
    
    // Listen on the given address without any authentication mechanism.
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    
    // Register "service" as the instance through which we'll communicate with
    // clients. In this case it corresponds to a *synchronous* service.
    builder.RegisterService(&service);
    
    // Finally assemble the server.
    std::unique_ptr<Server> server(builder.BuildAndStart());
    
    std::cout << "✅ TAPP gRPC Server listening on " << server_address << std::endl;
    std::cout << "🌐 Available services:" << std::endl;
    std::cout << "  📦 StartApp  - Deploy applications with measurement" << std::endl;
    std::cout << "  🔐 GetQuote  - Generate TDX attestation quotes" << std::endl;
    std::cout << "  🔑 GetPubkey - Retrieve Ethereum keys and addresses" << std::endl;
    std::cout << std::endl;
    std::cout << "💡 Press Ctrl+C to stop the server..." << std::endl;

    // Wait for the server to shutdown. Note that some other thread must be
    // responsible for shutting down the server for this call to ever return.
    server->Wait();
}

void print_usage(const std::string& prog_name) {
    std::cout << "TAPP gRPC Server - Trusted Application" << std::endl;
    std::cout << "Usage: " << prog_name << " [server_address]" << std::endl;
    std::cout << std::endl;
    std::cout << "Arguments:" << std::endl;
    std::cout << "  server_address  Address to bind the gRPC server (default: 0.0.0.0:50051)" << std::endl;
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  " << prog_name << std::endl;
    std::cout << "  " << prog_name << " 0.0.0.0:8080" << std::endl;
    std::cout << "  " << prog_name << " localhost:50051" << std::endl;
    std::cout << std::endl;
    std::cout << "Services:" << std::endl;
    std::cout << "  tapp_service.TappService/StartApp" << std::endl;
    std::cout << "  tapp_service.TappService/GetQuote" << std::endl;
    std::cout << "  tapp_service.TappService/GetPubkey" << std::endl;
}

int main(int argc, char** argv) {
    std::string server_address = "0.0.0.0:50051";
    
    if (argc > 1) {
        if (std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h") {
            print_usage(argv[0]);
            return 0;
        }
        server_address = argv[1];
    }
    
    std::cout << "🔧 Starting TAPP gRPC Server..." << std::endl;
    std::cout << "📡 Server Address: " << server_address << std::endl;
    
    try {
        RunServer(server_address);
    } catch (const std::exception& e) {
        std::cerr << "💥 Server failed to start: " << e.what() << std::endl;
        return 1;
    }
    
    std::cout << "👋 Server shutdown complete" << std::endl;
    return 0;
}