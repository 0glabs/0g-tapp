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

class TappServiceImpl final : public TappService::Service {
private:
    std::unique_ptr<boost_lib::BoostLib> boost_lib_;
    std::unique_ptr<key_tool::KeyToolLib> key_tool_lib_;

public:
    TappServiceImpl() {
        try {
            boost_lib_ = std::make_unique<boost_lib::BoostLib>();
            key_tool_lib_ = std::make_unique<key_tool::KeyToolLib>();
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
        
        try {
            auto result = boost_lib_->start_app(request->compose_content(), rtmr_index);
            
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