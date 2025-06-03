/**
 * @file test_grpc_service.cpp
 * @brief gRPC Service Integration Tests
 */

#include <gtest/gtest.h>
#include <grpcpp/grpcpp.h>
#include <memory>
#include <thread>
#include <chrono>

#include "tapp_service.grpc.pb.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;

using tapp_service::TappService;
using tapp_service::StartAppRequest;
using tapp_service::StartAppResponse;
using tapp_service::GetQuoteRequest;
using tapp_service::GetQuoteResponse;
// using tapp_service::GetPubkeyRequest;
// using tapp_service::GetPubkeyResponse;

class GrpcServiceTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Default server address
        server_address_ = "localhost:50051";
        
        // Override with environment variable if set
        const char* env_addr = std::getenv("TAPP_SERVER_ADDRESS");
        if (env_addr) {
            server_address_ = env_addr;
        }
        
        // Create gRPC channel
        channel_ = grpc::CreateChannel(server_address_, grpc::InsecureChannelCredentials());
        stub_ = TappService::NewStub(channel_);
        
        // Sample Docker Compose content for testing
        sample_compose_ = R"(
version: '3.8'
services:
  test-app:
    image: hello-world
    volumes:
      - ./data:/app/data
    environment:
      - TEST_MODE=true
)";
        
        // Check if server is available
        server_available_ = check_server_availability();
    }
    
    void TearDown() override {
        // Cleanup if needed
    }
    
    bool check_server_availability() {
        ClientContext context;
        context.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(2));
        
        GetQuoteRequest request;
        GetQuoteResponse response;
        
        Status status = stub_->GetQuote(&context, request, &response);
        return status.ok() || status.error_code() != grpc::StatusCode::UNAVAILABLE;
    }
    
    std::string server_address_;
    std::shared_ptr<Channel> channel_;
    std::unique_ptr<TappService::Stub> stub_;
    std::string sample_compose_;
    bool server_available_;
};

TEST_F(GrpcServiceTest, ServerAvailability) {
    if (!server_available_) {
        GTEST_SKIP() << "TDX gRPC server not available at " << server_address_ 
                     << ". Start server with: ./tapp_server";
    }
    
    // If we reach here, server is available
    SUCCEED() << "✅ gRPC server is available at " << server_address_;
}

// TEST_F(GrpcServiceTest, GetPubkeyInterface) {
//     if (!server_available_) {
//         GTEST_SKIP() << "gRPC server not available";
//     }
    
//     ClientContext context;
//     GetPubkeyRequest request;
//     GetPubkeyResponse response;
    
//     std::cout << "🔑 Testing GetPubkey interface..." << std::endl;
    
//     Status status = stub_->GetPubkey(&context, request, &response);
    
//     ASSERT_TRUE(status.ok()) << "gRPC call failed: " << status.error_message();
//     EXPECT_TRUE(response.success()) << "GetPubkey failed: " << response.message();
    
//     if (response.success()) {
//         EXPECT_FALSE(response.public_key().empty()) << "Public key should not be empty";
//         EXPECT_FALSE(response.eth_address().empty()) << "Ethereum address should not be empty";
//         EXPECT_FALSE(response.eth_address_hex().empty()) << "Hex address should not be empty";
        
//         // Check address format
//         EXPECT_EQ(response.eth_address().size(), 20) << "Ethereum address should be 20 bytes";
//         EXPECT_EQ(response.public_key().size(), 64) << "Public key should be 64 bytes";
//         EXPECT_EQ(response.eth_address_hex().substr(0, 2), "0x") << "Hex address should start with 0x";
        
//         std::cout << "✅ GetPubkey test passed" << std::endl;
//         std::cout << "   Ethereum Address: " << response.eth_address_hex() << std::endl;
//         std::cout << "   Public Key Size: " << response.public_key().size() << " bytes" << std::endl;
//     }
// }

// TEST_F(GrpcServiceTest, StartAppWithInvalidData) {
//     if (!server_available_) {
//         GTEST_SKIP() << "gRPC server not available";
//     }
    
//     ClientContext context;
//     StartAppRequest request;
//     StartAppResponse response;
    
//     std::cout << "❌ Testing StartApp with invalid data..." << std::endl;
    
//     // Test with empty compose content
//     request.set_compose_content("");  // Invalid: empty content
//     request.set_rtmr_index(3);
    
//     Status status = stub_->StartApp(&context, request, &response);
    
//     ASSERT_TRUE(status.ok()) << "gRPC call should succeed even with invalid data";
//     EXPECT_FALSE(response.success()) << "StartApp should fail with empty compose content";
//     EXPECT_FALSE(response.message().empty()) << "Error message should be provided";
    
//     std::cout << "✅ Invalid data handling test passed" << std::endl;
//     std::cout << "   Error Message: " << response.message() << std::endl;
// }

// TEST_F(GrpcServiceTest, StartAppWithInvalidRTMR) {
//     if (!server_available_) {
//         GTEST_SKIP() << "gRPC server not available";
//     }
    
//     ClientContext context;
//     StartAppRequest request;
//     StartAppResponse response;
    
//     std::cout << "📊 Testing StartApp with invalid RTMR index..." << std::endl;
    
//     // Test with invalid RTMR index (should auto-correct to 3)
//     request.set_compose_content(sample_compose_);
//     request.set_rtmr_index(-1);  // Invalid RTMR index
    
//     Status status = stub_->StartApp(&context, request, &response);
    
//     ASSERT_TRUE(status.ok()) << "gRPC call should succeed";
    
//     // Server should handle invalid RTMR gracefully (default to 3)
//     std::cout << "✅ Invalid RTMR handling test completed" << std::endl;
//     std::cout << "   Result: " << (response.success() ? "Success" : "Failed") << std::endl;
//     std::cout << "   Message: " << response.message() << std::endl;
// }

TEST_F(GrpcServiceTest, StartAppInterface) {
    if (!server_available_) {
        GTEST_SKIP() << "gRPC server not available";
    }
    
    ClientContext context;
    StartAppRequest request;
    StartAppResponse response;
    
    std::cout << "🚀 Testing StartApp interface..." << std::endl;
    
    // Set request data
    request.set_compose_content(sample_compose_);
    request.set_rtmr_index(3);
    
    Status status = stub_->StartApp(&context, request, &response);
    
    ASSERT_TRUE(status.ok()) << "gRPC call failed: " << status.error_message();
    
    // Note: StartApp might fail due to Docker not being available in test environment
    // We focus on testing the gRPC interface itself
    if (response.success()) {
        EXPECT_FALSE(response.volumes_hash().empty()) << "Volumes hash should not be empty";
        EXPECT_EQ(response.volumes_hash().size(), 32) << "Hash should be 32 bytes (SHA-256)";
        
        std::cout << "✅ StartApp test passed" << std::endl;
        std::cout << "   Message: " << response.message() << std::endl;
        std::cout << "   Hash Size: " << response.volumes_hash().size() << " bytes" << std::endl;
    } else {
        // StartApp might fail due to Docker not available, but gRPC interface works
        std::cout << "⚠️  StartApp returned failure (expected in test environment): " << response.message() << std::endl;
        EXPECT_FALSE(response.message().empty()) << "Error message should not be empty";
    }
}

TEST_F(GrpcServiceTest, GetQuoteInterface) {
    if (!server_available_) {
        GTEST_SKIP() << "gRPC server not available";
    }
    
    ClientContext context;
    GetQuoteRequest request;
    GetQuoteResponse response;
    
    std::cout << "🔐 Testing GetQuote interface..." << std::endl;
    
    // Test without custom report data
    Status status = stub_->GetQuote(&context, request, &response);
    
    ASSERT_TRUE(status.ok()) << "gRPC call failed: " << status.error_message();
    EXPECT_TRUE(response.success()) << "GetQuote failed: " << response.message();
    
    if (response.success()) {
        EXPECT_FALSE(response.quote_data().empty()) << "Quote data should not be empty";
        EXPECT_GT(response.quote_size(), 0) << "Quote size should be greater than 0";
        EXPECT_EQ(response.quote_data().size(), response.quote_size()) 
            << "Quote data size should match quote_size field";
        
        std::cout << "✅ GetQuote test passed" << std::endl;
        std::cout << "   Quote Size: " << response.quote_size() << " bytes" << std::endl;
    }
}

// TEST_F(GrpcServiceTest, GetQuoteWithCustomData) {
//     if (!server_available_) {
//         GTEST_SKIP() << "gRPC server not available";
//     }
    
//     ClientContext context;
//     GetQuoteRequest request;
//     GetQuoteResponse response;
    
//     // Test with custom report data
//     std::string custom_data = "test_report_data_12345";
//     request.set_report_data(custom_data);
    
//     std::cout << "🔐 Testing GetQuote with custom report data..." << std::endl;
    
//     Status status = stub_->GetQuote(&context, request, &response);
    
//     ASSERT_TRUE(status.ok()) << "gRPC call failed: " << status.error_message();
//     EXPECT_TRUE(response.success()) << "GetQuote with custom data failed: " << response.message();
    
//     if (response.success()) {
//         EXPECT_FALSE(response.quote_data().empty()) << "Quote data should not be empty";
//         EXPECT_GT(response.quote_size(), 0) << "Quote size should be greater than 0";
        
//         std::cout << "✅ GetQuote with custom data test passed" << std::endl;
//     }
// }

// TEST_F(GrpcServiceTest, ConcurrentRequests) {
//     if (!server_available_) {
//         GTEST_SKIP() << "gRPC server not available";
//     }
    
//     std::cout << "🔄 Testing concurrent requests..." << std::endl;
    
//     const int num_threads = 3;
//     std::vector<std::thread> threads;
//     std::vector<bool> results(num_threads, false);
    
//     // Launch concurrent GetPubkey requests
//     for (int i = 0; i < num_threads; ++i) {
//         threads.emplace_back([this, &results, i]() {
//             ClientContext context;
//             GetPubkeyRequest request;
//             GetPubkeyResponse response;
            
//             Status status = stub_->GetPubkey(&context, request, &response);
//             results[i] = status.ok() && response.success();
//         });
//     }
    
//     // Wait for all threads to complete
//     for (auto& thread : threads) {
//         thread.join();
//     }
    
//     // Check results
//     int successful_requests = 0;
//     for (bool result : results) {
//         if (result) successful_requests++;
//     }
    
//     EXPECT_GT(successful_requests, 0) << "At least one concurrent request should succeed";
//     std::cout << "✅ Concurrent requests test passed: " << successful_requests 
//               << "/" << num_threads << " requests succeeded" << std::endl;
// }

// Test runner with server instructions
class GrpcTestEnvironment : public ::testing::Environment {
public:
    void SetUp() override {
        std::cout << "================================================" << std::endl;
        std::cout << "TDX TAPP gRPC Service Integration Tests" << std::endl;
        std::cout << "================================================" << std::endl;
        std::cout << "To run these tests, start the gRPC server first:" << std::endl;
        std::cout << "  ./tapp_server" << std::endl;
        std::cout << "Or specify custom address:" << std::endl;
        std::cout << "  export TAPP_SERVER_ADDRESS=localhost:8080" << std::endl;
        std::cout << "================================================" << std::endl;
    }
};

// Register test environment
::testing::Environment* const grpc_env = ::testing::AddGlobalTestEnvironment(new GrpcTestEnvironment);