/**
 * @file test_boost.cpp
 * @brief Simplified Unit tests for Boost Library
 */

#include <gtest/gtest.h>
#include <fstream>
#include <filesystem>
#include <vector>
#include <string>

#include "boost.hpp"

class BoostLibTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create temporary directory for tests
        temp_dir_ = std::filesystem::temp_directory_path() / "boost_test";
        std::filesystem::create_directories(temp_dir_);
        
        // Create sample Docker Compose content
        sample_compose_ = R"(
version: '3.8'
services:
  app:
    image: nginx:latest
    volumes:
      - ./web:/usr/share/nginx/html
      - ./config:/etc/nginx/conf.d
)";
        
        // Create sample directories and files
        web_dir_ = temp_dir_ / "web";
        config_dir_ = temp_dir_ / "config";
        std::filesystem::create_directories(web_dir_);
        std::filesystem::create_directories(config_dir_);
        
        // Create sample files
        std::ofstream(web_dir_ / "index.html") << "<html><body>Hello World</body></html>";
        std::ofstream(config_dir_ / "default.conf") << "server { listen 80; }";
    }
    
    void TearDown() override {
        std::filesystem::remove_all(temp_dir_);
    }
    
    std::filesystem::path temp_dir_;
    std::filesystem::path web_dir_;
    std::filesystem::path config_dir_;
    std::string sample_compose_;
};

TEST_F(BoostLibTest, ConstructorDestructor) {
    EXPECT_NO_THROW({
        boost_lib::BoostLib boost;
    });
}

TEST_F(BoostLibTest, CalculateDirectoryHash) {
    boost_lib::BoostLib boost;
    
    auto hash = boost.calculate_directory_hash(temp_dir_.string());
    EXPECT_FALSE(hash.empty());
    EXPECT_EQ(hash.size(), boost_lib::HASH_LEN);
}

TEST_F(BoostLibTest, CalculateComposeVolumesHash) {
    boost_lib::BoostLib boost;
    
    // Change to temp directory so relative paths work
    auto old_cwd = std::filesystem::current_path();
    std::filesystem::current_path(temp_dir_);
    
    auto hash = boost.calculate_compose_volumes_hash(sample_compose_);
    
    std::filesystem::current_path(old_cwd);
    
    EXPECT_FALSE(hash.empty());
    EXPECT_EQ(hash.size(), boost_lib::HASH_LEN);
}

TEST_F(BoostLibTest, GenerateQuote) {
    boost_lib::BoostLib boost;
    
    auto result = boost.generate_quote();
    EXPECT_EQ(result.status, boost_lib::ErrorCode::SUCCESS);
    EXPECT_FALSE(result.quote_data.empty());
    EXPECT_FALSE(result.message.empty());
}

TEST_F(BoostLibTest, StartApp) {
    boost_lib::BoostLib boost;
    
    // Set test mode to skip actual docker startup
    setenv("BOOST_TEST_MODE", "1", 1);
    
    auto old_cwd = std::filesystem::current_path();
    std::filesystem::current_path(temp_dir_);
    
    auto result = boost.start_app(sample_compose_, 3);
    
    std::filesystem::current_path(old_cwd);
    unsetenv("BOOST_TEST_MODE");
    
    // Should succeed in hash calculation and RTMR extension
    EXPECT_EQ(result.status, boost_lib::ErrorCode::SUCCESS);
    EXPECT_FALSE(result.volumes_hash.empty());
    EXPECT_EQ(result.volumes_hash.size(), boost_lib::HASH_LEN);
}