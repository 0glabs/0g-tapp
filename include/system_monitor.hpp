/**
 * @file system_monitor.hpp
 * @brief System Monitoring Library for TAPP Service Logs and Status
 */

#ifndef SYSTEM_MONITOR_HPP
#define SYSTEM_MONITOR_HPP

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <chrono>
#include <functional>

namespace system_monitor {

enum class ErrorCode {
    SUCCESS = 0,
    SERVICE_NOT_FOUND = 1,
    PERMISSION_DENIED = 2,
    COMMAND_FAILED = 3,
    PARSE_ERROR = 4,
    INTERNAL_ERROR = 5
};

enum class ServiceHealthStatus {
    HEALTHY = 0,
    UNHEALTHY = 1,
    UNKNOWN = 2
};

enum class LogLevel {
    DEBUG = 0,
    INFO = 1,
    WARNING = 2,
    ERROR = 3
};

struct LogEntry {
    std::chrono::system_clock::time_point timestamp;
    std::string timestamp_str;
    LogLevel level;
    std::string message;
    std::string service_name;
    std::map<std::string, std::string> metadata;
};

struct ServiceInfo {
    std::string name;
    ServiceHealthStatus status;
    std::string status_message;
    std::chrono::seconds uptime;
    uint64_t memory_usage_mb;
    double cpu_usage_percent;
    int32_t pid;
    std::string version;
};

struct ServiceStatusResult {
    ErrorCode status;
    std::string message;
    std::vector<ServiceInfo> services;
    std::chrono::system_clock::time_point timestamp;
};

struct ServiceLogsResult {
    ErrorCode status;
    std::string message;
    std::vector<LogEntry> logs;
    int32_t total_lines;
    bool truncated;
};

class SystemMonitor {
public:
    SystemMonitor();
    ~SystemMonitor();

    // Service Status Operations
    ServiceStatusResult get_service_status(const std::string& service_name = "");
    
    // Service Logs Operations
    ServiceLogsResult get_service_logs(
        const std::string& service_name = "tapp-server",
        int32_t lines = 100,
        const std::string& since = "",
        const std::string& until = "",
        LogLevel min_level = LogLevel::DEBUG,
        const std::string& grep_pattern = "",
        bool json_format = false
    );

    // Stream logs (callback-based for gRPC streaming)
    ErrorCode start_log_stream(
        const std::string& service_name,
        LogLevel min_level,
        const std::string& grep_pattern,
        int32_t tail_lines,
        std::function<void(const LogEntry&, bool is_initial)> callback
    );
    
    void stop_log_stream();

private:
    class Impl;
    std::unique_ptr<Impl> pimpl_;
};

// Utility functions
std::string log_level_to_string(LogLevel level);
LogLevel string_to_log_level(const std::string& level_str);
std::string service_status_to_string(ServiceHealthStatus status);
std::string error_code_to_string(ErrorCode code);

} // namespace system_monitor

#endif // SYSTEM_MONITOR_HPP