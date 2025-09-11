/**
 * @file system_monitor.cpp
 * @brief System Monitoring Library Implementation
 */

#include "system_monitor.hpp"
#include <iostream>
#include <sstream>
#include <fstream>
#include <regex>
#include <thread>
#include <atomic>
#include <cstdlib>
#include <algorithm>
#include <optional>
#include <sys/wait.h>
#include <unistd.h>

namespace system_monitor {

class SystemMonitor::Impl {
public:
    Impl() : log_stream_running_(false) {}
    
    ~Impl() {
        stop_log_stream();
    }

    ServiceStatusResult get_service_status(const std::string& service_name) {
        ServiceStatusResult result;
        result.status = ErrorCode::SUCCESS;
        result.timestamp = std::chrono::system_clock::now();

        try {
            if (service_name.empty()) {
                // Get status for common TAPP-related services
                std::vector<std::string> services = {"tapp-server", "docker", "containerd"};
                for (const auto& svc : services) {
                    auto service_info = get_single_service_status(svc);
                    if (service_info.has_value()) {
                        result.services.push_back(service_info.value());
                    }
                }
            } else {
                auto service_info = get_single_service_status(service_name);
                if (service_info.has_value()) {
                    result.services.push_back(service_info.value());
                } else {
                    result.status = ErrorCode::SERVICE_NOT_FOUND;
                    result.message = "Service '" + service_name + "' not found";
                }
            }
            
            if (result.services.empty() && result.status == ErrorCode::SUCCESS) {
                result.status = ErrorCode::SERVICE_NOT_FOUND;
                result.message = "No services found";
            } else if (result.status == ErrorCode::SUCCESS) {
                result.message = "Successfully retrieved status for " + 
                    std::to_string(result.services.size()) + " service(s)";
            }
        } catch (const std::exception& e) {
            result.status = ErrorCode::INTERNAL_ERROR;
            result.message = "Error retrieving service status: " + std::string(e.what());
        }

        return result;
    }

    ServiceLogsResult get_service_logs(
        const std::string& service_name,
        int32_t lines,
        const std::string& since,
        const std::string& until,
        LogLevel min_level,
        const std::string& grep_pattern,
        bool json_format) {
        
        ServiceLogsResult result;
        result.status = ErrorCode::SUCCESS;
        result.total_lines = 0;
        result.truncated = false;

        try {
            // Build journalctl command
            std::string cmd = "journalctl -u " + service_name;
            
            if (!since.empty()) {
                cmd += " --since='" + since + "'";
            }
            if (!until.empty()) {
                cmd += " --until='" + until + "'";
            }
            if (lines > 0) {
                cmd += " -n " + std::to_string(lines);
            }
            
            // Add log level filtering
            switch (min_level) {
                case LogLevel::ERROR:
                    cmd += " -p err";
                    break;
                case LogLevel::WARNING:
                    cmd += " -p warning";
                    break;
                case LogLevel::INFO:
                    cmd += " -p info";
                    break;
                case LogLevel::DEBUG:
                    cmd += " -p debug";
                    break;
            }
            
            cmd += " --no-pager";
            if (json_format) {
                cmd += " -o json";
            }

            std::string output = execute_command(cmd);
            
            if (json_format) {
                result.logs = parse_json_logs(output, grep_pattern);
            } else {
                result.logs = parse_plain_logs(output, service_name, grep_pattern);
            }
            
            result.total_lines = static_cast<int32_t>(result.logs.size());
            result.message = "Retrieved " + std::to_string(result.total_lines) + " log entries";
            
        } catch (const std::exception& e) {
            result.status = ErrorCode::COMMAND_FAILED;
            result.message = "Error retrieving logs: " + std::string(e.what());
        }

        return result;
    }

    ErrorCode start_log_stream(
        const std::string& service_name,
        LogLevel min_level,
        const std::string& grep_pattern,
        int32_t tail_lines,
        std::function<void(const LogEntry&, bool is_initial)> callback) {
        
        stop_log_stream();
        
        log_stream_running_ = true;
        log_stream_thread_ = std::thread([this, service_name, min_level, grep_pattern, tail_lines, callback]() {
            try {
                // First send initial tail logs
                if (tail_lines > 0) {
                    auto initial_logs = get_service_logs(service_name, tail_lines, "", "", min_level, grep_pattern, false);
                    for (const auto& log : initial_logs.logs) {
                        if (!log_stream_running_) break;
                        callback(log, true);
                    }
                }
                
                // Build streaming command
                std::string cmd = "journalctl -u " + service_name + " -f --no-pager";
                
                switch (min_level) {
                    case LogLevel::ERROR:
                        cmd += " -p err";
                        break;
                    case LogLevel::WARNING:
                        cmd += " -p warning";
                        break;
                    case LogLevel::INFO:
                        cmd += " -p info";
                        break;
                    case LogLevel::DEBUG:
                        cmd += " -p debug";
                        break;
                }
                
                // Execute streaming command
                FILE* pipe = popen(cmd.c_str(), "r");
                if (!pipe) {
                    return;
                }
                
                char buffer[4096];
                while (log_stream_running_ && fgets(buffer, sizeof(buffer), pipe)) {
                    std::string line(buffer);
                    if (!line.empty() && line.back() == '\n') {
                        line.pop_back();
                    }
                    
                    // Apply grep filter if specified
                    if (!grep_pattern.empty() && line.find(grep_pattern) == std::string::npos) {
                        continue;
                    }
                    
                    // Parse and send log entry
                    auto logs = parse_plain_logs(line, service_name, "");
                    for (const auto& log : logs) {
                        if (!log_stream_running_) break;
                        callback(log, false);
                    }
                }
                
                pclose(pipe);
            } catch (const std::exception& e) {
                std::cerr << "Log streaming error: " << e.what() << std::endl;
            }
        });
        
        return ErrorCode::SUCCESS;
    }

    void stop_log_stream() {
        log_stream_running_ = false;
        if (log_stream_thread_.joinable()) {
            log_stream_thread_.join();
        }
    }

private:
    std::atomic<bool> log_stream_running_;
    std::thread log_stream_thread_;

    std::optional<ServiceInfo> get_single_service_status(const std::string& service_name) {
        try {
            // Check if service exists and get status
            std::string cmd = "systemctl status " + service_name + " --no-pager -l 2>/dev/null || echo 'SERVICE_NOT_FOUND'";
            std::string output = execute_command(cmd);
            
            if (output.find("SERVICE_NOT_FOUND") != std::string::npos) {
                return std::nullopt;
            }
            
            ServiceInfo info;
            info.name = service_name;
            info.status = ServiceHealthStatus::UNKNOWN;
            info.status_message = "Unknown";
            info.uptime = std::chrono::seconds(0);
            info.memory_usage_mb = 0;
            info.cpu_usage_percent = 0.0;
            info.pid = -1;
            info.version = "Unknown";
            
            // Parse systemctl output
            if (output.find("Active: active (running)") != std::string::npos) {
                info.status = ServiceHealthStatus::HEALTHY;
                info.status_message = "Running";
            } else if (output.find("Active: inactive") != std::string::npos) {
                info.status = ServiceHealthStatus::UNHEALTHY;
                info.status_message = "Inactive";
            } else if (output.find("Active: failed") != std::string::npos) {
                info.status = ServiceHealthStatus::UNHEALTHY;
                info.status_message = "Failed";
            }
            
            // Extract PID if available
            std::regex pid_regex(R"(Main PID: (\d+))");
            std::smatch pid_match;
            if (std::regex_search(output, pid_match, pid_regex)) {
                info.pid = std::stoi(pid_match[1].str());
                
                // Get additional process information if PID is available
                get_process_info(info.pid, info);
            }
            
            return info;
        } catch (const std::exception& e) {
            std::cerr << "Error getting service status for " << service_name << ": " << e.what() << std::endl;
            return std::nullopt;
        }
    }

    void get_process_info(int32_t pid, ServiceInfo& info) {
        try {
            // Get memory usage
            std::string mem_cmd = "ps -p " + std::to_string(pid) + " -o rss= 2>/dev/null";
            std::string mem_output = execute_command(mem_cmd);
            if (!mem_output.empty()) {
                info.memory_usage_mb = std::stoull(mem_output) / 1024; // Convert KB to MB
            }
            
            // Get CPU usage (simple approach)
            std::string cpu_cmd = "ps -p " + std::to_string(pid) + " -o %cpu= 2>/dev/null";
            std::string cpu_output = execute_command(cpu_cmd);
            if (!cpu_output.empty()) {
                info.cpu_usage_percent = std::stod(cpu_output);
            }
            
            // Get process start time for uptime calculation
            std::string uptime_cmd = "ps -p " + std::to_string(pid) + " -o etime= 2>/dev/null";
            std::string uptime_output = execute_command(uptime_cmd);
            if (!uptime_output.empty()) {
                // Parse elapsed time (simplified)
                info.uptime = parse_elapsed_time(uptime_output);
            }
        } catch (const std::exception& e) {
            // Non-critical errors, just continue
        }
    }

    std::chrono::seconds parse_elapsed_time(const std::string& etime_str) {
        // Simplified parsing of ps etime format
        // Format can be: seconds, mm:ss, hh:mm:ss, or dd-hh:mm:ss
        std::regex time_regex(R"((?:(\d+)-)?(?:(\d+):)?(\d+):(\d+))");
        std::smatch match;
        
        if (std::regex_search(etime_str, match, time_regex)) {
            int days = match[1].matched ? std::stoi(match[1].str()) : 0;
            int hours = match[2].matched ? std::stoi(match[2].str()) : 0;
            int minutes = std::stoi(match[3].str());
            int seconds = std::stoi(match[4].str());
            
            return std::chrono::seconds(days * 86400 + hours * 3600 + minutes * 60 + seconds);
        }
        
        return std::chrono::seconds(0);
    }

    std::string execute_command(const std::string& cmd) {
        FILE* pipe = popen(cmd.c_str(), "r");
        if (!pipe) {
            throw std::runtime_error("Failed to execute command: " + cmd);
        }
        
        std::string result;
        char buffer[4096];
        while (fgets(buffer, sizeof(buffer), pipe)) {
            result += buffer;
        }
        
        int exit_code = pclose(pipe);
        if (exit_code != 0 && result.empty()) {
            throw std::runtime_error("Command failed with exit code: " + std::to_string(exit_code));
        }
        
        return result;
    }

    std::vector<LogEntry> parse_json_logs(const std::string& json_output, const std::string& grep_pattern) {
        std::vector<LogEntry> logs;
        // JSON parsing would require a JSON library like nlohmann/json
        // For now, fall back to plain parsing
        return parse_plain_logs(json_output, "", grep_pattern);
    }

    std::vector<LogEntry> parse_plain_logs(const std::string& output, const std::string& service_name, const std::string& grep_pattern) {
        std::vector<LogEntry> logs;
        std::istringstream stream(output);
        std::string line;
        
        while (std::getline(stream, line)) {
            if (line.empty()) continue;
            
            // Apply grep filter
            if (!grep_pattern.empty() && line.find(grep_pattern) == std::string::npos) {
                continue;
            }
            
            LogEntry entry;
            entry.service_name = service_name;
            entry.timestamp = std::chrono::system_clock::now();
            entry.message = line;
            entry.level = LogLevel::INFO;
            
            // Simple parsing of systemd journal format
            // Format: MMM DD HH:MM:SS hostname service[pid]: message
            std::regex journal_regex(R"(^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+(.+?)\[\d+\]:\s*(.+)$)");
            std::smatch match;
            
            if (std::regex_search(line, match, journal_regex)) {
                entry.timestamp_str = match[1].str();
                entry.service_name = match[2].str();
                entry.message = match[3].str();
                
                // Determine log level from message content
                std::string msg_lower = match[3].str();
                std::transform(msg_lower.begin(), msg_lower.end(), msg_lower.begin(), ::tolower);
                
                if (msg_lower.find("error") != std::string::npos || msg_lower.find("fail") != std::string::npos) {
                    entry.level = LogLevel::ERROR;
                } else if (msg_lower.find("warn") != std::string::npos) {
                    entry.level = LogLevel::WARNING;
                } else if (msg_lower.find("debug") != std::string::npos) {
                    entry.level = LogLevel::DEBUG;
                } else {
                    entry.level = LogLevel::INFO;
                }
            } else {
                // Fallback for lines that don't match expected format
                entry.timestamp_str = "Unknown";
                entry.message = line;
            }
            
            logs.push_back(entry);
        }
        
        return logs;
    }
};

// SystemMonitor implementation

SystemMonitor::SystemMonitor() : pimpl_(std::make_unique<Impl>()) {}

SystemMonitor::~SystemMonitor() = default;

ServiceStatusResult SystemMonitor::get_service_status(const std::string& service_name) {
    return pimpl_->get_service_status(service_name);
}

ServiceLogsResult SystemMonitor::get_service_logs(
    const std::string& service_name,
    int32_t lines,
    const std::string& since,
    const std::string& until,
    LogLevel min_level,
    const std::string& grep_pattern,
    bool json_format) {
    
    return pimpl_->get_service_logs(service_name, lines, since, until, min_level, grep_pattern, json_format);
}

ErrorCode SystemMonitor::start_log_stream(
    const std::string& service_name,
    LogLevel min_level,
    const std::string& grep_pattern,
    int32_t tail_lines,
    std::function<void(const LogEntry&, bool is_initial)> callback) {
    
    return pimpl_->start_log_stream(service_name, min_level, grep_pattern, tail_lines, callback);
}

void SystemMonitor::stop_log_stream() {
    pimpl_->stop_log_stream();
}

// Utility functions

std::string log_level_to_string(LogLevel level) {
    switch (level) {
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO: return "INFO";
        case LogLevel::WARNING: return "WARNING";
        case LogLevel::ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}

LogLevel string_to_log_level(const std::string& level_str) {
    if (level_str == "DEBUG") return LogLevel::DEBUG;
    if (level_str == "INFO") return LogLevel::INFO;
    if (level_str == "WARNING" || level_str == "WARN") return LogLevel::WARNING;
    if (level_str == "ERROR") return LogLevel::ERROR;
    return LogLevel::INFO;
}

std::string service_status_to_string(ServiceHealthStatus status) {
    switch (status) {
        case ServiceHealthStatus::HEALTHY: return "HEALTHY";
        case ServiceHealthStatus::UNHEALTHY: return "UNHEALTHY";
        case ServiceHealthStatus::UNKNOWN: return "UNKNOWN";
        default: return "UNKNOWN";
    }
}

std::string error_code_to_string(ErrorCode code) {
    switch (code) {
        case ErrorCode::SUCCESS: return "SUCCESS";
        case ErrorCode::SERVICE_NOT_FOUND: return "SERVICE_NOT_FOUND";
        case ErrorCode::PERMISSION_DENIED: return "PERMISSION_DENIED";
        case ErrorCode::COMMAND_FAILED: return "COMMAND_FAILED";
        case ErrorCode::PARSE_ERROR: return "PARSE_ERROR";
        case ErrorCode::INTERNAL_ERROR: return "INTERNAL_ERROR";
        default: return "UNKNOWN";
    }
}

} // namespace system_monitor