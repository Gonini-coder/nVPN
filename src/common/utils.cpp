#include "nvpn_protocol.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>

namespace nvpn {

// Utility functions
namespace utils {

std::string bytes_to_hex(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (auto byte : data) {
        oss << std::setw(2) << static_cast<int>(byte);
    }
    return oss.str();
}

std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> result;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byte_string = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoi(byte_string, nullptr, 16));
        result.push_back(byte);
    }
    return result;
}

std::string get_current_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&time_t_now), "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

uint32_t get_timestamp_seconds() {
    return static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now().time_since_epoch()
        ).count()
    );
}

void print_hex_dump(const std::vector<uint8_t>& data, size_t max_bytes = 256) {
    size_t len = std::min(data.size(), max_bytes);
    
    for (size_t i = 0; i < len; i += 16) {
        // Offset
        std::cout << std::hex << std::setw(4) << std::setfill('0') << i << "  ";
        
        // Hex bytes
        for (size_t j = 0; j < 16 && (i + j) < len; j++) {
            std::cout << std::setw(2) << std::setfill('0') 
                     << static_cast<int>(data[i + j]) << " ";
        }
        
        // Padding
        for (size_t j = len - i; j < 16; j++) {
            std::cout << "   ";
        }
        
        std::cout << " ";
        
        // ASCII representation
        for (size_t j = 0; j < 16 && (i + j) < len; j++) {
            char c = static_cast<char>(data[i + j]);
            if (c >= 32 && c < 127) {
                std::cout << c;
            } else {
                std::cout << ".";
            }
        }
        
        std::cout << std::endl;
    }
    
    if (data.size() > max_bytes) {
        std::cout << "... (" << (data.size() - max_bytes) << " more bytes)" << std::endl;
    }
}

} // namespace utils

} // namespace nvpn