#include "client.hpp"
#include <iostream>
#include <sstream>
#include <cstring>
#include <algorithm>

namespace nvpn {

// TUNPacketHandler implementation
TUNPacketHandler::TUNPacketHandler(VPNClient* client)
    : client_(client) {
}

bool TUNPacketHandler::handle_packet(const std::vector<uint8_t>& packet) {
    if (packet.size() < 20) {
        return false;
    }
    
    // Check IP version
    uint8_t version = (packet[0] >> 4) & 0x0F;
    if (version != 4) {
        // IPv6 not supported in this simplified implementation
        return false;
    }
    
    // Get destination IP
    std::string dest_ip = IPPacketUtils::get_destination_ip(packet);
    
    // Check if packet should be routed through VPN
    if (!should_route_through_vpn(packet)) {
        return false;
    }
    
    // Packet will be encrypted and sent to server
    return true;
}

bool TUNPacketHandler::should_route_through_vpn(const std::vector<uint8_t>& packet) const {
    if (packet.size() < 20) {
        return false;
    }
    
    std::string dest_ip = IPPacketUtils::get_destination_ip(packet);
    
    // Check excluded routes first
    std::lock_guard<std::mutex> lock(routes_mutex_);
    
    for (const auto& route : excluded_routes_) {
        if (matches_route(dest_ip, route)) {
            return false;
        }
    }
    
    // If no specific routes defined, route everything
    if (routes_.empty()) {
        return true;
    }
    
    // Check if destination matches any defined route
    for (const auto& route : routes_) {
        if (matches_route(dest_ip, route)) {
            return true;
        }
    }
    
    return false;
}

void TUNPacketHandler::add_route(const std::string& route) {
    std::lock_guard<std::mutex> lock(routes_mutex_);
    
    // Check if route already exists
    if (std::find(routes_.begin(), routes_.end(), route) == routes_.end()) {
        routes_.push_back(route);
    }
}

void TUNPacketHandler::remove_route(const std::string& route) {
    std::lock_guard<std::mutex> lock(routes_mutex_);
    
    auto it = std::find(routes_.begin(), routes_.end(), route);
    if (it != routes_.end()) {
        routes_.erase(it);
    }
}

void TUNPacketHandler::clear_routes() {
    std::lock_guard<std::mutex> lock(routes_mutex_);
    routes_.clear();
}

void TUNPacketHandler::add_excluded_route(const std::string& route) {
    std::lock_guard<std::mutex> lock(routes_mutex_);
    
    if (std::find(excluded_routes_.begin(), excluded_routes_.end(), route) == excluded_routes_.end()) {
        excluded_routes_.push_back(route);
    }
}

void TUNPacketHandler::remove_excluded_route(const std::string& route) {
    std::lock_guard<std::mutex> lock(routes_mutex_);
    
    auto it = std::find(excluded_routes_.begin(), excluded_routes_.end(), route);
    if (it != excluded_routes_.end()) {
        excluded_routes_.erase(it);
    }
}

bool TUNPacketHandler::is_in_subnet(const std::string& ip, const std::string& subnet) const {
    // Parse IP
    struct in_addr ip_addr;
    if (inet_pton(AF_INET, ip.c_str(), &ip_addr) != 1) {
        return false;
    }
    
    // Parse subnet
    size_t slash = subnet.find('/');
    if (slash == std::string::npos) {
        // Single IP
        struct in_addr subnet_addr;
        if (inet_pton(AF_INET, subnet.c_str(), &subnet_addr) != 1) {
            return false;
        }
        return ip_addr.s_addr == subnet_addr.s_addr;
    }
    
    // CIDR notation
    std::string network = subnet.substr(0, slash);
    int prefix = std::stoi(subnet.substr(slash + 1));
    
    struct in_addr network_addr;
    if (inet_pton(AF_INET, network.c_str(), &network_addr) != 1) {
        return false;
    }
    
    uint32_t mask = htonl(0xFFFFFFFF << (32 - prefix));
    
    return (ip_addr.s_addr & mask) == (network_addr.s_addr & mask);
}

bool TUNPacketHandler::matches_route(const std::string& dest_ip, const std::string& route) const {
    // Check if it's a CIDR route
    if (route.find('/') != std::string::npos) {
        return is_in_subnet(dest_ip, route);
    }
    
    // Check if it's a single IP
    return dest_ip == route;
}

} // namespace nvpn
