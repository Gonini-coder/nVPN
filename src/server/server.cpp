#include "server.hpp"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <cstring>

namespace nvpn {

// VPNServer implementation
VPNServer::VPNServer()
    : running_(false)
    , next_session_id_(1) {
}

VPNServer::~VPNServer() {
    stop();
}

bool VPNServer::initialize(const ServerConfig& config) {
    config_ = config;
    
    // Initialize obfuscation
    obfuscation_manager_ = std::make_unique<ObfuscationManager>(config.obfuscation_mode);
    if (!config.sni_hostname.empty()) {
        obfuscation_manager_->set_sni_hostname(config.sni_hostname);
    }
    
    // Load certificates if provided
    if (!config.cert_path.empty() && !config.key_path.empty()) {
        if (!cert_manager_.load_certificate(config.cert_path) ||
            !cert_manager_.load_private_key(config.key_path)) {
            std::cerr << "Failed to load certificates" << std::endl;
            return false;
        }
    }
    
    // Initialize IP pool
    std::istringstream iss(config.vpn_network);
    std::string octet;
    std::vector<int> network_octets;
    while (std::getline(iss, octet, '.')) {
        network_octets.push_back(std::stoi(octet));
    }
    
    // Generate IP pool (skip .1 for gateway)
    for (int i = 2; i < 254; i++) {
        std::ostringstream oss;
        oss << network_octets[0] << "."
            << network_octets[1] << "."
            << network_octets[2] << "."
            << i;
        ip_pool_.push_back(oss.str());
    }
    
    return true;
}

bool VPNServer::start() {
    if (running_) {
        return false;
    }
    
    // Create TCP socket
    tcp_socket_ = std::make_unique<Socket>(Socket::Type::TCP);
    if (!tcp_socket_->create()) {
        std::cerr << "Failed to create TCP socket" << std::endl;
        return false;
    }
    
    if (!tcp_socket_->set_reuse_addr(true)) {
        std::cerr << "Warning: Failed to set SO_REUSEADDR" << std::endl;
    }
    
    if (!tcp_socket_->bind(config_.bind_address, config_.port)) {
        std::cerr << "Failed to bind TCP socket to " << config_.bind_address 
                  << ":" << config_.port << std::endl;
        return false;
    }
    
    if (!tcp_socket_->listen()) {
        std::cerr << "Failed to listen on TCP socket" << std::endl;
        return false;
    }
    
    // Create UDP socket
    udp_socket_ = std::make_unique<UDPSocket>();
    if (!udp_socket_->bind(config_.bind_address, config_.udp_port)) {
        std::cerr << "Failed to bind UDP socket to " << config_.bind_address 
                  << ":" << config_.udp_port << std::endl;
        return false;
    }
    
    running_ = true;
    
    // Start threads
    accept_thread_ = std::thread(&VPNServer::accept_loop, this);
    udp_thread_ = std::thread(&VPNServer::udp_loop, this);
    maintenance_thread_ = std::thread(&VPNServer::maintenance_loop, this);
    
    std::cout << "Server listening on TCP " << config_.bind_address << ":" << config_.port
              << " and UDP " << config_.bind_address << ":" << config_.udp_port << std::endl;
    
    return true;
}

void VPNServer::stop() {
    if (!running_) {
        return;
    }
    
    running_ = false;
    
    // Close sockets to unblock threads
    if (tcp_socket_) {
        tcp_socket_->close();
    }
    if (udp_socket_) {
        udp_socket_->close();
    }
    
    // Wait for threads
    if (accept_thread_.joinable()) {
        accept_thread_.join();
    }
    if (udp_thread_.joinable()) {
        udp_thread_.join();
    }
    if (maintenance_thread_.joinable()) {
        maintenance_thread_.join();
    }
    
    // Disconnect all clients
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        for (auto& pair : sessions_) {
            pair.second->stop();
        }
        sessions_.clear();
    }
    
    std::cout << "Server stopped" << std::endl;
}

bool VPNServer::is_running() const {
    return running_;
}

void VPNServer::accept_loop() {
    while (running_) {
        auto client_socket = tcp_socket_->accept();
        if (client_socket) {
            handle_new_connection(std::move(client_socket));
        }
    }
}

void VPNServer::udp_loop() {
    std::vector<uint8_t> data;
    std::string from_host;
    uint16_t from_port;
    
    while (running_) {
        if (udp_socket_->receive_from(data, from_host, from_port)) {
            if (!data.empty()) {
                handle_udp_packet(data, from_host, from_port);
            }
        }
    }
}

void VPNServer::maintenance_loop() {
    while (running_) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        cleanup_inactive_sessions();
        send_keepalive_packets();
    }
}

bool VPNServer::handle_new_connection(std::unique_ptr<Socket> client_socket) {
    // Check max clients
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        if (sessions_.size() >= config_.max_clients) {
            std::cerr << "Max clients reached, rejecting connection" << std::endl;
            return false;
        }
    }
    
    // Allocate IP address
    std::string assigned_ip = allocate_ip_address();
    if (assigned_ip.empty()) {
        std::cerr << "No available IP addresses" << std::endl;
        return false;
    }
    
    // Create session
    uint32_t session_id = next_session_id_++;
    auto session = std::make_unique<ClientSession>(session_id, std::move(client_socket), this);
    
    if (!session->initialize(assigned_ip)) {
        release_ip_address(assigned_ip);
        return false;
    }
    
    // Add to sessions
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        sessions_[session_id] = std::move(session);
        ip_to_session_[assigned_ip] = session_id;
    }

    // Start session
    sessions_[session_id]->start();
    
    std::cout << "New client connected: " << session_id << " (IP: " << assigned_ip << ")" << std::endl;
    
    return true;
}

void VPNServer::handle_udp_packet(const std::vector<uint8_t>& data, 
                                   const std::string& from_host, 
                                   uint16_t from_port) {
    // Deobfuscate
    std::vector<uint8_t> deobfuscated;
    if (obfuscation_manager_) {
        deobfuscated = obfuscation_manager_->deobfuscate(data);
    } else {
        deobfuscated = data;
    }
    
    if (deobfuscated.empty()) {
        return;
    }
    
    // Parse packet
    Packet packet = Packet::deserialize(deobfuscated);
    
    // Find session
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    for (auto& pair : sessions_) {
        if (pair.second->get_info().client_address == from_host) {
            pair.second->handle_packet(deobfuscated);
            break;
        }
    }
}

std::string VPNServer::allocate_ip_address() {
    std::lock_guard<std::mutex> lock(ip_pool_mutex_);
    
    for (const auto& ip : ip_pool_) {
        if (ip_to_session_.find(ip) == ip_to_session_.end()) {
            return ip;
        }
    }
    
    return "";
}

void VPNServer::release_ip_address(const std::string& ip) {
    std::lock_guard<std::mutex> lock(ip_pool_mutex_);
    ip_to_session_.erase(ip);
}

void VPNServer::cleanup_inactive_sessions() {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    
    auto now = std::chrono::steady_clock::now();
    std::vector<uint32_t> to_remove;
    
    for (auto& pair : sessions_) {
        auto info = pair.second->get_info();
        auto inactive_duration = std::chrono::duration_cast<std::chrono::seconds>(
            now - info.last_activity).count();
        
        if (inactive_duration > config_.handshake_timeout || !pair.second->is_active()) {
            to_remove.push_back(pair.first);
        }
    }
    
    for (uint32_t session_id : to_remove) {
        auto& session = sessions_[session_id];
        release_ip_address(session->get_info().assigned_ip);
        session->stop();
        sessions_.erase(session_id);
        std::cout << "Session " << session_id << " removed (inactive)" << std::endl;
    }
}

void VPNServer::send_keepalive_packets() {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    
    auto now = std::chrono::steady_clock::now();
    
    for (auto& pair : sessions_) {
        auto info = pair.second->get_info();
        auto inactive_duration = std::chrono::duration_cast<std::chrono::seconds>(
            now - info.last_activity).count();
        
        if (inactive_duration > config_.keepalive_interval) {
            // Send heartbeat
            Packet heartbeat;
            heartbeat.header.type = static_cast<uint8_t>(MessageType::HEARTBEAT);
            heartbeat.header.sequence = 0;
            heartbeat.header.timestamp = static_cast<uint32_t>(
                std::chrono::duration_cast<std::chrono::seconds>(
                    now.time_since_epoch()).count());
            
            pair.second->send_packet(heartbeat.serialize());
        }
    }
}

size_t VPNServer::get_active_sessions() const {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    return sessions_.size();
}

std::vector<SessionInfo> VPNServer::get_session_list() const {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    
    std::vector<SessionInfo> result;
    for (const auto& pair : sessions_) {
        result.push_back(pair.second->get_info());
    }
    
    return result;
}

bool VPNServer::disconnect_client(uint32_t session_id) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) {
        return false;
    }
    
    release_ip_address(it->second->get_info().assigned_ip);
    it->second->stop();
    sessions_.erase(it);
    
    return true;
}

void VPNServer::set_config(const ServerConfig& config) {
    config_ = config;
}

ServerConfig VPNServer::get_config() const {
    return config_;
}

// Obfuscation operations
std::vector<uint8_t> VPNServer::obfuscate(const std::vector<uint8_t>& data) const {
    if (obfuscation_manager_) {
        return obfuscation_manager_->obfuscate(data);
    }
    return data;
}

std::vector<uint8_t> VPNServer::deobfuscate(const std::vector<uint8_t>& data) const {
    if (obfuscation_manager_) {
        return obfuscation_manager_->deobfuscate(data);
    }
    return data;
}

} // namespace nvpn
