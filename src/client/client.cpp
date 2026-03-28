#include "client.hpp"
#include <iostream>
#include <sstream>
#include <cstring>
#include <thread>
#include <arpa/inet.h>

namespace nvpn{

// VPNClient implementation
VPNClient::VPNClient()
    : state_(ConnectionState::DISCONNECTED)
    , should_stop_(false) {
}

VPNClient::~VPNClient() {
    disconnect();
}

bool VPNClient::initialize(const ClientConfig& config) {
    config_ = config;
    
    // Initialize obfuscation
    obfuscation_manager_ = std::make_unique<ObfuscationManager>(config.obfuscation_mode);
    if (!config.sni_hostname.empty()) {
        obfuscation_manager_->set_sni_hostname(config.sni_hostname);
    }
    
    if (!config.front_domain.empty()) {
        obfuscation_manager_->set_domain_fronting(config.front_domain, config.server_host);
    }
    
    return true;
}

bool VPNClient::connect() {
    if (state_ != ConnectionState::DISCONNECTED) {
        std::cerr << "Already connected or connecting" << std::endl;
        return false;
    }
    
    state_ = ConnectionState::CONNECTING;
    should_stop_ = false;
    
    // Create TCP connection
    tcp_connection_ = std::make_unique<TCPConnection>();
    
    std::cout << "Connecting to " << config_.server_host << ":" << config_.server_port << std::endl;
    
    if (!tcp_connection_->connect(config_.server_host, config_.server_port)) {
        std::cerr << "Failed to connect to server" << std::endl;
        state_ = ConnectionState::DISCONNECTED;
        return false;
    }
    
    // Perform handshake
    if (!perform_handshake()) {
        std::cerr << "Handshake failed" << std::endl;
        tcp_connection_->disconnect();
        state_ = ConnectionState::DISCONNECTED;
        return false;
    }
    
    // Setup TUN device
    if (!setup_tun_device()) {
        std::cerr << "Failed to setup TUN device" << std::endl;
        tcp_connection_->disconnect();
        state_ = ConnectionState::DISCONNECTED;
        return false;
    }
    
    // Setup routing
    if (!setup_routing()) {
        std::cerr << "Failed to setup routing" << std::endl;
        tun_device_->destroy();
        tcp_connection_->disconnect();
        state_ = ConnectionState::DISCONNECTED;
        return false;
    }
    
    // Create UDP socket if enabled
    if (config_.use_udp) {
        udp_socket_ = std::make_unique<UDPSocket>();
        if (!udp_socket_->connect(config_.server_host, config_.server_udp_port)) {
            std::cerr << "Warning: Failed to connect UDP socket, falling back to TCP" << std::endl;
            udp_socket_.reset();
        }
    }
    
    state_ = ConnectionState::CONNECTED;
    
    // Start threads
    tun_read_thread_ = std::thread(&VPNClient::tun_read_loop, this);
    network_read_thread_ = std::thread(&VPNClient::network_read_loop, this);
    keepalive_thread_ = std::thread(&VPNClient::keepalive_loop, this);
    
    stats_.connected_time = std::chrono::steady_clock::now();
    
    std::cout << "VPN tunnel established" << std::endl;
    std::cout << "Local IP: " << assigned_ip_ << std::endl;
    std::cout << "Remote IP: " << server_tun_ip_ << std::endl;
    
    return true;
}

void VPNClient::disconnect() {
    if (state_ == ConnectionState::DISCONNECTED) {
        return;
    }
    
    should_stop_ = true;
    state_ = ConnectionState::DISCONNECTING;
    
    // Stop threads
    if (tun_read_thread_.joinable()) {
        tun_read_thread_.join();
    }
    if (network_read_thread_.joinable()) {
        network_read_thread_.join();
    }
    if (keepalive_thread_.joinable()) {
        keepalive_thread_.join();
    }
    
    // Restore routing
    restore_routing();
    
    // Destroy TUN device
    if (tun_device_) {
        tun_device_->destroy();
        tun_device_.reset();
    }
    
    // Disconnect from server
    if (tcp_connection_) {
        // Send disconnect message
        Packet disconnect_packet;
        disconnect_packet.header.type = static_cast<uint8_t>(MessageType::DISCONNECT);
        disconnect_packet.header.sequence = 0;
        disconnect_packet.header.timestamp = static_cast<uint32_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());
        
        auto serialized = disconnect_packet.serialize();
        auto obfuscated = obfuscation_manager_->obfuscate(serialized);
        
        uint32_t len = htonl(static_cast<uint32_t>(obfuscated.size()));
        tcp_connection_->send(std::vector<uint8_t>(
            reinterpret_cast<uint8_t*>(&len), 
            reinterpret_cast<uint8_t*>(&len) + sizeof(len)));
        tcp_connection_->send(obfuscated);
        
        tcp_connection_->disconnect();
        tcp_connection_.reset();
    }
    
    if (udp_socket_) {
        udp_socket_->close();
        udp_socket_.reset();
    }
    
    cleanup();
    
    state_ = ConnectionState::DISCONNECTED;
    std::cout << "Disconnected from server" << std::endl;
}

bool VPNClient::is_connected() const {
    return state_ == ConnectionState::CONNECTED;
}

ConnectionState VPNClient::get_state() const {
    return state_;
}

ConnectionStats VPNClient::get_stats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

std::string VPNClient::get_assigned_ip() const {
    return assigned_ip_;
}

bool VPNClient::perform_handshake() {
    state_ = ConnectionState::HANDSHAKE_SENT;
    
    // Generate ephemeral key pair
    X25519KeyExchange key_exchange;
    auto public_key = key_exchange.generate_keypair();
    
    if (public_key.empty()) {
        std::cerr << "Failed to generate key pair" << std::endl;
        return false;
    }
    
    // Create handshake packet
    Packet handshake_packet;
    handshake_packet.header.type = static_cast<uint8_t>(MessageType::HANDSHAKE);
    handshake_packet.header.version_major = 1;
    handshake_packet.header.version_minor = 0;
    handshake_packet.header.length = static_cast<uint16_t>(public_key.size());
    handshake_packet.header.sequence = 0;
    handshake_packet.header.timestamp = static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
    handshake_packet.header.flags = 0;
    handshake_packet.payload = public_key;
    
    // Add authentication if credentials provided
    if (!config_.username.empty()) {
        std::string auth = config_.username + ":" + config_.password;
        handshake_packet.payload.insert(handshake_packet.payload.end(), 
                                        auth.begin(), auth.end());
        handshake_packet.header.length = static_cast<uint16_t>(handshake_packet.payload.size());
    }
    
    // Send handshake
    auto serialized = handshake_packet.serialize();
    auto obfuscated = obfuscation_manager_->obfuscate(serialized);
    
    // Add length prefix
    uint32_t len = htonl(static_cast<uint32_t>(obfuscated.size()));
    std::vector<uint8_t> to_send;
    to_send.reserve(sizeof(len) + obfuscated.size());
    to_send.insert(to_send.end(), reinterpret_cast<uint8_t*>(&len), 
                   reinterpret_cast<uint8_t*>(&len) + sizeof(len));
    to_send.insert(to_send.end(), obfuscated.begin(), obfuscated.end());
    
    if (!tcp_connection_->send(to_send)) {
        std::cerr << "Failed to send handshake" << std::endl;
        return false;
    }
    
    // Wait for response
    std::vector<uint8_t> response;
    int retries = 10;
    while (retries-- > 0) {
        if (tcp_connection_->receive(response, sizeof(uint32_t))) {
            if (response.size() >= sizeof(uint32_t)) {
                break;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    if (response.size() < sizeof(uint32_t)) {
        std::cerr << "Handshake timeout" << std::endl;
        return false;
    }
    
    uint32_t response_len = ntohl(*reinterpret_cast<uint32_t*>(response.data()));
    
    if (response_len > MAX_PACKET_SIZE) {
        std::cerr << "Invalid response length" << std::endl;
        return false;
    }
    
    // Read response data
    std::vector<uint8_t> response_data;
    size_t total_received = 0;
    
    while (total_received < response_len) {
        std::vector<uint8_t> chunk;
        if (!tcp_connection_->receive(chunk, response_len - total_received)) {
            break;
        }
        response_data.insert(response_data.end(), chunk.begin(), chunk.end());
        total_received += chunk.size();
    }
    
    if (total_received != response_len) {
        std::cerr << "Incomplete handshake response" << std::endl;
        return false;
    }
    
    // Deobfuscate and parse response
    auto deobfuscated = obfuscation_manager_->deobfuscate(response_data);
    Packet response_packet = Packet::deserialize(deobfuscated);
    
    if (static_cast<MessageType>(response_packet.header.type) != MessageType::HANDSHAKE) {
        std::cerr << "Invalid handshake response" << std::endl;
        return false;
    }
    
    // Extract server public key and compute shared secret
    if (response_packet.payload.size() < 32) {
        std::cerr << "Invalid server public key" << std::endl;
        return false;
    }
    
    std::vector<uint8_t> server_public_key(response_packet.payload.begin(), 
                                           response_packet.payload.begin() + 32);
    auto shared_secret = key_exchange.compute_shared_secret(server_public_key);
    
    if (shared_secret.empty()) {
        std::cerr << "Failed to compute shared secret" << std::endl;
        return false;
    }
    
    // Derive session keys using HKDF
    std::vector<uint8_t> salt = CryptoRandom::generate_bytes(32);
    std::vector<uint8_t> info = {'S', 't', 'e', 'l', 't', 'h', 'V', 'P', 'N'};
    
    auto derived = KeyDerivation::derive_key(shared_secret, salt, info, 64);
    
    session_keys_.encryption_key = {};
    memcpy(session_keys_.encryption_key.data(), derived.data(), 32);
    memcpy(session_keys_.mac_key.data(), derived.data() + 32, 32);
    session_keys_.key_id = 1;
    
    // Initialize cipher
    std::array<uint8_t, 32> enc_key;
    memcpy(enc_key.data(), session_keys_.encryption_key.data(), 32);
    cipher_ = std::make_unique<AES256GCM>(enc_key);
    
    // Extract assigned IP from response
    if (response_packet.payload.size() > 32) {
        std::string ip_info(response_packet.payload.begin() + 32, 
                           response_packet.payload.end());
        size_t comma = ip_info.find(',');
        if (comma != std::string::npos) {
            assigned_ip_ = ip_info.substr(0, comma);
            server_tun_ip_ = ip_info.substr(comma + 1);
        }
    }
    
    if (assigned_ip_.empty()) {
        assigned_ip_ = "10.8.0.2";
        server_tun_ip_ = "10.8.0.1";
    }
    
    state_ = ConnectionState::CONNECTED;
    std::cout << "Handshake completed successfully" << std::endl;
    
    return true;
}

bool VPNClient::setup_tun_device() {
    TUNConfig tun_config;
    tun_config.local_address = assigned_ip_;
    tun_config.remote_address = server_tun_ip_;
    tun_config.netmask = "255.255.255.0";
    tun_config.mtu = config_.mtu;
    
    tun_device_ = std::make_unique<TUNDevice>();
    
    if (!tun_device_->create(tun_config)) {
        std::cerr << "Failed to create TUN device" << std::endl;
        return false;
    }
    
    return true;
}

bool VPNClient::setup_routing() {
    if (!config_.redirect_gateway) {
        return true;
    }
    
    // Add route to VPN server through default gateway
    // This prevents routing loops
    std::ostringstream oss;
    
#ifdef __linux__
    oss << "ip route add " << config_.server_host << " via $(ip route | grep default | awk '{print $3}')";
    system(oss.str().c_str());
    oss.str("");
    
    // Add default route through TUN
    oss << "ip route add default dev " << tun_device_->get_name() << " metric 100";
    system(oss.str().c_str());
    
#elif __APPLE__
    // Save current default route
    // Add new default route through TUN
    oss << "route add default -interface " << tun_device_->get_name();
    system(oss.str().c_str());
#endif
    
    // Setup DNS if requested
    if (config_.hijack_dns && !config_.dns_server.empty()) {
        DNSManager dns_manager;
        dns_manager.hijack_dns(config_.dns_server);
    }
    
    return true;
}

bool VPNClient::restore_routing() {
    std::ostringstream oss;
    
#ifdef __linux__
    // Remove TUN default route
    if (tun_device_) {
        oss << "ip route del default dev " << tun_device_->get_name();
        system(oss.str().c_str());
    }
    
#elif __APPLE__
    // Restore original default route
    // This is simplified - in production, save and restore original routes
#endif
    
    return true;
}

void VPNClient::tun_read_loop() {
    std::vector<uint8_t> packet;
    
    while (!should_stop_ && state_ == ConnectionState::CONNECTED) {
        if (tun_device_->read_packet(packet) && !packet.empty()) {
            handle_tun_packet(packet);
        }
    }
}

void VPNClient::network_read_loop() {
    std::vector<uint8_t> buffer;
    
    while (!should_stop_ && state_ == ConnectionState::CONNECTED) {
        // Read packet length
        std::vector<uint8_t> len_buffer;
        if (!tcp_connection_->receive(len_buffer, sizeof(uint32_t))) {
            if (!should_stop_) {
                std::cerr << "Connection lost" << std::endl;
                state_ = ConnectionState::DISCONNECTED;
            }
            break;
        }
        
        if (len_buffer.size() < sizeof(uint32_t)) {
            if (!should_stop_) {
                std::cerr << "Connection lost (incomplete length)" << std::endl;
                state_ = ConnectionState::DISCONNECTED;
            }
            break;
        }
        
        if (len_buffer.size() < sizeof(uint32_t)) {
            continue;
        }
        
        uint32_t packet_len = ntohl(*reinterpret_cast<uint32_t*>(len_buffer.data()));
        
        if (packet_len > MAX_PACKET_SIZE) {
            std::cerr << "Packet too large: " << packet_len << std::endl;
            continue;
        }
        
        // Read packet data
        std::vector<uint8_t> packet_data;
        size_t total_received = 0;
        
        while (total_received < packet_len) {
            std::vector<uint8_t> chunk;
            if (!tcp_connection_->receive(chunk, packet_len - total_received)) {
                break;
            }
            packet_data.insert(packet_data.end(), chunk.begin(), chunk.end());
            total_received += chunk.size();
        }
        
        if (total_received != packet_len) {
            std::cerr << "Incomplete packet received" << std::endl;
            continue;
        }
        
        handle_server_packet(packet_data);
    }
}

void VPNClient::keepalive_loop() {
    while (!should_stop_ && state_ == ConnectionState::CONNECTED) {
        std::this_thread::sleep_for(std::chrono::seconds(config_.keepalive_interval));
        
        if (should_stop_ || state_ != ConnectionState::CONNECTED) {
            break;
        }
        
        send_heartbeat();
    }
}

bool VPNClient::send_to_server(const std::vector<uint8_t>& data) {
    if (!tcp_connection_ || !tcp_connection_->is_connected()) {
        return false;
    }
    
    // Obfuscate
    auto obfuscated = obfuscation_manager_->obfuscate(data);
    
    // Add length prefix
    uint32_t len = htonl(static_cast<uint32_t>(obfuscated.size()));
    std::vector<uint8_t> to_send;
    to_send.reserve(sizeof(len) + obfuscated.size());
    to_send.insert(to_send.end(), reinterpret_cast<uint8_t*>(&len), 
                   reinterpret_cast<uint8_t*>(&len) + sizeof(len));
    to_send.insert(to_send.end(), obfuscated.begin(), obfuscated.end());
    
    if (!tcp_connection_->send(to_send)) {
        return false;
    }
    
    update_stats(to_send.size(), 0);
    return true;
}

bool VPNClient::receive_from_server(std::vector<uint8_t>& data) {
    // This is handled in network_read_loop
    return true;
}

bool VPNClient::handle_tun_packet(const std::vector<uint8_t>& packet) {
    if (!cipher_) {
        return false;
    }
    
    // Encrypt packet
    auto encrypted = cipher_->encrypt(packet);
    if (encrypted.empty()) {
        std::cerr << "Failed to encrypt packet" << std::endl;
        return false;
    }
    
    // Create data packet
    Packet data_packet;
    data_packet.header.type = static_cast<uint8_t>(MessageType::DATA);
    data_packet.header.sequence = 0;
    data_packet.header.timestamp = static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
    data_packet.header.length = static_cast<uint16_t>(encrypted.size());
    data_packet.payload = encrypted;
    
    // Send to server
    auto serialized = data_packet.serialize();
    return send_to_server(serialized);
}

bool VPNClient::handle_server_packet(const std::vector<uint8_t>& packet) {
    // Deobfuscate
    auto deobfuscated = obfuscation_manager_->deobfuscate(packet);
    if (deobfuscated.empty()) {
        return false;
    }
    
    // Parse packet
    Packet parsed = Packet::deserialize(deobfuscated);
    
    switch (static_cast<MessageType>(parsed.header.type)) {
        case MessageType::DATA:
            if (!cipher_) {
                return false;
            }
            
            // Decrypt
            {
                auto decrypted = cipher_->decrypt(parsed.payload);
                if (decrypted.empty()) {
                    std::cerr << "Failed to decrypt packet" << std::endl;
                    return false;
                }
                
                // Write to TUN
                if (tun_device_) {
                    tun_device_->write_packet(decrypted);
                }
            }
            break;
            
        case MessageType::HEARTBEAT:
            // Update activity timestamp
            break;
            
        case MessageType::DISCONNECT:
            std::cout << "Server requested disconnect" << std::endl;
            should_stop_ = true;
            break;
            
        default:
            break;
    }
    
    update_stats(0, packet.size());
    return true;
}

bool VPNClient::send_heartbeat() {
    Packet heartbeat;
    heartbeat.header.type = static_cast<uint8_t>(MessageType::HEARTBEAT);
    heartbeat.header.sequence = 0;
    heartbeat.header.timestamp = static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
    
    auto serialized = heartbeat.serialize();
    return send_to_server(serialized);
}

void VPNClient::update_stats(uint64_t bytes_sent, uint64_t bytes_received) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.bytes_sent += bytes_sent;
    stats_.bytes_received += bytes_received;
    
    if (bytes_sent > 0) {
        stats_.packets_sent++;
    }
    if (bytes_received > 0) {
        stats_.packets_received++;
    }
}

bool VPNClient::reconnect() {
    disconnect();
    
    int attempts = 0;
    while (attempts < config_.reconnect_attempts) {
        std::cout << "Reconnecting... (attempt " << (attempts + 1) << "/" 
                  << config_.reconnect_attempts << ")" << std::endl;
        
        if (connect()) {
            return true;
        }
        
        attempts++;
        std::this_thread::sleep_for(std::chrono::seconds(config_.reconnect_delay));
    }
    
    std::cerr << "Failed to reconnect after " << config_.reconnect_attempts << " attempts" << std::endl;
    return false;
}

void VPNClient::cleanup() {
    cipher_.reset();
    obfuscation_manager_.reset();
    tun_device_.reset();
    tcp_connection_.reset();
    udp_socket_.reset();
}

void VPNClient::set_config(const ClientConfig& config) {
    config_ = config;
}

ClientConfig VPNClient::get_config() const {
    return config_;
}

} // namespace nvpn
