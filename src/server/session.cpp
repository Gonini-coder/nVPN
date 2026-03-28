#include "server.hpp"
#include <iostream>
#include <cstring>

namespace nvpn {

// ClientSession implementation
ClientSession::ClientSession(uint32_t session_id, std::unique_ptr<Socket> socket, VPNServer* server)
    : session_id_(session_id)
    , socket_(std::move(socket))
    , server_(server)
    , active_(false) {
    
    info_.session_id = session_id;
    info_.bytes_sent = 0;
    info_.bytes_received = 0;
    info_.state = ConnectionState::DISCONNECTED;
}

ClientSession::~ClientSession() {
    stop();
}

bool ClientSession::initialize(const std::string& assigned_ip) {
    info_.assigned_ip = assigned_ip;
    info_.state = ConnectionState::CONNECTING;
    
    // Get client address
    sockaddr_in addr{};
    socklen_t addr_len = sizeof(addr);
    if (getpeername(socket_->get_handle(), reinterpret_cast<sockaddr*>(&addr), &addr_len) == 0) {
        info_.client_address = inet_ntoa(addr.sin_addr);
        info_.client_port = ntohs(addr.sin_port);
    }
    
    return true;
}

void ClientSession::start() {
    if (active_) {
        return;
    }
    
    active_ = true;
    receive_thread_ = std::thread(&ClientSession::receive_loop, this);
}

void ClientSession::stop() {
    active_ = false;
    
    if (socket_) {
        socket_->close();
    }
    
    if (receive_thread_.joinable()) {
        receive_thread_.join();
    }
    
    info_.state = ConnectionState::DISCONNECTED;
}

bool ClientSession::is_active() const {
    return active_;
}

SessionInfo ClientSession::get_info() const {
    std::lock_guard<std::mutex> lock(info_mutex_);
    return info_;
}

void ClientSession::update_activity() {
    std::lock_guard<std::mutex> lock(info_mutex_);
    info_.last_activity = std::chrono::steady_clock::now();
}

bool ClientSession::send_packet(const std::vector<uint8_t>& data) {
    if (!socket_ || !active_) {
        return false;
    }
    
    // Obfuscate
    std::vector<uint8_t> obfuscated;
    if (server_) {
        obfuscated = server_->obfuscate(data);
    } else {
        obfuscated = data;
    }
    
    ssize_t sent = socket_->send(obfuscated.data(), obfuscated.size());
    if (sent < 0) {
        active_ = false;
        return false;
    }
    
    {
        std::lock_guard<std::mutex> lock(info_mutex_);
        info_.bytes_sent += sent;
    }
    
    update_activity();
    return true;
}

bool ClientSession::handle_packet(const std::vector<uint8_t>& data) {
    Packet packet = Packet::deserialize(data);
    
    switch (static_cast<MessageType>(packet.header.type)) {
        case MessageType::HANDSHAKE:
            return perform_handshake();
            
        case MessageType::DATA:
            return handle_data_packet(packet);
            
        case MessageType::HEARTBEAT:
            return handle_heartbeat();
            
        case MessageType::DISCONNECT:
            return handle_disconnect();
            
        default:
            std::cerr << "Unknown message type: " << static_cast<int>(packet.header.type) << std::endl;
            return false;
    }
}

void ClientSession::set_keys(const SessionKeys& keys) {
    session_keys_ = keys;
    
    // Initialize cipher
    std::array<uint8_t, 32> enc_key;
    memcpy(enc_key.data(), keys.encryption_key.data(), 32);
    cipher_ = std::make_unique<AES256GCM>(enc_key);
}

SessionKeys ClientSession::get_keys() const {
    return session_keys_;
}

void ClientSession::receive_loop() {
    // Perform handshake first
    if (!perform_handshake()) {
        std::cerr << "Handshake failed for session " << session_id_ << std::endl;
        active_ = false;
        return;
    }
    
    std::vector<uint8_t> buffer;
    
    while (active_) {
        // Read packet length first (4 bytes)
        uint32_t packet_len = 0;
        ssize_t received = socket_->receive(&packet_len, sizeof(packet_len));
        
        if (received <= 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                continue;
            }
            break;
        }
        
        packet_len = ntohl(packet_len);
        
        if (packet_len > MAX_PACKET_SIZE) {
            std::cerr << "Packet too large: " << packet_len << std::endl;
            continue;
        }
        
        // Read packet data
        buffer.resize(packet_len);
        size_t total_received = 0;
        
        while (total_received < packet_len) {
            received = socket_->receive(buffer.data() + total_received, 
                                       packet_len - total_received);
            if (received <= 0) {
                break;
            }
            total_received += received;
        }
        
        if (total_received != packet_len) {
            std::cerr << "Incomplete packet received" << std::endl;
            continue;
        }
        
        // Deobfuscate
        std::vector<uint8_t> deobfuscated;
        if (server_) {
            deobfuscated = server_->deobfuscate(buffer);
        } else {
            deobfuscated = buffer;
        }
        
        if (deobfuscated.empty()) {
            continue;
        }
        
        // Update stats
        {
            std::lock_guard<std::mutex> lock(info_mutex_);
            info_.bytes_received += total_received;
        }
        update_activity();
        
        // Handle packet
        handle_packet(deobfuscated);
    }
    
    active_ = false;
    std::cout << "Session " << session_id_ << " disconnected" << std::endl;
}

bool ClientSession::perform_handshake() {
    info_.state = ConnectionState::HANDSHAKE_SENT;
    
    // Generate ephemeral key pair
    X25519KeyExchange key_exchange;
    auto public_key = key_exchange.generate_keypair();
    
    if (public_key.empty()) {
        std::cerr << "Failed to generate key pair" << std::endl;
        return false;
    }
    
    // Send ClientHello (or receive from client)
    // For simplicity, we'll do a basic handshake
    
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
    
    // Send handshake
    auto serialized = handshake_packet.serialize();
    
    // Add length prefix
    uint32_t len = htonl(static_cast<uint32_t>(serialized.size()));
    std::vector<uint8_t> to_send;
    to_send.reserve(sizeof(len) + serialized.size());
    to_send.insert(to_send.end(), reinterpret_cast<uint8_t*>(&len), 
                   reinterpret_cast<uint8_t*>(&len) + sizeof(len));
    to_send.insert(to_send.end(), serialized.begin(), serialized.end());
    
    if (!send_packet(to_send)) {
        return false;
    }
    
    // Wait for response (in real implementation)
    // For now, just set up dummy keys
    SessionKeys keys;
    auto enc_key = CryptoRandom::generate_bytes(32);
    auto mac_key = CryptoRandom::generate_bytes(32);
    std::copy(enc_key.begin(), enc_key.end(), keys.encryption_key.begin());
    std::copy(mac_key.begin(), mac_key.end(), keys.mac_key.begin());
    keys.key_id = 1;
    
    set_keys(keys);
    
    info_.state = ConnectionState::CONNECTED;
    info_.connected_time = std::chrono::steady_clock::now();
    update_activity();
    
    std::cout << "Session " << session_id_ << " handshake completed" << std::endl;
    
    return true;
}

bool ClientSession::handle_data_packet(const Packet& packet) {
    if (!cipher_) {
        std::cerr << "Cipher not initialized" << std::endl;
        return false;
    }
    
    // Decrypt payload
    auto decrypted = cipher_->decrypt(packet.payload);
    if (decrypted.empty()) {
        std::cerr << "Failed to decrypt packet" << std::endl;
        return false;
    }
    
    // Process decrypted data (IP packet)
    // In a real implementation, this would be forwarded to the TUN device
    // or processed according to the VPN routing rules
    
    // For now, just log
    // std::cout << "Received " << decrypted.size() << " bytes of data" << std::endl;
    
    return true;
}

bool ClientSession::handle_heartbeat() {
    // Send heartbeat response
    Packet response;
    response.header.type = static_cast<uint8_t>(MessageType::HEARTBEAT);
    response.header.sequence = 0;
    response.header.timestamp = static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
    
    send_packet(response.serialize());
    return true;
}

bool ClientSession::handle_disconnect() {
    active_ = false;
    return true;
}

} // namespace nvpn
