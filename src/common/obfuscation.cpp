#include "obfuscation.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <chrono>
#include <openssl/sha.h>
#include <thread>

namespace nvpn {

// TLS 1.3 obfuscation
TLSObfuscator::TLSObfuscator() 
    : rng_(std::random_device{}()) {
}

std::vector<uint8_t> TLSObfuscator::generate_random_bytes(size_t length) {
    std::vector<uint8_t> result(length);
    std::uniform_int_distribution<int> dist(0, 255);
    for (auto& byte : result) {
        byte = static_cast<uint8_t>(dist(rng_));
    }
    return result;
}

uint16_t TLSObfuscator::get_random_tls_version() {
    std::uniform_int_distribution<int> dist(0, 2);
    switch (dist(rng_)) {
        case 0: return 0x0301; // TLS 1.0
        case 1: return 0x0302; // TLS 1.1
        default: return 0x0303; // TLS 1.2
    }
}

std::vector<uint8_t> TLSObfuscator::generate_client_hello(const std::string& sni_hostname) {
    std::vector<uint8_t> record;
    
    // Record header
    record.push_back(0x16); // Handshake record type
    record.push_back(0x03);
    record.push_back(0x01); // TLS 1.0 version (for compatibility)
    
    // Handshake header
    record.push_back(0x01); // ClientHello
    
    // We'll fill in the length later
    size_t handshake_start = record.size();
    record.push_back(0x00);
    record.push_back(0x00);
    record.push_back(0x00);
    
    size_t handshake_content_start = record.size();
    
    // Client version
    record.push_back(0x03);
    record.push_back(0x03); // TLS 1.2
    
    // Random (32 bytes)
    auto random = generate_random_bytes(32);
    record.insert(record.end(), random.begin(), random.end());
    
    // Session ID length
    record.push_back(0x00);
    
    // Cipher suites
    record.push_back(0x00);
    record.push_back(0x02); // Length
    record.push_back(0xc0);
    record.push_back(0x2f); // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    
    // Compression methods
    record.push_back(0x01); // Length
    record.push_back(0x00); // Null
    
    // Extensions length (placeholder)
    size_t ext_len_pos = record.size();
    record.push_back(0x00);
    record.push_back(0x00);
    
    size_t ext_start = record.size();
    
    // SNI extension
    if (!sni_hostname.empty()) {
        record.push_back(0x00);
        record.push_back(0x00); // Extension type: server_name
        
        size_t sni_len_pos = record.size();
        record.push_back(0x00);
        record.push_back(0x00);
        
        size_t sni_start = record.size();
        
        // SNI list length
        record.push_back(0x00);
        
        // Host name entry
        record.push_back(0x00); // Name type: host_name
        
        // Hostname length
        uint16_t hostname_len = static_cast<uint16_t>(sni_hostname.length());
        record.push_back(static_cast<uint8_t>(hostname_len >> 8));
        record.push_back(static_cast<uint8_t>(hostname_len & 0xFF));
        
        // Hostname
        for (char c : sni_hostname) {
            record.push_back(static_cast<uint8_t>(c));
        }
        
        // Update SNI extension length
        uint16_t sni_len = static_cast<uint16_t>(record.size() - sni_start);
        record[sni_len_pos] = static_cast<uint8_t>(sni_len >> 8);
        record[sni_len_pos + 1] = static_cast<uint8_t>(sni_len & 0xFF);
        
        // Update SNI list length
        record[sni_start] = static_cast<uint8_t>((sni_len - 1) >> 8);
    }
    
    // Supported groups extension
    record.push_back(0x00);
    record.push_back(0x0a); // Extension type: supported_groups
    record.push_back(0x00);
    record.push_back(0x04); // Length
    record.push_back(0x00);
    record.push_back(0x02); // Supported groups list length
    record.push_back(0x00);
    record.push_back(0x17); // secp256r1
    
    // EC point formats extension
    record.push_back(0x00);
    record.push_back(0x0b); // Extension type: ec_point_formats
    record.push_back(0x00);
    record.push_back(0x02); // Length
    record.push_back(0x01); // EC point formats length
    record.push_back(0x00); // Uncompressed
    
    // Update extensions length
    uint16_t ext_len = static_cast<uint16_t>(record.size() - ext_start);
    record[ext_len_pos] = static_cast<uint8_t>(ext_len >> 8);
    record[ext_len_pos + 1] = static_cast<uint8_t>(ext_len & 0xFF);
    
    // Update handshake length
    uint32_t handshake_len = static_cast<uint32_t>(record.size() - handshake_content_start);
    record[handshake_start] = static_cast<uint8_t>((handshake_len >> 16) & 0xFF);
    record[handshake_start + 1] = static_cast<uint8_t>((handshake_len >> 8) & 0xFF);
    record[handshake_start + 2] = static_cast<uint8_t>(handshake_len & 0xFF);
    
    // Update record length
    uint16_t record_len = static_cast<uint16_t>(record.size() - 5);
    record[3] = static_cast<uint8_t>(record_len >> 8);
    record[4] = static_cast<uint8_t>(record_len & 0xFF);
    
    return record;
}

std::vector<uint8_t> TLSObfuscator::generate_server_hello() {
    std::vector<uint8_t> record;
    
    // Record header
    record.push_back(0x16); // Handshake
    record.push_back(0x03);
    record.push_back(0x03); // TLS 1.2
    
    // Handshake header
    record.push_back(0x02); // ServerHello
    record.push_back(0x00);
    record.push_back(0x00);
    record.push_back(0x46); // Length
    
    // Server version
    record.push_back(0x03);
    record.push_back(0x03); // TLS 1.2
    
    // Random (32 bytes)
    auto random = generate_random_bytes(32);
    record.insert(record.end(), random.begin(), random.end());
    
    // Session ID
    record.push_back(0x00); // Length
    
    // Cipher suite
    record.push_back(0xc0);
    record.push_back(0x2f); // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    
    // Compression method
    record.push_back(0x00); // Null
    
    // Extensions length
    record.push_back(0x00);
    record.push_back(0x00);
    
    // Update record length
    uint16_t record_len = static_cast<uint16_t>(record.size() - 5);
    record[3] = static_cast<uint8_t>(record_len >> 8);
    record[4] = static_cast<uint8_t>(record_len & 0xFF);
    
    return record;
}

std::vector<uint8_t> TLSObfuscator::generate_application_data(const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> record;
    
    // Record header
    record.push_back(0x17); // Application Data
    record.push_back(0x03);
    record.push_back(0x03); // TLS 1.2
    
    // Length
    uint16_t len = static_cast<uint16_t>(payload.size());
    record.push_back(static_cast<uint8_t>(len >> 8));
    record.push_back(static_cast<uint8_t>(len & 0xFF));
    
    // Payload
    record.insert(record.end(), payload.begin(), payload.end());
    
    return record;
}

std::vector<uint8_t> TLSObfuscator::wrap(const std::vector<uint8_t>& data) {
    return generate_application_data(data);
}

std::vector<uint8_t> TLSObfuscator::unwrap(const std::vector<uint8_t>& data) {
    if (data.size() < 5) {
        return {};
    }
    
    // Check if it's a TLS record
    if (data[0] != 0x17) { // Not application data
        return {};
    }
    
    // Extract length
    uint16_t len = (static_cast<uint16_t>(data[3]) << 8) | data[4];
    
    if (data.size() < 5 + len) {
        return {};
    }
    
    // Return payload
    return std::vector<uint8_t>(data.begin() + 5, data.begin() + 5 + len);
}

// HTTP/2 obfuscation
HTTP2Obfuscator::HTTP2Obfuscator()
    : rng_(std::random_device{}())
    , stream_id_(1) {
}

std::vector<uint8_t> HTTP2Obfuscator::encode_headers(
    const std::vector<std::pair<std::string, std::string>>& headers) {
    
    std::vector<uint8_t> encoded;
    
    for (const auto& header : headers) {
        // Literal header field with indexing
        encoded.push_back(0x40); // Literal with indexing
        
        // Name length
        encoded.push_back(static_cast<uint8_t>(header.first.length()));
        
        // Name
        for (char c : header.first) {
            encoded.push_back(static_cast<uint8_t>(c));
        }
        
        // Value length
        encoded.push_back(static_cast<uint8_t>(header.second.length()));
        
        // Value
        for (char c : header.second) {
            encoded.push_back(static_cast<uint8_t>(c));
        }
    }
    
    return encoded;
}

std::vector<uint8_t> HTTP2Obfuscator::generate_headers_frame(const std::string& path) {
    std::vector<uint8_t> frame;
    
    // Frame header (9 bytes)
    // Length (3 bytes) - will be set later
    size_t len_pos = frame.size();
    frame.push_back(0x00);
    frame.push_back(0x00);
    frame.push_back(0x00);
    
    // Type: HEADERS (0x01)
    frame.push_back(0x01);
    
    // Flags: END_HEADERS (0x04)
    frame.push_back(0x04);
    
    // Stream ID (4 bytes, first bit must be 0)
    frame.push_back(0x00);
    frame.push_back(static_cast<uint8_t>((stream_id_ >> 16) & 0x7F));
    frame.push_back(static_cast<uint8_t>((stream_id_ >> 8) & 0xFF));
    frame.push_back(static_cast<uint8_t>(stream_id_ & 0xFF));
    
    stream_id_ += 2;
    
    // Headers
    std::vector<std::pair<std::string, std::string>> headers = {
        {":method", "GET"},
        {":scheme", "https"},
        {":authority", "www.example.com"},
        {":path", path},
        {"user-agent", "Mozilla/5.0"},
        {"accept", "*/*"}
    };
    
    auto encoded_headers = encode_headers(headers);
    frame.insert(frame.end(), encoded_headers.begin(), encoded_headers.end());
    
    // Update length
    uint32_t payload_len = static_cast<uint32_t>(encoded_headers.size());
    frame[len_pos] = static_cast<uint8_t>((payload_len >> 16) & 0xFF);
    frame[len_pos + 1] = static_cast<uint8_t>((payload_len >> 8) & 0xFF);
    frame[len_pos + 2] = static_cast<uint8_t>(payload_len & 0xFF);
    
    return frame;
}

std::vector<uint8_t> HTTP2Obfuscator::generate_data_frame(const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> frame;
    
    // Frame header
    uint32_t len = static_cast<uint32_t>(payload.size());
    frame.push_back(static_cast<uint8_t>((len >> 16) & 0xFF));
    frame.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
    frame.push_back(static_cast<uint8_t>(len & 0xFF));
    
    // Type: DATA (0x00)
    frame.push_back(0x00);
    
    // Flags: 0
    frame.push_back(0x00);
    
    // Stream ID
    frame.push_back(0x00);
    frame.push_back(static_cast<uint8_t>((stream_id_ >> 16) & 0x7F));
    frame.push_back(static_cast<uint8_t>((stream_id_ >> 8) & 0xFF));
    frame.push_back(static_cast<uint8_t>(stream_id_ & 0xFF));
    
    // Payload
    frame.insert(frame.end(), payload.begin(), payload.end());
    
    return frame;
}

std::vector<uint8_t> HTTP2Obfuscator::generate_settings_frame() {
    std::vector<uint8_t> frame;
    
    // Settings payload
    std::vector<uint8_t> settings = {
        0x00, 0x01, 0x00, 0x00, 0x10, 0x00, // HEADER_TABLE_SIZE = 4096
        0x00, 0x03, 0x00, 0x00, 0x00, 0x64  // MAX_CONCURRENT_STREAMS = 100
    };
    
    uint32_t len = static_cast<uint32_t>(settings.size());
    frame.push_back(static_cast<uint8_t>((len >> 16) & 0xFF));
    frame.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
    frame.push_back(static_cast<uint8_t>(len & 0xFF));
    
    // Type: SETTINGS (0x04)
    frame.push_back(0x04);
    
    // Flags: 0
    frame.push_back(0x00);
    
    // Stream ID: 0
    frame.push_back(0x00);
    frame.push_back(0x00);
    frame.push_back(0x00);
    frame.push_back(0x00);
    
    // Payload
    frame.insert(frame.end(), settings.begin(), settings.end());
    
    return frame;
}

std::vector<uint8_t> HTTP2Obfuscator::wrap(const std::vector<uint8_t>& data) {
    // For simplicity, just wrap in a DATA frame
    return generate_data_frame(data);
}

std::vector<uint8_t> HTTP2Obfuscator::unwrap(const std::vector<uint8_t>& data) {
    if (data.size() < 9) {
        return {};
    }
    
    // Extract length
    uint32_t len = (static_cast<uint32_t>(data[0]) << 16) |
                   (static_cast<uint32_t>(data[1]) << 8) |
                   data[2];
    
    // Check if it's a DATA frame
    if (data[3] != 0x00) {
        return {};
    }
    
    if (data.size() < 9 + len) {
        return {};
    }
    
    return std::vector<uint8_t>(data.begin() + 9, data.begin() + 9 + len);
}

// WebSocket obfuscation
WebSocketObfuscator::WebSocketObfuscator()
    : rng_(std::random_device{}()) {
}

std::string WebSocketObfuscator::generate_websocket_key() {
    std::vector<uint8_t> key_bytes(16);
    std::uniform_int_distribution<int> dist(0, 255);
    for (auto& byte : key_bytes) {
        byte = static_cast<uint8_t>(dist(rng_));
    }
    
    // Base64 encode
    static const char base64_chars[] = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    std::string result;
    int i = 0;
    uint8_t array_3[3];
    uint8_t array_4[4];
    
    for (uint8_t byte : key_bytes) {
        array_3[i++] = byte;
        if (i == 3) {
            array_4[0] = (array_3[0] & 0xfc) >> 2;
            array_4[1] = ((array_3[0] & 0x03) << 4) + ((array_3[1] & 0xf0) >> 4);
            array_4[2] = ((array_3[1] & 0x0f) << 2) + ((array_3[2] & 0xc0) >> 6);
            array_4[3] = array_3[2] & 0x3f;
            
            for (int j = 0; j < 4; j++) {
                result += base64_chars[array_4[j]];
            }
            i = 0;
        }
    }
    
    if (i > 0) {
        for (int j = i; j < 3; j++) {
            array_3[j] = 0;
        }
        
        array_4[0] = (array_3[0] & 0xfc) >> 2;
        array_4[1] = ((array_3[0] & 0x03) << 4) + ((array_3[1] & 0xf0) >> 4);
        array_4[2] = ((array_3[1] & 0x0f) << 2) + ((array_3[2] & 0xc0) >> 6);
        array_4[3] = array_3[2] & 0x3f;
        
        for (int j = 0; j < (i + 1); j++) {
            result += base64_chars[array_4[j]];
        }
        
        while ((i++ < 3)) {
            result += '=';
        }
    }
    
    return result;
}

std::string WebSocketObfuscator::compute_accept_key(const std::string& key) {
    std::string magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    std::string combined = key + magic;
    
    // SHA-1 hash
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(combined.data()), combined.length(), hash);
    
    // Base64 encode
    static const char base64_chars[] = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    std::string result;
    int i = 0;
    uint8_t array_3[3];
    uint8_t array_4[4];
    
    for (int idx = 0; idx < SHA_DIGEST_LENGTH; idx++) {
        array_3[i++] = hash[idx];
        if (i == 3) {
            array_4[0] = (array_3[0] & 0xfc) >> 2;
            array_4[1] = ((array_3[0] & 0x03) << 4) + ((array_3[1] & 0xf0) >> 4);
            array_4[2] = ((array_3[1] & 0x0f) << 2) + ((array_3[2] & 0xc0) >> 6);
            array_4[3] = array_3[2] & 0x3f;
            
            for (int j = 0; j < 4; j++) {
                result += base64_chars[array_4[j]];
            }
            i = 0;
        }
    }
    
    if (i > 0) {
        for (int j = i; j < 3; j++) {
            array_3[j] = 0;
        }
        
        array_4[0] = (array_3[0] & 0xfc) >> 2;
        array_4[1] = ((array_3[0] & 0x03) << 4) + ((array_3[1] & 0xf0) >> 4);
        array_4[2] = ((array_3[1] & 0x0f) << 2) + ((array_3[2] & 0xc0) >> 6);
        array_4[3] = array_3[2] & 0x3f;
        
        for (int j = 0; j < (i + 1); j++) {
            result += base64_chars[array_4[j]];
        }
        
        while ((i++ < 3)) {
            result += '=';
        }
    }
    
    return result;
}

std::vector<uint8_t> WebSocketObfuscator::generate_masking_key() {
    std::uniform_int_distribution<int> dist(0, 255);
    std::vector<uint8_t> key(4);
    for (auto& byte : key) {
        byte = static_cast<uint8_t>(dist(rng_));
    }
    return key;
}

std::string WebSocketObfuscator::generate_handshake_request(const std::string& host, const std::string& path) {
    std::string key = generate_websocket_key();
    
    std::ostringstream oss;
    oss << "GET " << path << " HTTP/1.1\r\n";
    oss << "Host: " << host << "\r\n";
    oss << "Upgrade: websocket\r\n";
    oss << "Connection: Upgrade\r\n";
    oss << "Sec-WebSocket-Key: " << key << "\r\n";
    oss << "Sec-WebSocket-Version: 13\r\n";
    oss << "\r\n";
    
    return oss.str();
}

std::string WebSocketObfuscator::generate_handshake_response(const std::string& key) {
    std::string accept_key = compute_accept_key(key);
    
    std::ostringstream oss;
    oss << "HTTP/1.1 101 Switching Protocols\r\n";
    oss << "Upgrade: websocket\r\n";
    oss << "Connection: Upgrade\r\n";
    oss << "Sec-WebSocket-Accept: " << accept_key << "\r\n";
    oss << "\r\n";
    
    return oss.str();
}

std::vector<uint8_t> WebSocketObfuscator::generate_frame(const std::vector<uint8_t>& payload, bool mask) {
    std::vector<uint8_t> frame;
    
    // FIN=1, opcode=2 (binary)
    frame.push_back(0x82);
    
    uint64_t len = payload.size();
    std::vector<uint8_t> masking_key;
    
    if (mask) {
        masking_key = generate_masking_key();
    }
    
    if (len < 126) {
        frame.push_back(static_cast<uint8_t>((mask ? 0x80 : 0x00) | len));
    } else if (len < 65536) {
        frame.push_back(static_cast<uint8_t>((mask ? 0x80 : 0x00) | 126));
        frame.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
        frame.push_back(static_cast<uint8_t>(len & 0xFF));
    } else {
        frame.push_back(static_cast<uint8_t>((mask ? 0x80 : 0x00) | 127));
        for (int i = 7; i >= 0; i--) {
            frame.push_back(static_cast<uint8_t>((len >> (i * 8)) & 0xFF));
        }
    }
    
    if (mask) {
        frame.insert(frame.end(), masking_key.begin(), masking_key.end());
    }
    
    // Mask payload if needed
    if (mask) {
        for (size_t i = 0; i < payload.size(); i++) {
            frame.push_back(payload[i] ^ masking_key[i % 4]);
        }
    } else {
        frame.insert(frame.end(), payload.begin(), payload.end());
    }
    
    return frame;
}

std::vector<uint8_t> WebSocketObfuscator::wrap(const std::vector<uint8_t>& data) {
    return generate_frame(data, true);
}

std::vector<uint8_t> WebSocketObfuscator::unwrap(const std::vector<uint8_t>& data) {
    if (data.size() < 2) {
        return {};
    }
    
    size_t pos = 2;
    bool masked = (data[1] & 0x80) != 0;
    uint64_t len = data[1] & 0x7F;
    
    if (len == 126) {
        if (data.size() < 4) return {};
        len = (static_cast<uint64_t>(data[2]) << 8) | data[3];
        pos = 4;
    } else if (len == 127) {
        if (data.size() < 10) return {};
        len = 0;
        for (int i = 0; i < 8; i++) {
            len = (len << 8) | data[2 + i];
        }
        pos = 10;
    }
    
    std::vector<uint8_t> masking_key;
    if (masked) {
        if (data.size() < pos + 4) return {};
        masking_key.assign(data.begin() + pos, data.begin() + pos + 4);
        pos += 4;
    }
    
    if (data.size() < pos + len) {
        return {};
    }
    
    std::vector<uint8_t> result;
    result.reserve(len);
    
    for (uint64_t i = 0; i < len; i++) {
        uint8_t byte = data[pos + i];
        if (masked) {
            byte ^= masking_key[i % 4];
        }
        result.push_back(byte);
    }
    
    return result;
}

// Traffic shaping
TrafficShaper::TrafficShaper()
    : rng_(std::random_device{}()) {
}

std::vector<uint8_t> TrafficShaper::pad_to_size(const std::vector<uint8_t>& data, size_t target_size) {
    if (data.size() >= target_size) {
        return data;
    }
    
    std::vector<uint8_t> result = data;
    std::uniform_int_distribution<int> dist(0, 255);
    
    while (result.size() < target_size) {
        result.push_back(static_cast<uint8_t>(dist(rng_)));
    }
    
    return result;
}

std::vector<uint8_t> TrafficShaper::add_variable_padding(
    const std::vector<uint8_t>& data, size_t min_pad, size_t max_pad) {
    
    std::uniform_int_distribution<size_t> dist(min_pad, max_pad);
    size_t pad_size = dist(rng_);
    
    return pad_to_size(data, data.size() + pad_size);
}

std::vector<std::vector<uint8_t>> TrafficShaper::fragment_packet(
    const std::vector<uint8_t>& data, size_t max_fragment_size) {
    
    std::vector<std::vector<uint8_t>> fragments;
    
    for (size_t i = 0; i < data.size(); i += max_fragment_size) {
        size_t end = std::min(i + max_fragment_size, data.size());
        fragments.emplace_back(data.begin() + i, data.begin() + end);
    }
    
    return fragments;
}

void TrafficShaper::add_jitter(int base_delay_ms, int jitter_ms) {
    std::uniform_int_distribution<int> dist(-jitter_ms, jitter_ms);
    int delay = base_delay_ms + dist(rng_);
    if (delay > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(delay));
    }
}

// Domain fronting
DomainFronting::DomainFronting(const std::string& front_domain, const std::string& actual_domain)
    : front_domain_(front_domain)
    , actual_domain_(actual_domain) {
}

std::string DomainFronting::get_front_host() const {
    return front_domain_;
}

std::string DomainFronting::get_actual_host() const {
    return actual_domain_;
}

std::vector<std::pair<std::string, std::string>> DomainFronting::apply_fronting(
    const std::vector<std::pair<std::string, std::string>>& headers) {
    
    std::vector<std::pair<std::string, std::string>> result = headers;
    
    for (auto& header : result) {
        if (header.first == "Host") {
            header.second = front_domain_;
        }
    }
    
    // Add actual host in a custom header
    result.push_back({"X-Forwarded-Host", actual_domain_});
    
    return result;
}

// Obfuscation manager
ObfuscationManager::ObfuscationManager(ObfuscationMode mode)
    : mode_(mode)
    , domain_fronting_(nullptr) {
}

void ObfuscationManager::set_mode(ObfuscationMode mode) {
    mode_ = mode;
}

ObfuscationMode ObfuscationManager::get_mode() const {
    return mode_;
}

void ObfuscationManager::set_sni_hostname(const std::string& hostname) {
    sni_hostname_ = hostname;
}

void ObfuscationManager::set_domain_fronting(const std::string& front, const std::string& actual) {
    domain_fronting_ = std::make_unique<DomainFronting>(front, actual);
}

std::vector<uint8_t> ObfuscationManager::obfuscate(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> result = data;
    
    // Add variable padding
    result = traffic_shaper_.add_variable_padding(result, 0, 64);
    
    switch (mode_) {
        case ObfuscationMode::TLS_1_3:
            result = tls_obfuscator_.wrap(result);
            break;
            
        case ObfuscationMode::HTTP_2:
            result = http2_obfuscator_.wrap(result);
            break;
            
        case ObfuscationMode::WEBSOCKET:
            result = websocket_obfuscator_.wrap(result);
            break;
            
        case ObfuscationMode::RANDOM_PADDING:
            result = traffic_shaper_.pad_to_size(result, 
                ((result.size() + 255) / 256) * 256); // Round up to 256 bytes
            break;
            
        default:
            break;
    }
    
    return result;
}

std::vector<uint8_t> ObfuscationManager::deobfuscate(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> result = data;
    
    switch (mode_) {
        case ObfuscationMode::TLS_1_3:
            result = tls_obfuscator_.unwrap(result);
            break;
            
        case ObfuscationMode::HTTP_2:
            result = http2_obfuscator_.unwrap(result);
            break;
            
        case ObfuscationMode::WEBSOCKET:
            result = websocket_obfuscator_.unwrap(result);
            break;
            
        default:
            break;
    }
    
    return result;
}

} // namespace nvpn