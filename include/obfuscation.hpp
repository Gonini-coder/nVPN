#pragma once

#include "nvpn_protocol.hpp"
#include <vector>
#include <string>
#include <random>

namespace nvpn {

// Obfuscation strategies
enum class ObfuscationMode {
    NONE,           // No obfuscation
    TLS_1_3,        // Disguise as TLS 1.3 traffic
    HTTP_2,         // Disguise as HTTP/2 traffic
    WEBSOCKET,      // Disguise as WebSocket traffic
    RANDOM_PADDING, // Add random padding
    DOMAIN_FRONTING // Domain fronting technique
};

// TLS 1.3 obfuscation
class TLSObfuscator {
public:
    TLSObfuscator();
    
    // Wrap data in fake TLS records
    std::vector<uint8_t> wrap(const std::vector<uint8_t>& data);
    std::vector<uint8_t> unwrap(const std::vector<uint8_t>& data);
    
    // Generate fake TLS ClientHello
    std::vector<uint8_t> generate_client_hello(const std::string& sni_hostname);
    
    // Generate fake TLS ServerHello
    std::vector<uint8_t> generate_server_hello();
    
    // Generate fake TLS Application Data record
    std::vector<uint8_t> generate_application_data(const std::vector<uint8_t>& payload);

private:
    std::mt19937 rng_;
    
    std::vector<uint8_t> generate_random_bytes(size_t length);
    uint16_t get_random_tls_version();
};

// HTTP/2 obfuscation
class HTTP2Obfuscator {
public:
    HTTP2Obfuscator();
    
    std::vector<uint8_t> wrap(const std::vector<uint8_t>& data);
    std::vector<uint8_t> unwrap(const std::vector<uint8_t>& data);
    
    // Generate HTTP/2 HEADERS frame
    std::vector<uint8_t> generate_headers_frame(const std::string& path);
    
    // Generate HTTP/2 DATA frame
    std::vector<uint8_t> generate_data_frame(const std::vector<uint8_t>& payload);
    
    // Generate HTTP/2 SETTINGS frame
    std::vector<uint8_t> generate_settings_frame();

private:
    std::mt19937 rng_;
    uint32_t stream_id_;
    
    std::vector<uint8_t> encode_headers(const std::vector<std::pair<std::string, std::string>>& headers);
};

// WebSocket obfuscation
class WebSocketObfuscator {
public:
    WebSocketObfuscator();
    
    std::vector<uint8_t> wrap(const std::vector<uint8_t>& data);
    std::vector<uint8_t> unwrap(const std::vector<uint8_t>& data);
    
    // Generate WebSocket handshake request
    std::string generate_handshake_request(const std::string& host, const std::string& path);
    
    // Generate WebSocket handshake response
    std::string generate_handshake_response(const std::string& key);
    
    // Generate WebSocket frame
    std::vector<uint8_t> generate_frame(const std::vector<uint8_t>& payload, bool mask = true);

private:
    std::mt19937 rng_;
    
    std::string generate_websocket_key();
    std::string compute_accept_key(const std::string& key);
    std::vector<uint8_t> generate_masking_key();
};

// Traffic shaping and padding
class TrafficShaper {
public:
    TrafficShaper();
    
    // Add random padding to reach target size
    std::vector<uint8_t> pad_to_size(const std::vector<uint8_t>& data, size_t target_size);
    
    // Add variable padding
    std::vector<uint8_t> add_variable_padding(const std::vector<uint8_t>& data, size_t min_pad, size_t max_pad);
    
    // Fragment packet into smaller pieces
    std::vector<std::vector<uint8_t>> fragment_packet(const std::vector<uint8_t>& data, size_t max_fragment_size);
    
    // Add timing jitter
    void add_jitter(int base_delay_ms, int jitter_ms);

private:
    std::mt19937 rng_;
};

// Domain fronting
class DomainFronting {
public:
    DomainFronting(const std::string& front_domain, const std::string& actual_domain);
    
    std::string get_front_host() const;
    std::string get_actual_host() const;
    
    // Modify HTTP headers for domain fronting
    std::vector<std::pair<std::string, std::string>> apply_fronting(
        const std::vector<std::pair<std::string, std::string>>& headers
    );

private:
    std::string front_domain_;
    std::string actual_domain_;
};

// Main obfuscation manager
class ObfuscationManager {
public:
    ObfuscationManager(ObfuscationMode mode = ObfuscationMode::TLS_1_3);
    
    void set_mode(ObfuscationMode mode);
    ObfuscationMode get_mode() const;
    
    std::vector<uint8_t> obfuscate(const std::vector<uint8_t>& data);
    std::vector<uint8_t> deobfuscate(const std::vector<uint8_t>& data);
    
    // Set SNI hostname for TLS obfuscation
    void set_sni_hostname(const std::string& hostname);
    
    // Set domain fronting domains
    void set_domain_fronting(const std::string& front, const std::string& actual);

private:
    ObfuscationMode mode_;
    TLSObfuscator tls_obfuscator_;
    HTTP2Obfuscator http2_obfuscator_;
    WebSocketObfuscator websocket_obfuscator_;
    TrafficShaper traffic_shaper_;
    std::unique_ptr<DomainFronting> domain_fronting_;
    
    std::string sni_hostname_;
};

} // namespace nvpn