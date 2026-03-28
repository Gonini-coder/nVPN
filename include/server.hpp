#pragma once

#include "nvpn_protocol.hpp"
#include "crypto.hpp"
#include "network.hpp"
#include "obfuscation.hpp"
#include <thread>
#include <mutex>
#include <map>
#include <atomic>

namespace nvpn {

// Forward declarations
class ClientSession;

// Server configuration
struct ServerConfig {
    std::string bind_address;
    uint16_t port;
    uint16_t udp_port;
    
    std::string cert_path;
    std::string key_path;
    
    std::string vpn_network;
    std::string vpn_netmask;
    std::string vpn_gateway;
    
    size_t max_clients;
    int keepalive_interval;
    int handshake_timeout;
    
    ObfuscationMode obfuscation_mode;
    std::string sni_hostname;
    
    ServerConfig() 
        : bind_address("0.0.0.0")
        , port(DEFAULT_PORT)
        , udp_port(DEFAULT_PORT_UDP)
        , vpn_network("10.8.0.0")
        , vpn_netmask("255.255.255.0")
        , vpn_gateway("10.8.0.1")
        , max_clients(100)
        , keepalive_interval(30)
        , handshake_timeout(60)
        , obfuscation_mode(ObfuscationMode::TLS_1_3)
    {}
};

// Client session info
struct SessionInfo {
    uint32_t session_id;
    std::string client_address;
    uint16_t client_port;
    std::string assigned_ip;
    std::chrono::steady_clock::time_point connected_time;
    std::chrono::steady_clock::time_point last_activity;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    ConnectionState state;
    SessionKeys keys;
};

// VPN Server class
class VPNServer {
public:
    VPNServer();
    ~VPNServer();

    bool initialize(const ServerConfig& config);
    bool start();
    void stop();
    bool is_running() const;

    // Statistics
    size_t get_active_sessions() const;
    std::vector<SessionInfo> get_session_list() const;
    bool disconnect_client(uint32_t session_id);
    
    // Configuration
    void set_config(const ServerConfig& config);
    ServerConfig get_config() const;

    // Obfuscation operations
    std::vector<uint8_t> obfuscate(const std::vector<uint8_t>& data) const;
    std::vector<uint8_t> deobfuscate(const std::vector<uint8_t>& data) const;

private:
    ServerConfig config_;
    std::atomic<bool> running_;
    
    // Network sockets
    std::unique_ptr<Socket> tcp_socket_;
    std::unique_ptr<UDPSocket> udp_socket_;
    
    // Client sessions
    std::map<uint32_t, std::unique_ptr<ClientSession>> sessions_;
    mutable std::mutex sessions_mutex_;
    uint32_t next_session_id_;
    
    // IP address pool
    std::vector<std::string> ip_pool_;
    std::map<std::string, uint32_t> ip_to_session_;
    std::mutex ip_pool_mutex_;
    
    // Threads
    std::thread accept_thread_;
    std::thread udp_thread_;
    std::thread maintenance_thread_;
    
    // Obfuscation
    std::unique_ptr<ObfuscationManager> obfuscation_manager_;
    
    // Certificate manager
    CertificateManager cert_manager_;
    
    // Private methods
    void accept_loop();
    void udp_loop();
    void maintenance_loop();
    
    bool handle_new_connection(std::unique_ptr<Socket> client_socket);
    void handle_udp_packet(const std::vector<uint8_t>& data, const std::string& from_host, uint16_t from_port);
    
    std::string allocate_ip_address();
    void release_ip_address(const std::string& ip);
    
    void cleanup_inactive_sessions();
    void send_keepalive_packets();
};

// Client session handler
class ClientSession {
public:
    ClientSession(uint32_t session_id, std::unique_ptr<Socket> socket, VPNServer* server);
    ~ClientSession();

    bool initialize(const std::string& assigned_ip);
    void start();
    void stop();
    bool is_active() const;
    
    SessionInfo get_info() const;
    void update_activity();
    
    bool send_packet(const std::vector<uint8_t>& data);
    bool handle_packet(const std::vector<uint8_t>& data);
    
    void set_keys(const SessionKeys& keys);
    SessionKeys get_keys() const;

private:
    uint32_t session_id_;
    std::unique_ptr<Socket> socket_;
    VPNServer* server_;
    
    SessionInfo info_;
    mutable std::mutex info_mutex_;
    
    SessionKeys session_keys_;
    std::unique_ptr<AES256GCM> cipher_;
    
    std::atomic<bool> active_;
    std::thread receive_thread_;
    
    void receive_loop();
    bool perform_handshake();
    bool handle_data_packet(const Packet& packet);
    bool handle_heartbeat();
    bool handle_disconnect();
};

} // namespace nvpn