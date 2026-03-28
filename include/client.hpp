#pragma once

#include "nvpn_protocol.hpp"
#include "crypto.hpp"
#include "network.hpp"
#include "obfuscation.hpp"
#include "tun_device.hpp"
#include <thread>
#include <atomic>
#include <queue>
#include <mutex>
#include <condition_variable>

namespace nvpn {

// Client configuration
struct ClientConfig {
    std::string server_host;
    uint16_t server_port;
    uint16_t server_udp_port;
    
    std::string username;
    std::string password;
    std::string auth_token;
    
    std::string local_tun_ip;
    std::string remote_tun_ip;
    std::string dns_server;
    
    int mtu;
    int keepalive_interval;
    int reconnect_attempts;
    int reconnect_delay;
    
    bool use_udp;
    bool redirect_gateway;
    bool hijack_dns;
    
    ObfuscationMode obfuscation_mode;
    std::string sni_hostname;
    std::string front_domain;
    
    // Routes to tunnel (CIDR notation)
    std::vector<std::string> routes;
    
    // Routes to exclude from tunneling
    std::vector<std::string> excluded_routes;
    
    ClientConfig()
        : server_port(DEFAULT_PORT)
        , server_udp_port(DEFAULT_PORT_UDP)
        , mtu(1400)
        , keepalive_interval(25)
        , reconnect_attempts(5)
        , reconnect_delay(5)
        , use_udp(true)
        , redirect_gateway(true)
        , hijack_dns(true)
        , obfuscation_mode(ObfuscationMode::TLS_1_3)
    {}
};

// Connection statistics
struct ConnectionStats {
    std::chrono::steady_clock::time_point connected_time;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t packets_sent;
    uint64_t packets_received;
    uint32_t retransmissions;
    uint32_t dropped_packets;
    double average_latency_ms;
};

// VPN Client class
class VPNClient {
public:
    VPNClient();
    ~VPNClient();

    bool initialize(const ClientConfig& config);
    bool connect();
    void disconnect();
    bool is_connected() const;
    ConnectionState get_state() const;
    
    // Statistics
    ConnectionStats get_stats() const;
    std::string get_assigned_ip() const;
    
    // Configuration
    void set_config(const ClientConfig& config);
    ClientConfig get_config() const;

private:
    ClientConfig config_;
    std::atomic<ConnectionState> state_;
    std::atomic<bool> should_stop_;
    
    // Network connections
    std::unique_ptr<TCPConnection> tcp_connection_;
    std::unique_ptr<UDPSocket> udp_socket_;
    
    // TUN device
    std::unique_ptr<TUNDevice> tun_device_;
    
    // Crypto
    SessionKeys session_keys_;
    std::unique_ptr<AES256GCM> cipher_;
    
    // Obfuscation
    std::unique_ptr<ObfuscationManager> obfuscation_manager_;
    
    // Threads
    std::thread tun_read_thread_;
    std::thread network_read_thread_;
    std::thread keepalive_thread_;
    
    // Statistics
    ConnectionStats stats_;
    mutable std::mutex stats_mutex_;
    
    // Assigned IP from server
    std::string assigned_ip_;
    std::string server_tun_ip_;
    
    // Packet queues
    std::queue<std::vector<uint8_t>> outbound_queue_;
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    
    // Private methods
    bool perform_handshake();
    bool setup_tun_device();
    bool setup_routing();
    bool restore_routing();
    
    void tun_read_loop();
    void network_read_loop();
    void keepalive_loop();
    
    bool send_to_server(const std::vector<uint8_t>& data);
    bool receive_from_server(std::vector<uint8_t>& data);
    
    bool handle_tun_packet(const std::vector<uint8_t>& packet);
    bool handle_server_packet(const std::vector<uint8_t>& packet);
    
    bool send_heartbeat();
    void update_stats(uint64_t bytes_sent = 0, uint64_t bytes_received = 0);
    
    bool reconnect();
    void cleanup();
};

// TUN packet handler
class TUNPacketHandler {
public:
    TUNPacketHandler(VPNClient* client);
    
    bool handle_packet(const std::vector<uint8_t>& packet);
    bool should_route_through_vpn(const std::vector<uint8_t>& packet) const;
    
    void add_route(const std::string& route);
    void remove_route(const std::string& route);
    void clear_routes();
    
    void add_excluded_route(const std::string& route);
    void remove_excluded_route(const std::string& route);

private:
    VPNClient* client_;
    std::vector<std::string> routes_;
    std::vector<std::string> excluded_routes_;
    mutable std::mutex routes_mutex_;
    
    bool is_in_subnet(const std::string& ip, const std::string& subnet) const;
    bool matches_route(const std::string& dest_ip, const std::string& route) const;
};

} // namespace nvpn