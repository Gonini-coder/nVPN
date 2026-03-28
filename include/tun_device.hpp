#pragma once

#include "nvpn_protocol.hpp"
#include <string>
#include <functional>
#include <atomic>
#include <thread>

#ifdef __linux__
    #include <linux/if_tun.h>
#elif __APPLE__
    #include <sys/kern_control.h>
    #include <net/if_utun.h>
    #include <sys/sys_domain.h>
#endif

#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>

namespace nvpn {

// TUN device configuration
struct TUNConfig {
    std::string name;           // Interface name (e.g., "tun0")
    std::string local_address;    // Local VPN IP
    std::string remote_address; // Remote VPN IP
    std::string netmask;        // Netmask
    int mtu;                    // MTU size
    bool is_tap;                // TAP (Ethernet) vs TUN (IP) mode
    
    TUNConfig() : mtu(1400), is_tap(false) {}
};

// Platform-specific TUN device implementation
class TUNDevice {
public:
    using PacketCallback = std::function<void(const std::vector<uint8_t>&)>;

    TUNDevice();
    ~TUNDevice();

    // Disable copy
    TUNDevice(const TUNDevice&) = delete;
    TUNDevice& operator=(const TUNDevice&) = delete;

    // Initialize and configure TUN device
    bool create(const TUNConfig& config);
    bool destroy();
    
    // Read/write packets
    bool write_packet(const std::vector<uint8_t>& packet);
    bool read_packet(std::vector<uint8_t>& packet);
    
    // Start/stop packet processing loop
    bool start(PacketCallback callback);
    void stop();
    
    // Get device info
    std::string get_name() const;
    int get_mtu() const;
    bool is_running() const;
    int get_fd() const;

    // Route management
    bool add_route(const std::string& destination, const std::string& gateway);
    bool delete_route(const std::string& destination);
    bool set_default_route();
    bool restore_routes();

private:
    TUNConfig config_;
    int tun_fd_;
    std::atomic<bool> running_;
    std::thread read_thread_;
    PacketCallback packet_callback_;
    
    // Platform-specific implementations
    bool create_tun_linux();
    bool create_tun_macos();
    bool create_tun_windows();
    
    bool configure_interface();
    bool setup_routing();
    
    void read_loop();
};

// IP packet utilities
class IPPacketUtils {
public:
    // Parse IP packet
    static uint8_t get_ip_version(const std::vector<uint8_t>& packet);
    static uint8_t get_protocol(const std::vector<uint8_t>& packet);
    static std::string get_source_ip(const std::vector<uint8_t>& packet);
    static std::string get_destination_ip(const std::vector<uint8_t>& packet);
    static uint16_t get_source_port(const std::vector<uint8_t>& packet);
    static uint16_t get_destination_port(const std::vector<uint8_t>& packet);
    static size_t get_payload_offset(const std::vector<uint8_t>& packet);
    
    // Create IP packet
    static std::vector<uint8_t> create_ip_packet(
        const std::string& src_ip,
        const std::string& dst_ip,
        uint8_t protocol,
        const std::vector<uint8_t>& payload
    );
    
    // Calculate checksums
    static uint16_t calculate_ip_checksum(const std::vector<uint8_t>& header);
    static uint16_t calculate_tcp_checksum(const std::vector<uint8_t>& packet);
    static uint16_t calculate_udp_checksum(const std::vector<uint8_t>& packet);
};

// Routing table management
class RouteManager {
public:
    RouteManager();
    ~RouteManager();

    bool add_route(const std::string& destination, const std::string& gateway, const std::string& interface);
    bool delete_route(const std::string& destination);
    bool flush_routes();
    
    bool save_current_routes();
    bool restore_saved_routes();
    
    std::vector<std::string> get_routes() const;

private:
    std::vector<std::string> saved_routes_;
    
    bool execute_route_command(const std::string& command);
};

// DNS management
class DNSManager {
public:
    DNSManager();
    ~DNSManager();

    bool set_dns_servers(const std::vector<std::string>& dns_servers);
    bool restore_dns();
    
    bool hijack_dns(const std::string& vpn_dns_server);
    bool release_dns();

private:
    std::vector<std::string> original_dns_;
    std::string resolv_conf_backup_;
    
    bool backup_resolv_conf();
    bool write_resolv_conf(const std::vector<std::string>& dns_servers);
};

} // namespace nvpn