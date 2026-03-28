#include "tun_device.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <errno.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#ifdef __linux__
    #include <linux/if_tun.h>
#elif __APPLE__
    #include <sys/kern_control.h>
    #include <net/if_utun.h>
    #include <sys/sys_domain.h>
    #include <sys/socket.h>
#endif

namespace nvpn {

// TUN device implementation
TUNDevice::TUNDevice()
    : tun_fd_(-1)
    , running_(false) {
}

TUNDevice::~TUNDevice() {
    destroy();
}

bool TUNDevice::create(const TUNConfig& config) {
    config_ = config;
    
#ifdef __linux__
    if (!create_tun_linux()) {
        return false;
    }
#elif __APPLE__
    if (!create_tun_macos()) {
        return false;
    }
#else
    std::cerr << "TUN device not supported on this platform" << std::endl;
    return false;
#endif
    
    if (!configure_interface()) {
        close(tun_fd_);
        tun_fd_ = -1;
        return false;
    }
    
    return true;
}

#ifdef __linux__
bool TUNDevice::create_tun_linux() {
    tun_fd_ = open("/dev/net/tun", O_RDWR);
    if (tun_fd_ < 0) {
        std::cerr << "Failed to open /dev/net/tun: " << strerror(errno) << std::endl;
        return false;
    }
    
    struct ifreq ifr{};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    
    if (!config_.name.empty()) {
        strncpy(ifr.ifr_name, config_.name.c_str(), IFNAMSIZ - 1);
    }
    
    if (ioctl(tun_fd_, TUNSETIFF, (void*)&ifr) < 0) {
        std::cerr << "Failed to configure TUN device: " << strerror(errno) << std::endl;
        close(tun_fd_);
        tun_fd_ = -1;
        return false;
    }
    
    config_.name = ifr.ifr_name;
    
    // Set persistent
    int persist = 1;
    ioctl(tun_fd_, TUNSETPERSIST, persist);
    
    return true;
}
#endif

#ifdef __APPLE__
bool TUNDevice::create_tun_macos() {
    // Find an available utun device
    for (int i = 0; i < 256; i++) {
        std::string dev_name = "/dev/utun" + std::to_string(i);
        tun_fd_ = open(dev_name.c_str(), O_RDWR);
        
        if (tun_fd_ >= 0) {
            config_.name = "utun" + std::to_string(i);
            
            // Connect to the system
            struct sockaddr_ctl sc{};
            sc.sc_len = sizeof(sc);
            sc.sc_family = AF_SYSTEM;
            sc.ss_sysaddr = AF_SYS_CONTROL;
            
            // Get control ID
            struct ctl_info ctl_info{};
            strncpy(ctl_info.ctl_name, UTUN_CONTROL_NAME, sizeof(ctl_info.ctl_name) - 1);
            
            if (ioctl(tun_fd_, CTLIOCGINFO, &ctl_info) < 0) {
                close(tun_fd_);
                tun_fd_ = -1;
                continue;
            }
            
            sc.sc_id = ctl_info.ctl_id;
            sc.sc_unit = i + 1;
            
            if (connect(tun_fd_, (struct sockaddr*)&sc, sizeof(sc)) < 0) {
                close(tun_fd_);
                tun_fd_ = -1;
                continue;
            }
            
            return true;
        }
    }
    
    std::cerr << "Failed to create TUN device on macOS" << std::endl;
    return false;
}
#endif

bool TUNDevice::configure_interface() {
    std::ostringstream oss;
    
#ifdef __linux__
    // Bring interface up
    oss << "ip link set dev " << config_.name << " up";
    system(oss.str().c_str());
    oss.str("");
    
    // Set IP address
    oss << "ip addr add " << config_.local_address << "/" 
       << config_.netmask << " dev " << config_.name;
    system(oss.str().c_str());
    oss.str("");
    
    // Set MTU
    oss << "ip link set dev " << config_.name << " mtu " << config_.mtu;
    system(oss.str().c_str());
    
#elif __APPLE__
    // Bring interface up
    oss << "ifconfig " << config_.name << " inet " << config_.local_address 
       << " " << config_.remote_address << " up";
    system(oss.str().c_str());
    oss.str("");
    
    // Set MTU
    oss << "ifconfig " << config_.name << " mtu " << config_.mtu;
    system(oss.str().c_str());
#endif
    
    return true;
}

bool TUNDevice::destroy() {
    stop();
    
    if (tun_fd_ >= 0) {
        close(tun_fd_);
        tun_fd_ = -1;
    }
    
    return true;
}

bool TUNDevice::write_packet(const std::vector<uint8_t>& packet) {
    if (tun_fd_ < 0) {
        return false;
    }
    
    ssize_t written = write(tun_fd_, packet.data(), packet.size());
    return written == static_cast<ssize_t>(packet.size());
}

bool TUNDevice::read_packet(std::vector<uint8_t>& packet) {
    if (tun_fd_ < 0) {
        return false;
    }
    
    packet.resize(MAX_PACKET_SIZE);
    ssize_t n = read(tun_fd_, packet.data(), packet.size());
    
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            packet.clear();
            return true;
        }
        return false;
    }
    
    packet.resize(n);
    return true;
}

bool TUNDevice::start(PacketCallback callback) {
    if (running_) {
        return false;
    }
    
    packet_callback_ = callback;
    running_ = true;
    
    read_thread_ = std::thread(&TUNDevice::read_loop, this);
    
    return true;
}

void TUNDevice::stop() {
    running_ = false;
    
    if (read_thread_.joinable()) {
        read_thread_.join();
    }
}

void TUNDevice::read_loop() {
    std::vector<uint8_t> packet;
    
    while (running_) {
        if (read_packet(packet) && !packet.empty()) {
            if (packet_callback_) {
                packet_callback_(packet);
            }
        }
    }
}

std::string TUNDevice::get_name() const {
    return config_.name;
}

int TUNDevice::get_mtu() const {
    return config_.mtu;
}

bool TUNDevice::is_running() const {
    return running_;
}

int TUNDevice::get_fd() const {
    return tun_fd_;
}

bool TUNDevice::add_route(const std::string& destination, const std::string& gateway) {
    std::ostringstream oss;
#ifdef __linux__
    oss << "ip route add " << destination << " via " << gateway << " dev " << config_.name;
#elif __APPLE__
    oss << "route add " << destination << " " << gateway;
#endif
    return system(oss.str().c_str()) == 0;
}

bool TUNDevice::delete_route(const std::string& destination) {
    std::ostringstream oss;
#ifdef __linux__
    oss << "ip route del " << destination;
#elif __APPLE__
    oss << "route delete " << destination;
#endif
    return system(oss.str().c_str()) == 0;
}

bool TUNDevice::set_default_route() {
    std::ostringstream oss;
#ifdef __linux__
    oss << "ip route add default dev " << config_.name;
#elif __APPLE__
    oss << "route add default -interface " << config_.name;
#endif
    return system(oss.str().c_str()) == 0;
}

bool TUNDevice::restore_routes() {
    // This is a placeholder - in production, save and restore original routes
    return true;
}

// IP packet utilities
uint8_t IPPacketUtils::get_ip_version(const std::vector<uint8_t>& packet) {
    if (packet.empty()) return 0;
    return (packet[0] >> 4) & 0x0F;
}

uint8_t IPPacketUtils::get_protocol(const std::vector<uint8_t>& packet) {
    if (packet.size() < 10) return 0;
    return packet[9];
}

std::string IPPacketUtils::get_source_ip(const std::vector<uint8_t>& packet) {
    if (packet.size() < 16) return "";
    
    char ip_str[INET_ADDRSTRLEN];
    struct in_addr addr;
    addr.s_addr = (packet[12] << 24) | (packet[13] << 16) | (packet[14] << 8) | packet[15];
    inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
    
    return std::string(ip_str);
}

std::string IPPacketUtils::get_destination_ip(const std::vector<uint8_t>& packet) {
    if (packet.size() < 20) return "";
    
    char ip_str[INET_ADDRSTRLEN];
    struct in_addr addr;
    addr.s_addr = (packet[16] << 24) | (packet[17] << 16) | (packet[18] << 8) | packet[19];
    inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
    
    return std::string(ip_str);
}

uint16_t IPPacketUtils::get_source_port(const std::vector<uint8_t>& packet) {
    size_t header_len = (packet[0] & 0x0F) * 4;
    if (packet.size() < header_len + 2) return 0;
    
    return (static_cast<uint16_t>(packet[header_len]) << 8) | packet[header_len + 1];
}

uint16_t IPPacketUtils::get_destination_port(const std::vector<uint8_t>& packet) {
    size_t header_len = (packet[0] & 0x0F) * 4;
    if (packet.size() < header_len + 4) return 0;
    
    return (static_cast<uint16_t>(packet[header_len + 2]) << 8) | packet[header_len + 3];
}

size_t IPPacketUtils::get_payload_offset(const std::vector<uint8_t>& packet) {
    if (packet.size() < 1) return 0;
    return (packet[0] & 0x0F) * 4;
}

std::vector<uint8_t> IPPacketUtils::create_ip_packet(
    const std::string& src_ip,
    const std::string& dst_ip,
    uint8_t protocol,
    const std::vector<uint8_t>& payload) {
    
    size_t total_len = 20 + payload.size();
    std::vector<uint8_t> packet(total_len);
    
    // Version (4) and IHL (5)
    packet[0] = 0x45;
    
    // DSCP and ECN
    packet[1] = 0;
    
    // Total length
    packet[2] = (total_len >> 8) & 0xFF;
    packet[3] = total_len & 0xFF;
    
    // Identification
    packet[4] = 0;
    packet[5] = 0;
    
    // Flags and fragment offset
    packet[6] = 0x40; // Don't fragment
    packet[7] = 0;
    
    // TTL
    packet[8] = 64;
    
    // Protocol
    packet[9] = protocol;
    
    // Checksum field must be 0 for calculation
    packet[10] = 0;
    packet[11] = 0;
    
    // Source IP
    struct in_addr src_addr;
    inet_pton(AF_INET, src_ip.c_str(), &src_addr);
    memcpy(&packet[12], &src_addr, 4);
    
    // Destination IP
    struct in_addr dst_addr;
    inet_pton(AF_INET, dst_ip.c_str(), &dst_addr);
    memcpy(&packet[16], &dst_addr, 4);
    
    // Calculate checksum
    uint16_t checksum = calculate_ip_checksum(std::vector<uint8_t>(packet.begin(), packet.begin() + 20));
    packet[10] = (checksum >> 8) & 0xFF;
    packet[11] = checksum & 0xFF;
    
    // Payload
    memcpy(&packet[20], payload.data(), payload.size());
    
    return packet;
}

uint16_t IPPacketUtils::calculate_ip_checksum(const std::vector<uint8_t>& header) {
    uint32_t sum = 0;
    
    for (size_t i = 0; i < header.size(); i += 2) {
        uint16_t word = header[i];
        if (i + 1 < header.size()) {
            word = (word << 8) | header[i + 1];
        }
        sum += word;
    }
    
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return ~static_cast<uint16_t>(sum);
}

uint16_t IPPacketUtils::calculate_tcp_checksum(const std::vector<uint8_t>& packet) {
    // Pseudo-header + TCP header + data
    // Simplified implementation
    return 0;
}

uint16_t IPPacketUtils::calculate_udp_checksum(const std::vector<uint8_t>& packet) {
    // Pseudo-header + UDP header + data
    // Simplified implementation
    return 0;
}

// Route manager
RouteManager::RouteManager() {
}

RouteManager::~RouteManager() {
    restore_saved_routes();
}

bool RouteManager::save_current_routes() {
    // Save current default route
    // Implementation depends on platform
    return true;
}

bool RouteManager::restore_saved_routes() {
    // Restore saved routes
    return true;
}

bool RouteManager::add_route(const std::string& destination, const std::string& gateway, const std::string& interface) {
    std::ostringstream oss;
#ifdef __linux__
    oss << "ip route add " << destination << " via " << gateway;
    if (!interface.empty()) {
        oss << " dev " << interface;
    }
#elif __APPLE__
    oss << "route add " << destination << " " << gateway;
#endif
    return system(oss.str().c_str()) == 0;
}

bool RouteManager::delete_route(const std::string& destination) {
    std::ostringstream oss;
#ifdef __linux__
    oss << "ip route del " << destination;
#elif __APPLE__
    oss << "route delete " << destination;
#endif
    return system(oss.str().c_str()) == 0;
}

bool RouteManager::flush_routes() {
    std::ostringstream oss;
#ifdef __linux__
    oss << "ip route flush table main";
#elif __APPLE__
    oss << "route flush";
#endif
    return system(oss.str().c_str()) == 0;
}

std::vector<std::string> RouteManager::get_routes() const {
    std::vector<std::string> routes;
    // Parse output of 'ip route' or 'netstat -rn'
    return routes;
}

// DNS manager
DNSManager::DNSManager() {
}

DNSManager::~DNSManager() {
    restore_dns();
}

bool DNSManager::set_dns_servers(const std::vector<std::string>& dns_servers) {
    backup_resolv_conf();
    return write_resolv_conf(dns_servers);
}

bool DNSManager::restore_dns() {
    if (!resolv_conf_backup_.empty()) {
        std::ofstream ofs("/etc/resolv.conf");
        if (ofs) {
            ofs << resolv_conf_backup_;
            return true;
        }
    }
    return false;
}

bool DNSManager::hijack_dns(const std::string& vpn_dns_server) {
    return set_dns_servers({vpn_dns_server});
}

bool DNSManager::release_dns() {
    return restore_dns();
}

bool DNSManager::backup_resolv_conf() {
    std::ifstream ifs("/etc/resolv.conf");
    if (ifs) {
        std::ostringstream oss;
        oss << ifs.rdbuf();
        resolv_conf_backup_ = oss.str();
        return true;
    }
    return false;
}

bool DNSManager::write_resolv_conf(const std::vector<std::string>& dns_servers) {
    std::ofstream ofs("/etc/resolv.conf");
    if (!ofs) {
        return false;
    }
    
    for (const auto& server : dns_servers) {
        ofs << "nameserver " << server << std::endl;
    }
    
    return true;
}

} // namespace nvpn