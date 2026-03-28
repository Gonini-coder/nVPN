#pragma once

#include "nvpn_protocol.hpp"
#include <string>
#include <functional>
#include <memory>
#include <atomic>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <netdb.h>
#endif

namespace nvpn {

// Platform abstraction for sockets
#ifdef _WIN32
    using SocketType = SOCKET;
    constexpr SocketType INVALID_SOCKET_VALUE = INVALID_SOCKET;
#else
    using SocketType = int;
    constexpr SocketType INVALID_SOCKET_VALUE = -1;
#endif

// Socket wrapper class
class Socket {
public:
    enum class Type {
        TCP,
        UDP
    };

    Socket(Type type);
    ~Socket();

    // Disable copy
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;

    // Enable move
    Socket(Socket&& other) noexcept;
    Socket& operator=(Socket&& other) noexcept;

    bool create();
    bool bind(const std::string& address, uint16_t port);
    bool listen(int backlog = 128);
    bool connect(const std::string& address, uint16_t port);
    std::unique_ptr<Socket> accept();
    
    bool set_non_blocking(bool non_blocking);
    bool set_reuse_addr(bool reuse);
    bool set_tcp_nodelay(bool nodelay);
    bool set_keepalive(bool keepalive);
    bool set_send_buffer_size(int size);
    bool set_recv_buffer_size(int size);
    
    ssize_t send(const void* data, size_t length);
    ssize_t receive(void* buffer, size_t max_length);
    
    ssize_t send_to(const void* data, size_t length, const sockaddr* addr, socklen_t addr_len);
    ssize_t receive_from(void* buffer, size_t max_length, sockaddr* addr, socklen_t* addr_len);
    
    bool close();
    bool is_valid() const;
    SocketType get_handle() const;

private:
    Type type_;
    SocketType socket_;
    bool is_non_blocking_;
};

// TCP connection handler
class TCPConnection {
public:
    TCPConnection();
    explicit TCPConnection(Socket&& socket);
    ~TCPConnection();

    bool connect(const std::string& host, uint16_t port);
    bool disconnect();
    
    bool send(const std::vector<uint8_t>& data);
    bool receive(std::vector<uint8_t>& data, size_t max_length = MAX_PACKET_SIZE);
    
    bool is_connected() const;
    std::string get_remote_address() const;
    uint16_t get_remote_port() const;

private:
    std::unique_ptr<Socket> socket_;
    std::atomic<bool> connected_;
    std::string remote_address_;
    uint16_t remote_port_;
};

// UDP socket handler
class UDPSocket {
public:
    UDPSocket();
    ~UDPSocket();

    bool bind(const std::string& address, uint16_t port);
    bool connect(const std::string& host, uint16_t port);
    
    bool send(const std::vector<uint8_t>& data);
    bool send_to(const std::vector<uint8_t>& data, const std::string& host, uint16_t port);
    bool receive(std::vector<uint8_t>& data);
    bool receive_from(std::vector<uint8_t>& data, std::string& from_host, uint16_t& from_port);
    
    bool close();
    bool is_bound() const;

private:
    std::unique_ptr<Socket> socket_;
    std::atomic<bool> bound_;
    std::atomic<bool> connected_;
};

// Network utilities
class NetworkUtils {
public:
    static bool initialize_networking();
    static void cleanup_networking();
    
    static std::string resolve_hostname(const std::string& hostname);
    static std::string get_local_address();
    static std::vector<std::string> get_all_local_addresses();
    
    static bool is_valid_ipv4(const std::string& address);
    static bool is_valid_ipv6(const std::string& address);
    static bool is_valid_port(uint16_t port);
};

// Async I/O handler
class AsyncIOHandler {
public:
    using DataCallback = std::function<void(const std::vector<uint8_t>&)>;
    using ErrorCallback = std::function<void(const std::string&)>;

    AsyncIOHandler();
    ~AsyncIOHandler();

    bool start();
    void stop();
    
    void set_data_callback(DataCallback callback);
    void set_error_callback(ErrorCallback callback);
    
    bool register_socket(SocketType socket);
    bool unregister_socket(SocketType socket);

private:
    std::atomic<bool> running_;
    DataCallback data_callback_;
    ErrorCallback error_callback_;
    
    void io_loop();
};

} // namespace nvpn