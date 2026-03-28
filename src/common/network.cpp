#include "network.hpp"
#include <iostream>
#include <errno.h>
#include <string>
#include <thread>
#include <chrono>

namespace nvpn {

// Initialize networking (Windows only)
bool NetworkUtils::initialize_networking() {
#ifdef _WIN32
    WSADATA wsaData;
    return WSAStartup(MAKEWORD(2, 2), &wsaData) == 0;
#else
    return true;
#endif
}

void NetworkUtils::cleanup_networking() {
#ifdef _WIN32
    WSACleanup();
#endif
}

// Socket implementation
Socket::Socket(Type type) 
    : type_(type)
    , socket_(INVALID_SOCKET_VALUE)
    , is_non_blocking_(false) {
}

Socket::~Socket() {
    close();
}

Socket::Socket(Socket&& other) noexcept
    : type_(other.type_)
    , socket_(other.socket_)
    , is_non_blocking_(other.is_non_blocking_) {
    other.socket_ = INVALID_SOCKET_VALUE;
}

Socket& Socket::operator=(Socket&& other) noexcept {
    if (this != &other) {
        close();
        type_ = other.type_;
        socket_ = other.socket_;
        is_non_blocking_ = other.is_non_blocking_;
        other.socket_ = INVALID_SOCKET_VALUE;
    }
    return *this;
}

bool Socket::create() {
    int domain = AF_INET;
    int sock_type = (type_ == Type::TCP) ? SOCK_STREAM : SOCK_DGRAM;
    int protocol = (type_ == Type::TCP) ? IPPROTO_TCP : IPPROTO_UDP;
    
    socket_ = ::socket(domain, sock_type, protocol);
    
    if (socket_ == INVALID_SOCKET_VALUE) {
        std::cerr << "Failed to create socket: " << strerror(errno) << std::endl;
        return false;
    }
    
    return true;
}

bool Socket::bind(const std::string& address, uint16_t port) {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    if (address.empty() || address == "0.0.0.0") {
        addr.sin_addr.s_addr = INADDR_ANY;
    } else {
        if (inet_pton(AF_INET, address.c_str(), &addr.sin_addr) != 1) {
            std::cerr << "Invalid address: " << address << std::endl;
            return false;
        }
    }
    
    if (::bind(socket_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        std::cerr << "Failed to bind socket: " << strerror(errno) << std::endl;
        return false;
    }
    
    return true;
}

bool Socket::listen(int backlog) {
    if (::listen(socket_, backlog) != 0) {
        std::cerr << "Failed to listen on socket: " << strerror(errno) << std::endl;
        return false;
    }
    return true;
}

bool Socket::connect(const std::string& address, uint16_t port) {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, address.c_str(), &addr.sin_addr) != 1) {
        // Try to resolve hostname
        hostent* host = gethostbyname(address.c_str());
        if (host == nullptr) {
            std::cerr << "Failed to resolve hostname: " << address << std::endl;
            return false;
        }
        memcpy(&addr.sin_addr, host->h_addr, host->h_length);
    }
    
    if (::connect(socket_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        std::cerr << "Failed to connect: " << strerror(errno) << std::endl;
        return false;
    }
    
    return true;
}

std::unique_ptr<Socket> Socket::accept() {
    sockaddr_in client_addr{};
    socklen_t addr_len = sizeof(client_addr);
    
    SocketType client_socket = ::accept(socket_, reinterpret_cast<sockaddr*>(&client_addr), &addr_len);
    
    if (client_socket == INVALID_SOCKET_VALUE) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            std::cerr << "Failed to accept connection: " << strerror(errno) << std::endl;
        }
        return nullptr;
    }
    
    auto new_socket = std::make_unique<Socket>(Type::TCP);
    new_socket->socket_ = client_socket;
    
    return new_socket;
}

bool Socket::set_non_blocking(bool non_blocking) {
#ifdef _WIN32
    u_long mode = non_blocking ? 1 : 0;
    if (ioctlsocket(socket_, FIONBIO, &mode) != 0) {
        return false;
    }
#else
    int flags = fcntl(socket_, F_GETFL, 0);
    if (flags < 0) {
        return false;
    }
    
    if (non_blocking) {
        flags |= O_NONBLOCK;
    } else {
        flags &= ~O_NONBLOCK;
    }
    
    if (fcntl(socket_, F_SETFL, flags) < 0) {
        return false;
    }
#endif
    
    is_non_blocking_ = non_blocking;
    return true;
}

bool Socket::set_reuse_addr(bool reuse) {
    int opt = reuse ? 1 : 0;
    return setsockopt(socket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == 0;
}

bool Socket::set_tcp_nodelay(bool nodelay) {
    if (type_ != Type::TCP) return false;
    int opt = nodelay ? 1 : 0;
    return setsockopt(socket_, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) == 0;
}

bool Socket::set_keepalive(bool keepalive) {
    int opt = keepalive ? 1 : 0;
    return setsockopt(socket_, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt)) == 0;
}

bool Socket::set_send_buffer_size(int size) {
    return setsockopt(socket_, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) == 0;
}

bool Socket::set_recv_buffer_size(int size) {
    return setsockopt(socket_, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) == 0;
}

ssize_t Socket::send(const void* data, size_t length) {
    return ::send(socket_, data, length, 0);
}

ssize_t Socket::receive(void* buffer, size_t max_length) {
    return ::recv(socket_, buffer, max_length, 0);
}

ssize_t Socket::send_to(const void* data, size_t length, const sockaddr* addr, socklen_t addr_len) {
    return ::sendto(socket_, data, length, 0, addr, addr_len);
}

ssize_t Socket::receive_from(void* buffer, size_t max_length, sockaddr* addr, socklen_t* addr_len) {
    return ::recvfrom(socket_, buffer, max_length, 0, addr, addr_len);
}

bool Socket::close() {
    if (socket_ != INVALID_SOCKET_VALUE) {
#ifdef _WIN32
        ::closesocket(socket_);
#else
        ::close(socket_);
#endif
        socket_ = INVALID_SOCKET_VALUE;
    }
    return true;
}

bool Socket::is_valid() const {
    return socket_ != INVALID_SOCKET_VALUE;
}

SocketType Socket::get_handle() const {
    return socket_;
}

// TCPConnection implementation
TCPConnection::TCPConnection()
    : socket_(nullptr)
    , connected_(false) {
}

TCPConnection::TCPConnection(Socket&& socket)
    : socket_(std::make_unique<Socket>(std::move(socket)))
    , connected_(true) {
}

TCPConnection::~TCPConnection() {
    disconnect();
}

bool TCPConnection::connect(const std::string& host, uint16_t port) {
    socket_ = std::make_unique<Socket>(Socket::Type::TCP);
    
    if (!socket_->create()) {
        return false;
    }
    
    if (!socket_->connect(host, port)) {
        socket_->close();
        return false;
    }
    
    connected_ = true;
    remote_address_ = host;
    remote_port_ = port;
    
    return true;
}

bool TCPConnection::disconnect() {
    if (socket_) {
        socket_->close();
        socket_.reset();
    }
    connected_ = false;
    return true;
}

bool TCPConnection::send(const std::vector<uint8_t>& data) {
    if (!connected_ || !socket_) {
        return false;
    }
    
    size_t total_sent = 0;
    while (total_sent < data.size()) {
        ssize_t sent = socket_->send(data.data() + total_sent, data.size() - total_sent);
        if (sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            connected_ = false;
            return false;
        }
        total_sent += sent;
    }
    
    return true;
}

bool TCPConnection::receive(std::vector<uint8_t>& data, size_t max_length) {
    if (!connected_ || !socket_) {
        return false;
    }
    
    data.resize(max_length);
    ssize_t received = socket_->receive(data.data(), max_length);
    
    if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            data.clear();
            return true;
        }
        connected_ = false;
        return false;
    } else if (received == 0) {
        // Connection closed
        connected_ = false;
        return false;
    }
    
    data.resize(received);
    return true;
}

bool TCPConnection::is_connected() const {
    return connected_;
}

std::string TCPConnection::get_remote_address() const {
    return remote_address_;
}

uint16_t TCPConnection::get_remote_port() const {
    return remote_port_;
}

// UDPSocket implementation
UDPSocket::UDPSocket()
    : socket_(nullptr)
    , bound_(false)
    , connected_(false) {
}

UDPSocket::~UDPSocket() {
    close();
}

bool UDPSocket::bind(const std::string& address, uint16_t port) {
    socket_ = std::make_unique<Socket>(Socket::Type::UDP);
    
    if (!socket_->create()) {
        return false;
    }
    
    if (!socket_->set_reuse_addr(true)) {
        std::cerr << "Warning: Failed to set SO_REUSEADDR" << std::endl;
    }
    
    if (!socket_->bind(address, port)) {
        socket_->close();
        return false;
    }
    
    bound_ = true;
    return true;
}

bool UDPSocket::connect(const std::string& host, uint16_t port) {
    if (!socket_) {
        socket_ = std::make_unique<Socket>(Socket::Type::UDP);
        if (!socket_->create()) {
            return false;
        }
    }
    
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        hostent* he = gethostbyname(host.c_str());
        if (he == nullptr || he->h_addr_list[0] == nullptr) {
            return false;
        }
        memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    }
    
    if (::connect(socket_->get_handle(), reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        return false;
    }
    
    connected_ = true;
    return true;
}

bool UDPSocket::send(const std::vector<uint8_t>& data) {
    if (!socket_) return false;
    
    ssize_t sent = socket_->send(data.data(), data.size());
    return sent == static_cast<ssize_t>(data.size());
}

bool UDPSocket::send_to(const std::vector<uint8_t>& data, const std::string& host, uint16_t port) {
    if (!socket_) return false;
    
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        hostent* he = gethostbyname(host.c_str());
        if (he == nullptr || he->h_addr_list[0] == nullptr) {
            return false;
        }
        memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    }
    
    ssize_t sent = socket_->send_to(data.data(), data.size(), 
                                       reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    return sent == static_cast<ssize_t>(data.size());
}

bool UDPSocket::receive(std::vector<uint8_t>& data) {
    if (!socket_) return false;
    
    data.resize(MAX_PACKET_SIZE);
    ssize_t received = socket_->receive(data.data(), data.size());
    
    if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            data.clear();
            return true;
        }
        return false;
    }
    
    data.resize(received);
    return true;
}

bool UDPSocket::receive_from(std::vector<uint8_t>& data, std::string& from_host, uint16_t& from_port) {
    if (!socket_) return false;
    
    data.resize(MAX_PACKET_SIZE);
    sockaddr_in addr{};
    socklen_t addr_len = sizeof(addr);
    
    ssize_t received = socket_->receive_from(data.data(), data.size(), 
                                               reinterpret_cast<sockaddr*>(&addr), &addr_len);
    
    if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            data.clear();
            return true;
        }
        return false;
    }
    
    data.resize(received);
    from_host = inet_ntoa(addr.sin_addr);
    from_port = ntohs(addr.sin_port);
    
    return true;
}

bool UDPSocket::close() {
    if (socket_) {
        socket_->close();
        socket_.reset();
    }
    bound_ = false;
    connected_ = false;
    return true;
}

bool UDPSocket::is_bound() const {
    return bound_;
}

// Network utilities
std::string NetworkUtils::resolve_hostname(const std::string& hostname) {
    hostent* host = gethostbyname(hostname.c_str());
    if (host == nullptr || host->h_addr_list[0] == nullptr) {
        return "";
    }
    
    in_addr addr;
    memcpy(&addr, host->h_addr_list[0], sizeof(addr));
    return inet_ntoa(addr);
}

std::string NetworkUtils::get_local_address() {
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        return "";
    }
    
    return resolve_hostname(hostname);
}

std::vector<std::string> NetworkUtils::get_all_local_addresses() {
    std::vector<std::string> addresses;
    
    // This is a simplified implementation
    // In production, use getifaddrs() for complete interface enumeration
    std::string local = get_local_address();
    if (!local.empty()) {
        addresses.push_back(local);
    }
    addresses.push_back("127.0.0.1");
    
    return addresses;
}

bool NetworkUtils::is_valid_ipv4(const std::string& address) {
    sockaddr_in sa;
    return inet_pton(AF_INET, address.c_str(), &(sa.sin_addr)) == 1;
}

bool NetworkUtils::is_valid_ipv6(const std::string& address) {
    sockaddr_in6 sa;
    return inet_pton(AF_INET6, address.c_str(), &(sa.sin6_addr)) == 1;
}

bool NetworkUtils::is_valid_port(uint16_t port) {
    return port > 0 && port < 65535;
}

// AsyncIOHandler implementation
AsyncIOHandler::AsyncIOHandler()
    : running_(false) {
}

AsyncIOHandler::~AsyncIOHandler() {
    stop();
}

bool AsyncIOHandler::start() {
    if (running_) {
        return false;
    }
    running_ = true;
    // In a full implementation, this would start the I/O event loop thread
    return true;
}

void AsyncIOHandler::stop() {
    running_ = false;
}

void AsyncIOHandler::set_data_callback(DataCallback callback) {
    data_callback_ = callback;
}

void AsyncIOHandler::set_error_callback(ErrorCallback callback) {
    error_callback_ = callback;
}

bool AsyncIOHandler::register_socket(SocketType socket) {
    // In a full implementation, this would add the socket to the epoll/kqueue/IOCP
    (void)socket;
    return true;
}

bool AsyncIOHandler::unregister_socket(SocketType socket) {
    // In a full implementation, this would remove the socket from the epoll/kqueue/IOCP
    (void)socket;
    return true;
}

void AsyncIOHandler::io_loop() {
    // In a full implementation, this would be the event loop
    while (running_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

} // namespace nvpn