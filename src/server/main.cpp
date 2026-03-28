#include "server.hpp"
#include <iostream>
#include <csignal>
#include <cstring>
#include <fstream>
#include <thread>
#include <chrono>

using namespace nvpn;

static VPNServer* g_server = nullptr;

void signal_handler(int sig) {
    std::cout << "\nReceived signal " << sig << ", shutting down..." << std::endl;
    if (g_server) {
        g_server->stop();
    }
}

void print_usage(const char* program) {
    std::cout << "Usage: " << program << " [options]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -c, --config <file>    Configuration file (default: /etc/nvpn/server.conf)" << std::endl;
    std::cout << "  -p, --port <port>      TCP port (default: 8443)" << std::endl;
    std::cout << "  -u, --udp-port <port>  UDP port (default: 8444)" << std::endl;
    std::cout << "  -b, --bind <address>   Bind address (default: 0.0.0.0)" << std::endl;
    std::cout << "  -n, --network <net>    VPN network (default: 10.8.0.0/24)" << std::endl;
    std::cout << "  -h, --help             Show this help message" << std::endl;
}

ServerConfig parse_args(int argc, char* argv[]) {
    ServerConfig config;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) {
            if (i + 1 < argc) {
                // Load config from file
                i++;
            }
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0) {
            if (i + 1 < argc) {
                config.port = static_cast<uint16_t>(std::stoi(argv[++i]));
            }
        } else if (strcmp(argv[i], "-u") == 0 || strcmp(argv[i], "--udp-port") == 0) {
            if (i + 1 < argc) {
                config.udp_port = static_cast<uint16_t>(std::stoi(argv[++i]));
            }
        } else if (strcmp(argv[i], "-b") == 0 || strcmp(argv[i], "--bind") == 0) {
            if (i + 1 < argc) {
                config.bind_address = argv[++i];
            }
        } else if (strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--network") == 0) {
            if (i + 1 < argc) {
                std::string net = argv[++i];
                size_t slash = net.find('/');
                if (slash != std::string::npos) {
                    config.vpn_network = net.substr(0, slash);
                    int prefix = std::stoi(net.substr(slash + 1));
                    // Convert prefix to netmask
                    uint32_t mask = 0xFFFFFFFF << (32 - prefix);
                    config.vpn_netmask = std::to_string((mask >> 24) & 0xFF) + "." +
                                        std::to_string((mask >> 16) & 0xFF) + "." +
                                        std::to_string((mask >> 8) & 0xFF) + "." +
                                        std::to_string(mask & 0xFF);
                }
            }
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            exit(0);
        }
    }
    
    return config;
}

int main(int argc, char* argv[]) {
    std::cout << "nVPN Server v1.0.0" << std::endl;
    std::cout << "========================" << std::endl;
    
    // Initialize networking
    if (!NetworkUtils::initialize_networking()) {
        std::cerr << "Failed to initialize networking" << std::endl;
        return 1;
    }
    
    // Parse command line arguments
    ServerConfig config = parse_args(argc, argv);
    
    std::cout << "Configuration:" << std::endl;
    std::cout << "  Bind address: " << config.bind_address << std::endl;
    std::cout << "  TCP port: " << config.port << std::endl;
    std::cout << "  UDP port: " << config.udp_port << std::endl;
    std::cout << "  VPN network: " << config.vpn_network << "/" << config.vpn_netmask << std::endl;
    std::cout << "  Max clients: " << config.max_clients << std::endl;
    
    // Create and initialize server
    VPNServer server;
    g_server = &server;
    
    // Set up signal handlers
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);
    
    if (!server.initialize(config)) {
        std::cerr << "Failed to initialize server" << std::endl;
        return 1;
    }
    
    if (!server.start()) {
        std::cerr << "Failed to start server" << std::endl;
        return 1;
    }
    
    std::cout << "Server started successfully" << std::endl;
    std::cout << "Press Ctrl+C to stop" << std::endl;
    
    // Main loop - just wait for signals
    while (server.is_running()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        // Print statistics every 10 seconds
        static int counter = 0;
        if (++counter >= 10) {
            counter = 0;
            auto sessions = server.get_session_list();
            std::cout << "Active sessions: " << sessions.size() << std::endl;
        }
    }
    
    std::cout << "Server stopped" << std::endl;
    
    NetworkUtils::cleanup_networking();
    return 0;
}
