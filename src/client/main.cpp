#include "client.hpp"
#include <iostream>
#include <csignal>
#include <cstring>
#include <fstream>
#include <thread>
#include <chrono>

using namespace nvpn;

static VPNClient* g_client = nullptr;

void signal_handler(int sig) {
    std::cout << "\nReceived signal " << sig << ", disconnecting..." << std::endl;
    if (g_client) {
        g_client->disconnect();
    }
}

void print_usage(const char* program) {
    std::cout << "Usage: " << program << " [options]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -c, --config <file>     Configuration file (default: /etc/nvpn/client.conf)" << std::endl;
    std::cout << "  -s, --server <host>       Server hostname or IP" << std::endl;
    std::cout << "  -p, --port <port>         Server TCP port (default: 8443)" << std::endl;
    std::cout << "  -u, --udp-port <port>     Server UDP port (default: 8444)" << std::endl;
    std::cout << "  --username <user>         Username for authentication" << std::endl;
    std::cout << "  --password <pass>         Password for authentication" << std::endl;
    std::cout << "  --no-udp                  Disable UDP, use TCP only" << std::endl;
    std::cout << "  --redirect-gateway        Redirect all traffic through VPN" << std::endl;
    std::cout << "  --dns <server>            DNS server to use" << std::endl;
    std::cout << "  --sni <hostname>          SNI hostname for TLS obfuscation" << std::endl;
    std::cout << "  --obfuscation <mode>      Obfuscation mode: none, tls, http2, websocket" << std::endl;
    std::cout << "  -h, --help                Show this help message" << std::endl;
}

ClientConfig parse_args(int argc, char* argv[]) {
    ClientConfig config;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) {
            if (i + 1 < argc) {
                // Load config from file
                i++;
            }
        } else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--server") == 0) {
            if (i + 1 < argc) {
                config.server_host = argv[++i];
            }
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0) {
            if (i + 1 < argc) {
                config.server_port = static_cast<uint16_t>(std::stoi(argv[++i]));
            }
        } else if (strcmp(argv[i], "-u") == 0 || strcmp(argv[i], "--udp-port") == 0) {
            if (i + 1 < argc) {
                config.server_udp_port = static_cast<uint16_t>(std::stoi(argv[++i]));
            }
        } else if (strcmp(argv[i], "--username") == 0) {
            if (i + 1 < argc) {
                config.username = argv[++i];
            }
        } else if (strcmp(argv[i], "--password") == 0) {
            if (i + 1 < argc) {
                config.password = argv[++i];
            }
        } else if (strcmp(argv[i], "--no-udp") == 0) {
            config.use_udp = false;
        } else if (strcmp(argv[i], "--redirect-gateway") == 0) {
            config.redirect_gateway = true;
        } else if (strcmp(argv[i], "--dns") == 0) {
            if (i + 1 < argc) {
                config.dns_server = argv[++i];
            }
        } else if (strcmp(argv[i], "--sni") == 0) {
            if (i + 1 < argc) {
                config.sni_hostname = argv[++i];
            }
        } else if (strcmp(argv[i], "--obfuscation") == 0) {
            if (i + 1 < argc) {
                std::string mode = argv[++i];
                if (mode == "none") {
                    config.obfuscation_mode = ObfuscationMode::NONE;
                } else if (mode == "tls") {
                    config.obfuscation_mode = ObfuscationMode::TLS_1_3;
                } else if (mode == "http2") {
                    config.obfuscation_mode = ObfuscationMode::HTTP_2;
                } else if (mode == "websocket") {
                    config.obfuscation_mode = ObfuscationMode::WEBSOCKET;
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
    std::cout << "nVPN Client v1.0.0" << std::endl;
    std::cout << "========================" << std::endl;
    
    // Check for root privileges
    if (getuid() != 0) {
        std::cerr << "Warning: This program may require root privileges to create TUN device" << std::endl;
    }
    
    // Initialize networking
    if (!NetworkUtils::initialize_networking()) {
        std::cerr << "Failed to initialize networking" << std::endl;
        return 1;
    }
    
    // Parse command line arguments
    ClientConfig config = parse_args(argc, argv);
    
    if (config.server_host.empty()) {
        std::cerr << "Error: Server host not specified" << std::endl;
        print_usage(argv[0]);
        return 1;
    }
    
    std::cout << "Configuration:" << std::endl;
    std::cout << "  Server: " << config.server_host << ":" << config.server_port << std::endl;
    std::cout << "  UDP port: " << config.server_udp_port << std::endl;
    std::cout << "  Username: " << (config.username.empty() ? "(none)" : config.username) << std::endl;
    std::cout << "  Use UDP: " << (config.use_udp ? "yes" : "no") << std::endl;
    std::cout << "  Redirect gateway: " << (config.redirect_gateway ? "yes" : "no") << std::endl;
    std::cout << "  Obfuscation: " << static_cast<int>(config.obfuscation_mode) << std::endl;
    
    // Create and initialize client
    VPNClient client;
    g_client = &client;
    
    // Set up signal handlers
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);
    
    if (!client.initialize(config)) {
        std::cerr << "Failed to initialize client" << std::endl;
        return 1;
    }
    
    std::cout << "Connecting to server..." << std::endl;
    
    if (!client.connect()) {
        std::cerr << "Failed to connect to server" << std::endl;
        return 1;
    }
    
    std::cout << "Connected successfully!" << std::endl;
    std::cout << "Press Ctrl+C to disconnect" << std::endl;
    
    // Main loop - just wait for signals
    while (client.is_connected()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        // Print statistics every 30 seconds
        static int counter = 0;
        if (++counter >= 30) {
            counter = 0;
            auto stats = client.get_stats();
            std::cout << "Stats: sent=" << stats.bytes_sent 
                      << " received=" << stats.bytes_received << std::endl;
        }
    }
    
    std::cout << "Disconnected" << std::endl;
    
    NetworkUtils::cleanup_networking();
    return 0;
}
