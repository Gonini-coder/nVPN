#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <array>
#include <memory>

namespace nvpn {

// Protocol constants
constexpr uint16_t DEFAULT_PORT = 8443;
constexpr uint16_t DEFAULT_PORT_UDP = 8444;
constexpr size_t MAX_PACKET_SIZE = 65535;
constexpr size_t HEADER_SIZE = 16;
constexpr size_t NONCE_SIZE = 12;
constexpr size_t TAG_SIZE = 16;
constexpr size_t KEY_SIZE = 32;

// Protocol magic bytes (disguised as TLS 1.3)
constexpr std::array<uint8_t, 3> MAGIC_BYTES = {0x16, 0x03, 0x01};

// Message types (hidden in TLS record type field)
enum class MessageType : uint8_t {
    HANDSHAKE = 0x16,      // TLS Handshake
    DATA = 0x17,           // TLS Application Data
    HEARTBEAT = 0x18,      // TLS Heartbeat
    DISCONNECT = 0x15,     // TLS Alert
};

// Protocol states
enum class ConnectionState {
    DISCONNECTED,
    CONNECTING,
    HANDSHAKE_SENT,
    HANDSHAKE_RECEIVED,
    CONNECTED,
    DISCONNECTING
};

// Protocol header structure
struct ProtocolHeader {
    uint8_t type;           // Message type (disguised as TLS record type)
    uint8_t version_major;  // TLS major version
    uint8_t version_minor;  // TLS minor version
    uint16_t length;        // Payload length
    uint32_t sequence;      // Sequence number
    uint32_t timestamp;     // Timestamp for replay protection
    uint8_t flags;          // Additional flags
    uint8_t reserved[3];    // Reserved for future use

    std::vector<uint8_t> serialize() const;
    static ProtocolHeader deserialize(const std::vector<uint8_t>& data);
};

// Packet structure
struct Packet {
    ProtocolHeader header;
    std::vector<uint8_t> payload;
    std::vector<uint8_t> auth_tag;  // Authentication tag for AEAD

    std::vector<uint8_t> serialize() const;
    static Packet deserialize(const std::vector<uint8_t>& data);
};

// Session keys
struct SessionKeys {
    std::array<uint8_t, KEY_SIZE> encryption_key;
    std::array<uint8_t, KEY_SIZE> mac_key;
    uint64_t key_id;
};

// Protocol handler interface
class ProtocolHandler {
public:
    virtual ~ProtocolHandler() = default;
    
    virtual bool initialize() = 0;
    virtual bool handshake() = 0;
    virtual bool send_packet(const Packet& packet) = 0;
    virtual bool receive_packet(Packet& packet) = 0;
    virtual bool disconnect() = 0;
    
    virtual ConnectionState get_state() const = 0;
    virtual SessionKeys get_session_keys() const = 0;
};

} // namespace nvpn