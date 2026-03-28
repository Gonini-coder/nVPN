#include "nvpn_protocol.hpp"
#include <iostream>
#include <string>

namespace nvpn {

// Protocol header serialization
std::vector<uint8_t> ProtocolHeader::serialize() const {
    std::vector<uint8_t> result(HEADER_SIZE);
    
    result[0] = type;
    result[1] = version_major;
    result[2] = version_minor;
    result[3] = static_cast<uint8_t>((length >> 8) & 0xFF);
    result[4] = static_cast<uint8_t>(length & 0xFF);
    result[5] = static_cast<uint8_t>((sequence >> 24) & 0xFF);
    result[6] = static_cast<uint8_t>((sequence >> 16) & 0xFF);
    result[7] = static_cast<uint8_t>((sequence >> 8) & 0xFF);
    result[8] = static_cast<uint8_t>(sequence & 0xFF);
    result[9] = static_cast<uint8_t>((timestamp >> 24) & 0xFF);
    result[10] = static_cast<uint8_t>((timestamp >> 16) & 0xFF);
    result[11] = static_cast<uint8_t>((timestamp >> 8) & 0xFF);
    result[12] = static_cast<uint8_t>(timestamp & 0xFF);
    result[13] = flags;
    result[14] = reserved[0];
    result[15] = reserved[1];
    // Note: reserved[2] is not serialized due to HEADER_SIZE = 16
    
    return result;
}

ProtocolHeader ProtocolHeader::deserialize(const std::vector<uint8_t>& data) {
    ProtocolHeader header{};
    
    if (data.size() < HEADER_SIZE) {
        return header;
    }
    
    header.type = data[0];
    header.version_major = data[1];
    header.version_minor = data[2];
    header.length = (static_cast<uint16_t>(data[3]) << 8) | data[4];
    header.sequence = (static_cast<uint32_t>(data[5]) << 24) |
                      (static_cast<uint32_t>(data[6]) << 16) |
                      (static_cast<uint32_t>(data[7]) << 8) |
                      data[8];
    header.timestamp = (static_cast<uint32_t>(data[9]) << 24) |
                       (static_cast<uint32_t>(data[10]) << 16) |
                       (static_cast<uint32_t>(data[11]) << 8) |
                       data[12];
    header.flags = data[13];
    header.reserved[0] = data[14];
    header.reserved[1] = data[15];
    header.reserved[2] = 0; // Not serialized due to HEADER_SIZE = 16
    
    return header;
}

// Packet serialization
std::vector<uint8_t> Packet::serialize() const {
    std::vector<uint8_t> result = header.serialize();
    result.insert(result.end(), payload.begin(), payload.end());
    result.insert(result.end(), auth_tag.begin(), auth_tag.end());
    return result;
}

Packet Packet::deserialize(const std::vector<uint8_t>& data) {
    Packet packet;
    
    if (data.size() < HEADER_SIZE) {
        return packet;
    }
    
    packet.header = ProtocolHeader::deserialize(data);
    
    size_t payload_end = HEADER_SIZE + packet.header.length;
    if (data.size() >= payload_end) {
        packet.payload.assign(data.begin() + HEADER_SIZE, data.begin() + payload_end);
    }
    
    if (data.size() > payload_end) {
        packet.auth_tag.assign(data.begin() + payload_end, data.end());
    }
    
    return packet;
}

} // namespace nvpn