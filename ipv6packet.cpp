#include "ipv6packet.h"
#include <cstring>

IPv6Packet::IPv6Packet() {
    std::memset(&ipv6_header, 0, sizeof(ipv6_header));
    ipv6_header.version_class_flow = htonl(6 << 28); // IPv6 version
}

void IPv6Packet::setTrafficClass(uint8_t traffic_class) {
    ipv6_header.version_class_flow &= htonl(0xF00FFFFF); // Clear existing traffic class
    ipv6_header.version_class_flow |= htonl(static_cast<uint32_t>(traffic_class) << 20);
}

void IPv6Packet::setFlowLabel(uint32_t flow_label) {
    ipv6_header.version_class_flow &= htonl(0xFFF00000); // Clear existing flow label
    ipv6_header.version_class_flow |= htonl(flow_label & 0x000FFFFF);
}

void IPv6Packet::setPayloadLength(uint16_t length) {
    ipv6_header.payload_length = htons(length);
}

void IPv6Packet::setNextHeader(uint8_t next_header) {
    ipv6_header.next_header = next_header;
}

void IPv6Packet::setHopLimit(uint8_t hop_limit) {
    ipv6_header.hop_limit = hop_limit;
}

void IPv6Packet::setSourceAddress(const std::array<uint8_t, 16>& address) {
    ipv6_header.source_address = address;
}

void IPv6Packet::setDestAddress(const std::array<uint8_t, 16>& address) {
    ipv6_header.dest_address = address;
}

uint8_t IPv6Packet::getTrafficClass() const {
    return (ntohl(ipv6_header.version_class_flow) >> 20) & 0xFF;
}

uint32_t IPv6Packet::getFlowLabel() const {
    return ntohl(ipv6_header.version_class_flow) & 0x000FFFFF;
}

uint16_t IPv6Packet::getPayloadLength() const {
    return ntohs(ipv6_header.payload_length);
}

uint8_t IPv6Packet::getNextHeader() const {
    return ipv6_header.next_header;
}

uint8_t IPv6Packet::getHopLimit() const {
    return ipv6_header.hop_limit;
}

std::array<uint8_t, 16> IPv6Packet::getSourceAddress() const {
    return ipv6_header.source_address;
}

std::array<uint8_t, 16> IPv6Packet::getDestAddress() const {
    return ipv6_header.dest_address;
}

std::vector<uint8_t> IPv6Packet::toBytes() const {
    std::vector<uint8_t> bytes(sizeof(ipv6_header));
    std::memcpy(bytes.data(), &ipv6_header, sizeof(ipv6_header));
    return bytes;
}

void IPv6Packet::fromBytes(const std::vector<uint8_t>& bytes) {
    if (bytes.size() >= sizeof(ipv6_header)) {
        std::memcpy(&ipv6_header, bytes.data(), sizeof(ipv6_header));
    }
}
