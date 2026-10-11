#include "ipv4.h"

#include <arpa/inet.h>
#include <netinet/in.h>

#include <cstring>
#include <stdexcept>

ByteBuffer BuildIpv4Packet(Ipv4Address src_ip, Ipv4Address dst_ip,
                           const ByteBuffer& tcp_segment,
                           std::uint16_t identification, std::uint8_t ttl) {
  const std::size_t ip_hdr_len = 20;
  if (tcp_segment.size() > 65535 - ip_hdr_len) {
    throw std::length_error("IPv4 packet too large");
  }
  if (identification == 0) {
    throw std::invalid_argument("IPv4 identification must be non-zero");
  }
  const std::size_t total = ip_hdr_len + tcp_segment.size();

  ByteBuffer packet(total, 0);
  packet[0] = (4 << 4) | 5;  // version=4, IHL=5 (20 bytes)
  packet[1] = 0;             // TOS = 0

  // Total length in network byte order.
  std::uint16_t tlen = htons(static_cast<std::uint16_t>(total));
  std::memcpy(&packet[2], &tlen, 2);
  std::uint16_t id_n = htons(identification);
  std::memcpy(&packet[4], &id_n, 2);
  std::uint16_t flags_frag = htons(0x4000);
  std::memcpy(&packet[6], &flags_frag, 2);
  packet[8] = ttl;
  packet[9] = 6;
  packet[10] = 0;
  packet[11] = 0;
  std::memcpy(&packet[12], &src_ip, 4);
  std::memcpy(&packet[16], &dst_ip, 4);

  // compute checksum and convert to big-endian
  std::uint16_t checksum = ComputeInternetChecksum(packet.data(), ip_hdr_len);
  std::uint16_t be_checksum = htons(checksum);
  std::memcpy(&packet[10], &be_checksum, 2);

  // copy TCP segment after the IP header.
  if (!tcp_segment.empty()) {
    std::memcpy(&packet[ip_hdr_len], tcp_segment.data(), tcp_segment.size());
  }

  return packet;
}

bool ParseIpv4Header(const ByteBuffer& packet, Ipv4Header& hdr,
                     std::size_t& payload_offset) {
  if (packet.size() < 20) return false;

  std::uint8_t version = (packet[0] >> 4) & 0x0F;
  std::uint8_t ihl = packet[0] & 0x0F;
  if (version != 4 || ihl < 5) return false;

  std::size_t header_len = static_cast<std::size_t>(ihl) * 4;
  if (packet.size() < header_len) return false;

  hdr.version_ihl = packet[0];
  hdr.tos = packet[1];
  std::memcpy(&hdr.total_length, &packet[2], 2);
  hdr.total_length = ntohs(hdr.total_length);
  if (hdr.total_length < header_len || hdr.total_length > packet.size()) {
    return false;
  }
  std::memcpy(&hdr.identification, &packet[4], 2);
  hdr.identification = ntohs(hdr.identification);
  std::memcpy(&hdr.flags_fragoff, &packet[6], 2);
  hdr.flags_fragoff = ntohs(hdr.flags_fragoff);
  hdr.ttl = packet[8];
  hdr.protocol = packet[9];
  std::memcpy(&hdr.checksum, &packet[10], 2);
  hdr.checksum = ntohs(hdr.checksum);
  std::memcpy(&hdr.src_ip, &packet[12], 4);  // network byte order
  std::memcpy(&hdr.dst_ip, &packet[16], 4);  // network byte order

  payload_offset = header_len;
  return true;
}

bool VerifyIpv4Checksum(const ByteBuffer& packet, std::size_t header_len) {
  if (header_len < 20 || header_len > 60 || header_len % 4 != 0 ||
      packet.size() < header_len || (packet[0] >> 4) != 4) {
    return false;
  }

  std::size_t encoded_header_len =
      static_cast<std::size_t>(packet[0] & 0x0F) * 4;
  if (encoded_header_len != header_len) return false;

  return ComputeInternetChecksum(packet.data(), header_len) == 0;
}

std::uint16_t ComputeInternetChecksum(const void* data, std::size_t len) {
  const std::uint8_t* p = static_cast<const std::uint8_t*>(data);
  std::uint32_t sum = 0;

  // Interpret each word in network byte order explicitly.
  while (len > 1) {
    sum += (static_cast<std::uint16_t>(p[0]) << 8) | p[1];
    p += 2;
    len -= 2;
  }
  // If odd byte, pad with zero.
  if (len == 1) {
    sum += static_cast<std::uint16_t>(p[0]) << 8;
  }
  // Fold 32-bit sum to 16 bits.
  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }
  return static_cast<std::uint16_t>(~sum);
}

Ipv4Address StringToIp(const std::string& s) {
  struct in_addr addr;
  if (inet_pton(AF_INET, s.c_str(), &addr) != 1) return 0;
  // Zero is the invalid-input sentinel, so 0.0.0.0 is not representable.
  if (addr.s_addr == 0) return 0;
  return addr.s_addr;  // network byte order
}

std::string IpToString(Ipv4Address ip) {
  char buf[INET_ADDRSTRLEN];
  struct in_addr addr;
  addr.s_addr = ip;
  if (inet_ntop(AF_INET, &addr, buf, sizeof(buf)) == nullptr) return "";
  return std::string(buf);
}