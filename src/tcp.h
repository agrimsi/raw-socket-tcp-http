#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

// TCP flag bits in byte 13 of the TCP header.
constexpr std::uint8_t TCP_FIN = 0x01;
constexpr std::uint8_t TCP_SYN = 0x02;
constexpr std::uint8_t TCP_RST = 0x04;
constexpr std::uint8_t TCP_PSH = 0x08;
constexpr std::uint8_t TCP_ACK = 0x10;
constexpr std::uint8_t TCP_URG = 0x20;
constexpr std::uint8_t TCP_ECE = 0x40;
constexpr std::uint8_t TCP_CWR = 0x80;

// Parsed TCP header.
struct TcpHeader {
  std::uint16_t src_port;    // host byte order
  std::uint16_t dst_port;    // host byte order
  std::uint32_t seq_num;     // host byte order
  std::uint32_t ack_num;     // host byte order
  std::uint8_t data_offset;  // in 32-bit words (header length / 4)
  std::uint8_t flags;        // byte 13: FIN through CWR flags
  std::uint16_t window;      // host byte order
  std::uint16_t checksum;    // host byte order
  std::uint16_t urgent_ptr;  // host byte order
  // Options
  int mss = -1;  // -1 if not present
};

// Build a TCP segment (header + payload).
// If mss > 0, append a 4-byte MSS option (TCP header becomes 24 bytes).
// MSS options are only included in SYN segments. mss == -1 means no MSS
// option; other invalid values, including values above 65535, are rejected.
// The TCP checksum is computed using the pseudo-header with the given IPs.
// src_ip and dst_ip must be in network byte order.
std::vector<std::uint8_t> BuildTcpSegment(
    std::uint16_t src_port, std::uint16_t dst_port, std::uint32_t seq_num,
    std::uint32_t ack_num, std::uint8_t flags, std::uint16_t window,
    const std::uint8_t* payload, std::size_t payload_len, std::uint32_t src_ip,
    std::uint32_t dst_ip, int mss = -1);

// Parse a TCP header from raw bytes (starting at the TCP header, after the IP
// header). Returns true on success.
bool ParseTcpHeader(const std::uint8_t* data, std::size_t len, TcpHeader& hdr,
                    std::size_t& header_len);

// Verify TCP checksum using the pseudo-header. tcp_data points to the complete
// TCP segment, including its existing checksum field; tcp_len is the total
// TCP length (header + payload). src_ip and dst_ip must be in network byte
// order.
bool VerifyTcpChecksum(const std::uint8_t* tcp_data, std::size_t tcp_len,
                       std::uint32_t src_ip, std::uint32_t dst_ip);