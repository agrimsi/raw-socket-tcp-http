#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

using ByteBuffer = std::vector<std::uint8_t>;
using Ipv4Address = std::uint32_t;

// 20 bytes IPv4 header
struct Ipv4Header {
  // version (IPv4 here), and Internet Header Length (5 chunks of 4 bytes each)
  std::uint8_t version_ihl;

  // identify type of service to be able to prioritize specific packets
  std::uint8_t tos;

  // total size of entire IP packet (header+payload) in host byte order
  // prevents nic from reading garbage data by marking packet ends
  std::uint16_t total_length;

  // a non-zero id assigned to packet by the sender, in host byte order
  std::uint16_t identification;

  // flags and fragment offset, in host byte order
  // offset to assemble packets that arrived out of order
  std::uint16_t flags_fragoff;

  // time to live dropped by 1 on each hop. prevent infinite routing loops
  std::uint8_t ttl;

  // identify protocol so that the destination os knows which layer gets data
  // value of 6 indicates to hand it to the tcp handler
  std::uint8_t protocol;

  // header checksum, in host byte order
  std::uint16_t checksum;

  // source address, stored in network byte order
  std::uint32_t src_ip;

  // destination address, stored in network byte order
  std::uint32_t dst_ip;
};

static_assert(sizeof(Ipv4Header) == 20, "Ipv4Headermust be 20 bytes");

// Build an IPv4 header and prepend it to a buffer containing TCP segment +
// payload. Returns the complete packet.
ByteBuffer BuildIpv4Packet(Ipv4Address src_ip, Ipv4Address dst_ip,
                           const ByteBuffer& tcp_segment,
                           std::uint16_t identification, std::uint8_t ttl = 64);

// Parse an IPv4 header from a raw packet.  Returns true on success.
// On success, fills hdr and sets payload_offset to the start of the IPv4
// payload. The payload is not necessarily TCP or the first fragment.
bool ParseIpv4Header(const ByteBuffer& packet, Ipv4Header& hdr,
                     std::size_t& payload_offset);

// Return true if valid checksum
bool VerifyIpv4Checksum(const ByteBuffer& packet, std::size_t header_len);

std::uint16_t ComputeInternetChecksum(const void* data, std::size_t len);

Ipv4Address StringToIp(const std::string& s);

std::string IpToString(Ipv4Address ip);
