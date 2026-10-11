#include "tcp.h"

#include <arpa/inet.h>

#include <cstring>
#include <limits>
#include <stdexcept>
#include <vector>

#include "ipv4.h"

namespace {

constexpr std::size_t TCP_MIN_HEADER_LEN = 20;
constexpr std::size_t TCP_MAX_HEADER_LEN = 60;
constexpr std::size_t IPV4_MAX_PACKET_LEN = 65535;
constexpr std::uint8_t IPPROTO_TCP_VALUE = 6;

std::uint16_t TcpChecksum(const std::uint8_t* tcp_data, std::size_t tcp_len,
                          std::uint32_t src_ip, std::uint32_t dst_ip) {
  const std::size_t pseudo_header_len = 12;
  std::vector<std::uint8_t> checksum_data(
      pseudo_header_len + tcp_len + (tcp_len % 2), 0);

  std::memcpy(checksum_data.data(), &src_ip, sizeof(src_ip));
  std::memcpy(checksum_data.data() + 4, &dst_ip, sizeof(dst_ip));
  checksum_data[9] = IPPROTO_TCP_VALUE;
  std::uint16_t network_tcp_len = htons(static_cast<std::uint16_t>(tcp_len));
  std::memcpy(checksum_data.data() + 10, &network_tcp_len,
              sizeof(network_tcp_len));
  std::memcpy(checksum_data.data() + pseudo_header_len, tcp_data, tcp_len);

  return ComputeInternetChecksum(checksum_data.data(), checksum_data.size());
}

}  // namespace

std::vector<std::uint8_t> BuildTcpSegment(
    std::uint16_t src_port, std::uint16_t dst_port, std::uint32_t seq_num,
    std::uint32_t ack_num, std::uint8_t flags, std::uint16_t window,
    const std::uint8_t* payload, std::size_t payload_len, std::uint32_t src_ip,
    std::uint32_t dst_ip, int mss) {
  if (mss < -1 || mss > std::numeric_limits<std::uint16_t>::max() || mss == 0 ||
      (mss >= 0 && !(flags & TCP_SYN))) {
    throw std::invalid_argument("invalid MSS option");
  }
  if (payload_len > 0 && payload == nullptr) {
    throw std::invalid_argument("null TCP payload");
  }

  const std::size_t header_len = mss >= 0 ? 24 : TCP_MIN_HEADER_LEN;
  if (payload_len > IPV4_MAX_PACKET_LEN - 20 - header_len) {
    throw std::length_error("TCP segment too large");
  }
  const std::size_t total_len = header_len + payload_len;
  std::vector<std::uint8_t> segment(total_len, 0);

  std::uint16_t network16 = htons(src_port);
  std::memcpy(segment.data(), &network16, sizeof(network16));
  network16 = htons(dst_port);
  std::memcpy(segment.data() + 2, &network16, sizeof(network16));

  std::uint32_t network32 = htonl(seq_num);
  std::memcpy(segment.data() + 4, &network32, sizeof(network32));
  network32 = htonl(ack_num);
  std::memcpy(segment.data() + 8, &network32, sizeof(network32));

  segment[12] = static_cast<std::uint8_t>((header_len / 4) << 4);
  segment[13] = flags;
  network16 = htons(window);
  std::memcpy(segment.data() + 14, &network16, sizeof(network16));
  segment[18] = 0;
  segment[19] = 0;

  if (mss >= 0) {
    segment[20] = 2;
    segment[21] = 4;
    network16 = htons(static_cast<std::uint16_t>(mss));
    std::memcpy(segment.data() + 22, &network16, sizeof(network16));
  }
  if (payload_len > 0) {
    std::memcpy(segment.data() + header_len, payload, payload_len);
  }

  std::uint16_t checksum =
      TcpChecksum(segment.data(), segment.size(), src_ip, dst_ip);
  network16 = htons(checksum);
  std::memcpy(segment.data() + 16, &network16, sizeof(network16));
  return segment;
}

bool ParseTcpHeader(const std::uint8_t* data, std::size_t len, TcpHeader& hdr,
                    std::size_t& header_len) {
  if (data == nullptr || len < TCP_MIN_HEADER_LEN) return false;

  TcpHeader parsed{};
  std::size_t parsed_header_len = 0;
  std::uint16_t network16 = 0;
  std::uint32_t network32 = 0;
  std::memcpy(&network16, data, sizeof(network16));
  parsed.src_port = ntohs(network16);
  std::memcpy(&network16, data + 2, sizeof(network16));
  parsed.dst_port = ntohs(network16);
  std::memcpy(&network32, data + 4, sizeof(network32));
  parsed.seq_num = ntohl(network32);
  std::memcpy(&network32, data + 8, sizeof(network32));
  parsed.ack_num = ntohl(network32);
  parsed.data_offset = data[12] >> 4;
  parsed.flags = data[13];
  if (parsed.data_offset < 5) return false;

  parsed_header_len = static_cast<std::size_t>(parsed.data_offset) * 4;
  if (parsed_header_len > TCP_MAX_HEADER_LEN || parsed_header_len > len) {
    return false;
  }

  std::memcpy(&network16, data + 14, sizeof(network16));
  parsed.window = ntohs(network16);
  std::memcpy(&network16, data + 16, sizeof(network16));
  parsed.checksum = ntohs(network16);
  std::memcpy(&network16, data + 18, sizeof(network16));
  parsed.urgent_ptr = ntohs(network16);

  parsed.mss = -1;
  bool found_mss = false;
  std::size_t option_offset = TCP_MIN_HEADER_LEN;
  while (option_offset < parsed_header_len) {
    std::uint8_t kind = data[option_offset];
    if (kind == 0) {
      for (std::size_t padding = option_offset + 1; padding < parsed_header_len;
           ++padding) {
        if (data[padding] != 0) return false;
      }
      break;
    }
    if (kind == 1) {
      ++option_offset;
      continue;
    }
    if (option_offset + 1 >= parsed_header_len) return false;
    std::uint8_t option_len = data[option_offset + 1];
    if (option_len < 2 || option_offset + option_len > parsed_header_len) {
      return false;
    }
    if (kind == 2) {
      if (option_len != 4 || found_mss) return false;
      std::memcpy(&network16, data + option_offset + 2, sizeof(network16));
      parsed.mss = ntohs(network16);
      if (parsed.mss <= 0) return false;
      found_mss = true;
    }
    option_offset += option_len;
  }

  if (found_mss && (parsed.flags & TCP_SYN) == 0) return false;

  hdr = parsed;
  header_len = parsed_header_len;
  return true;
}

bool VerifyTcpChecksum(const std::uint8_t* tcp_data, std::size_t tcp_len,
                       std::uint32_t src_ip, std::uint32_t dst_ip) {
  if (tcp_data == nullptr || tcp_len < TCP_MIN_HEADER_LEN ||
      tcp_len > IPV4_MAX_PACKET_LEN - 20) {
    return false;
  }
  return TcpChecksum(tcp_data, tcp_len, src_ip, dst_ip) == 0;
}