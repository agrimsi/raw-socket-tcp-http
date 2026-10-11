#pragma once

#include <cstdint>
#include <vector>

// Creates a raw socket with IP_HDRINCL set. The application supplies the
// IPv4 header for outgoing packets, although Linux may still fill or modify
// fields such as total length and the IPv4 header checksum. IP_HDRINCL mainly
// controls outgoing packet construction.
// Protocol is IPPROTO_TCP so we receive TCP segments.
class RawSocket {
 public:
  RawSocket();
  ~RawSocket();

  RawSocket(const RawSocket&) = delete;
  RawSocket& operator=(const RawSocket&) = delete;

  RawSocket(RawSocket&& other) noexcept;
  RawSocket& operator=(RawSocket&& other) noexcept;

  int SendPacket(const std::vector<std::uint8_t>& packet,
                 std::uint32_t dst_ip) const;

  int RecvPacket(std::vector<std::uint8_t>& buf, int timeout_ms = -1) const;
  int GetFd() const { return fd_; }

 private:
  int fd_;
};