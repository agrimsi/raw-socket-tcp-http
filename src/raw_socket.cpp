#include "raw_socket.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstring>
#include <stdexcept>
#include <string>

RawSocket::RawSocket() : fd_(-1) {
  fd_ = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
  if (fd_ < 0) {
    throw std::runtime_error(std::string("socket: ") + std::strerror(errno));
  }

  int enabled = 1;
  if (setsockopt(fd_, IPPROTO_IP, IP_HDRINCL, &enabled, sizeof(enabled)) < 0) {
    int saved_errno = errno;
    close(fd_);
    fd_ = -1;
    throw std::runtime_error(std::string("setsockopt(IP_HDRINCL): ") +
                             std::strerror(saved_errno));
  }
}

RawSocket::~RawSocket() {
  if (fd_ >= 0) {
    close(fd_);
  }
}

RawSocket::RawSocket(RawSocket&& other) noexcept : fd_(other.fd_) {
  other.fd_ = -1;
}

RawSocket& RawSocket::operator=(RawSocket&& other) noexcept {
  if (this != &other) {
    if (fd_ >= 0) {
      close(fd_);
    }
    fd_ = other.fd_;
    other.fd_ = -1;
  }
  return *this;
}
// Send a fully-formed packet (IP header + TCP header + payload).
int RawSocket::SendPacket(const std::vector<std::uint8_t>& packet,
                          std::uint32_t dst_ip) const {
  if (fd_ < 0) {
    errno = EBADF;
    return -1;
  }
  if (packet.size() < 20 || packet.size() > 65535) {
    errno = EINVAL;
    return -1;
  }

  const std::uint8_t version = packet[0] >> 4;
  const std::uint8_t ihl = packet[0] & 0x0F;
  const std::size_t header_len = static_cast<std::size_t>(ihl) * 4;
  if (version != 4 || ihl < 5 || header_len > packet.size() ||
      packet[9] != IPPROTO_TCP) {
    errno = EINVAL;
    return -1;
  }

  std::uint16_t total_length = 0;
  std::memcpy(&total_length, packet.data() + 2, sizeof(total_length));
  if (ntohs(total_length) != packet.size()) {
    errno = EINVAL;
    return -1;
  }

  std::uint32_t packet_dst_ip = 0;
  std::memcpy(&packet_dst_ip, packet.data() + 16, sizeof(packet_dst_ip));
  if (packet_dst_ip != dst_ip) {
    errno = EINVAL;
    return -1;
  }

  sockaddr_in destination{};
  destination.sin_family = AF_INET;
  destination.sin_addr.s_addr = dst_ip;

  ssize_t sent = sendto(fd_, packet.data(), packet.size(), 0,
                        reinterpret_cast<const sockaddr*>(&destination),
                        sizeof(destination));
  if (sent < 0) {
    return -1;
  }
  if (static_cast<std::size_t>(sent) != packet.size()) {
    errno = EIO;
    return -1;
  }
  return static_cast<int>(sent);
}

// Receive a raw packet into buf, including its IPv4 header
int RawSocket::RecvPacket(std::vector<std::uint8_t>& buf,
                          int timeout_ms) const {
  if (fd_ < 0) {
    buf.clear();
    errno = EBADF;
    return -1;
  }
  if (timeout_ms < -1) {
    buf.clear();
    errno = EINVAL;
    return -1;
  }
  buf.clear();

  using Clock = std::chrono::steady_clock;
  const Clock::time_point deadline =
      timeout_ms == -1 ? Clock::time_point::max()
                       : Clock::now() + std::chrono::milliseconds(timeout_ms);

  while (true) {
    int wait_ms = -1;
    if (timeout_ms >= 0) {
      auto remaining = deadline - Clock::now();
      if (remaining <= Clock::duration::zero()) {
        wait_ms = 0;
      } else {
        wait_ms = static_cast<int>(
            std::chrono::ceil<std::chrono::milliseconds>(remaining).count());
      }
    }

    pollfd descriptor{};
    descriptor.fd = fd_;
    descriptor.events = POLLIN;

    int ready = poll(&descriptor, 1, wait_ms);
    if (ready == 0) {
      return 0;
    }
    if (ready < 0) {
      if (errno == EINTR) {
        if (timeout_ms >= 0 && Clock::now() >= deadline) {
          buf.clear();
          return 0;
        }
        continue;
      }
      return -1;
    }
    if (descriptor.revents & POLLNVAL) {
      errno = EBADF;
      return -1;
    }
    if (!(descriptor.revents & POLLIN) &&
        (descriptor.revents & (POLLERR | POLLHUP))) {
      errno = EIO;
      return -1;
    }

    constexpr std::size_t MAX_PACKET_SIZE = 65536;
    buf.resize(MAX_PACKET_SIZE);
    ssize_t received = recv(fd_, buf.data(), buf.size(), MSG_DONTWAIT);
    if (received >= 0) {
      buf.resize(static_cast<std::size_t>(received));
      return static_cast<int>(received);
    }
    buf.clear();
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
      if (timeout_ms >= 0 && Clock::now() >= deadline) {
        return 0;
      }
      continue;
    }
    return -1;
  }
}
