#pragma once

#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

// DIR SRC_IP:SPORT > DST_IP:DPORT ttl=T id=I seq=S ack=A flags=0xFF win=W
// len=L mss=M

class PacketLog {
 public:
  PacketLog() : fp_(nullptr), error_(false) {}
  ~PacketLog() { Close(); }
  bool Open(const std::string& path) {
    bool close_ok = true;
    if (fp_ != nullptr) {
      close_ok = std::fclose(fp_) == 0;
      fp_ = nullptr;
    }
    if (!close_ok) {
      error_ = true;
      return false;
    }

    error_ = false;
    if (path.empty()) return true;
    fp_ = std::fopen(path.c_str(), "w");
    if (fp_ == nullptr) error_ = true;
    return fp_ != nullptr;
  }
  void Close() {
    if (fp_) {
      if (std::fclose(fp_) != 0) error_ = true;
      fp_ = nullptr;
    }
  }
  bool IsOpen() const { return fp_ != nullptr; }
  bool HasError() const { return error_; }

  bool Log(const char* dir, const std::string& src_ip, std::uint16_t src_port,
           const std::string& dst_ip, std::uint16_t dst_port, std::uint8_t ttl,
           std::uint16_t id, std::uint32_t seq, std::uint32_t ack,
           std::uint8_t flags, std::uint16_t window, std::uint16_t payload_len,
           int mss) {
    if (fp_ == nullptr) return true;
    if (dir == nullptr ||
        (std::strcmp(dir, "SEND") != 0 && std::strcmp(dir, "RECV") != 0)) {
      error_ = true;
      return false;
    }
    if (mss == 0 || mss < -1 || mss > 65535) {
      error_ = true;
      return false;
    }

    int written;
    if (mss > 0) {
      written = std::fprintf(
          fp_,
          "%s %s:%u > %s:%u ttl=%u id=%u seq=%" PRIu32 " ack=%" PRIu32
          " flags=0x%02x win=%u len=%u mss=%d\n",
          dir, src_ip.c_str(), static_cast<unsigned>(src_port), dst_ip.c_str(),
          static_cast<unsigned>(dst_port), static_cast<unsigned>(ttl),
          static_cast<unsigned>(id), seq, ack, static_cast<unsigned>(flags),
          static_cast<unsigned>(window), static_cast<unsigned>(payload_len),
          mss);
    } else {
      written = std::fprintf(
          fp_,
          "%s %s:%u > %s:%u ttl=%u id=%u seq=%" PRIu32 " ack=%" PRIu32
          " flags=0x%02x win=%u len=%u mss=-\n",
          dir, src_ip.c_str(), static_cast<unsigned>(src_port), dst_ip.c_str(),
          static_cast<unsigned>(dst_port), static_cast<unsigned>(ttl),
          static_cast<unsigned>(id), seq, ack, static_cast<unsigned>(flags),
          static_cast<unsigned>(window), static_cast<unsigned>(payload_len));
    }
    if (written < 0 || std::fflush(fp_) != 0) {
      error_ = true;
      return false;
    }
    return true;
  }

 private:
  std::FILE* fp_;
  bool error_;

  PacketLog(const PacketLog&) = delete;
  PacketLog& operator=(const PacketLog&) = delete;
};