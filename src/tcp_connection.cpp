#include "tcp_connection.h"

#include <arpa/inet.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <limits>
#include <random>
#include <stdexcept>
#include <utility>

namespace {

constexpr int HANDSHAKE_RETRY_MS = 1000;
constexpr int HANDSHAKE_TIMEOUT_MS = 8000;
constexpr int DATA_RTO_MS = 1000;
constexpr int DATA_TIMEOUT_MS = 10000;
constexpr int FIN_TIMEOUT_MS = 2000;
constexpr int TIME_WAIT_MS = 2000;
constexpr int MAX_RETRANSMITS = 10;
constexpr int POLL_MS = 50;
constexpr std::uint16_t DEFAULT_MSS = 1460;
constexpr std::uint16_t DEFAULT_PEER_MSS = 536;

using Clock = std::chrono::steady_clock;

std::uint32_t RandomIsn() {
  std::random_device device;
  std::mt19937 generator(device());
  std::uniform_int_distribution<std::uint32_t> distribution(0, UINT32_MAX);
  return distribution(generator);
}

std::uint16_t RandomPort() {
  std::random_device device;
  std::mt19937 generator(device());
  std::uniform_int_distribution<unsigned> distribution(61000, 65535);
  return static_cast<std::uint16_t>(distribution(generator));
}

std::int64_t MillisecondsSince(Clock::time_point point) {
  return std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() -
                                                               point)
      .count();
}

bool SeqLess(std::uint32_t left, std::uint32_t right) {
  const std::uint32_t distance = right - left;
  return left != right && distance < 0x80000000u;
}

bool SeqLessOrEqual(std::uint32_t left, std::uint32_t right) {
  return left == right || SeqLess(left, right);
}

bool SeqGreater(std::uint32_t left, std::uint32_t right) {
  return SeqLess(right, left);
}

bool SeqGreaterOrEqual(std::uint32_t left, std::uint32_t right) {
  return left == right || SeqGreater(left, right);
}

std::size_t BufferedBytes(
    const std::vector<std::uint8_t>& in_order,
    const std::map<std::uint32_t, std::vector<std::uint8_t>, SeqCompare>&
        out_of_order) {
  std::size_t total = in_order.size();
  for (const auto& entry : out_of_order) total += entry.second.size();
  return total;
}

}  // namespace

TcpConnection::TcpConnection(PacketLog& plog)
    : plog_(plog),
      state_(TcpState::CLOSED),
      local_ip_(0),
      remote_ip_(0),
      local_port_(0),
      remote_port_(0),
      snd_una_(0),
      snd_nxt_(0),
      snd_iss_(0),
      rcv_nxt_(0),
      rcv_irs_(0),
      peer_window_(65535),
      snd_wl1_(0),
      snd_wl2_(0),
      our_mss_(DEFAULT_MSS),
      peer_mss_(DEFAULT_PEER_MSS),
      peer_fin_(false),
      peer_fin_seq_(0),
      pending_fin_(false),
      pending_fin_seq_(0),
      our_fin_sent_(false),
      our_fin_acked_(false),
      our_fin_seq_(0),
      cwnd_(DEFAULT_MSS),
      ssthresh_(65535),
      dup_ack_count_(0),
      in_fast_recovery_(false),
      ip_id_counter_(1),
      progress_time_(Clock::now()),
      time_wait_deadline_(Clock::time_point::min()),
      receive_window_right_edge_(OUR_WINDOW) {}

TcpConnection::~TcpConnection() {
  if (state_ != TcpState::CLOSED && state_ != TcpState::LISTEN &&
      state_ != TcpState::TIME_WAIT && local_ip_ != 0 && remote_ip_ != 0 &&
      local_port_ != 0 && remote_port_ != 0) {
    try {
      SendRst();
    } catch (...) {
    }
  }
}

void TcpConnection::ResetConnectionState() {
  state_ = TcpState::CLOSED;
  local_ip_ = remote_ip_ = 0;
  local_port_ = remote_port_ = 0;
  snd_una_ = snd_nxt_ = snd_iss_ = 0;
  rcv_nxt_ = rcv_irs_ = 0;
  peer_window_ = OUR_WINDOW;
  snd_wl1_ = snd_wl2_ = 0;
  peer_mss_ = DEFAULT_PEER_MSS;
  send_buffer_.clear();
  ooo_buffer_.clear();
  recv_buffer_.clear();
  peer_fin_ = false;
  peer_fin_seq_ = 0;
  pending_fin_ = false;
  pending_fin_seq_ = 0;
  our_fin_sent_ = false;
  our_fin_acked_ = false;
  our_fin_seq_ = 0;
  cwnd_ = DEFAULT_MSS;
  ssthresh_ = OUR_WINDOW;
  dup_ack_count_ = 0;
  in_fast_recovery_ = false;
  ip_id_counter_ = 1;
  last_ack_time_ = Clock::now();
  progress_time_ = last_ack_time_;
  time_wait_deadline_ = Clock::time_point::min();
  receive_window_right_edge_ = OUR_WINDOW;
}

void TcpConnection::ExpireTimeWait() {
  if (state_ == TcpState::TIME_WAIT && Clock::now() >= time_wait_deadline_) {
    state_ = TcpState::CLOSED;
  }
}

void TcpConnection::AbortConnection(bool send_rst) {
  if (send_rst && state_ != TcpState::CLOSED && state_ != TcpState::LISTEN &&
      local_ip_ != 0 && remote_ip_ != 0 && local_port_ != 0 &&
      remote_port_ != 0) {
    try {
      SendRst();
    } catch (...) {
    }
  }
  send_buffer_.clear();
  ooo_buffer_.clear();
  state_ = TcpState::CLOSED;
  errno = ECONNRESET;
}

std::uint16_t TcpConnection::ReceiveWindow() const {
  const std::uint32_t edge_distance = receive_window_right_edge_ - rcv_nxt_;
  if (edge_distance >= 0x80000000u) return 0;
  const std::size_t buffered = BufferedBytes(recv_buffer_, ooo_buffer_);
  const std::size_t reserved = pending_fin_ ? 1u : 0u;
  const std::size_t available =
      buffered + reserved >= RECEIVE_BUFFER_CAPACITY
          ? 0
          : RECEIVE_BUFFER_CAPACITY - buffered - reserved;
  return static_cast<std::uint16_t>(std::min<std::size_t>(
      std::min<std::uint32_t>(edge_distance, OUR_WINDOW), available));
}

bool TcpConnection::LogPacket(const char* direction, const std::string& src_ip,
                              std::uint16_t src_port, const std::string& dst_ip,
                              std::uint16_t dst_port, std::uint8_t ttl,
                              std::uint16_t id, std::uint32_t seq,
                              std::uint32_t ack, std::uint8_t flags,
                              std::uint16_t window, std::uint16_t payload_len,
                              int mss) {
  if (!plog_.Log(direction, src_ip, src_port, dst_ip, dst_port, ttl, id, seq,
                 ack, flags, window, payload_len, mss)) {
    errno = EIO;
    return false;
  }
  return true;
}

bool TcpConnection::SequenceAcceptable(std::uint32_t sequence,
                                       std::size_t length) const {
  const std::uint32_t right = receive_window_right_edge_;
  if (right == rcv_nxt_ || SeqLess(right, rcv_nxt_))
    return length == 0 && sequence == rcv_nxt_;
  if (length == 0) {
    return SeqGreaterOrEqual(sequence, rcv_nxt_) && SeqLess(sequence, right);
  }
  const std::uint32_t last = sequence + static_cast<std::uint32_t>(length - 1);
  return (SeqGreaterOrEqual(sequence, rcv_nxt_) && SeqLess(sequence, right)) ||
         (SeqGreaterOrEqual(last, rcv_nxt_) && SeqLess(last, right));
}

void TcpConnection::ReopenReceiveWindow() {
  const std::size_t buffered = BufferedBytes(recv_buffer_, ooo_buffer_);
  const std::size_t reserved = pending_fin_ ? 1u : 0u;
  const std::size_t available =
      buffered + reserved >= RECEIVE_BUFFER_CAPACITY
          ? 0
          : RECEIVE_BUFFER_CAPACITY - buffered - reserved;
  const std::uint32_t candidate =
      rcv_nxt_ + static_cast<std::uint32_t>(available);
  if (SeqGreater(candidate, receive_window_right_edge_))
    receive_window_right_edge_ = candidate;
}

void TcpConnection::UpdatePeerWindow(const TcpHeader& tcp) {
  if ((tcp.flags & TCP_ACK) == 0) return;
  const std::uint16_t previous_peer_window = peer_window_;
  if (SeqGreater(tcp.seq_num, snd_wl1_) ||
      (tcp.seq_num == snd_wl1_ && SeqGreaterOrEqual(tcp.ack_num, snd_wl2_))) {
    const bool reopened = previous_peer_window == 0 && tcp.window != 0;
    peer_window_ = tcp.window;
    snd_wl1_ = tcp.seq_num;
    snd_wl2_ = tcp.ack_num;
    if (reopened) progress_time_ = Clock::now();
  }
}

std::uint16_t TcpConnection::NextIpId() {
  std::uint16_t id = ip_id_counter_++;
  if (ip_id_counter_ == 0) ip_id_counter_ = 1;
  return id == 0 ? 1 : id;
}

void TcpConnection::SendSegment(std::uint8_t flags, const std::uint8_t* payload,
                                std::size_t len, int mss_opt) {
  const std::uint32_t sequence = (flags & TCP_SYN) ? snd_iss_ : snd_nxt_;
  const std::uint16_t window = ReceiveWindow();
  ByteBuffer tcp =
      BuildTcpSegment(local_port_, remote_port_, sequence, rcv_nxt_, flags,
                      window, payload, len, local_ip_, remote_ip_, mss_opt);
  const std::uint16_t id = NextIpId();
  ByteBuffer packet = BuildIpv4Packet(local_ip_, remote_ip_, tcp, id);
  if (sock_.SendPacket(packet, remote_ip_) != static_cast<int>(packet.size())) {
    throw std::runtime_error("failed to send TCP segment");
  }
  if (!LogPacket("SEND", IpToString(local_ip_), local_port_,
                 IpToString(remote_ip_), remote_port_, 64, id, sequence,
                 rcv_nxt_, flags, window, static_cast<std::uint16_t>(len),
                 mss_opt))
    throw std::runtime_error("failed to write packet log");
}

void TcpConnection::SendAck() { SendSegment(TCP_ACK, nullptr, 0, -1); }

void TcpConnection::SendFin() {
  if (!our_fin_sent_) {
    our_fin_seq_ = snd_nxt_++;
    our_fin_sent_ = true;
  }
  ByteBuffer tcp = BuildTcpSegment(local_port_, remote_port_, our_fin_seq_,
                                   rcv_nxt_, TCP_FIN | TCP_ACK, ReceiveWindow(),
                                   nullptr, 0, local_ip_, remote_ip_, -1);
  const std::uint16_t id = NextIpId();
  ByteBuffer packet = BuildIpv4Packet(local_ip_, remote_ip_, tcp, id);
  if (sock_.SendPacket(packet, remote_ip_) != static_cast<int>(packet.size())) {
    throw std::runtime_error("failed to send FIN");
  }
  if (!LogPacket("SEND", IpToString(local_ip_), local_port_,
                 IpToString(remote_ip_), remote_port_, 64, id, our_fin_seq_,
                 rcv_nxt_, TCP_FIN | TCP_ACK, ReceiveWindow(), 0, -1))
    throw std::runtime_error("failed to write packet log");
}

void TcpConnection::SendRst() { SendSegment(TCP_RST | TCP_ACK, nullptr, 0); }

// client
// active open
// this performs three way handshake to destination
// source port is randomized in 61000 to 65535
// src_ip and dst_ip are IPv4 addresses in network byte order.
// Returns true on successful three-way handshake.
bool TcpConnection::Connect(std::uint32_t src_ip, std::uint32_t dst_ip,
                            std::uint16_t dst_port) {
  ResetConnectionState();
  local_ip_ = src_ip;
  remote_ip_ = dst_ip;
  local_port_ = RandomPort();
  remote_port_ = dst_port;
  snd_iss_ = RandomIsn();
  snd_una_ = snd_iss_;
  snd_nxt_ = snd_iss_ + 1;
  snd_wl1_ = snd_iss_;
  snd_wl2_ = snd_iss_;
  state_ = TcpState::SYN_SENT;
  try {
    SendSegment(TCP_SYN, nullptr, 0, our_mss_);
  } catch (...) {
    AbortConnection(false);
    errno = EIO;
    return false;
  }

  const Clock::time_point start = Clock::now();
  Clock::time_point last_send = start;
  while (state_ == TcpState::SYN_SENT) {
    if (MillisecondsSince(start) > HANDSHAKE_TIMEOUT_MS) {
      AbortConnection(false);
      errno = ETIMEDOUT;
      return false;
    }
    const ProcessResult result = ProcessIncoming(std::max(
        0,
        HANDSHAKE_RETRY_MS - static_cast<int>(MillisecondsSince(last_send))));
    if (result == ProcessResult::ERROR) {
      AbortConnection(false);
      return false;
    }
    if (state_ == TcpState::SYN_SENT &&
        MillisecondsSince(last_send) >= HANDSHAKE_RETRY_MS) {
      try {
        SendSegment(TCP_SYN, nullptr, 0, our_mss_);
      } catch (...) {
        AbortConnection(false);
        errno = EIO;
        return false;
      }
      last_send = Clock::now();
    }
  }
  last_ack_time_ = Clock::now();
  return state_ == TcpState::ESTABLISHED;
}

// server
// passive open
// wait for SYN on listen_port and then complete the handshake.
// on success, it filles the remote_ip and remote_port with the client's
// address.
// local_ip is filled with the destination ip that the syn was sent to
// so the server replies from the correct address. All returned IP addresses
// are in network byte order.
bool TcpConnection::Accept(std::uint16_t listen_port,
                           std::uint32_t& out_local_ip,
                           std::uint32_t& out_remote_ip,
                           std::uint16_t& out_remote_port) {
  ResetConnectionState();
  local_port_ = listen_port;
  local_ip_ = remote_ip_ = 0;
  remote_port_ = 0;
  state_ = TcpState::LISTEN;

  while (state_ == TcpState::LISTEN) {
    const ProcessResult result = ProcessIncoming(-1);
    if (result == ProcessResult::ERROR) {
      const int saved_errno = errno;
      ResetConnectionState();
      errno = saved_errno;
      return false;
    }
    if (result == ProcessResult::TIMEOUT) continue;
    if (state_ != TcpState::SYN_RECEIVED) continue;

    // Immediately transmit the SYN-ACK segment upon transitioning to
    // SYN_RECEIVED
    try {
      SendSegment(TCP_SYN | TCP_ACK, nullptr, 0, our_mss_);
    } catch (...) {
      AbortConnection(false);
      return false;
    }

    const Clock::time_point start = Clock::now();
    Clock::time_point last_send = start;
    while (state_ == TcpState::SYN_RECEIVED) {
      if (MillisecondsSince(start) > HANDSHAKE_TIMEOUT_MS) {
        ResetConnectionState();
        local_port_ = listen_port;
        state_ = TcpState::LISTEN;
        break;
      }
      const ProcessResult result = ProcessIncoming(std::max(
          0,
          HANDSHAKE_RETRY_MS - static_cast<int>(MillisecondsSince(last_send))));
      if (result == ProcessResult::ERROR) {
        const int saved_errno = errno;
        ResetConnectionState();
        errno = saved_errno;
        return false;
      }
      if (state_ == TcpState::SYN_RECEIVED &&
          MillisecondsSince(last_send) >= HANDSHAKE_RETRY_MS) {
        try {
          SendSegment(TCP_SYN | TCP_ACK, nullptr, 0, our_mss_);
        } catch (...) {
          AbortConnection(false);
          return false;
        }
        last_send = Clock::now();
      }
    }
    if (state_ == TcpState::ESTABLISHED) {
      out_local_ip = local_ip_;
      out_remote_ip = remote_ip_;
      out_remote_port = remote_port_;
      last_ack_time_ = Clock::now();
      return true;
    }
  }
  return false;
}

// for reliable data transfer.
// blocks until all data is sent and acked.
// or connection is broken.
// overloaded send function
bool TcpConnection::Send(const std::uint8_t* data, std::size_t len) {
  if ((data == nullptr && len != 0) ||
      (state_ != TcpState::ESTABLISHED && state_ != TcpState::CLOSE_WAIT)) {
    errno = EINVAL;
    return false;
  }
  std::size_t offset = 0;
  progress_time_ = Clock::now();
  while (offset < len || !send_buffer_.empty()) {
    if (state_ == TcpState::CLOSED) {
      errno = (errno == ETIMEDOUT) ? ETIMEDOUT : ECONNRESET;
      return false;
    }
    if (MillisecondsSince(progress_time_) >= DATA_TIMEOUT_MS) {
      AbortConnection(true);
      errno = ETIMEDOUT;
      return false;
    }
    while (offset < len) {
      const std::size_t in_flight = snd_nxt_ - snd_una_;
      const std::size_t window = EffectiveWindow();
      if (in_flight >= window) break;
      const std::size_t segment_limit =
          std::min<std::size_t>(our_mss_, peer_mss_);
      const std::size_t segment_len =
          std::min({segment_limit, window - in_flight, len - offset});
      if (segment_len == 0) break;

      const std::uint8_t flags = TCP_ACK | TCP_PSH;
      ByteBuffer tcp = BuildTcpSegment(
          local_port_, remote_port_, snd_nxt_, rcv_nxt_, flags, ReceiveWindow(),
          data + offset, segment_len, local_ip_, remote_ip_, -1);
      const std::uint16_t id = NextIpId();
      ByteBuffer packet = BuildIpv4Packet(local_ip_, remote_ip_, tcp, id);
      if (sock_.SendPacket(packet, remote_ip_) !=
          static_cast<int>(packet.size())) {
        AbortConnection(true);
        errno = EIO;
        return false;
      }
      if (!LogPacket("SEND", IpToString(local_ip_), local_port_,
                     IpToString(remote_ip_), remote_port_, 64, id, snd_nxt_,
                     rcv_nxt_, flags, ReceiveWindow(),
                     static_cast<std::uint16_t>(segment_len), -1)) {
        AbortConnection(false);
        errno = EIO;
        return false;
      }

      UnackedSegment segment{
          snd_nxt_,
          static_cast<std::uint32_t>(segment_len),
          flags,
          -1,
          std::vector<std::uint8_t>(data + offset, data + offset + segment_len),
          Clock::now(),
          0};
      send_buffer_.push_back(std::move(segment));
      snd_nxt_ += static_cast<std::uint32_t>(segment_len);
      offset += segment_len;
    }
    const ProcessResult result = ProcessIncoming(POLL_MS);
    if (result == ProcessResult::ERROR) {
      AbortConnection(true);
      return false;
    }
    if (result == ProcessResult::TIMEOUT) {
      try {
        if (!RetransmitCheck()) return false;
      } catch (...) {
        const int saved_errno = errno == 0 ? EIO : errno;
        AbortConnection(true);
        errno = saved_errno;
        return false;
      }
    } else {
      while (true) {
        const ProcessResult pending = ProcessIncoming(0);
        if (pending == ProcessResult::ERROR) {
          AbortConnection(true);
          return false;
        }
        if (pending != ProcessResult::PROCESSED) break;
      }
      try {
        if (!RetransmitCheck()) return false;
      } catch (...) {
        const int saved_errno = errno == 0 ? EIO : errno;
        AbortConnection(true);
        errno = saved_errno;
        return false;
      }
    }
  }
  return true;
}

std::int32_t TcpConnection::Recv(std::uint8_t* buf, std::size_t max_len,
                                 int timeout_s) {
  if (max_len == 0) return 0;
  if (buf == nullptr ||
      max_len >
          static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max()) ||
      timeout_s < 0) {
    errno = EINVAL;
    return -1;
  }
  const Clock::time_point deadline =
      Clock::now() + std::chrono::seconds(timeout_s);
  while (recv_buffer_.empty()) {
    if (peer_fin_) return 0;
    if (state_ == TcpState::CLOSED) {
      errno = ECONNRESET;
      return -1;
    }
    if (Clock::now() >= deadline) {
      errno = ETIMEDOUT;
      return -1;
    }
    const ProcessResult result = ProcessIncoming(POLL_MS);
    if (result == ProcessResult::ERROR) return -1;
    if (result == ProcessResult::TIMEOUT) {
      if (Clock::now() >= deadline) {
        errno = ETIMEDOUT;
        return -1;
      }
      try {
        if (!RetransmitCheck()) return -1;
      } catch (...) {
        const int saved_errno = errno == 0 ? EIO : errno;
        AbortConnection(true);
        errno = saved_errno;
        return -1;
      }
    } else {
      while (true) {
        const ProcessResult pending = ProcessIncoming(0);
        if (pending == ProcessResult::ERROR) return -1;
        if (pending != ProcessResult::PROCESSED) break;
      }
    }
  }
  const std::size_t count = std::min(max_len, recv_buffer_.size());
  std::memcpy(buf, recv_buffer_.data(), count);
  recv_buffer_.erase(recv_buffer_.begin(), recv_buffer_.begin() + count);
  if (count > 0) {
    // Always reopen first so the new right edge is current, then decide
    // whether the right edge actually advanced before sending an ACK.
    // The old condition (old_window==0 || new_window>old_window) could miss
    // cases where the window size was capped by receive_window_right_edge_
    // rather than by buffer capacity, leaving usable space unadvertised.
    const std::uint32_t old_right_edge = receive_window_right_edge_;
    ReopenReceiveWindow();
    if (receive_window_right_edge_ != old_right_edge) {
      try {
        SendAck();
      } catch (...) {
        errno = EIO;
        return -1;
      }
    }
  }
  return static_cast<std::int32_t>(count);
}

std::vector<std::uint8_t> TcpConnection::RecvAll() {
  // Returns all bytes received before EOF or error.  On a clean EOF the
  // result is complete; on timeout or error it is truncated.
  // Callers that need to detect incomplete transfers MUST inspect errno after
  // this returns: errno == 0 (or EAGAIN from a zero-timeout poll) indicates
  // clean EOF, while any other non-zero errno signals an error.
  std::vector<std::uint8_t> result;
  std::vector<std::uint8_t> buffer(65536);
  errno = 0;
  while (true) {
    const std::int32_t count = Recv(buffer.data(), buffer.size());
    if (count <= 0) break;
    result.insert(result.end(), buffer.begin(), buffer.begin() + count);
  }
  return result;
}

void TcpConnection::Close() {
  ExpireTimeWait();
  if (state_ == TcpState::TIME_WAIT) {
    while (state_ == TcpState::TIME_WAIT) {
      const ProcessResult result = ProcessIncoming(POLL_MS);
      if (result == ProcessResult::ERROR) {
        errno = EIO;
        state_ = TcpState::CLOSED;
        return;
      }
    }
    return;
  }
  if (state_ == TcpState::CLOSED || state_ == TcpState::LISTEN ||
      state_ == TcpState::SYN_SENT || state_ == TcpState::SYN_RECEIVED) {
    state_ = TcpState::CLOSED;
    return;
  }
  if (state_ != TcpState::ESTABLISHED && state_ != TcpState::CLOSE_WAIT &&
      state_ != TcpState::FIN_WAIT_1 && state_ != TcpState::FIN_WAIT_2 &&
      state_ != TcpState::LAST_ACK && state_ != TcpState::CLOSING) {
    state_ = TcpState::CLOSED;
    return;
  }

  if (state_ == TcpState::ESTABLISHED || state_ == TcpState::CLOSE_WAIT) {
    const TcpState previous_state = state_;
    try {
      SendFin();
    } catch (...) {
      AbortConnection(false);
      errno = EIO;
      return;
    }
    state_ = previous_state == TcpState::CLOSE_WAIT ? TcpState::LAST_ACK
                                                    : TcpState::FIN_WAIT_1;
  }
  const Clock::time_point start = Clock::now();
  Clock::time_point last_send = start;
  bool failed = false;
  while (state_ != TcpState::CLOSED &&
         (state_ == TcpState::TIME_WAIT ||
          MillisecondsSince(start) <= FIN_TIMEOUT_MS)) {
    if (ProcessIncoming(POLL_MS) == ProcessResult::ERROR) {
      failed = true;
      break;
    }
    if (!our_fin_acked_ && MillisecondsSince(last_send) >= DATA_RTO_MS) {
      try {
        SendFin();
      } catch (...) {
        failed = true;
        break;
      }
      last_send = Clock::now();
    }
  }
  if (state_ != TcpState::CLOSED || failed) errno = failed ? EIO : ETIMEDOUT;
  state_ = TcpState::CLOSED;
}

ProcessResult TcpConnection::ProcessIncoming(int timeout_ms) {
  const bool was_time_wait = state_ == TcpState::TIME_WAIT;
  ExpireTimeWait();
  if (state_ == TcpState::CLOSED) {
    errno = ECONNRESET;
    return was_time_wait ? ProcessResult::TIMEOUT : ProcessResult::ERROR;
  }
  const Clock::time_point start = Clock::now();
  while (true) {
    int remaining = timeout_ms;
    if (timeout_ms > 0) {
      const auto elapsed = MillisecondsSince(start);
      if (elapsed >= timeout_ms) return ProcessResult::TIMEOUT;
      remaining = timeout_ms - static_cast<int>(elapsed);
    }
    ByteBuffer packet;
    const int received = sock_.RecvPacket(packet, remaining);
    if (received == 0) {
      errno = EAGAIN;
      return ProcessResult::TIMEOUT;
    }
    if (received < 0) return ProcessResult::ERROR;

    Ipv4Header ip{};
    std::size_t payload_offset = 0;
    if (!ParseIpv4Header(packet, ip, payload_offset) || ip.protocol != 6)
      continue;
    const std::size_t ip_header_len =
        static_cast<std::size_t>(packet[0] & 0x0F) * 4;
    if (!VerifyIpv4Checksum(packet, ip_header_len)) continue;
    if (ip.total_length < payload_offset || packet.size() < ip.total_length)
      continue;
    packet.resize(ip.total_length);

    const std::size_t tcp_len = ip.total_length - payload_offset;
    if (tcp_len < 20) continue;
    const std::uint8_t* tcp_data = packet.data() + payload_offset;
    TcpHeader tcp{};
    std::size_t tcp_header_len = 0;
    if (!ParseTcpHeader(tcp_data, tcp_len, tcp, tcp_header_len)) continue;

    bool match = false;
    if (state_ == TcpState::LISTEN) {
      match = tcp.dst_port == local_port_ && (tcp.flags & TCP_SYN) &&
              !(tcp.flags & TCP_ACK);
    } else {
      match = ip.src_ip == remote_ip_ && ip.dst_ip == local_ip_ &&
              tcp.src_port == remote_port_ && tcp.dst_port == local_port_;
    }
    if (!match) continue;
    if (!VerifyTcpChecksum(tcp_data, tcp_len, ip.src_ip, ip.dst_ip)) continue;
    const std::size_t payload_len = tcp_len - tcp_header_len;

    if (state_ == TcpState::LISTEN) {
      if ((tcp.flags & TCP_SYN) == 0 || (tcp.flags & TCP_ACK) != 0 ||
          (tcp.flags & (TCP_RST | TCP_FIN)) != 0 || payload_len != 0)
        continue;
    } else if (state_ == TcpState::SYN_SENT) {
      if (tcp.flags & TCP_RST) {
        if (!(tcp.flags & TCP_ACK) || tcp.ack_num != snd_iss_ + 1) continue;
      } else if ((tcp.flags & (TCP_SYN | TCP_ACK)) != (TCP_SYN | TCP_ACK) ||
                 (tcp.flags & (TCP_FIN | TCP_RST)) != 0 ||
                 tcp.ack_num != snd_iss_ + 1 || payload_len != 0) {
        continue;
      }
    } else if (state_ == TcpState::SYN_RECEIVED) {
      if (tcp.flags & TCP_RST) {
        if (!SequenceAcceptable(tcp.seq_num, 0)) continue;
      } else if (!(tcp.flags & TCP_ACK) ||
                 (tcp.flags & (TCP_SYN | TCP_FIN)) != 0 ||
                 tcp.ack_num != snd_iss_ + 1 || tcp.seq_num != rcv_nxt_ ||
                 payload_len != 0) {
        continue;
      }
    } else if (state_ != TcpState::CLOSED) {
      const std::size_t sequence_length = payload_len +
                                          ((tcp.flags & TCP_FIN) ? 1u : 0u) +
                                          ((tcp.flags & TCP_SYN) ? 1u : 0u);
      const bool duplicate_time_wait_fin =
          state_ == TcpState::TIME_WAIT && (tcp.flags & TCP_FIN) != 0 &&
          tcp.seq_num + static_cast<std::uint32_t>(payload_len) ==
              peer_fin_seq_;
      if (!duplicate_time_wait_fin &&
          !SequenceAcceptable(tcp.seq_num, sequence_length)) {
        // RFC 793: for a valid, checksummed segment that falls outside the
        // current window, send a cumulative ACK so the sender can resync.
        // (RST segments are silently dropped per the spec.)
        if ((tcp.flags & TCP_RST) == 0) {
          // Log the packet before sending the ACK so the trace is complete.
          if (!LogPacket("RECV", IpToString(ip.src_ip), tcp.src_port,
                         IpToString(ip.dst_ip), tcp.dst_port, ip.ttl,
                         ip.identification, tcp.seq_num, tcp.ack_num, tcp.flags,
                         tcp.window, static_cast<std::uint16_t>(payload_len),
                         tcp.mss))
            return ProcessResult::ERROR;
          SendAck();
          return ProcessResult::PROCESSED;
        }
        continue;
      }
      if (tcp.flags & TCP_ACK) {
        if (SeqLess(tcp.ack_num, snd_una_) ||
            SeqGreater(tcp.ack_num, snd_nxt_)) {
          continue;
        }
      }
      if (tcp.flags & TCP_SYN) continue;
    }

    if (state_ == TcpState::LISTEN) {
      local_ip_ = ip.dst_ip;
      remote_ip_ = ip.src_ip;
      remote_port_ = tcp.src_port;
    }

    const std::uint8_t* payload =
        payload_len ? tcp_data + tcp_header_len : nullptr;
    if (!LogPacket("RECV", IpToString(ip.src_ip), tcp.src_port,
                   IpToString(ip.dst_ip), tcp.dst_port, ip.ttl,
                   ip.identification, tcp.seq_num, tcp.ack_num, tcp.flags,
                   tcp.window, static_cast<std::uint16_t>(payload_len),
                   tcp.mss))
      return ProcessResult::ERROR;
    try {
      HandleSegment(ip, tcp, payload, payload_len);
    } catch (...) {
      errno = EIO;
      return ProcessResult::ERROR;
    }
    return ProcessResult::PROCESSED;
  }
}

void TcpConnection::HandleSegment(const Ipv4Header&, const TcpHeader& tcp,
                                  const std::uint8_t* payload,
                                  std::size_t payload_len) {
  if (state_ == TcpState::TIME_WAIT && (tcp.flags & TCP_FIN) != 0) {
    SendAck();
    time_wait_deadline_ =
        Clock::now() + std::chrono::milliseconds(TIME_WAIT_MS);
    return;
  }
  if (tcp.flags & TCP_RST) {
    if (state_ == TcpState::SYN_RECEIVED) {
      const std::uint16_t listen_port = local_port_;
      ResetConnectionState();
      local_port_ = listen_port;
      state_ = TcpState::LISTEN;
      return;
    }
    state_ = TcpState::CLOSED;
    errno = ECONNRESET;
    return;
  }
  if (state_ == TcpState::SYN_SENT) {
    if ((tcp.flags & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK) &&
        tcp.ack_num == snd_iss_ + 1) {
      rcv_irs_ = tcp.seq_num;
      rcv_nxt_ = tcp.seq_num + 1;
      receive_window_right_edge_ = rcv_nxt_ + OUR_WINDOW;
      peer_window_ = tcp.window;
      snd_wl1_ = tcp.seq_num;
      snd_wl2_ = tcp.ack_num;
      if (tcp.mss > 0) peer_mss_ = tcp.mss;
      snd_una_ = tcp.ack_num;
      state_ = TcpState::ESTABLISHED;
      SendAck();
    }
    return;
  }
  if (state_ == TcpState::LISTEN) {
    rcv_irs_ = tcp.seq_num;
    rcv_nxt_ = tcp.seq_num + 1;
    receive_window_right_edge_ = rcv_nxt_ + OUR_WINDOW;
    peer_window_ = tcp.window;
    snd_wl1_ = tcp.seq_num;
    snd_wl2_ = tcp.ack_num;
    if (tcp.mss > 0) peer_mss_ = tcp.mss;
    state_ = TcpState::SYN_RECEIVED;
    snd_iss_ = RandomIsn();
    snd_una_ = snd_iss_;
    snd_nxt_ = snd_iss_ + 1;
    SendSegment(TCP_SYN | TCP_ACK, nullptr, 0, our_mss_);
    return;
  }
  const std::uint16_t previous_peer_window = peer_window_;
  UpdatePeerWindow(tcp);
  const bool peer_window_changed = peer_window_ != previous_peer_window;
  if (tcp.flags & TCP_ACK) {
    if (SeqGreater(tcp.ack_num, snd_una_) &&
        SeqLessOrEqual(tcp.ack_num, snd_nxt_)) {
      std::uint32_t data_acknowledged = 0;
      snd_una_ = tcp.ack_num;
      last_ack_time_ = Clock::now();
      while (!send_buffer_.empty()) {
        UnackedSegment& segment = send_buffer_.front();
        const std::uint32_t segment_end =
            segment.seq_start + segment.sequence_length;
        if (SeqLessOrEqual(segment_end, snd_una_)) {
          data_acknowledged += segment.sequence_length;
          send_buffer_.erase(send_buffer_.begin());
        } else if (SeqGreater(snd_una_, segment.seq_start)) {
          const std::size_t consumed = snd_una_ - segment.seq_start;
          data_acknowledged += static_cast<std::uint32_t>(consumed);
          segment.payload.erase(segment.payload.begin(),
                                segment.payload.begin() + consumed);
          segment.seq_start = snd_una_;
          segment.sequence_length -= static_cast<std::uint32_t>(consumed);
          segment.sent_at = Clock::now();
          break;
        } else {
          break;
        }
      }
      if (data_acknowledged > 0)
        OnAckReceived(static_cast<std::int32_t>(data_acknowledged));
      if (data_acknowledged > 0) progress_time_ = Clock::now();
      dup_ack_count_ = 0;
      if (our_fin_sent_ && SeqGreaterOrEqual(tcp.ack_num, our_fin_seq_ + 1)) {
        our_fin_acked_ = true;
        if (state_ == TcpState::FIN_WAIT_1) state_ = TcpState::FIN_WAIT_2;
        if (state_ == TcpState::LAST_ACK)
          state_ = TcpState::CLOSED;
        else if (state_ == TcpState::CLOSING) {
          state_ = TcpState::TIME_WAIT;
          time_wait_deadline_ =
              Clock::now() + std::chrono::milliseconds(TIME_WAIT_MS);
        }
      }
    } else if (tcp.ack_num == snd_una_ && payload_len == 0 &&
               !peer_window_changed && !our_fin_sent_ &&
               !send_buffer_.empty() &&
               (tcp.flags & (TCP_FIN | TCP_SYN | TCP_RST | TCP_PSH | TCP_URG |
                             TCP_ECE | TCP_CWR)) == 0) {
      ++dup_ack_count_;
      if (dup_ack_count_ == 3)
        OnFastRetransmit();
      else if (dup_ack_count_ > 3 && in_fast_recovery_) {
        // Standard Reno: Inflate window by 1 MSS for each additional dup ACK
        cwnd_ += peer_mss_;
      }
    }
  }

  if (state_ == TcpState::SYN_RECEIVED) {
    if ((tcp.flags & TCP_ACK) && tcp.ack_num == snd_iss_ + 1)
      state_ = TcpState::ESTABLISHED;
    return;
  }

  const std::size_t original_payload_len = payload_len;
  const std::uint32_t original_fin_seq =
      tcp.seq_num + static_cast<std::uint32_t>(original_payload_len);
  const bool fin_acceptable =
      (tcp.flags & TCP_FIN) != 0 && SequenceAcceptable(original_fin_seq, 1);
  if (payload_len > 0 && !peer_fin_) {
    std::uint32_t start = tcp.seq_num;
    std::size_t offset = 0;
    const std::uint32_t right_edge = receive_window_right_edge_;
    const std::uint32_t payload_end =
        tcp.seq_num + static_cast<std::uint32_t>(payload_len);
    if (right_edge == rcv_nxt_ || SeqLess(right_edge, rcv_nxt_) ||
        !SeqLess(start, right_edge)) {
      payload_len = 0;
    } else if (SeqGreater(payload_end, right_edge)) {
      payload_len = right_edge - tcp.seq_num;
    }
    if (SeqLess(start, rcv_nxt_)) {
      offset = rcv_nxt_ - start;
      if (offset >= payload_len) offset = payload_len;
      start = rcv_nxt_;
    }
    const std::size_t available =
        RECEIVE_BUFFER_CAPACITY - BufferedBytes(recv_buffer_, ooo_buffer_);
    const std::size_t limit = std::min(payload_len - offset, available);
    for (std::size_t index = 0; index < limit;) {
      const std::uint32_t byte_seq = start + static_cast<std::uint32_t>(index);
      bool present = false;
      for (const auto& entry : ooo_buffer_) {
        const std::uint32_t entry_end = entry.first + entry.second.size();
        if (SeqLessOrEqual(entry.first, byte_seq) &&
            SeqLess(byte_seq, entry_end)) {
          present = true;
          break;
        }
      }
      if (present) {
        ++index;
        continue;
      }
      const std::size_t run_start = index;
      while (index < limit) {
        const std::uint32_t current = start + static_cast<std::uint32_t>(index);
        bool covered = false;
        for (const auto& entry : ooo_buffer_) {
          const std::uint32_t entry_end = entry.first + entry.second.size();
          if (SeqLessOrEqual(entry.first, current) &&
              SeqLess(current, entry_end)) {
            covered = true;
            break;
          }
        }
        if (covered) break;
        ++index;
      }
      ooo_buffer_.emplace(
          start + static_cast<std::uint32_t>(run_start),
          std::vector<std::uint8_t>(payload + offset + run_start,
                                    payload + offset + index));
    }
  }
  if ((tcp.flags & TCP_FIN) && !peer_fin_) {
    const std::uint32_t fin_seq = original_fin_seq;
    if (fin_acceptable && !pending_fin_) {
      pending_fin_ = true;
      pending_fin_seq_ = fin_seq;
    }
  }
  ProcessPendingDataAndFin();
  if (payload_len > 0 || (tcp.flags & TCP_FIN)) SendAck();
}

void TcpConnection::ProcessPendingDataAndFin() {
  while (true) {
    auto candidate = ooo_buffer_.end();
    for (auto it = ooo_buffer_.begin(); it != ooo_buffer_.end(); ++it) {
      const std::uint32_t end = it->first + it->second.size();
      if (SeqLessOrEqual(it->first, rcv_nxt_) && SeqGreater(end, rcv_nxt_)) {
        candidate = it;
        break;
      }
    }
    if (candidate == ooo_buffer_.end()) break;
    const std::size_t skip = rcv_nxt_ - candidate->first;
    recv_buffer_.insert(recv_buffer_.end(), candidate->second.begin() + skip,
                        candidate->second.end());
    rcv_nxt_ += static_cast<std::uint32_t>(candidate->second.size() - skip);
    ooo_buffer_.erase(candidate);
  }
  if (pending_fin_ && pending_fin_seq_ == rcv_nxt_) {
    peer_fin_ = true;
    peer_fin_seq_ = pending_fin_seq_;
    ++rcv_nxt_;
    pending_fin_ = false;
    if (state_ == TcpState::ESTABLISHED)
      state_ = TcpState::CLOSE_WAIT;
    else if (state_ == TcpState::FIN_WAIT_1)
      state_ = our_fin_acked_ ? TcpState::TIME_WAIT : TcpState::CLOSING;
    else if (state_ == TcpState::FIN_WAIT_2)
      state_ = TcpState::TIME_WAIT;
    if (state_ == TcpState::TIME_WAIT) {
      time_wait_deadline_ =
          Clock::now() + std::chrono::milliseconds(TIME_WAIT_MS);
    }
  }
}

bool TcpConnection::RetransmitCheck() {
  if (send_buffer_.empty() ||
      MillisecondsSince(send_buffer_.front().sent_at) < DATA_RTO_MS)
    return true;
  if (send_buffer_.front().retransmit_count >= MAX_RETRANSMITS) {
    AbortConnection(true);
    errno = ETIMEDOUT;
    return false;
  }
  OnRtoTimeout();
  RetransmitSegment(send_buffer_.front());
  return true;
}

void TcpConnection::RetransmitSegment(UnackedSegment& segment) {
  ByteBuffer tcp = BuildTcpSegment(
      local_port_, remote_port_, segment.seq_start, rcv_nxt_, segment.flags,
      ReceiveWindow(), segment.payload.data(), segment.payload.size(),
      local_ip_, remote_ip_, segment.mss_option);
  const std::uint16_t id = NextIpId();
  ByteBuffer packet = BuildIpv4Packet(local_ip_, remote_ip_, tcp, id);
  if (sock_.SendPacket(packet, remote_ip_) != static_cast<int>(packet.size())) {
    throw std::runtime_error("failed to retransmit TCP segment");
  }
  if (!LogPacket("SEND", IpToString(local_ip_), local_port_,
                 IpToString(remote_ip_), remote_port_, 64, id,
                 segment.seq_start, rcv_nxt_, segment.flags, ReceiveWindow(),
                 static_cast<std::uint16_t>(segment.payload.size()),
                 segment.mss_option))
    throw std::runtime_error("failed to write packet log");
  segment.sent_at = Clock::now();
  ++segment.retransmit_count;
}

void TcpConnection::OnAckReceived(std::int32_t acked_bytes) {
  if (acked_bytes <= 0) return;
  if (in_fast_recovery_) {
    cwnd_ = ssthresh_;
    in_fast_recovery_ = false;
  } else if (cwnd_ < ssthresh_) {
    cwnd_ += std::min<double>(acked_bytes, peer_mss_);
  } else if (cwnd_ > 0) {
    cwnd_ += static_cast<double>(peer_mss_) * acked_bytes / cwnd_;
  }
}

void TcpConnection::OnRtoTimeout() {
  ssthresh_ = std::max(cwnd_ / 2.0, static_cast<double>(peer_mss_) * 2);
  cwnd_ = peer_mss_;
  in_fast_recovery_ = false;
}

void TcpConnection::OnFastRetransmit() {
  ssthresh_ = std::max(cwnd_ / 2.0, static_cast<double>(peer_mss_) * 2);
  cwnd_ = ssthresh_ + 3.0 * peer_mss_;
  in_fast_recovery_ = true;
  if (!send_buffer_.empty() &&
      send_buffer_.front().retransmit_count < MAX_RETRANSMITS) {
    RetransmitSegment(send_buffer_.front());
  }
}

std::size_t TcpConnection::EffectiveWindow() const {
  const std::size_t congestion = static_cast<std::size_t>(std::max(0.0, cwnd_));
  return std::min(congestion, static_cast<std::size_t>(peer_window_));
}
