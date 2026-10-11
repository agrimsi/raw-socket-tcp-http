#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "ipv4.h"
#include "packet_log.h"
#include "raw_socket.h"
#include "tcp.h"

enum class TcpState {
  CLOSED,
  LISTEN,
  SYN_SENT,
  SYN_RECEIVED,
  ESTABLISHED,
  FIN_WAIT_1,
  FIN_WAIT_2,
  CLOSE_WAIT,
  LAST_ACK,
  CLOSING,
  TIME_WAIT
};

// Holds one unacknowledged segment for retransmission.
struct UnackedSegment {
  std::uint32_t seq_start;
  std::uint32_t sequence_length;
  std::uint8_t flags;
  int mss_option;
  std::vector<std::uint8_t> payload;
  std::chrono::steady_clock::time_point sent_at;
  int retransmit_count;
};

// Sequence numbers are compared with wraparound helpers in connection logic.
// This comparator intentionally provides ordinary strict weak ordering for the
// std::map; wraparound ordering must not be used as a map comparator.
struct SeqCompare {
  bool operator()(std::uint32_t a, std::uint32_t b) const { return a < b; }
};

enum class ProcessResult { PROCESSED, TIMEOUT, ERROR };

class TcpConnection {
 public:
  TcpConnection(PacketLog& plog);
  ~TcpConnection();
  TcpConnection(const TcpConnection&) = delete;
  TcpConnection& operator=(const TcpConnection&) = delete;

  bool Connect(std::uint32_t src_ip, std::uint32_t dst_ip,
               std::uint16_t dst_port);

  bool Accept(std::uint16_t listen_port, std::uint32_t& local_ip,
              std::uint32_t& remote_ip, std::uint16_t& remote_port);

  bool Send(const std::uint8_t* data, std::size_t len);
  bool Send(const std::vector<std::uint8_t>& data) {
    return Send(data.data(), data.size());
  }
  bool Send(const std::string& data) {
    return Send(reinterpret_cast<const std::uint8_t*>(data.data()),
                data.size());
  }

  // Returns a positive byte count when data is delivered, 0 on graceful peer
  // EOF, and -1 on timeout or error
  std::int32_t Recv(std::uint8_t* buf, std::size_t max_len, int timeout_s = 10);
  // Returns data received before EOF or error. On an incomplete/error return,
  // errno retains the reason reported by Recv().
  std::vector<std::uint8_t> RecvAll();

  // graceful closure
  // send fin, wait for ack and peer fin, ack the peer fin
  void Close();

  TcpState State() const { return state_; }
  bool IsConnected() const {
    return state_ == TcpState::ESTABLISHED || state_ == TcpState::CLOSE_WAIT;
  }
  bool PeerFinReceived() const { return peer_fin_; }

 private:
  void SendSegment(std::uint8_t flags, const std::uint8_t* payload,
                   std::size_t len, int mss_opt = -1);
  void SendAck();
  void SendFin();
  void SendRst();

  // true if packet was processed
  ProcessResult ProcessIncoming(int timeout_ms);

  void ResetConnectionState();
  void ExpireTimeWait();
  void AbortConnection(bool send_rst);
  void ReopenReceiveWindow();
  std::uint16_t ReceiveWindow() const;
  bool SequenceAcceptable(std::uint32_t sequence, std::size_t length) const;
  void UpdatePeerWindow(const TcpHeader& tcp);
  void ProcessPendingDataAndFin();
  bool LogPacket(const char* direction, const std::string& src_ip,
                 std::uint16_t src_port, const std::string& dst_ip,
                 std::uint16_t dst_port, std::uint8_t ttl, std::uint16_t id,
                 std::uint32_t seq, std::uint32_t ack, std::uint8_t flags,
                 std::uint16_t window, std::uint16_t payload_len, int mss);
  void RetransmitSegment(UnackedSegment& segment);

  void HandleSegment(const Ipv4Header& ip_hdr, const TcpHeader& tcp_hdr,
                     const std::uint8_t* payload, std::size_t payload_len);

  // retransmission logic here
  bool RetransmitCheck();

  // congestion control implemented here
  void OnAckReceived(std::int32_t acked_bytes);
  void OnRtoTimeout();
  void OnFastRetransmit();
  std::size_t EffectiveWindow() const;

  // packet id gen here
  std::uint16_t NextIpId();

  // state variables
  RawSocket sock_;
  PacketLog& plog_;

  TcpState state_;

  std::uint32_t local_ip_;
  std::uint32_t remote_ip_;
  std::uint16_t local_port_;
  std::uint16_t remote_port_;

  // Sequence numbers.
  std::uint32_t snd_una_;  // oldest unacknowledged byte
  std::uint32_t snd_nxt_;  // next byte to send
  std::uint32_t snd_iss_;  // initial send sequence number

  std::uint32_t rcv_nxt_;  // next expected byte from peer
  std::uint32_t rcv_irs_;  // initial receive sequence number

  // Peer's advertised window and the sequence numbers used to accept
  // window updates (RFC 793 SND.WL1/SND.WL2).
  std::uint16_t peer_window_;
  std::uint32_t snd_wl1_;
  std::uint32_t snd_wl2_;
  // Our advertised window (fixed at 65535)
  static constexpr std::uint16_t OUR_WINDOW = 65535;
  static constexpr std::size_t RECEIVE_BUFFER_CAPACITY = OUR_WINDOW;

  // MSS negotiation.
  std::uint16_t our_mss_;   // always 1460
  std::uint16_t peer_mss_;  // from peer's SYN/SYN-ACK, default 536

  // Retransmission buffer: segments sent but not yet ACKed.
  std::vector<UnackedSegment> send_buffer_;

  // Out-of-order receive buffer: seq -> data with sequence-space
  // comparison.
  std::map<std::uint32_t, std::vector<std::uint8_t>, SeqCompare> ooo_buffer_;

  // In-order received data ready for the application.
  std::vector<std::uint8_t> recv_buffer_;

  // FIN tracking.
  bool peer_fin_;
  std::uint32_t peer_fin_seq_;
  bool pending_fin_;
  std::uint32_t pending_fin_seq_;
  bool our_fin_sent_;
  bool our_fin_acked_;
  std::uint32_t our_fin_seq_;

  // Congestion control
  double cwnd_;      // congestion window in bytes
  double ssthresh_;  // slow start threshold
  std::uint32_t dup_ack_count_;
  bool in_fast_recovery_;

  // IP identification counter.
  std::uint16_t ip_id_counter_;

  // Timeout tracking.
  std::chrono::steady_clock::time_point last_ack_time_;
  std::chrono::steady_clock::time_point progress_time_;
  std::chrono::steady_clock::time_point time_wait_deadline_;

  // Absolute right edge of the receive window most recently opened to peer.
  // It never moves backwards when an out-of-order segment is buffered.
  std::uint32_t receive_window_right_edge_;
};