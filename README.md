# User-Space TCP/IPv4 Stack & HTTP/1.1 Server/Client over Raw Sockets

## Overview

This repository contains a full user-space TCP/IPv4 network protocol stack and HTTP/1.1 client/server implemented in C++17 using Linux raw sockets (`SOCK_RAW`, `IPPROTO_TCP`).

By bypassing the kernel TCP layer, the implementation manually constructs every 20-byte IPv4 header, builds TCP segments, manages connection states (3-way handshake, teardown, resets), enforces Reno-style sliding-window congestion control, buffers out-of-order segments, and handles HTTP/1.1 message parsing. The system operates across a 4-node virtual routed network topology configured with static routing table rules and strict reverse-path filtering.



## Network Topology & Routing Architecture

The network consists of four Linux virtual machines connected across four isolated internal networks (LAN A, LAN B, LAN C, and Link D). Traffic routing is asymmetric, forcing forward and reverse paths through distinct intermediate network interfaces.

```text
               LAN A                       LAN B                       LAN C
            10.10.1.0/24                10.10.2.0/24                10.10.3.0/24
┌─────────┐ .10        .1 ┌────┐ .1            .2 ┌────┐ .1        .10 ┌────────┐
│ Client  ├───────────────┤ r1 ├──────────────────┤ r2 ├───────────────┤ Server │
└────┬────┘               └────┘                  └─┬──┘               └────────┘
     │ .2                                           │ .1
     └──────────────────────────────────────────────┘
                       Link D (10.10.4.0/30)
```

### Addressing & Routing Rules

* **Client $\rightarrow$ Server Traffic Path**: Travels over LAN A to Router `r1`, then LAN B to Router `r2`, then LAN C to `Server` (`Client` $\rightarrow$ `r1` $\rightarrow$ `r2` $\rightarrow$ `Server`).


* **Server $\rightarrow$ Client Traffic Path**: Bypasses Router `r1` completely by traveling over LAN C to Router `r2`, then directly across Link D to `Client` (`Server` $\rightarrow$ `r2` $\rightarrow$ `Client`).


* **Reverse-Path Filtering (`rp_filter`)**:
* `r1` and `Server` enforce strict reverse-path filtering (`rp_filter = 1`). Strict mode drops incoming packets if the receiving interface does not match the best return route in the routing table, preventing IP spoofing and asymmetric route leaks.


* `Client` and `r2` require loose filtering (`rp_filter = 2`) due to intentionally asymmetric forward/reverse paths across Link D.

## TCP/IPv4 Raw Socket Protocol Stack

```text
┌─────────────────────────────────────────────────────────────┐
│                    HTTP/1.1 Application                     │
│               Client (GET)  │  Server (200/404)             │
└──────────────────────────────┬──────────────────────────────┘
                               │ (Byte Stream Interface)
┌──────────────────────────────▼──────────────────────────────┐
│                    User-Space TCP Stack                     │
│  - State Machine (SYN/ESTABLISHED/FIN)                      │
│  - Sliding Window & Reno Congestion Control (cwnd/ssthresh) │
│  - Out-of-Order Segment Reassembly Queue                    │
│  - Cumulative ACKs & Timeout Retransmissions (RTO)          │
└──────────────────────────────┬──────────────────────────────┘
                               │ (20-byte TCP Segments)
┌──────────────────────────────▼──────────────────────────────┐
│                     IPv4 Frame Builder                      │
│  - Manual 20-byte IP Header Construction & Checksum         │
│  - Identification & TTL Management                          │
└──────────────────────────────┬──────────────────────────────┘
                               │ (IP Packets)
┌──────────────────────────────▼──────────────────────────────┐
│             Linux Raw Socket (SOCK_RAW / IP_HDRINCL)        │
└─────────────────────────────────────────────────────────────┘
```

### 1. Raw Socket & Kernel Suppression Interface (`raw_socket.cpp`)

* **`IP_HDRINCL` Socket Mode**: Operating system sockets are created with `socket(AF_INET, SOCK_RAW, IPPROTO_TCP)` and configured with `IP_HDRINCL`. This forces the kernel to pass user-constructed IPv4 headers directly to the network interface without altering packet fields.


* **Kernel RST Suppression via `iptables**`: When a raw TCP segment is received, the host Linux kernel's TCP stack (unaware of the user-space socket connection) attempts to send a TCP `RST` to terminate what it perceives as an orphaned connection. Shell launchers execute `iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP` to suppress kernel-generated resets.



### 2. IPv4 Header Management (`ipv4.cpp`)

* **Header Structure**: Manually constructs 20-byte IPv4 headers including Version (4), IHL (5), Total Length, Non-zero Identification, Flags (`0x4000` Don't Fragment), TTL (64), Protocol (6 for TCP), Internet Checksum, Source IP, and Destination IP.


* **Checksum Calculation**: Computes 16-bit 1's complement sums over 16-bit big-endian words across the IP header.



### 3. User-Space TCP Connection & State Machine (`tcp_connection.cpp`)

* **Handshake & Sequence Numbers**: Chooses a randomized Initial Sequence Number (ISN) and executes a full 3-way handshake (`SYN` $\rightarrow$ `SYN-ACK` $\rightarrow$ `ACK`). Retransmits unacknowledged `SYN` segments at exponential RTO backoff intervals.


* **Reliable Transfer & Out-of-Order Reassembly**:
* Maintains a sliding receive window ($65,535$ bytes).


* Received segments falling inside the window are placed into an ordered reassembly queue (`std::map<uint32_t, ByteBuffer>`). Gaps in sequence numbers trigger cumulative ACKs pointing to the highest contiguous byte received, ensuring loss recovery without throughput collapse.




* **Reno Congestion Control**:
* Tracks Congestion Window (`cwnd`) and Slow Start Threshold (`ssthresh`).


* Operates in **Slow Start** (exponential `cwnd` growth per ACK) when $\text{cwnd} < \text{ssthresh}$.


* Transitions to **Congestion Avoidance** (linear `cwnd` growth of $1 \text{ MSS}$ per RTT) when $\text{cwnd} \ge \text{ssthresh}$.


* On packet loss timeout, sets $\text{ssthresh} = \max(2 \times \text{MSS}, \frac{\text{cwnd}}{2})$ and resets $\text{cwnd} = 1 \text{ MSS}$.




* **Connection Teardown**: Sends `FIN` segments, processes cumulative `FIN-ACK` confirmations, and responds to incoming `RST` frames by terminating connection handles immediately.


## HTTP/1.1 Protocol Implementation

### HTTP Client (`client_main.cpp`)

* Issues formatted HTTP/1.1 `GET` requests containing mandatory `Host` and `Connection: close` headers.


* Parses status codes from HTTP status lines and streams output to target files or `stdout`.


* Handles multiple response framing modes:
* `Content-Length`: Pre-buffers fixed byte counts.


* `Transfer-Encoding: chunked`: Parses hexadecimal chunk-size headers, strips chunk extensions/OWS, and stops at zero-length terminal chunks (`0\r\n\r\n`).


* EOF / Connection Close: Reads payload bytes until socket teardown.





### HTTP Server (`server_main.cpp`)

* Single-threaded event-driven server managing raw connections with `poll()` timeouts.


* **Security & Path Mapping**:
* Validates document root boundaries (`IsInsideDocroot`) via `realpath()` checks to prevent directory traversal attacks (`../`).


* Resolves directory requests to `index.html`.




* **Content Type Resolution**: Maps file extensions (`.html`, `.css`, `.js`, `.json`, `.png`, `.jpg`, `.pdf`, etc.) to standard MIME types.


* **Error Handling**: Generates HTML bodies for HTTP status errors: `400 Bad Request`, `403 Forbidden`, `404 Not Found`, and `501 Not Implemented`.



## System Verification & Experiments

### Network Diagnostic & Path Routing (Report R1–R3)

* **Asymmetric Traceroute Analysis**: Running `traceroute` from Client (`10.10.1.10`) to Server (`10.10.3.10`) traverses 3 hops (`r1` $\rightarrow$ `r2` $\rightarrow$ `server`). Return traffic from Server to Client traverses 2 hops across Link D (`r2` $\rightarrow$ `client`), demonstrating static asymmetric routing table configuration.


* **Reverse Path Filter Verification**: Verified strict filtering on `r1` to block asymmetric entry on LAN B, while allowing loose path routing on `r2` for Link D cross-traffic.



### User-Space TCP & HTTP Interoperability (Report R4–R6)

* **Standard Interoperability Test**: Successfully downloaded $>100 \text{ KB}$ binary files from standard `python3 -m http.server` instances using the raw socket client. MD5 checksums matched `curl` downloads identically (`md5sum out.bin == md5sum curl.bin`).


* **Server Cross-Client Compatibility**: Verified that `curl`, `wget`, and custom raw socket clients can concurrently request files from the custom HTTP server with matching payload hashes.


* **Wire Captures & Packet Logging**: Captured raw Wireshark/tcpdump execution logs confirming 3-way handshake sequence matches, `cwnd` expansion, out-of-order block buffering, cumulative ACKs, and connection teardowns.




## Build and Usage Instructions

### Requirements

* Ubuntu 22.04 LTS (x86-64)


* C++17 Compiler (`g++` 11 or newer)


* Root privileges (`sudo`) for raw socket binding and `iptables` execution



### Build Steps

Compile both client and server binaries using `make`:

```bash
make
```

To clear build artifacts:

```bash
make clean
```

### Running the System

#### 1. Configure VM Network Routing (Run as root on each VM)

```bash
# On Client VM:
sudo ./netcfg/client.sh IF_A IF_D

# On Router 1 (r1) VM:
sudo ./netcfg/r1.sh IF_A IF_B

# On Router 2 (r2) VM:
sudo ./netcfg/r2.sh IF_B IF_C IF_D

# On Server VM:
sudo ./netcfg/server.sh IF_C
```

#### 2. Start HTTP Server

```bash
sudo ./server/run-server -p 8080 -d ./www --log server.log
```

#### 3. Execute HTTP Client

```bash
sudo ./client/run-client http://10.10.3.10:8080/index.html -o out.html --log client.log
```


## Directory Structure

```text
.
├── Makefile                   # C++17 build system rules
├── README.md                  # Project overview and usage guide
├── report.pdf                 # Routing and TCP experiment analysis report
├── client/
│   └── run-client             # Executable launcher for HTTP client (suppresses kernel RSTs)
├── server/
│   └── run-server             # Executable launcher for HTTP server (suppresses kernel RSTs)
├── netcfg/
│   ├── client.sh              # Network & ip route setup script for Client
│   ├── r1.sh                  # Network & ip route setup script for Router 1
│   ├── r2.sh                  # Network & ip route setup script for Router 2
│   └── server.sh              # Network & ip route setup script for Server
├── src/
│   ├── client_main.cpp        # HTTP Client main loop and URL parser
│   ├── server_main.cpp        # HTTP Server main loop and file router
│   ├── raw_socket.h           # POSIX raw socket wrapper
│   ├── raw_socket.cpp         # Raw socket initialization & sendto/recv routines
│   ├── ipv4.h                 # IPv4 header structures & checksum prototypes
│   ├── ipv4.cpp               # IPv4 packet builder and parser
│   ├── tcp.h                  # TCP segment structure definitions
│   ├── tcp.cpp                # TCP segment building & parsing
│   ├── tcp_connection.h       # TCP Connection state machine interface
│   ├── tcp_connection.cpp     # Reno congestion control, sliding window & reassembly
│   └── packet_log.h           # Wire packet logging formatter
└── www/
    └── index.html             # Default root HTML file for web server
```