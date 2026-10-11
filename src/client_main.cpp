
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>

#include "ipv4.h"
#include "tcp_connection.h"

struct ParsedUrl {
  std::string raw_host;
  std::string ip;
  std::uint16_t port = 80;
  std::string path = "/";
  bool valid = false;
};

static ParsedUrl ParseUrl(const std::string& url) {
  ParsedUrl parsed;
  const std::string prefix = "http://";
  if (url.compare(0, prefix.size(), prefix) != 0) return parsed;

  const std::string rest = url.substr(prefix.size());
  const std::size_t slash = rest.find('/');
  const std::size_t question = rest.find('?');
  // authority ends at whichever delimiter appears first.
  const std::size_t auth_end = std::min(slash, question);
  const std::string host_port =
      auth_end == std::string::npos ? rest : rest.substr(0, auth_end);
  if (host_port.empty()) return parsed;
  parsed.raw_host = host_port;
  if (slash != std::string::npos) {
    parsed.path = rest.substr(slash);
  } else if (question != std::string::npos) {
    parsed.path = "/" + rest.substr(question);
  }
  std::string hostname = host_port;
  const std::size_t colon = host_port.rfind(':');
  if (colon != std::string::npos) {
    const std::string port_text = host_port.substr(colon + 1);
    if (port_text.empty()) return parsed;
    char* end = nullptr;
    const long port = std::strtol(port_text.c_str(), &end, 10);
    if (*end != '\0' || port <= 0 || port > 65535) return parsed;
    parsed.port = static_cast<std::uint16_t>(port);
    hostname = host_port.substr(0, colon);
  }
  if (hostname.empty()) return parsed;

  const Ipv4Address numeric = StringToIp(hostname);
  if (numeric != 0) {
    parsed.ip = hostname;
  } else {
    addrinfo hints{};
    hints.ai_family = AF_INET;
    addrinfo* result = nullptr;
    if (getaddrinfo(hostname.c_str(), nullptr, &hints, &result) != 0 ||
        result == nullptr) {
      return parsed;
    }
    const auto* address = reinterpret_cast<const sockaddr_in*>(result->ai_addr);
    parsed.ip = IpToString(address->sin_addr.s_addr);
    freeaddrinfo(result);
    if (parsed.ip.empty()) return parsed;
  }
  parsed.valid = true;
  return parsed;
}

static std::string LocalIpFor(const std::string& destination) {
  const int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (socket_fd < 0) return {};
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(80);
  if (inet_pton(AF_INET, destination.c_str(), &address.sin_addr) != 1 ||
      connect(socket_fd, reinterpret_cast<sockaddr*>(&address),
              sizeof(address)) < 0) {
    close(socket_fd);
    return {};
  }
  sockaddr_in local{};
  socklen_t length = sizeof(local);
  if (getsockname(socket_fd, reinterpret_cast<sockaddr*>(&local), &length) <
      0) {
    close(socket_fd);
    return {};
  }
  close(socket_fd);
  return IpToString(local.sin_addr.s_addr);
}

static std::string Lower(const std::string& value) {
  std::string result = value;
  std::transform(result.begin(), result.end(), result.begin(),
                 [](unsigned char character) {
                   return static_cast<char>(std::tolower(character));
                 });
  return result;
}

static std::string HeaderValue(const std::string& headers,
                               const std::string& name) {
  const std::string lower = Lower(headers);
  const std::string needle = Lower(name) + ":";
  std::size_t position = lower.find(needle);
  while (position != std::string::npos && position != 0 &&
         lower[position - 1] != '\n') {
    position = lower.find(needle, position + 1);
  }
  if (position == std::string::npos) return {};
  std::size_t start = position + needle.size();
  // Trim leading OWS (RFC 7230 §3.2.3).
  while (start < headers.size() &&
         (headers[start] == ' ' || headers[start] == '\t'))
    ++start;
  const std::size_t end = headers.find("\r\n", start);
  std::string value = headers.substr(
      start, end == std::string::npos ? std::string::npos : end - start);
  // Trim trailing OWS.
  while (!value.empty() && (value.back() == ' ' || value.back() == '\t'))
    value.pop_back();
  return value;
}

static std::int32_t ReceiveMore(TcpConnection& connection,
                                std::vector<std::uint8_t>& data,
                                std::uint8_t* buffer, std::size_t capacity) {
  const std::int32_t count = connection.Recv(buffer, capacity);
  if (count > 0) data.insert(data.end(), buffer, buffer + count);
  return count;
}

int main(int argc, char* argv[]) {
  std::string url_text;
  std::string output;
  std::string log_path;
  for (int index = 1; index < argc; ++index) {
    const std::string argument = argv[index];
    if (argument == "-o" && index + 1 < argc)
      output = argv[++index];
    else if (argument == "--log" && index + 1 < argc)
      log_path = argv[++index];
    else if (url_text.empty())
      url_text = argument;
  }
  if (url_text.empty()) return 2;

  const ParsedUrl url = ParseUrl(url_text);
  if (!url.valid) return 2;
  const std::string local_text = LocalIpFor(url.ip);
  if (local_text.empty()) return 2;

  PacketLog log;
  if (!log.Open(log_path)) return 2;
  TcpConnection connection(log);
  if (!connection.Connect(StringToIp(local_text), StringToIp(url.ip), url.port))
    return 2;

  const std::string request = "GET " + url.path +
                              " HTTP/1.1\r\nHost: " + url.raw_host +
                              "\r\nConnection: close\r\n\r\n";
  if (!connection.Send(request)) {
    connection.Close();
    return 2;
  }

  static constexpr unsigned long long kMaxBodyBytes = 256ULL * 1024 * 1024;

  std::vector<std::uint8_t> received;
  std::uint8_t buffer[4096];
  int status = 0;
  std::size_t header_end = std::string::npos;
  std::size_t body_start = 0;
  std::string response;  // final response header block (without body)

  while (true) {
    // Accumulate until we have a complete header block.
    while (header_end == std::string::npos) {
      if (ReceiveMore(connection, received, buffer, sizeof(buffer)) <= 0) {
        connection.Close();
        return 2;
      }
      const std::string text(received.begin(), received.end());
      header_end = text.find("\r\n\r\n");
    }

    response.assign(received.begin(), received.begin() + header_end);
    body_start = header_end + 4;

    const std::size_t status_end = response.find("\r\n");
    const std::string status_line = response.substr(0, status_end);
    std::fprintf(stderr, "%s\n", status_line.c_str());
    const std::size_t status_space = status_line.find(' ');
    status = status_space == std::string::npos
                 ? 0
                 : std::atoi(status_line.c_str() + status_space + 1);

    // A 1xx status is informational; discard it and read the real response.
    if (status >= 100 && status < 200) {
      // Consume exactly the interim headers (body_start bytes) and restart.
      received.erase(received.begin(), received.begin() + body_start);
      header_end = std::string::npos;
      continue;
    }
    break;
  }

  std::vector<std::uint8_t> body;
  const std::string transfer =
      Lower(HeaderValue(response, "Transfer-Encoding"));
  const std::string length_text = HeaderValue(response, "Content-Length");
  if (transfer.find("chunked") != std::string::npos) {
    std::size_t position = body_start;
    while (true) {
      while (std::string(received.begin() + position, received.end())
                 .find("\r\n") == std::string::npos) {
        if (ReceiveMore(connection, received, buffer, sizeof(buffer)) <= 0) {
          connection.Close();
          return 2;
        }
      }
      std::string wire_line(received.begin() + position, received.end());
      wire_line = wire_line.substr(0, wire_line.find("\r\n"));
      const std::size_t line_length = wire_line.size();
      std::string line = wire_line;
      const std::size_t extension = line.find(';');
      if (extension != std::string::npos) line.resize(extension);
      // Strip any trailing OWS before parsing (some servers emit it).
      while (!line.empty() && (line.back() == ' ' || line.back() == '\t'))
        line.pop_back();
      if (line.empty()) {
        connection.Close();
        return 2;
      }
      char* chunk_end = nullptr;
      const unsigned long long chunk =
          std::strtoull(line.c_str(), &chunk_end, 16);
      if (chunk_end == line.c_str() || *chunk_end != '\0') {
        connection.Close();
        return 2;
      }
      // Reject excessively large chunk sizes to prevent overflow / OOM.
      if (chunk > kMaxBodyBytes) {
        connection.Close();
        return 2;
      }
      position += line_length + 2;
      if (chunk == 0) {
        while (true) {
          const std::string tail(received.begin() + position, received.end());
          const std::size_t end_line = tail.find("\r\n");
          if (end_line == std::string::npos) {
            if (ReceiveMore(connection, received, buffer, sizeof(buffer)) <=
                0) {
              connection.Close();
              return 2;
            }
          } else {
            position += end_line + 2;
            if (end_line == 0) break;
          }
        }
        break;
      }
      // Ensure position + chunk + 2 cannot overflow std::size_t.
      if (chunk + 2 > kMaxBodyBytes ||
          position > received.max_size() - chunk - 2) {
        connection.Close();
        return 2;
      }
      while (received.size() < position + chunk + 2) {
        if (ReceiveMore(connection, received, buffer, sizeof(buffer)) <= 0) {
          connection.Close();
          return 2;
        }
      }
      body.insert(body.end(), received.begin() + position,
                  received.begin() + position + chunk);
      if (received[position + chunk] != '\r' ||
          received[position + chunk + 1] != '\n') {
        connection.Close();
        return 2;
      }
      position += chunk + 2;
    }
  } else if (!length_text.empty()) {
    char* end = nullptr;
    const unsigned long long length =
        std::strtoull(length_text.c_str(), &end, 10);
    if (end == length_text.c_str() || *end != '\0') {
      connection.Close();
      return 2;
    }
    // Reject implausibly large Content-Length to avoid OOM / overflow.
    if (length > kMaxBodyBytes) {
      connection.Close();
      return 2;
    }
    // Guard against body_start + length overflowing std::size_t.
    if (length > received.max_size() - body_start) {
      connection.Close();
      return 2;
    }
    while (received.size() < body_start + length) {
      if (ReceiveMore(connection, received, buffer, sizeof(buffer)) <= 0) {
        connection.Close();
        return 2;
      }
    }
    body.assign(received.begin() + body_start,
                received.begin() + body_start + length);
  } else {
    std::int32_t recv_result = 0;
    while ((recv_result = ReceiveMore(connection, received, buffer,
                                      sizeof(buffer))) > 0) {
    }
    if (recv_result < 0) {
      connection.Close();
      return 2;
    }
    body.assign(received.begin() + body_start, received.end());
  }

  connection.Close();
  if (!output.empty()) {
    std::ofstream file(output, std::ios::binary);
    if (!file) return 2;
    file.write(reinterpret_cast<const char*>(body.data()), body.size());
    if (!file) return 2;
  } else {
    std::fwrite(body.data(), 1, body.size(), stdout);
    std::fflush(stdout);
  }
  return status >= 200 && status < 300 ? 0 : 1;
}
