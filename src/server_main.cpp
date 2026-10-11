#include <sys/stat.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <climits>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "ipv4.h"
#include "tcp_connection.h"

static volatile std::sig_atomic_t running = 1;

static void StopServer(int) { running = 0; }

static std::string Lower(const std::string& value) {
  std::string result = value;
  std::transform(result.begin(), result.end(), result.begin(),
                 [](unsigned char character) {
                   return static_cast<char>(std::tolower(character));
                 });
  return result;
}

static std::string ContentType(const std::string& path) {
  const std::size_t dot = path.rfind('.');
  if (dot == std::string::npos) return "application/octet-stream";
  const std::string extension = Lower(path.substr(dot));
  if (extension == ".html" || extension == ".htm") return "text/html";
  if (extension == ".txt") return "text/plain";
  if (extension == ".css") return "text/css";
  if (extension == ".js") return "application/javascript";
  if (extension == ".json") return "application/json";
  if (extension == ".png") return "image/png";
  if (extension == ".jpg" || extension == ".jpeg") return "image/jpeg";
  if (extension == ".gif") return "image/gif";
  if (extension == ".pdf") return "application/pdf";
  return "application/octet-stream";
}

static bool IsDirectory(const std::string& path) {
  struct stat status{};
  return stat(path.c_str(), &status) == 0 && S_ISDIR(status.st_mode);
}

static bool ReadFile(const std::string& path, std::vector<std::uint8_t>& data) {
  std::ifstream file(path, std::ios::binary);
  if (!file) return false;
  data.assign(std::istreambuf_iterator<char>(file),
              std::istreambuf_iterator<char>());
  return true;
}

static bool RegularFile(const std::string& path) {
  struct stat status{};
  return stat(path.c_str(), &status) == 0 && S_ISREG(status.st_mode);
}

static bool IsInsideDocroot(const std::string& root, const std::string& path) {
  char real_root[PATH_MAX];
  char real_path[PATH_MAX];
  if (realpath(root.c_str(), real_root) == nullptr) return false;
  if (realpath(path.c_str(), real_path) == nullptr) return false;
  // Confirm real_path starts with real_root + '/'  (or equals real_root).
  const std::size_t root_len = std::strlen(real_root);
  if (std::strncmp(real_path, real_root, root_len) != 0) return false;
  return real_path[root_len] == '/' || real_path[root_len] == '\0';
}

static bool HasDotDot(const std::string& target) {
  const std::size_t query = target.find('?');
  const std::string path = target.substr(0, query);
  std::size_t start = 0;
  while (start < path.size()) {
    std::size_t end = path.find('/', start);
    if (end == std::string::npos) end = path.size();
    if (path.substr(start, end - start) == "..") return true;
    start = end + 1;
  }
  return false;
}

static std::string ResponseHead(int status, const std::string& reason,
                                std::size_t length, const std::string& type) {
  std::ostringstream response;
  response << "HTTP/1.1 " << status << ' ' << reason << "\r\n"
           << "Content-Length: " << length << "\r\n"
           << "Content-Type: " << type << "\r\n"
           << "Connection: close\r\n\r\n";
  return response.str();
}

static std::string ErrorBody(int status, const std::string& reason) {
  return "<!DOCTYPE html><html><head><title>" + std::to_string(status) + " " +
         reason + "</title></head><body><h1>" + std::to_string(status) + " " +
         reason + "</h1></body></html>\n";
}

int main(int argc, char* argv[]) {
  std::uint16_t port = 8080;
  std::string docroot = "./www";
  std::string log_path;
  for (int index = 1; index < argc; ++index) {
    const std::string argument = argv[index];
    if (argument == "-p" && index + 1 < argc) {
      const char* port_str = argv[++index];
      char* port_end = nullptr;
      errno = 0;
      const long port_val = std::strtol(port_str, &port_end, 10);
      if (port_end == port_str || *port_end != '\0' || errno == ERANGE ||
          port_val <= 0 || port_val > 65535) {
        std::fprintf(stderr, "Invalid port: %s\n", port_str);
        return 1;
      }
      port = static_cast<std::uint16_t>(port_val);
    } else if (argument == "-d" && index + 1 < argc)
      docroot = argv[++index];
    else if (argument == "--log" && index + 1 < argc)
      log_path = argv[++index];
  }

  std::signal(SIGINT, StopServer);
  std::signal(SIGTERM, StopServer);
  std::signal(SIGPIPE, SIG_IGN);

  PacketLog log;
  if (!log.Open(log_path)) return 1;
  while (docroot.size() > 1 && docroot.back() == '/') docroot.pop_back();

  while (running) {
    try {
      TcpConnection connection(log);
      std::uint32_t local_ip = 0;
      std::uint32_t remote_ip = 0;
      std::uint16_t remote_port = 0;
      if (!connection.Accept(port, local_ip, remote_ip, remote_port)) continue;

      static constexpr std::size_t kMaxHeaderBytes = 64 * 1024;
      std::string request;
      std::uint8_t buffer[2048];
      const auto start = std::chrono::steady_clock::now();
      while (request.find("\r\n\r\n") == std::string::npos) {
        if (request.size() >= kMaxHeaderBytes) break;
        if (std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - start)
                .count() >= 10)
          break;
        const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                                 std::chrono::steady_clock::now() - start)
                                 .count();
        const int remaining_ms = (10 - static_cast<int>(elapsed)) * 1000;
        const std::int32_t count =
            connection.Recv(buffer, sizeof(buffer), remaining_ms);
        if (count <= 0) break;
        request.append(reinterpret_cast<const char*>(buffer), count);
      }
      const std::size_t head_end = request.find("\r\n\r\n");
      if (head_end == std::string::npos) {
        connection.Close();
        continue;
      }

      const std::size_t line_end = request.find("\r\n");
      const std::string line = request.substr(0, line_end);
      const std::size_t first_space = line.find(' ');
      const std::size_t second_space = first_space == std::string::npos
                                           ? std::string::npos
                                           : line.find(' ', first_space + 1);
      bool valid = first_space != std::string::npos &&
                   second_space != std::string::npos &&
                   line.find(' ', second_space + 1) == std::string::npos;
      std::string method;
      std::string target;
      std::string version;
      if (valid) {
        method = line.substr(0, first_space);
        target = line.substr(first_space + 1, second_space - first_space - 1);
        version = line.substr(second_space + 1);
        valid = !method.empty() && !target.empty() && target[0] == '/' &&
                version.size() == 8 && version.compare(0, 5, "HTTP/") == 0 &&
                std::isdigit(static_cast<unsigned char>(version[5])) &&
                version[6] == '.' &&
                std::isdigit(static_cast<unsigned char>(version[7]));
      }

      int status = 200;
      std::string reason = "OK";
      std::string type = "text/html";
      std::vector<std::uint8_t> body;
      bool send_body = true;
      if (!valid) {
        status = 400;
        reason = "Bad Request";
      } else if (method != "GET" && method != "HEAD") {
        status = 501;
        reason = "Not Implemented";
      } else if (HasDotDot(target)) {
        status = 403;
        reason = "Forbidden";
      } else {
        send_body = method == "GET";
        std::string path = target;
        const std::size_t query = path.find('?');
        if (query != std::string::npos) path.resize(query);
        std::string file_path = docroot + path;
        if (path.back() == '/' || IsDirectory(file_path)) {
          if (file_path.back() != '/') file_path += '/';
          file_path += "index.html";
        }
        if (!RegularFile(file_path) || !ReadFile(file_path, body)) {
          status = 404;
          reason = "Not Found";
        } else if (!IsInsideDocroot(docroot, file_path)) {
          // Symlink resolved outside the document root – deny access.
          status = 403;
          reason = "Forbidden";
          body.clear();
        } else {
          type = ContentType(file_path);
        }
      }
      if (status != 200) {
        const std::string error = ErrorBody(status, reason);
        body.assign(error.begin(), error.end());
        type = "text/html";
      }

      const std::string head = ResponseHead(status, reason, body.size(), type);
      std::vector<std::uint8_t> response(head.begin(), head.end());
      if (send_body) response.insert(response.end(), body.begin(), body.end());
      if (!connection.Send(response)) {
        // Send failure: log and close; the connection is already broken.
        std::fprintf(stderr, "Send failed; closing connection\n");
      }
      connection.Close();
    } catch (...) {
      if (!running) break;
    }
  }
  return 0;
}
