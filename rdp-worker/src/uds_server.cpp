#include "privion/rdp/uds_server.hpp"

#include <cerrno>
#include <cstring>
#include <vector>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

namespace privion::rdp {
namespace {

void set_error(std::string* error, const char* code) {
  if (error != nullptr) {
    *error = code;
  }
}

bool read_exact(int fd, unsigned char* buf, std::size_t len, std::string* error) {
  std::size_t got = 0;
  while (got < len) {
    ssize_t n = ::read(fd, buf + got, len - got);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      set_error(error, "read_failed");
      return false;
    }
    if (n == 0) {
      set_error(error, "short_read");
      return false;
    }
    got += static_cast<std::size_t>(n);
  }
  return true;
}

bool write_exact(int fd, const unsigned char* buf, std::size_t len,
                 std::string* error) {
  std::size_t sent = 0;
  while (sent < len) {
    ssize_t n = ::write(fd, buf + sent, len - sent);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      set_error(error, "write_failed");
      return false;
    }
    sent += static_cast<std::size_t>(n);
  }
  return true;
}

}  // namespace

UdsServer::~UdsServer() { close_all(); }

void UdsServer::close_all() noexcept {
  if (listen_fd_ >= 0) {
    ::close(listen_fd_);
    listen_fd_ = -1;
  }
  if (bound_ && !path_.empty()) {
    ::unlink(path_.c_str());
    bound_ = false;
  }
}

bool UdsServer::listen(const std::string& path, uid_t allowed_uid,
                       std::string* error) {
  if (path.empty() || path.size() >= sizeof(sockaddr_un::sun_path)) {
    set_error(error, "bad_path");
    return false;
  }
  path_ = path;
  allowed_uid_ = allowed_uid;

  listen_fd_ = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (listen_fd_ < 0) {
    set_error(error, "socket_failed");
    return false;
  }

  ::unlink(path_.c_str());  // best-effort remove a stale socket

  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  std::memcpy(addr.sun_path, path_.c_str(), path_.size());

  // Create the socket node with 0600 by constraining the process umask during
  // bind, then hardening explicitly with chmod (defense in depth).
  mode_t old_umask = ::umask(0177);
  int rc = ::bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
  ::umask(old_umask);
  if (rc != 0) {
    set_error(error, "bind_failed");
    close_all();
    return false;
  }
  bound_ = true;
  if (::chmod(path_.c_str(), S_IRUSR | S_IWUSR) != 0) {
    set_error(error, "chmod_failed");
    close_all();
    return false;
  }
  if (::listen(listen_fd_, 1) != 0) {
    set_error(error, "listen_failed");
    close_all();
    return false;
  }
  return true;
}

int UdsServer::accept_verified(std::string* error) {
  if (listen_fd_ < 0) {
    set_error(error, "not_listening");
    return -1;
  }
  int conn = ::accept4(listen_fd_, nullptr, nullptr, SOCK_CLOEXEC);
  if (conn < 0) {
    set_error(error, "accept_failed");
    return -1;
  }
  ucred cred{};
  socklen_t len = sizeof(cred);
  if (::getsockopt(conn, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0) {
    set_error(error, "peercred_failed");
    ::close(conn);
    return -1;
  }
  if (cred.uid != allowed_uid_) {
    set_error(error, "peer_uid_denied");
    ::close(conn);
    return -1;
  }
  return conn;
}

bool write_frame(int fd, std::string_view payload, std::string* error) {
  if (payload.size() > kMaxFrameBytes) {
    set_error(error, "frame_too_large");
    return false;
  }
  std::uint32_t n = static_cast<std::uint32_t>(payload.size());
  unsigned char hdr[4] = {
      static_cast<unsigned char>((n >> 24) & 0xFF),
      static_cast<unsigned char>((n >> 16) & 0xFF),
      static_cast<unsigned char>((n >> 8) & 0xFF),
      static_cast<unsigned char>(n & 0xFF),
  };
  if (!write_exact(fd, hdr, sizeof(hdr), error)) {
    return false;
  }
  return write_exact(fd, reinterpret_cast<const unsigned char*>(payload.data()),
                     payload.size(), error);
}

namespace {

std::optional<std::uint32_t> read_frame_len(int fd, std::string* error) {
  unsigned char hdr[4];
  if (!read_exact(fd, hdr, sizeof(hdr), error)) {
    return std::nullopt;
  }
  std::uint32_t n = (static_cast<std::uint32_t>(hdr[0]) << 24) |
                    (static_cast<std::uint32_t>(hdr[1]) << 16) |
                    (static_cast<std::uint32_t>(hdr[2]) << 8) |
                    static_cast<std::uint32_t>(hdr[3]);
  if (n > kMaxFrameBytes) {
    set_error(error, "frame_too_large");
    return std::nullopt;
  }
  return n;
}

}  // namespace

std::optional<std::string> read_frame(int fd, std::string* error) {
  auto n = read_frame_len(fd, error);
  if (!n) {
    return std::nullopt;
  }
  std::string out;
  out.resize(*n);
  if (*n > 0 &&
      !read_exact(fd, reinterpret_cast<unsigned char*>(out.data()), *n, error)) {
    return std::nullopt;
  }
  return out;
}

std::optional<SecureBuffer> read_frame_secure(int fd, std::string* error) {
  auto n = read_frame_len(fd, error);
  if (!n) {
    return std::nullopt;
  }
  std::vector<unsigned char> tmp(*n);
  if (*n > 0 && !read_exact(fd, tmp.data(), *n, error)) {
    secure_zero(tmp.data(), tmp.size());
    return std::nullopt;
  }
  SecureBuffer buf(
      std::string_view(reinterpret_cast<const char*>(tmp.data()), tmp.size()));
  secure_zero(tmp.data(), tmp.size());
  return buf;
}

}  // namespace privion::rdp
