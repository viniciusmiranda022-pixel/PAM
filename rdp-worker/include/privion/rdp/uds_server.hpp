// Unix Domain Socket transport (ADR 0006 §6). The ONLY ingress: no TCP, HTTP,
// WebSocket, or published port. The socket is created with mode 0600 and every
// accepted peer is verified via SO_PEERCRED against an allowed uid. One job per
// connection. Messages are length-prefixed frames (uint32 big-endian length).
#ifndef PRIVION_RDP_UDS_SERVER_HPP
#define PRIVION_RDP_UDS_SERVER_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <sys/types.h>

#include "privion/rdp/secure_buffer.hpp"

namespace privion::rdp {

inline constexpr std::uint32_t kMaxFrameBytes = 64u * 1024u;

class UdsServer {
public:
  UdsServer() = default;
  ~UdsServer();

  UdsServer(const UdsServer&) = delete;
  UdsServer& operator=(const UdsServer&) = delete;

  // Binds `path` (mode 0600) and starts listening. Only `allowed_uid` may
  // connect. Returns false with `error` set on failure.
  bool listen(const std::string& path, uid_t allowed_uid,
              std::string* error = nullptr);

  // Accepts one connection and verifies its peer uid == allowed_uid. On success
  // returns a connected fd (caller closes it). On refusal returns -1 and sets
  // `error` (the offending connection is closed).
  int accept_verified(std::string* error = nullptr);

  int fd() const noexcept { return listen_fd_; }
  const std::string& path() const noexcept { return path_; }

private:
  void close_all() noexcept;

  int listen_fd_ = -1;
  std::string path_;
  uid_t allowed_uid_ = static_cast<uid_t>(-1);
  bool bound_ = false;
};

// Frame I/O. write_frame prefixes a uint32 big-endian length. read_frame and
// read_frame_secure enforce kMaxFrameBytes. read_frame_secure delivers the
// payload into a SecureBuffer for credential material.
bool write_frame(int fd, std::string_view payload, std::string* error = nullptr);
std::optional<std::string> read_frame(int fd, std::string* error = nullptr);
std::optional<SecureBuffer> read_frame_secure(int fd, std::string* error = nullptr);

}  // namespace privion::rdp

#endif  // PRIVION_RDP_UDS_SERVER_HPP
