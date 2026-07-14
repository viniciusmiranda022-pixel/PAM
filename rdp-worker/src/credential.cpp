#include "privion/rdp/credential.hpp"

#include <cerrno>
#include <string>
#include <string_view>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace privion::rdp {
namespace {

void set_error(std::string* error, const char* code) {
  if (error != nullptr) {
    *error = code;
  }
}

// Trims a single trailing '\n' (and a preceding '\r') so a secret file written
// with a text editor does not carry the newline into the credential.
void trim_trailing_newline(std::vector<unsigned char>& v) {
  if (!v.empty() && v.back() == '\n') {
    v.pop_back();
  }
  if (!v.empty() && v.back() == '\r') {
    v.pop_back();
  }
}

std::optional<SecureBuffer> read_fd_to_buffer(int fd, std::string* error) {
  std::vector<unsigned char> raw;
  unsigned char chunk[512];
  for (;;) {
    ssize_t n = ::read(fd, chunk, sizeof(chunk));
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      set_error(error, "read_failed");
      secure_zero(chunk, sizeof(chunk));
      return std::nullopt;
    }
    if (n == 0) {
      break;
    }
    if (raw.size() + static_cast<std::size_t>(n) > kMaxCredentialBytes) {
      set_error(error, "credential_too_large");
      secure_zero(chunk, sizeof(chunk));
      secure_zero(raw.data(), raw.size());
      return std::nullopt;
    }
    raw.insert(raw.end(), chunk, chunk + n);
  }
  secure_zero(chunk, sizeof(chunk));
  trim_trailing_newline(raw);
  if (raw.empty()) {
    set_error(error, "empty_credential");
    return std::nullopt;
  }
  SecureBuffer buf(std::string_view(reinterpret_cast<const char*>(raw.data()),
                                    raw.size()));
  secure_zero(raw.data(), raw.size());
  return buf;
}

}  // namespace

std::optional<SecureBuffer> read_credential_from_fd(int fd, std::string* error) {
  if (fd < 0) {
    set_error(error, "bad_fd");
    return std::nullopt;
  }
  return read_fd_to_buffer(fd, error);
}

std::optional<SecureBuffer> read_credential_from_file(const std::string& path,
                                                      std::string* error) {
  // Open first (O_NOFOLLOW rejects a symlink target; O_CLOEXEC keeps the fd from
  // leaking), then validate the OPEN fd with fstat — no TOCTOU window between a
  // stat() and the open(), and no following of a swapped symlink.
  int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) {
    set_error(error, errno == ELOOP ? "symlink_refused" : "open_failed");
    return std::nullopt;
  }
  struct stat st{};
  if (::fstat(fd, &st) != 0) {
    set_error(error, "fstat_failed");
    ::close(fd);
    return std::nullopt;
  }
  if (!S_ISREG(st.st_mode)) {
    set_error(error, "not_regular_file");
    ::close(fd);
    return std::nullopt;
  }
  // Permission bits must be exactly 0400 (owner read only).
  if ((st.st_mode & 07777) != 0400) {
    set_error(error, "insecure_mode");
    ::close(fd);
    return std::nullopt;
  }
  if (st.st_uid != ::geteuid()) {
    set_error(error, "wrong_owner");
    ::close(fd);
    return std::nullopt;
  }
  auto result = read_fd_to_buffer(fd, error);
  ::close(fd);
  return result;
}

}  // namespace privion::rdp
