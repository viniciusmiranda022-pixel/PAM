// Credential ingestion (ADR 0006 §5, HR-05/HR-06). The credential is read ONCE,
// only from an inherited file descriptor or a secret file with mode 0400, into a
// SecureBuffer. It never comes from argv, environment, or the target config, and
// is never logged. Reading trims a single trailing newline.
#ifndef PRIVION_RDP_CREDENTIAL_HPP
#define PRIVION_RDP_CREDENTIAL_HPP

#include <optional>
#include <string>

#include "privion/rdp/secure_buffer.hpp"

namespace privion::rdp {

// Reads from an already-open fd (e.g. inherited from the harness). The fd is
// read to EOF and NOT closed by this function. Returns nullopt with `error` set
// on failure (e.g. empty). Max size guards against a runaway read.
std::optional<SecureBuffer> read_credential_from_fd(int fd,
                                                    std::string* error = nullptr);

// Reads from a secret file that MUST be a regular file with mode exactly 0400
// and owned by the current euid. Any weaker permission is refused (error set).
std::optional<SecureBuffer> read_credential_from_file(const std::string& path,
                                                      std::string* error = nullptr);

inline constexpr std::size_t kMaxCredentialBytes = 4096;

}  // namespace privion::rdp

#endif  // PRIVION_RDP_CREDENTIAL_HPP
