// privion-rdp-lab-harness — LAB ONLY driver for the isolated worker (PR-17B).
// Stands in for the backend during the P0: it reads a NON-SECRET target file and
// a credential from a 0400 secret file or an inherited fd, then hands the worker
// exactly {target JSON, username, credential} over the authenticated UDS. It is
// NOT the product broker and never persists or logs the credential.

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "privion/rdp/credential.hpp"
#include "privion/rdp/secure_buffer.hpp"
#include "privion/rdp/uds_server.hpp"

using namespace privion::rdp;

namespace {

int connect_uds(const std::string& path) {
  int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return -1;
  }
  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  if (path.size() >= sizeof(addr.sun_path)) {
    ::close(fd);
    return -1;
  }
  std::memcpy(addr.sun_path, path.c_str(), path.size());
  if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    ::close(fd);
    return -1;
  }
  return fd;
}

std::string read_text_file(const std::string& path) {
  std::ifstream in(path);
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

}  // namespace

int main(int argc, char** argv) {
  std::string socket_path, target_file, username, cred_file;
  int cred_fd = -1;
  long session_seconds = -1;  // -1 = wait for worker to close; >=0 = TERMINATE after N
  for (int i = 1; i < argc; ++i) {
    std::string_view a = argv[i];
    auto next = [&](const char* n) -> const char* {
      if (i + 1 >= argc) { std::fprintf(stderr, "missing value for %s\n", n); std::exit(2); }
      return argv[++i];
    };
    if (a == "--socket") socket_path = next("--socket");
    else if (a == "--target-file") target_file = next("--target-file");
    else if (a == "--username") username = next("--username");
    else if (a == "--cred-file") cred_file = next("--cred-file");
    else if (a == "--cred-fd") cred_fd = std::atoi(next("--cred-fd"));
    else if (a == "--session-seconds") session_seconds = std::atol(next("--session-seconds"));
    else { std::fprintf(stderr, "unknown arg: %.*s\n", static_cast<int>(a.size()), a.data()); return 2; }
  }
  if (socket_path.empty() || target_file.empty() || username.empty() ||
      (cred_file.empty() && cred_fd < 0)) {
    std::fprintf(stderr,
                 "usage: privion-rdp-lab-harness --socket PATH --target-file "
                 "PATH --username U (--cred-file PATH0400 | --cred-fd N)\n");
    return 2;
  }

  std::string err;
  std::optional<SecureBuffer> cred =
      cred_fd >= 0 ? read_credential_from_fd(cred_fd, &err)
                   : read_credential_from_file(cred_file, &err);
  if (!cred) {
    std::fprintf(stderr, "harness: credential read failed: %s\n", err.c_str());
    return 1;
  }

  std::string target_json = read_text_file(target_file);
  if (target_json.empty()) {
    std::fprintf(stderr, "harness: empty target file\n");
    return 1;
  }

  int fd = connect_uds(socket_path);
  if (fd < 0) {
    std::fprintf(stderr, "harness: connect failed\n");
    return 1;
  }

  bool ok = write_frame(fd, target_json, &err) &&
            write_frame(fd, username, &err) &&
            write_frame(fd,
                        std::string_view(reinterpret_cast<const char*>(cred->data()),
                                         cred->size()),
                        &err);
  cred->wipe();
  if (!ok) {
    std::fprintf(stderr, "harness: send failed: %s\n", err.c_str());
    ::close(fd);
    return 1;
  }
  std::fprintf(stderr, "harness: job submitted (credential not logged)\n");

  if (session_seconds >= 0) {
    // Deterministic lab end: hold the session for N seconds, then TERMINATE.
    std::this_thread::sleep_for(std::chrono::seconds(session_seconds));
    write_frame(fd, "TERMINATE", &err);
    std::fprintf(stderr, "harness: sent TERMINATE after %lds\n", session_seconds);
  } else {
    // Hold the connection until the worker ends the session and closes.
    char scratch[16];
    while (::read(fd, scratch, sizeof(scratch)) > 0) {
    }
  }
  ::close(fd);
  return 0;
}
