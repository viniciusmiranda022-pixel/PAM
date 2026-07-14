#include "privion/rdp/uds_server.hpp"

#include <atomic>
#include <cstring>
#include <string>
#include <thread>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "privion/rdp/secure_buffer.hpp"
#include "privion_test.hpp"

using namespace privion::rdp;

namespace {

std::string unique_path(const char* tag) {
  return std::string("/tmp/privion-uds-") + tag + "-" +
         std::to_string(::getpid()) + ".sock";
}

// Connects to a UDS path; returns fd or -1.
int connect_uds(const std::string& path) {
  int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) {
    return -1;
  }
  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  std::memcpy(addr.sun_path, path.c_str(), path.size());
  if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    ::close(fd);
    return -1;
  }
  return fd;
}

}  // namespace

TEST(socket_created_with_mode_0600) {
  std::string path = unique_path("mode");
  UdsServer server;
  std::string err;
  CHECK(server.listen(path, ::geteuid(), &err));
  struct stat st{};
  CHECK(::stat(path.c_str(), &st) == 0);
  CHECK_EQ(static_cast<int>(st.st_mode & 0777), 0600);
}

TEST(accept_verified_and_frame_roundtrip) {
  std::string path = unique_path("frame");
  UdsServer server;
  std::string err;
  CHECK(server.listen(path, ::geteuid(), &err));

  std::atomic<bool> client_ok{false};
  std::thread client([&] {
    int fd = connect_uds(path);
    if (fd < 0) {
      return;
    }
    std::string e;
    bool ok = write_frame(fd, "target-json", &e) &&
              write_frame(fd, "the-secret", &e);
    client_ok = ok;
    ::close(fd);
  });

  int conn = server.accept_verified(&err);
  CHECK(conn >= 0);
  if (conn >= 0) {
    auto f1 = read_frame(conn, &err);
    CHECK(f1.has_value());
    CHECK_EQ(*f1, std::string("target-json"));
    auto secret = read_frame_secure(conn, &err);
    CHECK(secret.has_value());
    CHECK_EQ(secret->size(), 10u);
    CHECK(std::memcmp(secret->data(), "the-secret", 10) == 0);
    ::close(conn);
  }
  client.join();
  CHECK(client_ok.load());
}

TEST(peer_uid_mismatch_refused) {
  std::string path = unique_path("uid");
  UdsServer server;
  std::string err;
  // Allow a uid that is NOT ours -> our connection must be refused.
  CHECK(server.listen(path, ::geteuid() + 1, &err));

  std::thread client([&] {
    int fd = connect_uds(path);
    if (fd >= 0) {
      // server will close us; a write may fail — that's fine.
      char b = 0;
      (void)::write(fd, &b, 1);
      ::close(fd);
    }
  });

  int conn = server.accept_verified(&err);
  CHECK_EQ(conn, -1);
  CHECK_EQ(err, std::string("peer_uid_denied"));
  client.join();
}

TEST(oversized_frame_refused) {
  // A declared length beyond kMaxFrameBytes must be refused by the reader.
  int sv[2];
  CHECK(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  unsigned char hdr[4] = {0xFF, 0xFF, 0xFF, 0xFF};  // ~4 GiB
  (void)::write(sv[1], hdr, sizeof(hdr));
  std::string err;
  auto f = read_frame(sv[0], &err);
  CHECK(!f.has_value());
  CHECK_EQ(err, std::string("frame_too_large"));
  ::close(sv[0]);
  ::close(sv[1]);
}

PRIVION_TEST_MAIN()
