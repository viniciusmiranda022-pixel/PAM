#include "privion/rdp/credential.hpp"

#include <cstring>
#include <string>

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "privion_test.hpp"

using namespace privion::rdp;

namespace {

std::string tmp_path(const char* tag) {
  return std::string("/tmp/privion-cred-") + tag + "-" +
         std::to_string(::getpid());
}

void write_file(const std::string& path, const char* data, mode_t mode) {
  int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
  (void)::write(fd, data, std::strlen(data));
  ::close(fd);
  ::chmod(path.c_str(), mode);
}

}  // namespace

TEST(reads_from_fd_and_trims_newline) {
  int sv[2];
  CHECK(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  const char* secret = "s3cr3t\n";
  (void)::write(sv[1], secret, std::strlen(secret));
  ::close(sv[1]);  // EOF for reader
  std::string err;
  auto buf = read_credential_from_fd(sv[0], &err);
  ::close(sv[0]);
  CHECK(buf.has_value());
  if (buf) {
    CHECK_EQ(buf->size(), 6u);  // newline trimmed
    CHECK(std::memcmp(buf->data(), "s3cr3t", 6) == 0);
  }
}

TEST(rejects_empty_fd) {
  int sv[2];
  CHECK(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  ::close(sv[1]);
  std::string err;
  auto buf = read_credential_from_fd(sv[0], &err);
  ::close(sv[0]);
  CHECK(!buf.has_value());
  CHECK_EQ(err, std::string("empty_credential"));
}

TEST(reads_secret_file_0400) {
  std::string path = tmp_path("ok");
  write_file(path, "filesecret", 0400);
  std::string err;
  auto buf = read_credential_from_file(path, &err);
  ::unlink(path.c_str());
  CHECK(buf.has_value());
  if (buf) {
    CHECK_EQ(buf->size(), 10u);
  }
}

TEST(rejects_insecure_mode) {
  std::string path = tmp_path("mode");
  write_file(path, "filesecret", 0444);  // group/other readable
  std::string err;
  auto buf = read_credential_from_file(path, &err);
  ::unlink(path.c_str());
  CHECK(!buf.has_value());
  CHECK_EQ(err, std::string("insecure_mode"));
}

TEST(rejects_missing_file) {
  std::string err;
  auto buf = read_credential_from_file(tmp_path("nope"), &err);
  CHECK(!buf.has_value());
  CHECK_EQ(err, std::string("open_failed"));
}

TEST(rejects_symlink) {
  std::string target = tmp_path("real");
  write_file(target, "filesecret", 0400);
  std::string link = tmp_path("link");
  ::unlink(link.c_str());
  CHECK(::symlink(target.c_str(), link.c_str()) == 0);
  std::string err;
  auto buf = read_credential_from_file(link, &err);
  ::unlink(link.c_str());
  ::unlink(target.c_str());
  CHECK(!buf.has_value());
  CHECK_EQ(err, std::string("symlink_refused"));
}

PRIVION_TEST_MAIN()
