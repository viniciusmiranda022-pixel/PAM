#include "privion/rdp/secure_buffer.hpp"

#include <cstring>

#include "privion_test.hpp"

using privion::rdp::SecureBuffer;
using privion::rdp::secure_zero;

TEST(holds_and_reports_data) {
  SecureBuffer b("hunter2");
  CHECK_EQ(b.size(), 7u);
  CHECK(!b.empty());
  CHECK(std::memcmp(b.data(), "hunter2", 7) == 0);
}

TEST(wipe_empties) {
  SecureBuffer b("secret");
  b.wipe();
  CHECK(b.empty());
  CHECK_EQ(b.size(), 0u);
  b.wipe();  // idempotent
  CHECK(b.empty());
}

TEST(move_transfers_and_clears_source) {
  SecureBuffer a("topsecret");
  SecureBuffer b(std::move(a));
  CHECK_EQ(b.size(), 9u);
  CHECK(a.empty());
  SecureBuffer c;
  c = std::move(b);
  CHECK_EQ(c.size(), 9u);
  CHECK(b.empty());
}

TEST(secure_zero_overwrites) {
  char buf[8];
  std::memcpy(buf, "abcdefg", 8);
  secure_zero(buf, sizeof(buf));
  for (char c : buf) {
    CHECK_EQ(c, '\0');
  }
  secure_zero(nullptr, 0);  // must not crash
}

TEST(assign_replaces) {
  SecureBuffer b("one");
  b.assign("twotwo");
  CHECK_EQ(b.size(), 6u);
  CHECK(std::memcmp(b.data(), "twotwo", 6) == 0);
}

PRIVION_TEST_MAIN()
