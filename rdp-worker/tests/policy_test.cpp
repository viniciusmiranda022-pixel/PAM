#include "privion/rdp/policy.hpp"

#include "privion_test.hpp"

using privion::rdp::kRdpPort;
using privion::rdp::LabAllowlist;

TEST(permits_only_exact_entries) {
  LabAllowlist a;
  a.allow("192.0.2.10", kRdpPort);
  CHECK(a.permits("192.0.2.10", 3389));
  // wrong port refused
  CHECK(!a.permits("192.0.2.10", 3390));
  CHECK(!a.permits("192.0.2.10", 22));
  // wrong address refused
  CHECK(!a.permits("192.0.2.11", 3389));
  CHECK(!a.permits("10.0.0.1", 3389));
}

TEST(empty_allowlist_denies_all) {
  LabAllowlist a;
  CHECK(a.empty());
  CHECK(!a.permits("192.0.2.10", 3389));
}

TEST(dedupes_entries) {
  LabAllowlist a;
  a.allow("192.0.2.10", 3389);
  a.allow("192.0.2.10", 3389);
  CHECK_EQ(a.size(), 1u);
}

TEST(multiple_targets) {
  LabAllowlist a;
  a.allow("192.0.2.10", 3389);
  a.allow("192.0.2.20", 3389);
  CHECK(a.permits("192.0.2.10", 3389));
  CHECK(a.permits("192.0.2.20", 3389));
  CHECK(!a.permits("192.0.2.30", 3389));
}

PRIVION_TEST_MAIN()
