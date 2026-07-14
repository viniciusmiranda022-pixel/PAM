#include "privion/rdp/log_redaction.hpp"

#include <string>

#include "privion_test.hpp"

using privion::rdp::LifecycleEvent;
using privion::rdp::Redactor;

TEST(redacts_single_and_multiple) {
  Redactor r;
  r.add_secret("hunter2");
  CHECK(r.redact("pw=hunter2").find("hunter2") == std::string::npos);
  std::string multi = r.redact("a=hunter2 b=hunter2");
  CHECK(multi.find("hunter2") == std::string::npos);
  CHECK(multi.find(Redactor::kMask) != std::string::npos);
}

TEST(empty_secret_ignored) {
  Redactor r;
  r.add_secret("");
  CHECK_EQ(r.secret_count(), 0u);
  CHECK_EQ(r.redact("nothing"), std::string("nothing"));
}

TEST(clear_removes_secrets) {
  Redactor r;
  r.add_secret("s3cr3t");
  r.clear();
  CHECK_EQ(r.secret_count(), 0u);
  CHECK(r.redact("s3cr3t").find("s3cr3t") != std::string::npos);
}

// Sentinel: a secret routed through a lifecycle event must never appear in the
// serialized output.
TEST(event_json_redacts_secret_and_only_allowed_fields) {
  Redactor r;
  r.add_secret("P@ssw0rd!");
  LifecycleEvent ev;
  ev.timestamp = "2026-07-13T00:00:00Z";
  ev.labJobId = "job-1";
  ev.targetAlias = "windows-nla-lab";
  ev.state = "Connected";
  ev.result = "ok";
  ev.reasonCode = "connected P@ssw0rd! leaked?";  // pretend a leak slipped in
  ev.durationMs = 12;
  ev.workerPid = 4242;
  ev.freerdpVersion = "3.28.0";
  std::string json = ev.to_json(r);

  CHECK(json.find("P@ssw0rd!") == std::string::npos);
  // Only the allowed fields are present; forbidden identifiers are not.
  for (const char* key : {"timestamp", "labJobId", "targetAlias", "state",
                          "result", "reasonCode", "durationMs", "workerPid",
                          "freerdpVersion"}) {
    CHECK(json.find(key) != std::string::npos);
  }
  for (const char* forbidden : {"userId", "assetId", "sourceIp", "approvalId",
                                "brokerToken"}) {
    CHECK(json.find(forbidden) == std::string::npos);
  }
}

PRIVION_TEST_MAIN()
