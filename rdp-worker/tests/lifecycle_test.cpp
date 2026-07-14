#include "privion/rdp/lifecycle.hpp"

#include "privion_test.hpp"

using privion::rdp::Lifecycle;
using privion::rdp::State;

TEST(happy_path_transitions) {
  Lifecycle lc;
  CHECK(lc.state() == State::Idle);
  CHECK(lc.begin_connect());
  CHECK(lc.state() == State::Connecting);
  CHECK(lc.mark_connected());
  CHECK(lc.state() == State::Connected);
  CHECK(lc.is_active());
}

TEST(illegal_transitions_rejected) {
  Lifecycle lc;
  // cannot mark_connected before begin_connect
  CHECK(!lc.mark_connected());
  CHECK(lc.state() == State::Idle);
  CHECK(lc.begin_connect());
  // cannot begin_connect twice
  CHECK(!lc.begin_connect());
}

TEST(terminate_from_connected_ends_closed) {
  Lifecycle lc;
  lc.begin_connect();
  lc.mark_connected();
  lc.terminate("end_of_job");
  CHECK(lc.is_closed());
  CHECK(lc.state() == State::Closed);
  CHECK_EQ(lc.reason_code(), std::string("end_of_job"));
}

TEST(terminate_from_idle_and_connecting) {
  Lifecycle a;
  a.terminate("aborted");
  CHECK(a.is_closed());

  Lifecycle b;
  b.begin_connect();
  b.terminate("connect_failed");
  CHECK(b.is_closed());
  CHECK_EQ(b.reason_code(), std::string("connect_failed"));
}

TEST(terminate_is_idempotent) {
  Lifecycle lc;
  lc.begin_connect();
  lc.mark_connected();
  lc.terminate("first");
  lc.terminate("second");  // must not overwrite terminal state/reason
  CHECK(lc.is_closed());
  CHECK_EQ(lc.reason_code(), std::string("first"));
}

PRIVION_TEST_MAIN()
