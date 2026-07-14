#include "privion/rdp/lab_guard.hpp"

#include "privion_test.hpp"

using privion::rdp::is_production_env;

TEST(production_detected_exactly) {
  CHECK(is_production_env("production"));
  CHECK(!is_production_env("Production"));
  CHECK(!is_production_env("prod"));
  CHECK(!is_production_env("staging"));
  CHECK(!is_production_env("lab"));
  CHECK(!is_production_env(""));
  CHECK(!is_production_env(nullptr));
}

PRIVION_TEST_MAIN()
