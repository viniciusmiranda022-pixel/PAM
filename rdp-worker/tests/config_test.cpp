#include "privion/rdp/config.hpp"

#include <string>

#include "privion_test.hpp"

using privion::rdp::parse_lab_target;

TEST(parses_valid_target) {
  std::string json = R"({"targetAlias":"windows-nla-lab","address":"192.0.2.10","port":3389,"domain":"LAB"})";
  std::string err;
  auto t = parse_lab_target(json, &err);
  CHECK(t.has_value());
  if (t) {
    CHECK_EQ(t->targetAlias, std::string("windows-nla-lab"));
    CHECK_EQ(t->address, std::string("192.0.2.10"));
    CHECK_EQ(t->port, 3389);
    CHECK_EQ(t->domain, std::string("LAB"));
  }
}

TEST(domain_is_optional) {
  std::string err;
  auto t = parse_lab_target(
      R"({"targetAlias":"x","address":"10.0.0.1","port":3389})", &err);
  CHECK(t.has_value());
  if (t) {
    CHECK(t->domain.empty());
  }
}

TEST(rejects_nested_object) {
  std::string err;
  auto t = parse_lab_target(
      R"({"targetAlias":"x","address":"10.0.0.1","port":3389,"extra":{"a":1}})",
      &err);
  CHECK(!t.has_value());
  CHECK_EQ(err, std::string("nested_object"));
}

TEST(rejects_array) {
  std::string err;
  auto t = parse_lab_target(R"({"targetAlias":["x"]})", &err);
  CHECK(!t.has_value());
  CHECK_EQ(err, std::string("array_not_allowed"));
}

TEST(rejects_missing_required) {
  std::string err;
  auto t = parse_lab_target(R"({"targetAlias":"x","port":3389})", &err);
  CHECK(!t.has_value());
  CHECK_EQ(err, std::string("missing_required_field"));
}

TEST(rejects_bad_port) {
  std::string err;
  CHECK(!parse_lab_target(
             R"({"targetAlias":"x","address":"a","port":70000})", &err)
             .has_value());
  CHECK_EQ(err, std::string("port_out_of_range"));
  CHECK(!parse_lab_target(
             R"({"targetAlias":"x","address":"a","port":"3389"})", &err)
             .has_value());
}

TEST(rejects_unknown_key) {
  std::string err;
  auto t = parse_lab_target(
      R"({"targetAlias":"x","address":"a","port":3389,"cmd":"rm"})", &err);
  CHECK(!t.has_value());
  CHECK_EQ(err, std::string("unknown_key"));
}

TEST(rejects_duplicate_key) {
  std::string err;
  auto t = parse_lab_target(
      R"({"targetAlias":"x","address":"a","port":3389,"address":"b"})", &err);
  CHECK(!t.has_value());
  CHECK_EQ(err, std::string("duplicate_key"));
}

TEST(rejects_trailing_content) {
  std::string err;
  auto t = parse_lab_target(
      R"({"targetAlias":"x","address":"a","port":3389} garbage)", &err);
  CHECK(!t.has_value());
  CHECK_EQ(err, std::string("trailing_content"));
}

PRIVION_TEST_MAIN()
