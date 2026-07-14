// Minimal header-only test harness (no external dependency — the build must
// work offline with a pinned toolchain). One test executable per file; each
// ends with PRIVION_TEST_MAIN().
#ifndef PRIVION_TEST_HPP
#define PRIVION_TEST_HPP

#include <cstdio>
#include <functional>
#include <string>
#include <vector>

namespace privion::test {

struct Case {
  std::string name;
  std::function<void()> fn;
};

inline std::vector<Case>& registry() {
  static std::vector<Case> r;
  return r;
}

inline int& failures() {
  static int f = 0;
  return f;
}

struct Reg {
  Reg(std::string name, std::function<void()> fn) {
    registry().push_back({std::move(name), std::move(fn)});
  }
};

inline int run_all() {
  int failed = 0;
  for (auto& c : registry()) {
    int before = failures();
    c.fn();
    bool ok = failures() == before;
    std::fprintf(stderr, "[%s] %s\n", ok ? "PASS" : "FAIL", c.name.c_str());
    if (!ok) {
      ++failed;
    }
  }
  std::fprintf(stderr, "%d/%zu tests passed\n",
               static_cast<int>(registry().size()) - failed, registry().size());
  return failed == 0 ? 0 : 1;
}

}  // namespace privion::test

#define TEST(test_name)                                                     \
  static void test_name();                                                  \
  static ::privion::test::Reg privion_reg_##test_name(#test_name,           \
                                                      test_name);           \
  static void test_name()

#define CHECK(cond)                                                         \
  do {                                                                      \
    if (!(cond)) {                                                          \
      ++::privion::test::failures();                                        \
      std::fprintf(stderr, "  CHECK failed: %s (%s:%d)\n", #cond, __FILE__, \
                   __LINE__);                                               \
    }                                                                       \
  } while (0)

#define CHECK_EQ(a, b)                                                      \
  do {                                                                      \
    if (!((a) == (b))) {                                                    \
      ++::privion::test::failures();                                        \
      std::fprintf(stderr, "  CHECK_EQ failed: %s == %s (%s:%d)\n", #a, #b, \
                   __FILE__, __LINE__);                                     \
    }                                                                       \
  } while (0)

#define PRIVION_TEST_MAIN() \
  int main() { return ::privion::test::run_all(); }

#endif  // PRIVION_TEST_HPP
