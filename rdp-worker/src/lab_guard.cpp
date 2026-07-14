#include "privion/rdp/lab_guard.hpp"

#include <cstdlib>
#include <cstring>

namespace privion::rdp {

bool is_production_env(const char* pam_env) noexcept {
  return pam_env != nullptr && std::strcmp(pam_env, "production") == 0;
}

bool running_in_production() noexcept {
  return is_production_env(std::getenv("PAM_ENV"));
}

}  // namespace privion::rdp
