// Lab-only guards (ADR 0006 §Políticas). The worker is a laboratory artifact:
//   - it must be COMPILED with PRIVION_LAB_ONLY (enforced with #error in main);
//   - it must REFUSE to start when PAM_ENV=production (checked at runtime).
// The predicate is pure so it can be unit-tested without setting the real env.
#ifndef PRIVION_RDP_LAB_GUARD_HPP
#define PRIVION_RDP_LAB_GUARD_HPP

namespace privion::rdp {

// Returns true when the given PAM_ENV value denotes production (case-sensitive
// "production"). A null/empty value is NOT production.
bool is_production_env(const char* pam_env) noexcept;

// Reads PAM_ENV from the environment and returns is_production_env of it.
bool running_in_production() noexcept;

}  // namespace privion::rdp

#endif  // PRIVION_RDP_LAB_GUARD_HPP
