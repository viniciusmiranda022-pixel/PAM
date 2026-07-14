// Log redaction (HR-06) and the structured lifecycle event model (ADR 0006 §6).
// Two responsibilities:
//   1. redact(): strip any registered secret substring from a log line so a
//      credential (or the native FreeRDP WLog) can never leak.
//   2. LifecycleEvent: the ONLY audit fields the spike is allowed to emit —
//      purely technical, never userId/assetId/sourceIp/broker-token.
#ifndef PRIVION_RDP_LOG_REDACTION_HPP
#define PRIVION_RDP_LOG_REDACTION_HPP

#include <string>
#include <string_view>
#include <vector>

namespace privion::rdp {

// Holds the set of secret literals that must never appear in output. Register a
// secret once (e.g. the credential right after reading it); every emitted line
// is scrubbed. Secrets are held only long enough to scrub and are wiped on
// clear().
class Redactor {
public:
  static constexpr std::string_view kMask = "***REDACTED***";

  Redactor() = default;
  ~Redactor() { clear(); }
  // Non-copyable: a secret store must not be silently duplicated.
  Redactor(const Redactor&) = delete;
  Redactor& operator=(const Redactor&) = delete;

  void add_secret(std::string_view secret);
  void clear() noexcept;

  // Returns a copy of `line` with every registered secret replaced by kMask.
  std::string redact(std::string_view line) const;

  std::size_t secret_count() const noexcept { return secrets_.size(); }

private:
  std::vector<std::string> secrets_;
};

// Allowed lifecycle-event fields (ADR 0006 §6). Anything not here is out of
// scope for the spike and must not be simulated.
struct LifecycleEvent {
  std::string timestamp;       // ISO-8601 UTC
  std::string labJobId;        // opaque lab id, not a broker token
  std::string targetAlias;     // alias from lab-targets.json, not a prod assetId
  std::string state;           // lifecycle state name
  std::string result;          // "ok" | "error" | "refused"
  std::string reasonCode;      // machine code, e.g. "policy_denied"
  long long durationMs = 0;
  long long workerPid = 0;
  std::string freerdpVersion;  // filled by --selftest / native build

  // Serializes to a compact JSON object, redacted through `r`.
  std::string to_json(const Redactor& r) const;
};

}  // namespace privion::rdp

#endif  // PRIVION_RDP_LOG_REDACTION_HPP
