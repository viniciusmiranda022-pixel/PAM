// Connection lifecycle as an explicit state machine (ADR 0006 §1). Pure logic,
// no FreeRDP dependency, so teardown is deterministic and unit-testable:
// terminate() from any active state always ends at Closed. The watchdog and the
// admin/end-of-job signal drive terminate().
#ifndef PRIVION_RDP_LIFECYCLE_HPP
#define PRIVION_RDP_LIFECYCLE_HPP

#include <string>
#include <string_view>

namespace privion::rdp {

enum class State {
  Idle,
  Connecting,
  Connected,
  TearingDown,
  Closed,
};

std::string_view to_string(State s) noexcept;

class Lifecycle {
public:
  State state() const noexcept { return state_; }
  const std::string& reason_code() const noexcept { return reason_code_; }

  // Valid forward transitions. Each returns false if not allowed from the
  // current state (the machine never jumps illegally).
  bool begin_connect();          // Idle -> Connecting
  bool mark_connected();         // Connecting -> Connected

  // terminate() is always legal from any non-terminal state and always ends at
  // Closed, going through TearingDown. Idempotent once Closed.
  void terminate(std::string_view reason_code);

  bool is_active() const noexcept {
    return state_ == State::Connecting || state_ == State::Connected;
  }
  bool is_closed() const noexcept { return state_ == State::Closed; }

private:
  State state_ = State::Idle;
  std::string reason_code_;
};

}  // namespace privion::rdp

#endif  // PRIVION_RDP_LIFECYCLE_HPP
