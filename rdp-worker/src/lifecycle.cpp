#include "privion/rdp/lifecycle.hpp"

namespace privion::rdp {

std::string_view to_string(State s) noexcept {
  switch (s) {
    case State::Idle: return "Idle";
    case State::Connecting: return "Connecting";
    case State::Connected: return "Connected";
    case State::TearingDown: return "TearingDown";
    case State::Closed: return "Closed";
  }
  return "Unknown";
}

bool Lifecycle::begin_connect() {
  if (state_ != State::Idle) {
    return false;
  }
  state_ = State::Connecting;
  return true;
}

bool Lifecycle::mark_connected() {
  if (state_ != State::Connecting) {
    return false;
  }
  state_ = State::Connected;
  return true;
}

void Lifecycle::terminate(std::string_view reason_code) {
  if (state_ == State::Closed) {
    return;  // idempotent
  }
  state_ = State::TearingDown;
  reason_code_.assign(reason_code);
  // TearingDown is transient: the native client closes the asset connection
  // here; the pure state machine records the terminal state deterministically.
  state_ = State::Closed;
}

}  // namespace privion::rdp
