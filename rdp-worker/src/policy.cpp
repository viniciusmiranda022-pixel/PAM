#include "privion/rdp/policy.hpp"

namespace privion::rdp {

void LabAllowlist::allow(std::string address, std::uint16_t port) {
  AllowEntry entry{std::move(address), port};
  for (const auto& e : entries_) {
    if (e == entry) {
      return;
    }
  }
  entries_.push_back(std::move(entry));
}

bool LabAllowlist::permits(const std::string& address, std::uint16_t port) const {
  for (const auto& e : entries_) {
    if (e.address == address && e.port == port) {
      return true;
    }
  }
  return false;
}

}  // namespace privion::rdp
