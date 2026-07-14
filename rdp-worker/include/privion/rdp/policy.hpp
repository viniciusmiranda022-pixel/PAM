// Lab egress allowlist (HR-04/HR-07/HR-08). The worker may only reach a target
// that is explicitly on the lab allowlist; any other address or port is refused.
// In the spike the allowlist is provided by the lab harness — there is no
// backend and no user-supplied destination.
#ifndef PRIVION_RDP_POLICY_HPP
#define PRIVION_RDP_POLICY_HPP

#include <cstdint>
#include <string>
#include <vector>

namespace privion::rdp {

struct AllowEntry {
  std::string address;
  std::uint16_t port;
  bool operator==(const AllowEntry&) const = default;
};

// Default RDP port; the only port permitted unless the allowlist says otherwise.
inline constexpr std::uint16_t kRdpPort = 3389;

class LabAllowlist {
public:
  // Adds an explicit (address, port) the worker is allowed to reach.
  void allow(std::string address, std::uint16_t port);

  // True only if (address, port) is explicitly allowed.
  bool permits(const std::string& address, std::uint16_t port) const;

  std::size_t size() const noexcept { return entries_.size(); }
  bool empty() const noexcept { return entries_.empty(); }

private:
  std::vector<AllowEntry> entries_;
};

}  // namespace privion::rdp

#endif  // PRIVION_RDP_POLICY_HPP
