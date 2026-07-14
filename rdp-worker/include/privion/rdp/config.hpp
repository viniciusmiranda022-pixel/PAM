// Lab target configuration (ADR 0006 §5). Holds ONLY non-secret connection data
// resolved by the lab harness — the credential never travels here. Parsed from a
// small flat JSON object (lab-targets.json); nested structures are rejected.
#ifndef PRIVION_RDP_CONFIG_HPP
#define PRIVION_RDP_CONFIG_HPP

#include <cstdint>
#include <optional>
#include <string>

namespace privion::rdp {

struct LabTarget {
  std::string targetAlias;
  std::string address;
  std::uint16_t port = 0;
  std::string domain;
};

// Parses a single flat JSON object into a LabTarget. Returns std::nullopt on any
// malformed input, nested structure, missing required field, or out-of-range
// port. `error` (if non-null) receives a short machine-readable reason.
// Required keys: targetAlias, address, port. `domain` is optional.
std::optional<LabTarget> parse_lab_target(const std::string& json,
                                          std::string* error = nullptr);

}  // namespace privion::rdp

#endif  // PRIVION_RDP_CONFIG_HPP
