#include "privion/rdp/log_redaction.hpp"

#include "privion/rdp/secure_buffer.hpp"

#include <sstream>

namespace privion::rdp {

void Redactor::add_secret(std::string_view secret) {
  if (!secret.empty()) {
    secrets_.emplace_back(secret);
  }
}

void Redactor::clear() noexcept {
  for (auto& s : secrets_) {
    if (!s.empty()) {
      secure_zero(s.data(), s.size());
    }
  }
  secrets_.clear();
}

std::string Redactor::redact(std::string_view line) const {
  std::string out(line);
  for (const auto& secret : secrets_) {
    if (secret.empty()) {
      continue;
    }
    std::string::size_type pos = 0;
    while ((pos = out.find(secret, pos)) != std::string::npos) {
      out.replace(pos, secret.size(), kMask);
      pos += kMask.size();
    }
  }
  return out;
}

namespace {

std::string json_escape(std::string_view s) {
  std::string out;
  out.reserve(s.size() + 2);
  for (char c : s) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\u%04x", c);
          out += buf;
        } else {
          out += c;
        }
    }
  }
  return out;
}

}  // namespace

std::string LifecycleEvent::to_json(const Redactor& r) const {
  auto field = [&](std::string_view v) { return json_escape(r.redact(v)); };
  std::ostringstream os;
  os << '{'
     << "\"timestamp\":\"" << field(timestamp) << "\","
     << "\"labJobId\":\"" << field(labJobId) << "\","
     << "\"targetAlias\":\"" << field(targetAlias) << "\","
     << "\"state\":\"" << field(state) << "\","
     << "\"result\":\"" << field(result) << "\","
     << "\"reasonCode\":\"" << field(reasonCode) << "\","
     << "\"durationMs\":" << durationMs << ","
     << "\"workerPid\":" << workerPid << ","
     << "\"freerdpVersion\":\"" << field(freerdpVersion) << "\""
     << '}';
  return os.str();
}

}  // namespace privion::rdp
