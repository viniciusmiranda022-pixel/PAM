#include "privion/rdp/config.hpp"

#include <cctype>
#include <cstdlib>
#include <vector>

namespace privion::rdp {
namespace {

void set_error(std::string* error, const char* code) {
  if (error != nullptr) {
    *error = code;
  }
}

void skip_ws(const std::string& s, std::size_t& i) {
  while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) {
    ++i;
  }
}

// Parses a JSON string literal starting at s[i] == '"'. Advances i past the
// closing quote. Rejects control characters; supports the common escapes.
bool parse_string(const std::string& s, std::size_t& i, std::string& out) {
  if (i >= s.size() || s[i] != '"') {
    return false;
  }
  ++i;
  out.clear();
  while (i < s.size()) {
    char c = s[i++];
    if (c == '"') {
      return true;
    }
    if (c == '\\') {
      if (i >= s.size()) {
        return false;
      }
      char e = s[i++];
      switch (e) {
        case '"': out += '"'; break;
        case '\\': out += '\\'; break;
        case '/': out += '/'; break;
        case 'n': out += '\n'; break;
        case 't': out += '\t'; break;
        case 'r': out += '\r'; break;
        default: return false;  // reject unsupported escapes (incl. \u here)
      }
      continue;
    }
    if (static_cast<unsigned char>(c) < 0x20) {
      return false;  // raw control char
    }
    out += c;
  }
  return false;  // unterminated
}

}  // namespace

std::optional<LabTarget> parse_lab_target(const std::string& json,
                                          std::string* error) {
  // Reject anything with nested structures up front (flat object only).
  bool seen_open = false;
  for (char c : json) {
    if (c == '{') {
      if (seen_open) {
        set_error(error, "nested_object");
        return std::nullopt;
      }
      seen_open = true;
    } else if (c == '[') {
      set_error(error, "array_not_allowed");
      return std::nullopt;
    }
  }

  std::size_t i = 0;
  skip_ws(json, i);
  if (i >= json.size() || json[i] != '{') {
    set_error(error, "expected_object");
    return std::nullopt;
  }
  ++i;

  LabTarget target;
  bool has_alias = false, has_address = false, has_port = false;
  std::vector<std::string> seen_keys;

  while (true) {
    skip_ws(json, i);
    if (i < json.size() && json[i] == '}') {
      ++i;
      break;
    }
    std::string key;
    if (!parse_string(json, i, key)) {
      set_error(error, "bad_key");
      return std::nullopt;
    }
    for (const auto& k : seen_keys) {
      if (k == key) {
        set_error(error, "duplicate_key");
        return std::nullopt;
      }
    }
    seen_keys.push_back(key);
    skip_ws(json, i);
    if (i >= json.size() || json[i] != ':') {
      set_error(error, "expected_colon");
      return std::nullopt;
    }
    ++i;
    skip_ws(json, i);

    if (key == "port") {
      std::size_t start = i;
      while (i < json.size() && (std::isdigit(static_cast<unsigned char>(json[i])))) {
        ++i;
      }
      if (i == start) {
        set_error(error, "port_not_number");
        return std::nullopt;
      }
      long value = std::strtol(json.substr(start, i - start).c_str(), nullptr, 10);
      if (value <= 0 || value > 65535) {
        set_error(error, "port_out_of_range");
        return std::nullopt;
      }
      target.port = static_cast<std::uint16_t>(value);
      has_port = true;
    } else {
      std::string value;
      if (!parse_string(json, i, value)) {
        set_error(error, "bad_string_value");
        return std::nullopt;
      }
      if (key == "targetAlias") {
        target.targetAlias = value;
        has_alias = true;
      } else if (key == "address") {
        target.address = value;
        has_address = true;
      } else if (key == "domain") {
        target.domain = value;
      } else {
        set_error(error, "unknown_key");
        return std::nullopt;
      }
    }

    skip_ws(json, i);
    if (i < json.size() && json[i] == ',') {
      ++i;
      continue;
    }
    if (i < json.size() && json[i] == '}') {
      ++i;
      break;
    }
    set_error(error, "expected_comma_or_end");
    return std::nullopt;
  }

  // No trailing content after the closing brace.
  skip_ws(json, i);
  if (i != json.size()) {
    set_error(error, "trailing_content");
    return std::nullopt;
  }
  if (!has_alias || !has_address || !has_port) {
    set_error(error, "missing_required_field");
    return std::nullopt;
  }
  return target;
}

}  // namespace privion::rdp
