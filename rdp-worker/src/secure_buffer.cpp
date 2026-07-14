#include "privion/rdp/secure_buffer.hpp"

#include <utility>

#if defined(__STDC_LIB_EXT1__)
#include <cstring>
#endif

namespace privion::rdp {

void secure_zero(void* ptr, std::size_t len) noexcept {
  if (ptr == nullptr || len == 0) {
    return;
  }
  // volatile pointer prevents the write from being optimized away as dead.
  volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
  while (len-- > 0) {
    *p++ = 0;
  }
}

SecureBuffer::SecureBuffer(std::string_view data) { assign(data); }

SecureBuffer::~SecureBuffer() { wipe(); }

SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept
    : bytes_(std::move(other.bytes_)) {
  other.bytes_.clear();
}

SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
  if (this != &other) {
    wipe();
    bytes_ = std::move(other.bytes_);
    other.bytes_.clear();
  }
  return *this;
}

void SecureBuffer::assign(std::string_view data) {
  wipe();
  bytes_.assign(data.begin(), data.end());
}

void SecureBuffer::wipe() noexcept {
  if (!bytes_.empty()) {
    secure_zero(bytes_.data(), bytes_.size());
  }
  bytes_.clear();
  bytes_.shrink_to_fit();
}

}  // namespace privion::rdp
