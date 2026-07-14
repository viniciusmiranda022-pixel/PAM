// SecureBuffer — holds sensitive bytes (e.g. a credential) and guarantees the
// memory is overwritten when it is no longer needed (HR-05/HR-06). Non-copyable
// so a secret cannot be silently duplicated; movable so ownership can be handed
// to the FreeRDP boundary and then wiped.
#ifndef PRIVION_RDP_SECURE_BUFFER_HPP
#define PRIVION_RDP_SECURE_BUFFER_HPP

#include <cstddef>
#include <string_view>
#include <vector>

namespace privion::rdp {

class SecureBuffer {
public:
  SecureBuffer() = default;
  explicit SecureBuffer(std::string_view data);
  ~SecureBuffer();

  SecureBuffer(const SecureBuffer&) = delete;
  SecureBuffer& operator=(const SecureBuffer&) = delete;

  SecureBuffer(SecureBuffer&& other) noexcept;
  SecureBuffer& operator=(SecureBuffer&& other) noexcept;

  void assign(std::string_view data);

  // Overwrites the backing storage with zeros and drops it. Idempotent.
  void wipe() noexcept;

  const unsigned char* data() const noexcept { return bytes_.data(); }
  std::size_t size() const noexcept { return bytes_.size(); }
  bool empty() const noexcept { return bytes_.empty(); }

private:
  std::vector<unsigned char> bytes_;
};

// Overwrites [ptr, ptr+len) with zeros in a way the compiler must not elide.
void secure_zero(void* ptr, std::size_t len) noexcept;

}  // namespace privion::rdp

#endif  // PRIVION_RDP_SECURE_BUFFER_HPP
