// FreeRDP boundary (ADR 0006 §1). This is the ONLY translation unit that knows
// the FreeRDP API. Everything above the worker talks to this class, never to
// libfreerdp directly. Compiled against libfreerdp only when PRIVION_WITH_FREERDP
// is defined; otherwise it is a logic-build stub whose connect()/run_session()
// refuse and whose version reports "not linked".
#ifndef PRIVION_RDP_FREERDP_CLIENT_HPP
#define PRIVION_RDP_FREERDP_CLIENT_HPP

#include <atomic>
#include <string>
#include <string_view>

#include "privion/rdp/config.hpp"
#include "privion/rdp/secure_buffer.hpp"

namespace privion::rdp {

class FreeRdpClient {
public:
  // Sink for native FreeRDP (WLog) output. Every native log line is routed here
  // so the caller can redact it before it reaches stdout/stderr — the library
  // must never write around the Redactor (HR-06).
  using LogSink = void (*)(void* ctx, const char* line);

  FreeRdpClient() = default;
  ~FreeRdpClient();

  FreeRdpClient(const FreeRdpClient&) = delete;
  FreeRdpClient& operator=(const FreeRdpClient&) = delete;

  static bool available() noexcept;
  static std::string version();

  // Installs the WLog capture sink (process-global; one job per process). Must be
  // called before connect() so no native line escapes unredacted.
  static void set_log_sink(LogSink sink, void* ctx) noexcept;

  // Connects to `target` with `username`/`password`. NLA is enabled; the
  // certificate callback rejects untrusted certs (P0), unless the lab escape
  // hatch PRIVION_LAB_TOFU_CERT=1 is set (accept-once, lab only). Returns false
  // with `error` set on failure (logic build: always "freerdp_not_linked").
  bool connect(const LabTarget& target, std::string_view username,
               const SecureBuffer& password, std::string* error);

  // Runs the RDP session event loop until the asset disconnects or `stop`
  // becomes true (admin/watchdog). Processes FreeRDP event handles; polls `stop`
  // on a bounded timeout. Returns false with `error` on a transport error.
  bool run_session(const std::atomic<bool>& stop, std::string* error);

  void disconnect() noexcept;
  bool connected() const noexcept { return connected_; }

private:
  bool connected_ = false;
  void* ctx_ = nullptr;  // a freerdp* in the native build
};

}  // namespace privion::rdp

#endif  // PRIVION_RDP_FREERDP_CLIENT_HPP
