#include "privion/rdp/freerdp_client.hpp"

// The native path is compiled ONLY when the build links libfreerdp. In the
// sandbox logic build (PRIVION_WITH_FREERDP undefined) none of the FreeRDP
// headers are included, so the worker's non-native logic can be built and tested
// without the native dependency. The native path is exercised by the CI
// `rdp-worker-build-test` job against FreeRDP 3.28.0 (verified API), not here.

#if defined(PRIVION_WITH_FREERDP)

#include <cstdlib>
#include <string>

#include <freerdp/error.h>
#include <freerdp/freerdp.h>
#include <freerdp/settings.h>
#include <winpr/synch.h>
#include <winpr/wlog.h>

namespace privion::rdp {
namespace {

FreeRdpClient::LogSink g_sink = nullptr;
void* g_sink_ctx = nullptr;

// WLog callback: route every native line through the caller's redacting sink so
// libfreerdp never writes to stdout/stderr around the Redactor (HR-06).
BOOL privion_wlog_message(const wLogMessage* msg) {
  if (msg != nullptr && msg->TextString != nullptr && g_sink != nullptr) {
    g_sink(g_sink_ctx, msg->TextString);
  }
  return TRUE;
}

void install_wlog_capture() {
  wLog* root = WLog_GetRoot();
  if (root == nullptr) {
    return;
  }
  WLog_SetLogAppenderType(root, WLOG_APPENDER_CALLBACK);
  wLogAppender* appender = WLog_GetLogAppender(root);
  static wLogCallbacks callbacks;
  callbacks.message = privion_wlog_message;
  callbacks.data = nullptr;
  callbacks.image = nullptr;
  callbacks.package = nullptr;
  WLog_ConfigureAppender(appender, "callbacks", static_cast<void*>(&callbacks));
  WLog_SetLogLevel(root, WLOG_WARN);
}

// Certificate policy for the P0: reject an untrusted/unknown certificate
// (return 0). FreeRDP only calls this when its automatic verification (system
// trust store / known_hosts) did not already accept the cert, so a trusted cert
// is accepted without reaching here and an untrusted one is refused. The lab
// escape hatch PRIVION_LAB_TOFU_CERT=1 accepts once (lab only). Per-asset trust
// policy is PR-17D.
DWORD privion_verify_cert(freerdp*, const char* /*host*/, UINT16 /*port*/,
                          const char* /*common_name*/, const char* /*subject*/,
                          const char* /*issuer*/, const char* /*fingerprint*/,
                          DWORD /*flags*/) {
  const char* tofu = std::getenv("PRIVION_LAB_TOFU_CERT");
  if (tofu != nullptr && std::string(tofu) == "1") {
    return 2;  // accept for this session only (lab)
  }
  return 0;  // reject untrusted certificate
}

}  // namespace

FreeRdpClient::~FreeRdpClient() { disconnect(); }

bool FreeRdpClient::available() noexcept { return true; }

std::string FreeRdpClient::version() {
  int major = 0, minor = 0, revision = 0;
  freerdp_get_version(&major, &minor, &revision);
  return std::to_string(major) + "." + std::to_string(minor) + "." +
         std::to_string(revision);
}

void FreeRdpClient::set_log_sink(LogSink sink, void* ctx) noexcept {
  g_sink = sink;
  g_sink_ctx = ctx;
}

bool FreeRdpClient::connect(const LabTarget& target, std::string_view username,
                            const SecureBuffer& password, std::string* error) {
  disconnect();
  install_wlog_capture();

  freerdp* instance = freerdp_new();
  if (instance == nullptr) {
    if (error) *error = "freerdp_new_failed";
    return false;
  }
  if (!freerdp_context_new(instance)) {
    if (error) *error = "freerdp_context_new_failed";
    freerdp_free(instance);
    return false;
  }
  instance->VerifyCertificateEx = privion_verify_cert;

  rdpSettings* s = instance->context->settings;
  freerdp_settings_set_string(s, FreeRDP_ServerHostname, target.address.c_str());
  freerdp_settings_set_uint32(s, FreeRDP_ServerPort, target.port);
  if (!target.domain.empty()) {
    freerdp_settings_set_string(s, FreeRDP_Domain, target.domain.c_str());
  }
  std::string user(username);
  freerdp_settings_set_string(s, FreeRDP_Username, user.c_str());
  std::string pw(reinterpret_cast<const char*>(password.data()), password.size());
  freerdp_settings_set_string(s, FreeRDP_Password, pw.c_str());
  secure_zero(pw.data(), pw.size());
  freerdp_settings_set_bool(s, FreeRDP_NlaSecurity, TRUE);

  if (!freerdp_connect(instance)) {
    if (error) *error = "freerdp_connect_failed";
    freerdp_context_free(instance);
    freerdp_free(instance);
    return false;
  }
  ctx_ = instance;
  connected_ = true;
  return true;
}

bool FreeRdpClient::run_session(const std::atomic<bool>& stop, std::string* error) {
  if (ctx_ == nullptr) {
    if (error) *error = "not_connected";
    return false;
  }
  freerdp* instance = static_cast<freerdp*>(ctx_);
  rdpContext* context = instance->context;

  while (!freerdp_shall_disconnect_context(context)) {
    if (stop.load()) {
      break;  // admin/watchdog requested teardown
    }
    HANDLE handles[64];
    DWORD count = freerdp_get_event_handles(context, handles, 64);
    if (count == 0) {
      if (error) *error = "get_event_handles_failed";
      return false;
    }
    DWORD status = WaitForMultipleObjects(count, handles, FALSE, 250);
    if (status == WAIT_FAILED) {
      if (error) *error = "wait_failed";
      return false;
    }
    if (!freerdp_check_event_handles(context)) {
      if (freerdp_get_last_error(context) == FREERDP_ERROR_SUCCESS) {
        break;  // normal server-side disconnect
      }
      if (error) *error = "check_event_handles_failed";
      return false;
    }
  }
  return true;
}

void FreeRdpClient::disconnect() noexcept {
  if (ctx_ != nullptr) {
    freerdp* instance = static_cast<freerdp*>(ctx_);
    freerdp_abort_connect_context(instance->context);
    freerdp_disconnect(instance);
    freerdp_context_free(instance);
    freerdp_free(instance);
    ctx_ = nullptr;
  }
  connected_ = false;
}

}  // namespace privion::rdp

#else  // logic build (no libfreerdp)

namespace privion::rdp {

FreeRdpClient::~FreeRdpClient() { disconnect(); }

bool FreeRdpClient::available() noexcept { return false; }

std::string FreeRdpClient::version() { return "not-linked"; }

void FreeRdpClient::set_log_sink(LogSink, void*) noexcept {}

bool FreeRdpClient::connect(const LabTarget&, std::string_view,
                            const SecureBuffer&, std::string* error) {
  if (error) *error = "freerdp_not_linked";
  return false;
}

bool FreeRdpClient::run_session(const std::atomic<bool>&, std::string* error) {
  if (error) *error = "freerdp_not_linked";
  return false;
}

void FreeRdpClient::disconnect() noexcept { connected_ = false; }

}  // namespace privion::rdp

#endif  // PRIVION_WITH_FREERDP
