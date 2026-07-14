// privion-rdp-worker-lab — isolated RDP Worker spike (PR-17B), LAB ONLY.
// Single ingress: a Unix Domain Socket (0600 + peer credentials). One job per
// connection: {target JSON, username, credential frame}. The credential is held
// in a SecureBuffer and never logged. Refuses to start with PAM_ENV=production.
// Deterministic teardown: SIGTERM/SIGINT, a TERMINATE control frame, EOF, an
// optional --max-seconds watchdog, or the asset disconnecting.
// See docs/adr/0006-rdp-worker-spike.md.

#ifndef PRIVION_LAB_ONLY
#error "privion-rdp-worker-lab must be built with PRIVION_LAB_ONLY=ON (lab-only artifact)"
#endif

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "privion/rdp/config.hpp"
#include "privion/rdp/credential.hpp"
#include "privion/rdp/freerdp_client.hpp"
#include "privion/rdp/lab_guard.hpp"
#include "privion/rdp/lifecycle.hpp"
#include "privion/rdp/log_redaction.hpp"
#include "privion/rdp/policy.hpp"
#include "privion/rdp/secure_buffer.hpp"
#include "privion/rdp/uds_server.hpp"

#ifndef PRIVION_WORKER_VERSION
#define PRIVION_WORKER_VERSION "0.0.0-dev"
#endif
#ifndef FREERDP_EXPECTED_VERSION
#define FREERDP_EXPECTED_VERSION "unset"
#endif

namespace {

using namespace privion::rdp;
using clock_type = std::chrono::steady_clock;

std::atomic<bool> g_stop{false};

extern "C" void on_signal(int) { g_stop.store(true); }

std::string iso_now() {
  std::time_t t = std::time(nullptr);
  std::tm tm{};
  gmtime_r(&t, &tm);
  char buf[32];
  std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
  return buf;
}

// Technical, non-secret correlation id for the lab job (not a broker token):
// 16 hex chars from /dev/urandom, else pid+time.
std::string make_job_id() {
  unsigned char r[8];
  int fd = ::open("/dev/urandom", O_RDONLY | O_CLOEXEC);
  bool ok = false;
  if (fd >= 0) {
    ok = ::read(fd, r, sizeof(r)) == static_cast<ssize_t>(sizeof(r));
    ::close(fd);
  }
  char out[17];
  if (ok) {
    for (int i = 0; i < 8; ++i) std::snprintf(out + i * 2, 3, "%02x", r[i]);
  } else {
    std::snprintf(out, sizeof(out), "%08lx%08lx",
                  static_cast<unsigned long>(::getpid()),
                  static_cast<unsigned long>(std::time(nullptr)) & 0xffffffff);
  }
  return std::string(out, 16);
}

struct Emitter {
  const Redactor& r;
  std::string job_id;
  clock_type::time_point started;

  void emit(const std::string& target_alias, const std::string& state,
            const char* result, const std::string& reason_code) const {
    LifecycleEvent ev;
    ev.timestamp = iso_now();
    ev.labJobId = job_id;
    ev.targetAlias = target_alias;
    ev.state = state;
    ev.result = result;
    ev.reasonCode = reason_code;
    ev.durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                        clock_type::now() - started)
                        .count();
    ev.workerPid = static_cast<long long>(::getpid());
    ev.freerdpVersion = FreeRdpClient::version();
    std::fprintf(stdout, "%s\n", ev.to_json(r).c_str());
    std::fflush(stdout);
  }
};

// WLog sink: redact every native line before it reaches stderr (HR-06).
void log_sink(void* ctx, const char* line) {
  const Redactor* red = static_cast<const Redactor*>(ctx);
  std::string redacted = red ? red->redact(line ? line : "") : "";
  std::fprintf(stderr, "freerdp: %s\n", redacted.c_str());
}

int run_selftest() {
  std::fprintf(stdout, "worker: privion-rdp-worker-lab %s\n", PRIVION_WORKER_VERSION);
  std::fprintf(stdout, "freerdp: %s (expected %s)\n",
               FreeRdpClient::version().c_str(), FREERDP_EXPECTED_VERSION);
  SecureBuffer sb("selftest-secret");
  sb.wipe();
  if (!sb.empty()) { std::fprintf(stderr, "selftest: wipe failed\n"); return 1; }
  Redactor r;
  r.add_secret("hunter2");
  if (r.redact("pw=hunter2").find("hunter2") != std::string::npos) {
    std::fprintf(stderr, "selftest: redaction failed\n");
    return 1;
  }
  if (FreeRdpClient::available()) {
    if (FreeRdpClient::version() != std::string(FREERDP_EXPECTED_VERSION)) {
      std::fprintf(stderr, "selftest: FreeRDP version mismatch (got %s, expected %s)\n",
                   FreeRdpClient::version().c_str(), FREERDP_EXPECTED_VERSION);
      return 1;
    }
    std::fprintf(stdout, "selftest: native FreeRDP %s confirmed\n", FREERDP_EXPECTED_VERSION);
  } else {
    std::fprintf(stdout, "selftest: logic build (FreeRDP not linked) — native check "
                         "is performed by CI job rdp-worker-build-test\n");
  }
  std::fprintf(stdout, "selftest: ok\n");
  return 0;
}

struct Args {
  bool selftest = false;
  std::string socket_path;
  uid_t allow_uid = static_cast<uid_t>(-1);
  std::vector<AllowEntry> allow_targets;
  unsigned max_seconds = 0;  // 0 = no watchdog
};

bool parse_target_spec(const std::string& spec, AllowEntry& out) {
  auto colon = spec.rfind(':');
  if (colon == std::string::npos || colon == 0 || colon + 1 >= spec.size()) return false;
  out.address = spec.substr(0, colon);
  long port = std::strtol(spec.c_str() + colon + 1, nullptr, 10);
  if (port <= 0 || port > 65535) return false;
  out.port = static_cast<std::uint16_t>(port);
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  if (running_in_production()) {
    std::fprintf(stderr, "privion-rdp-worker-lab: refusing to start with "
                         "PAM_ENV=production (lab-only artifact)\n");
    return 78;  // EX_CONFIG
  }

  Args args;
  for (int i = 1; i < argc; ++i) {
    std::string_view a = argv[i];
    auto next = [&](const char* name) -> const char* {
      if (i + 1 >= argc) { std::fprintf(stderr, "missing value for %s\n", name); std::exit(2); }
      return argv[++i];
    };
    if (a == "--selftest") args.selftest = true;
    else if (a == "--socket") args.socket_path = next("--socket");
    else if (a == "--allow-uid") args.allow_uid = static_cast<uid_t>(std::strtoul(next("--allow-uid"), nullptr, 10));
    else if (a == "--max-seconds") args.max_seconds = static_cast<unsigned>(std::strtoul(next("--max-seconds"), nullptr, 10));
    else if (a == "--allow-target") {
      AllowEntry e;
      if (!parse_target_spec(next("--allow-target"), e)) {
        std::fprintf(stderr, "bad --allow-target (want addr:port)\n");
        return 2;
      }
      args.allow_targets.push_back(std::move(e));
    } else {
      std::fprintf(stderr, "unknown argument: %.*s\n", static_cast<int>(a.size()), a.data());
      return 2;
    }
  }

  if (args.selftest) return run_selftest();
  if (args.socket_path.empty()) {
    std::fprintf(stderr, "usage: privion-rdp-worker-lab --socket PATH "
                         "--allow-target addr:port [--allow-uid N] [--max-seconds N] | --selftest\n");
    return 2;
  }

  // Signals -> deterministic teardown.
  std::signal(SIGTERM, on_signal);
  std::signal(SIGINT, on_signal);
  std::signal(SIGALRM, on_signal);
  std::signal(SIGPIPE, SIG_IGN);

  Redactor redactor;
  Emitter em{redactor, make_job_id(), clock_type::now()};

  LabAllowlist allowlist;
  for (const auto& e : args.allow_targets) allowlist.allow(e.address, e.port);
  if (allowlist.empty()) {
    std::fprintf(stderr, "refusing to run with an empty lab allowlist\n");
    return 2;
  }

  uid_t allow_uid = args.allow_uid == static_cast<uid_t>(-1) ? ::geteuid() : args.allow_uid;
  UdsServer server;
  std::string err;
  if (!server.listen(args.socket_path, allow_uid, &err)) {
    std::fprintf(stderr, "listen failed: %s\n", err.c_str());
    return 1;
  }

  int conn = server.accept_verified(&err);
  if (conn < 0) {
    em.emit("", "refused", "refused", err);
    return 1;
  }

  auto target_json = read_frame(conn, &err);
  auto username = target_json ? read_frame(conn, &err) : std::optional<std::string>{};
  auto password = username ? read_frame_secure(conn, &err) : std::optional<SecureBuffer>{};
  if (!target_json || !username || !password) {
    em.emit("", "refused", "refused", "bad_job_envelope");
    ::close(conn);
    return 1;
  }
  // Register secret material so nothing below (incl. WLog) can leak it. Pass
  // string_view to avoid extra temporary copies of the password.
  redactor.add_secret(std::string_view(reinterpret_cast<const char*>(password->data()),
                                       password->size()));
  redactor.add_secret(*username);

  std::string perr;
  auto target = parse_lab_target(*target_json, &perr);
  if (!target) {
    em.emit("", "refused", "refused", perr);
    redactor.clear();
    ::close(conn);
    return 1;
  }
  if (!allowlist.permits(target->address, target->port)) {
    em.emit(target->targetAlias, "refused", "refused", "egress_denied");
    redactor.clear();
    ::close(conn);
    return 1;
  }

  // Route native FreeRDP logs through the redactor before connecting.
  FreeRdpClient::set_log_sink(log_sink, &redactor);

  Lifecycle lc;
  lc.begin_connect();
  em.emit(target->targetAlias, std::string(to_string(lc.state())), "ok", "connecting");

  FreeRdpClient client;
  if (!client.connect(*target, *username, *password, &err)) {
    lc.terminate("connect_failed");
    em.emit(target->targetAlias, std::string(to_string(lc.state())), "error", err);
    password->wipe();
    redactor.clear();
    ::close(conn);
    return 1;
  }
  lc.mark_connected();
  em.emit(target->targetAlias, std::string(to_string(lc.state())), "ok", "connected");
  password->wipe();  // credential handed to the FreeRDP boundary

  if (args.max_seconds > 0) ::alarm(args.max_seconds);  // watchdog -> SIGALRM -> g_stop

  // Control-frame reader: a TERMINATE frame or EOF requests teardown.
  std::thread control([conn] {
    std::string e;
    for (;;) {
      auto frame = read_frame(conn, &e);
      if (!frame) { g_stop.store(true); return; }         // EOF/error
      if (*frame == "TERMINATE") { g_stop.store(true); return; }
    }
  });

  std::string serr;
  bool session_ok = client.run_session(g_stop, &serr);

  // Deterministic teardown: stop the control reader and drop the asset link.
  g_stop.store(true);
  ::shutdown(conn, SHUT_RDWR);  // unblock the control reader's read
  control.join();
  client.disconnect();
  lc.terminate(session_ok ? "end_of_job" : serr);
  em.emit(target->targetAlias, std::string(to_string(lc.state())),
          session_ok ? "ok" : "error", session_ok ? "closed" : serr);

  redactor.clear();
  ::close(conn);
  return session_ok ? 0 : 1;
}
