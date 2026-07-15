#!/usr/bin/env python3
"""P0 evidence helper for the isolated RDP Worker (PR-17B).

Responsibilities kept OUT of the shell so the credential can never reach
argv/env/`set -x`/a core dump:

  --validate  <cred-file>            validate the 0400 secret file; print OK
  --scan      <cred-file> <ev-dir>   validate + leak-scan (no writes);
                                     print CLEAN | LEAK_PRESENT
  --scan-final <cred-file> <ev-dir>  validate + leak-scan the COMPLETE evidence
                                     package, then write ONLY
                                     <ev-dir>/secret-sentinel.json;
                                     print CLEAN | LEAK_PRESENT
  --summarize <facts-file> <ev-dir>  read facts + worker events, compute the
                                     per-scenario verdict, write manifest.json /
                                     summary.json / summary.txt; print the verdict

The secret NEVER touches the shell: the scan modes open the secret file with
O_NOFOLLOW + O_CLOEXEC, validate it on the open fd with fstat (regular file,
owner == euid, mode exactly 0400, size cap), read it once, and search the
evidence directory for the secret bytes. Only a status token is ever printed
(never the secret, not even on error). --summarize handles all JSON assembly so
the shell driver never hand-builds JSON around untrusted event text.

Exit codes: 0 = OK/CLEAN/summarized, 2 = usage/validation error, 3 = LEAK_PRESENT.
"""
import datetime
import json
import os
import stat
import sys

MAX_CREDENTIAL_BYTES = 4096
READ_CHUNK = 65536
SENTINEL_FILE = "secret-sentinel.json"

EXPECTED_ENUM = (
    "connect", "auth_reject", "cert_trusted", "cert_reject", "egress_denied",
    "watchdog", "asset_disconnect", "network_unreachable", "terminate",
)


def _fail(code: str) -> "typing.NoReturn":  # noqa: F821
    """Print only a short error token (never the secret) and exit 2."""
    sys.stderr.write(f"p0-evidence: error: {code}\n")
    sys.exit(2)


# ── secure credential handling ──────────────────────────────────────────────
def read_secret(path: str) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as e:
        _fail("symlink_refused" if e.errno == 40 else "open_failed")  # ELOOP=40
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            _fail("not_regular_file")
        if (st.st_mode & 0o777) != 0o400:
            _fail("insecure_mode")
        if st.st_uid != os.geteuid():
            _fail("wrong_owner")
        if st.st_size > MAX_CREDENTIAL_BYTES:
            _fail("credential_too_large")
        data = b""
        while len(data) <= MAX_CREDENTIAL_BYTES:
            chunk = os.read(fd, READ_CHUNK)
            if not chunk:
                break
            data += chunk
    finally:
        os.close(fd)
    if data.endswith(b"\r\n"):
        data = data[:-2]
    elif data.endswith(b"\n"):
        data = data[:-1]
    if not data:
        _fail("empty_credential")
    return data


def scan(secret: bytes, evdir: str, exclude=frozenset()) -> "tuple[bool, int]":
    """Return (leaked, files_scanned) for `secret` under `evdir`."""
    n = len(secret)
    leaked = False
    count = 0
    for root, _dirs, files in os.walk(evdir):
        for name in files:
            if name in exclude:
                continue
            path = os.path.join(root, name)
            try:
                with open(path, "rb") as fh:
                    count += 1
                    tail = b""
                    while True:
                        chunk = fh.read(READ_CHUNK)
                        if not chunk:
                            break
                        if secret in (tail + chunk):
                            leaked = True
                            break
                        tail = chunk[-(n - 1):] if n > 1 else b""
            except OSError:
                continue
            if leaked:
                return True, count
    return leaked, count


def scan_final(cred_path: str, evdir: str) -> bool:
    """Scan the COMPLETE evidence package (everything except a pre-existing
    sentinel from a re-run), then write ONLY secret-sentinel.json. The sentinel
    file carries just the result token — never the credential."""
    secret = read_secret(cred_path)
    leaked, count = scan(secret, evdir, exclude=frozenset({SENTINEL_FILE}))
    del secret
    payload = {
        "artifact": "privion-rdp-worker-lab P0 secret sentinel",
        "result": "LEAK_PRESENT" if leaked else "CLEAN",
        "files_scanned": count,
        "generated_at": datetime.datetime.now(datetime.timezone.utc)
                        .strftime("%Y-%m-%dT%H:%M:%SZ"),
        "note": ("scanned the complete evidence package (logs, facts, resources, "
                 "manifest, summaries) after they were finalized; no other file "
                 "is modified after this scan"),
    }
    _write_json(os.path.join(evdir, SENTINEL_FILE), payload)
    return leaked


# ── evidence summary / verdict ──────────────────────────────────────────────
def read_facts(path: str) -> dict:
    facts = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.rstrip("\n")
                if not line or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                facts[key] = val
    except OSError:
        _fail("facts_unreadable")
    return facts


def read_events(evdir: str) -> list:
    """Parse worker-events.jsonl (one lifecycle JSON object per line)."""
    events = []
    path = os.path.join(evdir, "worker-events.jsonl")
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                if isinstance(obj, dict):
                    events.append(obj)
    except OSError:
        pass  # no events (e.g. worker died before emitting) is itself a signal
    return events


def _as_int(value) -> "int|None":
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def observe(events: list) -> dict:
    """Reduce the event stream to the non-secret signals the verdict needs."""
    connected = False
    connected_ms = None
    freerdp_version = None
    for ev in events:
        if freerdp_version is None and ev.get("freerdpVersion"):
            freerdp_version = ev.get("freerdpVersion")
        if ev.get("reasonCode") == "connected":
            connected = True
            if connected_ms is None:
                connected_ms = _as_int(ev.get("durationMs"))
    terminal = events[-1] if events else {}
    terminal_ms = _as_int(terminal.get("durationMs"))
    session_active_ms = None
    if connected_ms is not None and terminal_ms is not None:
        session_active_ms = terminal_ms - connected_ms
    return {
        "event_count": len(events),
        "connected": connected,
        "connected_ms": connected_ms,
        "terminal_result": terminal.get("result"),
        "terminal_reason": terminal.get("reasonCode"),
        "terminal_ms": terminal_ms,
        "session_active_ms": session_active_ms,
        "freerdp_version": freerdp_version,
    }


def compute_verdict(facts: dict, obs: dict) -> "tuple[str,str]":
    """Return (verdict, reason). Conservative and honest:
    - FAIL only on a contradiction of the EXPLICIT expected result (never
      inferred from the scenario label), or when TOFU voids a certificate claim;
    - PASS only where the worker's signal is deterministic (clean connect with
      TOFU rules honoured; egress_denied refusal; TERMINATE-driven clean close);
    - INCONCLUSIVE where the observation is consistent but the specific cause
      (auth vs cert vs network, watchdog vs asset close) must be confirmed by
      the operator in worker-stderr.txt. INCONCLUSIVE is NEVER success (driver
      exit 25). The whole-P0 acceptance is never decided here.
    """
    expected = facts.get("expected", "")
    tofu = facts.get("tofu", "0") == "1"
    session_set = facts.get("session_seconds", "unset") != "unset"
    connected = obs["connected"]
    result = obs["terminal_result"]
    reason = obs["terminal_reason"] or "none"

    # Certificate claims are voided by the accept-once escape hatch, regardless
    # of scenario name or outcome: accept-once proves nothing about the chain.
    if expected == "cert_trusted" and tofu:
        return "FAIL", "tofu_voids_cert_trust_verdict"
    if expected == "cert_reject" and tofu:
        return "FAIL", "tofu_voids_cert_reject_verdict"

    if expected in ("connect", "cert_trusted"):
        if not connected:
            return "FAIL", f"expected_connect_but_no_connection:{reason}"
        if result == "ok":
            if expected == "cert_trusted":
                # TOFU=0 here: a successful connect implies the trust store
                # verified the chain (the worker rejects otherwise).
                return "PASS", "connected_via_verified_trust_chain"
            return "PASS", "connected_and_clean_close"
        return "INCONCLUSIVE", f"connected_but_unclean_close:{reason}"

    if expected == "terminate":
        if not connected:
            return "FAIL", f"expected_session_but_no_connection:{reason}"
        if result == "ok" and session_set:
            return "PASS", "terminate_closed_session_deterministically"
        if result == "ok":
            return "INCONCLUSIVE", "clean_close_but_terminate_was_not_sent"
        return "INCONCLUSIVE", f"connected_but_unclean_close:{reason}"

    if expected == "egress_denied":
        if connected:
            return "FAIL", "egress_not_enforced_connection_succeeded"
        if reason == "egress_denied":
            return "PASS", "worker_refused_egress_denied"
        return "INCONCLUSIVE", f"no_connection_but_reason_not_egress_denied:{reason}"

    if expected in ("auth_reject", "cert_reject"):
        if connected:
            return "FAIL", "expected_reject_but_connected"
        return "INCONCLUSIVE", f"connection_refused_confirm_reason_in_worker_stderr:{reason}"

    if expected == "network_unreachable":
        if connected:
            return "FAIL", "expected_unreachable_but_connected"
        # Fail-closed observed (no session); the worker's generic connect error
        # cannot distinguish network vs auth vs cert — operator confirms cause.
        return "INCONCLUSIVE", f"no_connection_fail_closed_confirm_network_cause:{reason}"

    if expected == "watchdog":
        if not connected:
            return "FAIL", f"expected_session_but_no_connection:{reason}"
        if session_set:
            return "INCONCLUSIVE", "terminate_was_sent_not_pure_watchdog"
        return "INCONCLUSIVE", "session_then_close_confirm_watchdog_timing"

    if expected == "asset_disconnect":
        if not connected:
            return "FAIL", f"expected_session_but_no_connection:{reason}"
        if session_set:
            return "INCONCLUSIVE", "terminate_was_sent_confirm_asset_side_disconnect"
        return "INCONCLUSIVE", "session_then_close_confirm_asset_disconnect_in_evidence"

    return "INCONCLUSIVE", "unknown_expected_result"


def summarize(facts_path: str, evdir: str) -> str:
    facts = read_facts(facts_path)
    if facts.get("expected") not in EXPECTED_ENUM:
        _fail("facts_missing_valid_expected")
    obs = observe(read_events(evdir))
    verdict, reason = compute_verdict(facts, obs)

    manifest = {
        "artifact": "privion-rdp-worker-lab P0 evidence",
        "note": "worker-isolated smoke (PR-17B); NOT the integrated product (P1)",
        "scenario": facts.get("scenario"),
        "expected_result": facts.get("expected"),
        "worker": {
            "path": facts.get("worker_path"),
            "sha256": facts.get("worker_sha256"),
            "version_line": facts.get("worker_version"),
            "freerdp_version": obs["freerdp_version"],
        },
        "harness": {
            "path": facts.get("harness_path"),
            "sha256": facts.get("harness_sha256"),
        },
        "allowlist_applied": facts.get("allow_target"),
        "tofu_accept_once": facts.get("tofu") == "1",
        "session_seconds": facts.get("session_seconds"),
        "max_seconds": facts.get("max_seconds"),
        "socket_timeout": facts.get("socket_timeout"),
        "started": facts.get("started"),
        "ended": facts.get("ended"),
        "duration_monotonic_ms": _as_int(facts.get("duration_monotonic_ms")),
        "worker_rc": _as_int(facts.get("worker_rc")),
        "harness_rc": _as_int(facts.get("harness_rc")),
        "peak_rss_kb": facts.get("peak_rss_kb"),
        "cpu_user_seconds": facts.get("cpu_user_seconds"),
        "cpu_system_seconds": facts.get("cpu_system_seconds"),
        "clk_tck": facts.get("clk_tck"),
        "events": obs,
        "secret_sentinel": f"recorded separately in {SENTINEL_FILE} (written after this file)",
    }
    summary = {
        "scenario": facts.get("scenario"),
        "expected_result": facts.get("expected"),
        "verdict": verdict,
        "reason": reason,
        "script_approves_p0": False,
        "observed": {
            "connected": obs["connected"],
            "terminal_result": obs["terminal_result"],
            "terminal_reason": obs["terminal_reason"],
            "duration_ms_to_connected": obs["connected_ms"],
            "terminal_duration_ms": obs["terminal_ms"],
            "session_active_ms": obs["session_active_ms"],
        },
        "worker_rc": _as_int(facts.get("worker_rc")),
        "harness_rc": _as_int(facts.get("harness_rc")),
        "secret_sentinel": f"recorded separately in {SENTINEL_FILE} (written after this file)",
        "tofu_accept_once": facts.get("tofu") == "1",
        "started": facts.get("started"),
        "ended": facts.get("ended"),
    }

    _write_json(os.path.join(evdir, "manifest.json"), manifest)
    _write_json(os.path.join(evdir, "summary.json"), summary)
    _write_text(os.path.join(evdir, "summary.txt"), _summary_text(summary, obs, facts))
    return verdict


def _write_json(path: str, obj: dict) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, sort_keys=True)
        fh.write("\n")


def _write_text(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _summary_text(summary: dict, obs: dict, facts: dict) -> str:
    lines = [
        "privion-rdp-worker-lab — P0 scenario evidence (PR-17B, worker-isolated)",
        "=" * 72,
        "",
        "This script records ONE scenario and NEVER approves the P0.",
        "P0 acceptance = ALL eliminatory scenarios green + operator & reviewer",
        "sign-off in docs/rdp-p0-evidence-template.md. RDP stays disabled at",
        "runtime (SUPPORTED_PROTOCOLS = [\"vnc\"]); PR-17C is blocked until then.",
        "Driver exit codes: 0=PASS 2=precondition 10=operational 20=FAIL",
        "25=INCONCLUSIVE 30=secret-leak — only PASS returns zero.",
        "",
        f"scenario           : {summary['scenario']}",
        f"expected_result    : {summary['expected_result']}",
        f"VERDICT            : {summary['verdict']}",
        f"reason             : {summary['reason']}",
        "",
        f"connected          : {obs['connected']}",
        f"terminal_result    : {obs['terminal_result']}",
        f"terminal_reason    : {obs['terminal_reason']}",
        f"ms_to_connected    : {obs['connected_ms']}",
        f"session_active_ms  : {obs['session_active_ms']}",
        f"duration_mono_ms   : {facts.get('duration_monotonic_ms')}",
        f"cpu_user_seconds   : {facts.get('cpu_user_seconds')}",
        f"cpu_system_seconds : {facts.get('cpu_system_seconds')}",
        f"peak_rss_kb        : {facts.get('peak_rss_kb')}",
        f"worker_rc          : {summary['worker_rc']}",
        f"harness_rc         : {summary['harness_rc']}",
        f"secret_sentinel    : see {SENTINEL_FILE} (written after this file)",
        f"tofu_accept_once   : {summary['tofu_accept_once']}",
        f"allowlist_applied  : {facts.get('allow_target')}",
        f"freerdp_version    : {obs['freerdp_version']}",
        f"started / ended    : {summary['started']} / {summary['ended']}",
        "",
    ]
    return "\n".join(lines)


# ── entrypoint ──────────────────────────────────────────────────────────────
def main() -> int:
    args = sys.argv[1:]
    if len(args) == 2 and args[0] == "--validate":
        read_secret(args[1])
        print("OK")
        return 0
    if len(args) == 3 and args[0] == "--scan":
        secret = read_secret(args[1])
        leaked, _count = scan(secret, args[2])
        del secret
        if leaked:
            print("LEAK_PRESENT")
            return 3
        print("CLEAN")
        return 0
    if len(args) == 3 and args[0] == "--scan-final":
        if scan_final(args[1], args[2]):
            print("LEAK_PRESENT")
            return 3
        print("CLEAN")
        return 0
    if len(args) == 3 and args[0] == "--summarize":
        print(summarize(args[1], args[2]))
        return 0
    sys.stderr.write(
        "usage: p0-evidence-secret-scan.py --validate <cred-file>\n"
        "       p0-evidence-secret-scan.py --scan <cred-file> <ev-dir>\n"
        "       p0-evidence-secret-scan.py --scan-final <cred-file> <ev-dir>\n"
        "       p0-evidence-secret-scan.py --summarize <facts-file> <ev-dir>\n")
    return 2


if __name__ == "__main__":
    sys.exit(main())
