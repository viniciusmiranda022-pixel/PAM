# privion-rdp-worker-lab — isolated RDP Worker spike (PR-17B)

**LAB ONLY.** This is the isolated RDP Worker spike from PR-17B. It encapsulates
`libfreerdp` behind a small C++20 process, reachable only over a Unix Domain
Socket. It is **not** wired into the gateway, backend, frontend, or the main
Compose, and it refuses to start with `PAM_ENV=production`.

Frozen contract: [`docs/adr/0006-rdp-worker-spike.md`](../docs/adr/0006-rdp-worker-spike.md)
and [`docs/protocols/rdp-worker-spike.md`](../docs/protocols/rdp-worker-spike.md).
Engine decision: [`docs/adr/0005-rdp-engine.md`](../docs/adr/0005-rdp-engine.md).

## Architecture

```
lab harness ──UDS(0600 + peer creds)──▶ privion-rdp-worker-lab ──▶ libfreerdp 3.28.0 ──▶ RDP asset
```

- One job per connection: `{target JSON, username, credential frame}`.
- Destination comes only from the harness and must be on the worker's lab
  allowlist (`--allow-target addr:port`); anything else is refused.
- The credential is held in a `SecureBuffer`, registered with the log redactor,
  handed to the FreeRDP boundary, then wiped. It is never in argv/env/config/logs.
- `freerdp_client` is the ONLY translation unit that knows the FreeRDP API.

## Build

```bash
./scripts/build.sh              # logic build (no libfreerdp) — offline, fast
ctest --test-dir build --output-on-failure
./scripts/run-selftest.sh       # reports FreeRDP "not-linked" in a logic build

./scripts/build.sh --native     # native build (links pinned FreeRDP) — see below
```

The **logic build** compiles everything except the native FreeRDP call and runs
all unit tests. The **native build** links FreeRDP 3.28.0 and is exercised by the
CI job `rdp-worker-build-test` (and the `Dockerfile`).

## FreeRDP pin (defense in depth)

FreeRDP 3.28.0 is pinned by **three** controls in
[`cmake/freerdp-pin.cmake`](cmake/freerdp-pin.cmake):

- **tag** `3.28.0`;
- **commit SHA** `5370fb26fbf034ecd11d3026b6ad639b5fff493f` (the tag dereferences
  to it — provenance);
- **source SHA-256** — the byte integrity of the exact archive the build
  compiles, fetched from the immutable commit-based URL and verified via
  `URL_HASH` (fail-closed).

Base images are pinned by digest and platform (`--platform=linux/amd64`) in the
`Dockerfile`. `scripts/pin-freerdp.sh` verifies (does not generate) the pin.

```bash
./scripts/pin-freerdp.sh                # verify tag -> committed commit SHA
./scripts/pin-freerdp.sh --source-hash  # (trusted host) download the pinned URL
                                        # and print its SHA-256 for freerdp-pin.cmake
```

> **Status:** all three controls are registered — tag `3.28.0`, commit
> `5370fb26…`, and `FREERDP_SOURCE_SHA256`
> (`61b7c02f…0ffae3`, official `pub.freerdp.com/releases/freerdp-3.28.0.tar.gz`,
> 11040961 bytes, computed on a trusted host). `URL_HASH` verifies the bytes
> **before extraction** and fails on any change.
>
> **Build-time egress vs runtime.** The public URL is fetched **only at build time**
> of this lab-only worker (in CI). The worker at **runtime has no internet egress**
> — it reaches only the authorized asset via the lab allowlist. Mirroring the exact
> official file into a Privion-controlled **immutable artifact repository** (offline
> / air-gapped builds, vendor availability) is tracked as **backlog BLD-ART-01**,
> required before a production release — not a blocker for this spike.

## Smoke P0 (real targets, outside CI)

`scripts/run-p0.sh` drives **one** job per scenario against a real Windows/xrdp
target and records secret-free evidence for
[`docs/rdp-smoke-runbook.md`](../docs/rdp-smoke-runbook.md) — full per-scenario
commands, the certificate trust store, and the exit codes live there; the
sign-off sheet is [`docs/rdp-p0-evidence-template.md`](../docs/rdp-p0-evidence-template.md).
It requires a native build, a non-secret target file, and a `0400` credential
file, and it **never approves the P0 on its own** (per-scenario verdict only;
acceptance is the operator + reviewer's, and needs ALL eliminatory scenarios
`PASS`).

The credential never enters the shell: `scripts/p0-evidence-secret-scan.py`
opens the `0400` file with `O_NOFOLLOW` + `fstat` (regular file, owner == euid,
mode `0400`, size cap), reads it internally, and returns only a token
(`OK` / `CLEAN` / `LEAK_PRESENT`). The leak scan runs LAST, over the complete
evidence package, and then writes only `secret-sentinel.json`. The driver
requires a passing `--selftest` confirming a native FreeRDP 3.28.0 worker before
any session, and only `PASS` exits zero (0 PASS · 2 precondition ·
10 operational · 20 FAIL · 25 INCONCLUSIVE · 30 secret leak).
`tests/run-p0-script-test.sh` exercises the driver offline (Python worker +
harness stubs over a real UDS) and runs in CI alongside `bash -n` and ShellCheck.

## Scope guard

`scripts/ci/check-rdp-worker-scope.sh` (repo root) fails if the spike leaks into
the product: `SUPPORTED_PROTOCOLS` other than `["vnc"]`, product/Compose
references to the worker, a TCP/HTTP/WebSocket listener, or any Guacamole
dependency.
