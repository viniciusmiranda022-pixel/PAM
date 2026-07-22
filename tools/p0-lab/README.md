# P0 lab automation (`tools/p0-lab/`)

Fail-closed automation for the **real P0** of the isolated RDP Worker, meant to be
driven by **Claude Code running on the operator's machine** (not a cloud session,
which has no Docker/targets). It wraps the repository's own artifacts —
`rdp-worker/scripts/run-p0.sh`, `rdp-worker/scripts/p0-evidence-secret-scan.py`,
`docs/rdp-smoke-runbook.md`, `docs/rdp-p0-evidence-template.md`,
`scripts/ci/check-rdp-worker-scope.sh` — and never touches the product runtime.

## Guarantees

- **No product change.** Nothing here edits `backend/gateway/frontend/infra`,
  `SUPPORTED_PROTOCOLS` stays `["vnc"]`, and PR-17C is not started.
- **Secrets never in the shell.** Credentials are `0400` files referenced by
  path; the driver reads them with `O_NOFOLLOW`+`fstat`. No password enters
  argv/env/stdout/logs. Generated CA keys are `0400` and git-ignored.
- **Fail-closed.** Anything that cannot truly run is `BLOCKED`/`INCONCLUSIVE` —
  never `PASS`. Only `PASS` from the driver exits 0; `25`=INCONCLUSIVE.
- **Nothing is committed/pushed.** Evidence lives under `artifacts/` (ignored).

## One-time setup

```bash
cd tools/p0-lab
cp p0-lab.env.example p0-lab.env      # fill in targets/usernames + 0400 cred file PATHS
umask 077
printf '%s' 'valid-password'   > cred.valid   && chmod 0400 cred.valid
printf '%s' 'wrong-password'   > cred.invalid && chmod 0400 cred.invalid
# set P0_CRED_VALID_FILE / P0_CRED_INVALID_FILE to those paths in p0-lab.env
```

The **Windows-with-NLA** target is the only piece no automation can fabricate —
provide it as a VM and set `P0_WIN_TARGET` / `P0_WIN_USER`. The **xrdp** target
can be auto-provisioned (set `P0_XRDP_IMAGE` to a pinned image + `P0_XRDP_CRED_FILE`).

## Required local environment (point #11 — read before running)

Bash scripts do **not** run in PowerShell. On **Windows**, run the whole flow from
a Linux shell:

- **WSL2** with a Bash shell (Ubuntu recommended), **or** a Linux VM;
- **Docker** reachable from that shell — Docker Desktop with WSL2 integration, or
  Docker Engine inside the Linux VM;
- because Docker Desktop/WSL2 do **not** route container IPs from the host, the
  xrdp scenarios use **container mode** (the worker runs in a container on the lab
  network — `41-worker-image.sh` builds the runner image). `run-all.sh` selects
  host vs. container automatically per target;
- `openssl` for the CA; `syft` + (`grype` or `trivy`) for SBOM/CVE (else that
  phase is BLOCKED with the exact tool to install);
- **admin/root** only where noted (firewall rules, some container operations);
- the **Windows-with-NLA VM** and a routable IP/account (you provide);
- Hyper-V/VMware/KVM only if you host the Windows/xrdp targets as full VMs.

`00-inventory.sh` reports which of these are present; anything missing becomes a
`BLOCKED` scenario, never a false `PASS`.

## Phases (exact sequence)

| Script | Phase | What it does | Needs |
|---|---|---|---|
| `00-inventory.sh` | 1 | OS, virt (WSL2/Docker Desktop), toolchain, target reachability | nothing |
| `10-repo-validate.sh` | 2 | scope guard + scans + offline suite + **native build + selftest gate (FreeRDP 3.28.0)** | build toolchain or container |
| `20-discover-lab.sh` | 3 | reports present vs. missing lab inputs (no secrets) | nothing |
| `30-make-ca.sh` | 4a | controlled CA + trusted server cert + untrusted cert (keys 0400) | openssl |
| `40-xrdp-target.sh` | 4b | xrdp container on an internal net + **readiness contract** (process/port/sesman/graphical); BLOCKED if unmet | docker/podman + pinned image |
| `41-worker-image.sh` | 4c | builds the container-mode runner image (worker+harness+driver) | docker/podman |
| `45-xrdp-cert.sh` | — | **install / swap / restore** the xrdp server cert (trusted↔untrusted) + restart | container target |
| `50-run-scenario.sh` | 5+6 | one scenario via the driver + **differential** proc/socket residue + threads + verdict | native worker |
| `55-teardown-scenario.sh` | 5 | automated `sigterm`/`sigint`/`asset-disconnect` mid-session | native worker (+container for asset) |
| `70-sbom-cve.sh` | — | real SBOM + CVE scan; **BLOCKED** (with tool to install) if scanner absent | syft + grype/trivy |
| `60-consolidate.sh` | 7+8+9 | classified secret sentinel + `resources.txt` stats + strict global verdict | scenario results |
| `run-all.sh` | all | orchestrates the above, negative-controls first, BLOCKs missing deps | — |

Self-tests for the automation itself: `bash tests/selftest.sh` (offline, stubs).

Run everything:

```bash
cd tools/p0-lab && ./run-all.sh
```

Or a single scenario manually (e.g. the interactive asset-disconnect):

```bash
PRIVION_SCENARIO=asset-disconnect PRIVION_EXPECTED_RESULT=asset_disconnect \
PRIVION_MAX_SECONDS=60 PRIVION_TARGET_FILE=<t.json> PRIVION_USERNAME=labuser \
PRIVION_CRED_FILE=<cred.valid> ./50-run-scenario.sh
```

## Driver exit codes (only PASS is success)

`0`=PASS · `2`=precondition/BLOCKED · `10`=operational · `20`=FAIL ·
`25`=INCONCLUSIVE · `30`=secret leak. Eliminatory scenarios such as `auth_reject`
and `cert_reject` come back `INCONCLUSIVE` **by design** — the operator confirms
the specific cause in the redacted `worker-stderr.txt`, then signs.

## Trust store for the certificate scenarios

TOFU stays **off** (`PRIVION_LAB_TOFU_CERT=0`) for cert scenarios; `TOFU=1` makes
the driver FAIL them on purpose. For the **trusted** scenario, the xrdp asset must
present `ca/server.crt` and the worker's trust store must contain `ca/lab-ca.crt`
(`export SSL_CERT_FILE=$P0_CA_DIR/lab-ca.crt`, or mount it read-only in the
container). For **untrusted**, the asset presents `ca/untrusted.crt`.

## After the run

Read `artifacts/p0/<UTC>/evidence-matrix.md`, `summary.json`, `resources.txt` and
`secret-sentinel.json`. The global **technical** verdict is exactly one of
`PASS` / `FAIL` / `INCONCLUSIVE` / `BLOCKED` (never a made-up "pending" token); a
separate `signoff_required: true` records that the **operator + reviewer signature**
in `docs/rdp-p0-evidence-template.md` is always required — signatures record
acceptance, they do not change the technical result, and the automation never
approves the P0 itself. Only after a genuine `PASS` **and** signatures is PR-17C
unblocked (runtime stays `["vnc"]` until PR-17G). Rotate the test credentials when
done.

## Known limitations (honest scope)

- Everything logic-side is covered by `tests/selftest.sh` (runs in this repo).
  The Docker/xrdp/Windows execution paths (`40/41/45/55`, container mode, SBOM/CVE)
  are **structured fail-closed but can only be exercised on the operator's host** —
  they were not run in the cloud session that authored them.
- `asset-disconnect` is automated only against the **managed xrdp container** (via
  `docker network disconnect`); dropping a Windows VM's link mid-session may still
  be manual on some setups.
- The xrdp cert swap targets the **xrdp default TLS layout**; a nonconforming image
  makes the cert scenarios `BLOCKED`, not falsely passed.
