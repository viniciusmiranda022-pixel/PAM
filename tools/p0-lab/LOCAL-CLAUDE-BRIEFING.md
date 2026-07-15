# Briefing — run the real RDP Worker P0 with local Claude Code

Paste the block below into **Claude Code running on your machine**, at the root of
the `PAM` repository. It is a closed, fail-closed operational prompt. The heavy
lifting is already scripted in `tools/p0-lab/`; the prompt tells the local agent
to drive those scripts, discover the environment, and stop only for real external
dependencies.

Start Claude Code in **normal (approval) mode** — approve Docker/cert/firewall/
virtualization/package steps as they come. Do **not** use
`--dangerously-skip-permissions` for this.

**Environment:** these are Bash scripts — on **Windows** run them from **WSL2**
(or a Linux VM) with **Docker** reachable. Container IPs are not routable from the
Windows/Docker-Desktop host, so the xrdp scenarios run in **container mode** (the
runner image built by `41-worker-image.sh`); `run-all.sh` picks host vs. container
per target automatically.

---

```text
You are the engineer executing the REAL P0 of this repository's isolated RDP Worker.

Non-negotiable architectural context:
- The product is a multiprotocol PAM built on explicit, isolated per-protocol adapters.
- VNC is the protocol currently ENABLED at runtime; RDP is the first NEW protocol,
  in implementation, via our own RDP Worker over FreeRDP. Generic proxy is forbidden.
- SUPPORTED_PROTOCOLS=["vnc"] is only the current runtime-enable state, not the product scope.
- Do NOT enable RDP in backend/gateway/frontend. Do NOT start PR-17C.
  Do NOT change SUPPORTED_PROTOCOLS. Do NOT modify the product runtime to make a test pass.
- Do NOT simulate lab results. NEVER mark PASS a scenario that was not really executed.
- Do NOT commit, push, or open a PR without my explicit authorization.
- NEVER put passwords/tokens/keys in argv, env, stdout, logs, or persisted shell history.

The automation already exists in tools/p0-lab/. Use it; do not reinvent it. Discover
real command names, env vars and exit codes from the repo — do not guess them.

Step 0 — Orientation (read, don't change):
- show: git branch, git status, HEAD vs origin/main; confirm the RDP track is intact
  (rdp-worker/ present, ci job rdp-worker-build-test present) and that NO vnc-only
  containment artifacts exist.
- read fully: tools/p0-lab/README.md, tools/p0-lab/*.sh, docs/rdp-smoke-runbook.md,
  docs/rdp-p0-evidence-template.md, rdp-worker/scripts/run-p0.sh,
  rdp-worker/scripts/p0-evidence-secret-scan.py, scripts/ci/check-rdp-worker-scope.sh,
  and the RDP ADRs (0005, 0006).

Step 1 — Config:
- cp tools/p0-lab/p0-lab.env.example tools/p0-lab/p0-lab.env
- Fill in the NON-SECRET identifiers you already know (targets, usernames, ports).
- Create the 0400 credential files (umask 077; printf ... ; chmod 0400) and set their
  PATHS in p0-lab.env. Never inline a password.

Step 1b — Self-test the automation before using it:
- cd tools/p0-lab && bash tests/selftest.sh   # must be all-green (offline, stubs)

Step 2 — Run the phases via the orchestrator, fail-closed:
- cd tools/p0-lab && ./run-all.sh
  It runs: inventory (1) -> repo validation incl. native build + selftest gate that
  REQUIRES FreeRDP exactly 3.28.0 (2) -> lab discovery (3) -> CA + certs (4a) ->
  xrdp target if configured (4b) -> scenarios negative-controls-first (5/6) ->
  broad secret sentinel + evidence matrix + global verdict (7/8/9).
- If the native build or selftest does not PASS, STOP: do not run scenarios against
  real targets. Report the exact failure from artifacts/p0/<ts>/repository-validation.txt.

Step 3 — Scenario execution rules:
- Order: host-denied, port-denied, cert-untrusted (TOFU=0), cred-invalid, then
  windows-nla, xrdp, cert-trusted (TOFU=0, lab CA in the trust store), terminate,
  watchdog, asset-disconnect, plus network-unreachable and the N-session baseline.
- TOFU=0 for ALL certificate scenarios. Never use PRIVION_LAB_TOFU_CERT=1 to pass one.
- For each scenario the wrapper records: driver exit code, PASS/FAIL/BLOCKED/
  INCONCLUSIVE, secret-sentinel result, pre/post process+socket snapshots, leftover
  count. Driver exit codes: 0=PASS 2=precondition 10=operational 20=FAIL 25=INCONCLUSIVE
  30=secret-leak. Only PASS is success; INCONCLUSIVE is NOT a pass.
- Any residual worker/harness process or privion-p0 tmpdir after teardown => FAIL.

Step 4 — Stop and ask me ONLY for genuine external dependencies:
- the Windows-with-NLA target address + a valid test account (I provide the VM);
- valid/invalid xrdp credentials if not yet created;
- authorization to change firewall/network, create a VM/container, or install packages;
- administrative privilege;
- anything that would publish a service or delete/overwrite data.
Everything that does NOT depend on these, do automatically. Mark the rest BLOCKED with
the exact list of what you need and example formats.

Step 5 — Evidence and consolidation:
- Everything lands under artifacts/p0/<UTC>/: environment-inventory.txt,
  repository-validation.txt, lab-discovery.txt, lab-ca.txt, xrdp-target.txt,
  driver-<scenario>.log, proc/sock pre+post, scenario-results.jsonl,
  evidence-matrix.md, summary.json, secret-sentinel.json, and per-scenario evidence
  dirs (with the driver's own secret-sentinel.json per run).
- Present the matrix (scenario, expected, script verdict, driver rc, sentinel) and the
  global verdict, which can only be: FAIL / BLOCKED / INCONCLUSIVE / PASS_PENDING_SIGNOFF.
- Fill docs/rdp-p0-evidence-template.md with the sanitized results (no raw secrets, no
  raw infrastructure detail beyond what the template asks). Operator + reviewer sign
  manually — signature is NOT automated.

Step 6 — Outcome:
- If all eliminatory scenarios are genuinely PASS (sentinel CLEAN everywhere):
  report "P0 technically ready for human review", request operator+reviewer signature,
  keep SUPPORTED_PROTOCOLS=["vnc"], and do NOT start PR-17C.
- If any FAIL: give the likely root cause, the evidence files, and a MINIMAL proposed
  fix — do not change the runtime without my approval.
- If BLOCKED/INCONCLUSIVE: list exactly what is missing and the commands for me to
  complete it; preserve all collected artifacts.

Begin at Step 0. Between phases, do not ask whether to continue EXCEPT for the Step 4
external dependencies. Never fabricate a result to fill a gap.
```

---

## What this automates vs. what only you provide

**Automated by the local agent:** repo inspection, native build + selftest, offline
suite, scope guard, xrdp container, CA + trusted/untrusted certs, the negative-control
scenarios, process/socket/CPU/RAM/latency capture, the broad secret sentinel, and the
matrix/JSON generation.

**You must provide (real dependencies):** a Windows-with-NLA VM + test account; approval
for firewall/network/VM/package changes; administrative privilege; and the final human
operator + reviewer signatures. The scripts stop cleanly at each of these and tell the
agent exactly what is needed.
