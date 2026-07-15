# Native build of privion-rdp-worker-lab over pinned FreeRDP 3.28.0 (ADR 0006 §3).
# Build context = rdp-worker/. Exercised by CI job rdp-worker-build-test.
#
# Base images pinned BY DIGEST (resolved 2026-07-13 from Docker Hub). The
# homologated platform (linux/amd64) is selected at build time via
# `docker build --platform=linux/amd64` (see CI), not hard-coded in FROM. The
# FreeRDP source is fetched by URL and verified with URL_HASH — no dynamic
# resolution.

# --- builder -----------------------------------------------------------------
FROM ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90 AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential cmake ninja-build ca-certificates pkg-config \
      libssl-dev zlib1g-dev libicu-dev liburiparser-dev libcjson-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /w
COPY . /w

# Build native (ExternalProject downloads + hash-verifies the pinned FreeRDP
# source, then builds) + tests + selftest. No dynamic pin resolution here.
RUN cmake -S . -B build-native -G Ninja \
      -DPRIVION_LAB_ONLY=ON -DPRIVION_WITH_FREERDP=ON -DPRIVION_BUILD_TESTS=ON \
 && cmake --build build-native
RUN ctest --test-dir build-native --output-on-failure
RUN ./build-native/privion-rdp-worker-lab --selftest

# --- runtime -----------------------------------------------------------------
FROM ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90 AS runtime
# ca-certificates gives OpenSSL a system trust store so FreeRDP can verify a
# server certificate that chains to an OS-trusted (or lab) CA. This is the
# PROPOSED trust mechanism for the P0 certificate scenarios — prepared here, but
# only proven effective by the real scenarios 4/5 (TOFU=0 + controlled CA +
# chained cert accepted + unknown cert refused). A lab-internal CA is supplied
# at run time via a read-only bundle + SSL_CERT_FILE (see the runbook); the TOFU
# accept-once escape hatch is NEVER accepted as proof of trust.
RUN apt-get update && apt-get install -y --no-install-recommends \
      libssl3 zlib1g libicu74 liburiparser1 libcjson1 ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --user-group --no-create-home --shell /usr/sbin/nologin privion \
 && mkdir -p /run/privion && chown privion:privion /run/privion && chmod 0700 /run/privion
COPY --from=builder /w/build-native/privion-rdp-worker-lab /usr/local/bin/privion-rdp-worker-lab
COPY --from=builder /w/build-native/freerdp/install/lib/ /usr/local/lib/
RUN ldconfig
# Lab-only artifact: runs as a dedicated non-root user; the binary also refuses to
# start with PAM_ENV=production. Recommended run flags (compose/k8s, not baked in):
#   --read-only --cap-drop=ALL --security-opt no-new-privileges
#   --pids-limit=64 --memory=512m, private UDS under /run/privion.
USER privion
WORKDIR /run/privion
ENTRYPOINT ["/usr/local/bin/privion-rdp-worker-lab"]
