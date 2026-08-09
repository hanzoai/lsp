# syntax=docker/dockerfile:1

# lsp — the jailed language-server daemon.
#
# Three stages:
#   1. build  — compiles the static Go binary.
#   2. tools  — compiles the language servers the runtime will run.
#   3. runtime — lean Debian with the toolchains + tini, non-root.
#
# The isolation is the Go-NATIVE jailer built into the binary (namespaces +
# minimal chroot + seccomp) running under a gVisor RuntimeClass — NOT nsjail.
# nsjail is incompatible with gVisor (it calls prctl(SECUREBITS), which gVisor
# does not implement, and needs a cgroup ns plus a netlink net-ns gVisor
# rejects), so this image ships no jailer binary at all: the daemon re-execs
# ITSELF as the jail child.
#
# Built in CI on the self-hosted amd64 scale set — never on GitHub's builders,
# never on a developer's laptop. The cluster is amd64; the image targets
# linux/amd64.

# ── 1. The daemon ────────────────────────────────────────────────────────────
FROM golang:1.26.5-bookworm AS build
WORKDIR /src
# Module graph first for layer caching. There are no dependencies today — stdlib
# only, by design — but this keeps the shape right if one is ever added.
COPY go.mod ./
RUN go mod download
COPY . .
# CGO off ⇒ a fully static binary with no shared-library surface of its own. The
# jail child re-execs this exact binary.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/lsp .

# ── 2. The language servers ──────────────────────────────────────────────────
#
# PINNED, not @latest. A floating server version means two builds of the same
# commit answer differently, and the thing that changed is a binary nobody
# reviewed. Bumping is one line here.
#
# Phase 1 ships Go only. Adding a language is: install its server below, and
# internal/lsp/langs.go already carries the entry — Lang.Available() lights it up
# at runtime with no code change.
FROM golang:1.26.5-bookworm AS tools
ARG GOPLS_VERSION=v0.23.0
RUN GOBIN=/out CGO_ENABLED=0 go install golang.org/x/tools/gopls@${GOPLS_VERSION}

# ── 3. Runtime ───────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

# ca-certificates for the FETCH phase's TLS to the module proxy; tini to reap the
# jail children (each root forks a language server, which forks `go list`).
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates tini curl \
    && rm -rf /var/lib/apt/lists/*

# The Go toolchain, which gopls shells out to for `go list` and which the fetch
# phase runs as `go mod download`. A pinned tarball rather than apt: Debian's
# golang lags, and the toolchain version decides which repositories resolve —
# GOTOOLCHAIN=local (langs.go) never downloads a newer one, so a repo whose
# go.mod names a Go past this pin degrades to unresolved imports. Kept at the
# latest 1.26.x so the fleet's own repos (cloud requires 1.26.5) resolve; bump
# this line when a repo needs a newer one.
ARG GO_VERSION=1.26.5
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in amd64) goarch=amd64 ;; arm64) goarch=arm64 ;; *) echo "unsupported arch $arch"; exit 1 ;; esac; \
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${goarch}.tar.gz" -o /tmp/go.tgz; \
    tar -C /usr/local -xzf /tmp/go.tgz; \
    rm /tmp/go.tgz
ENV PATH="/usr/local/go/bin:${PATH}"

COPY --from=tools /out/gopls /usr/local/bin/gopls
COPY --from=build /out/lsp /usr/local/bin/lsp

# Roots and dependency caches live on a PVC mounted at /var/lib/lsp. The staging
# directory each jail chroots into is /tmp, an emptyDir — it holds nothing but
# mountpoints and must be writable by the non-root uid.
#
# THE UID IS FIXED, NOT ALLOCATED. `useradd -r` takes whatever system id happens
# to be free in the base image, so the number changes when the base image changes
# and nothing in this file says so. Two things downstream need it to be a
# constant and a NUMBER:
#
#   * `runAsNonRoot: true` is refused against a USER given as a name — the
#     kubelet cannot prove `lsp` is not root without resolving /etc/passwd inside
#     the image, so it does not try:
#       container has runAsNonRoot and image has non-numeric user (lsp),
#       cannot verify user is non-root
#     That is a CreateContainerConfigError at every start, not a warning.
#   * `fsGroup` on the PVC must name the same group, or the volume mounts
#     root-owned and the first `go mod download` into it fails on EACCES.
#
# 65532 is the conventional distroless non-root id, so this agrees with every
# other hardened image in the fleet rather than inventing a number.
RUN groupadd -g 65532 lsp && useradd -u 65532 -g 65532 -d /home/lsp -m lsp \
    && mkdir -p /var/lib/lsp/roots /var/lib/lsp/deps \
    && chown -R 65532:65532 /var/lib/lsp

ENV LSP_LISTEN=":8000" \
    LSP_ROOTS="/var/lib/lsp/roots" \
    LSP_DEPS="/var/lib/lsp/deps" \
    LSP_STAGE="/tmp/jail" \
    LSP_PROXY="https://proxy.golang.org,direct" \
    LSP_SUMDB="sum.golang.org"
# LSP_KEY is NOT set here. It comes from KMS through a KMSSecret; an unset key
# makes the daemon refuse every request rather than serve whoever asks.

# The NUMBER, not the name — see the useradd above. `USER lsp` reads better and
# is the one spelling the kubelet cannot check.
USER 65532
EXPOSE 8000

# tini as PID 1 so orphaned language-server processes are reaped.
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/usr/local/bin/lsp"]
