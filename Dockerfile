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

# ── 2. gopls ─────────────────────────────────────────────────────────────────
#
# The one server that is BUILT rather than downloaded, because the Go build
# stage is already here. Every other server arrives as its project's own
# release artifact in the runtime stage, beside the toolchain it needs.
FROM golang:1.26.5-bookworm AS tools
ARG GOPLS_VERSION=v0.23.0
RUN GOBIN=/out CGO_ENABLED=0 go install golang.org/x/tools/gopls@${GOPLS_VERSION}

# ── 3. Runtime ───────────────────────────────────────────────────────────────
#
# EVERY VERSION BELOW IS PINNED, and none of them is `latest`. A floating server
# means two builds of the same commit answer differently, and the thing that
# changed is a binary nobody reviewed. Bumping one is one line here.
#
# A language is SERVED when its server binary is on PATH — internal/lsp/langs.go
# carries the entry and Lang.Available() reads this image to decide whether the
# entry is true. So this file, and only this file, is what makes a language real.
#
# The image is large, and that is the honest cost of nine languages: a compiler
# or an interpreter per language, because a language server resolves definitions
# by type-checking source and cannot do it without one. It is pulled once per
# node and the daemon is long-lived.
FROM debian:bookworm-slim AS runtime

# ca-certificates for the FETCH phase's TLS to the module proxy; tini to reap the
# jail children (each root forks a language server, which forks `go list`).
# curl and unzip fetch and unpack the toolchains below.
#
# Then the half of the toolchain set that Debian versions better than we would:
#
#   python3   pyright reads a tree's import search path out of a real
#             interpreter; without one it sees only its bundled typeshed.
#   ruby      ruby-lsp is a gem, and the standard library it indexes is this
#             interpreter's.
#   php-*     composer IS a PHP program, so the PHP fetch needs the interpreter
#             even though the server itself is a Node one.
#   g++       the C++ standard headers clangd resolves <vector> in, and the
#             compiler a gem with a native extension builds with.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates tini curl unzip \
      python3 \
      ruby ruby-dev \
      php-cli php-curl php-mbstring php-zip \
      g++ make \
    && rm -rf /var/lib/apt/lists/*

# ── Go ───────────────────────────────────────────────────────────────────────
#
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

# ── Node, and the three languages that ride on it ────────────────────────────
#
# One runtime, three servers: TypeScript/JavaScript, Python (pyright) and PHP
# (intelephense) are all Node programs. That is most of why this image can speak
# nine languages without being nine images.
#
# typescript is pinned to 5.x DELIBERATELY. TypeScript 7 is the native rewrite
# and ships no `bin/tsserver`; typescript-language-server drives tsserver, so
# the pair only exists at 5.x. When the server moves to the native protocol,
# both lines move together.
#
# --ignore-scripts on the global install, for the same reason the fetch phase
# uses it: a package's install hook is code nobody read. None of these four has
# one, which is what makes the flag free rather than brave.
ARG NODE_VERSION=24.19.0
ARG TYPESCRIPT_VERSION=5.9.3
ARG TYPESCRIPT_SERVER_VERSION=5.3.0
ARG PYRIGHT_VERSION=1.1.411
ARG INTELEPHENSE_VERSION=1.18.5
RUN set -eux; \
    curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.gz" -o /tmp/node.tgz; \
    tar -C /usr/local --strip-components=1 --no-same-owner -xzf /tmp/node.tgz \
        --exclude='*/CHANGELOG.md' --exclude='*/LICENSE' --exclude='*/README.md'; \
    rm /tmp/node.tgz; \
    npm install -g --ignore-scripts --no-audit --no-fund \
      "typescript@${TYPESCRIPT_VERSION}" \
      "typescript-language-server@${TYPESCRIPT_SERVER_VERSION}" \
      "pyright@${PYRIGHT_VERSION}" \
      "intelephense@${INTELEPHENSE_VERSION}"; \
    npm cache clean --force

# ── Rust ─────────────────────────────────────────────────────────────────────
#
# The component tarballs, NOT rustup, and the difference is what is left in the
# image afterwards. rustup is a toolchain DOWNLOADER: with it installed, a
# tenant's rust-toolchain.toml is an instruction to go and get another compiler
# — an unbounded download in the phase that has a network, and a hang in the
# phase that does not. The real binaries under /usr/local read no toolchain file
# and can fetch nothing. It is the Rust spelling of GOTOOLCHAIN=local.
#
# rust-src is not an extra: rust-analyzer resolves the standard library from
# SOURCE, so without it every std symbol in every answer is unresolved.
ARG RUST_VERSION=1.97.1
RUN set -eux; \
    for pkg in \
        "rustc-${RUST_VERSION}-x86_64-unknown-linux-gnu" \
        "cargo-${RUST_VERSION}-x86_64-unknown-linux-gnu" \
        "rust-std-${RUST_VERSION}-x86_64-unknown-linux-gnu" \
        "rust-analyzer-${RUST_VERSION}-x86_64-unknown-linux-gnu" \
        "rust-src-${RUST_VERSION}" ; do \
      curl -fsSL "https://static.rust-lang.org/dist/${pkg}.tar.gz" -o /tmp/rust.tgz; \
      mkdir /tmp/rust; \
      tar -C /tmp/rust --strip-components=1 --no-same-owner -xzf /tmp/rust.tgz; \
      /tmp/rust/install.sh --prefix=/usr/local --disable-ldconfig; \
      rm -rf /tmp/rust /tmp/rust.tgz; \
    done

# ── C and C++ ────────────────────────────────────────────────────────────────
#
# clangd from the project's own release rather than apt: one pinned archive that
# carries its resource directory — the builtin headers it resolves <stddef.h>
# in — beside the binary, which it finds by resolving its own path. Hence the
# symlink into /usr/local/bin rather than a copy.
ARG CLANGD_VERSION=22.1.6
RUN set -eux; \
    curl -fsSL "https://github.com/clangd/clangd/releases/download/${CLANGD_VERSION}/clangd-linux-${CLANGD_VERSION}.zip" -o /tmp/clangd.zip; \
    unzip -q /tmp/clangd.zip -d /usr/local; \
    mv "/usr/local/clangd_${CLANGD_VERSION}" /usr/local/clangd; \
    chmod +x /usr/local/clangd/bin/clangd; \
    ln -s /usr/local/clangd/bin/clangd /usr/local/bin/clangd; \
    rm /tmp/clangd.zip

# ── Java ─────────────────────────────────────────────────────────────────────
#
# A JDK because jdtls IS a Java program, and a JDK rather than a JRE because it
# is also what jdtls reads the platform's own sources out of (lib/src.zip).
#
# The milestone, not the snapshot: `snapshots/latest.txt` moves, and a build
# that reads it is a build whose language server nobody chose. A milestone is a
# version plus the build stamp that identifies it, which together are immutable.
#
# `bin/jdtls` is the project's own Python launcher, and it is what langs.go
# starts rather than a hand-written `java -jar`: it already asks Equinox for a
# CASCADED configuration (`osgi.sharedConfiguration.area.readOnly=true`), which
# is the one thing an OSGi application needs to run from a read-only
# installation. Reproducing that argv here would be a second copy of it to keep
# right. It resolves its own path, so the symlink onto PATH is enough.
#
# `config_linux` is x86_64's, which is this image's — see the platform list in
# hanzo.yml. An arm64 image would need the launcher to pick config_linux_arm,
# and it does not.
ARG JDK_VERSION=21.0.12
ARG JDK_BUILD=8
ARG JDTLS_VERSION=1.60.0
ARG JDTLS_BUILD=202606262232
RUN set -eux; \
    curl -fsSL "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-${JDK_VERSION}%2B${JDK_BUILD}/OpenJDK21U-jdk_x64_linux_hotspot_${JDK_VERSION}_${JDK_BUILD}.tar.gz" -o /tmp/jdk.tgz; \
    mkdir -p /usr/local/jdk; \
    tar -C /usr/local/jdk --strip-components=1 --no-same-owner -xzf /tmp/jdk.tgz; \
    rm /tmp/jdk.tgz; \
    ln -s /usr/local/jdk/bin/java /usr/local/bin/java; \
    curl -fsSL "https://download.eclipse.org/jdtls/milestones/${JDTLS_VERSION}/jdt-language-server-${JDTLS_VERSION}-${JDTLS_BUILD}.tar.gz" -o /tmp/jdtls.tgz; \
    mkdir -p /usr/local/jdtls; \
    tar -C /usr/local/jdtls --no-same-owner -xzf /tmp/jdtls.tgz; \
    rm /tmp/jdtls.tgz; \
    ln -s /usr/local/jdtls/bin/jdtls /usr/local/bin/jdtls

# ── PHP ──────────────────────────────────────────────────────────────────────
#
# composer, for the fetch phase only: `--no-scripts --no-plugins` is composer's
# own switch for "place vendor/, run none of its authors' code", the exact shape
# of npm's --ignore-scripts. The server itself is intelephense, installed with
# Node above.
ARG COMPOSER_VERSION=2.10.2
RUN set -eux; \
    curl -fsSL "https://getcomposer.org/download/${COMPOSER_VERSION}/composer.phar" -o /usr/local/bin/composer; \
    chmod +x /usr/local/bin/composer

# ── Ruby ─────────────────────────────────────────────────────────────────────
#
# Installed into Debian's own gem directory (/var/lib/gems) rather than a private
# one, so RubyGems finds it with no GEM_HOME in the jail's built environment —
# the bind in internal/lsp/root.go is the whole of the wiring. The executable
# lands in /usr/local/bin, which is already on the jail's PATH.
ARG RUBY_LSP_VERSION=0.26.10
RUN gem install ruby-lsp --version "${RUBY_LSP_VERSION}" --no-document

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
