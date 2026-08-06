# lsp — the jailed language-server daemon

`ghcr.io/hanzoai/lsp` · module `github.com/hanzoai/lsp` · Go, stdlib only · linux/amd64

Holds immutable per-`(org, repo, commit)` working trees, runs a language server
over each inside a jail with no network, and answers position questions about
them. It is the backend `/v1/code/lsp/*` resolves to.

## Why it is a separate daemon

A static symbol index knows what a repository says about itself. It cannot tell
you where `dep.Greet` is DEFINED, because the definition is in a module the
repository only names. Finding it means downloading that module and
type-checking both halves — running a third-party binary over untrusted bytes.
That does not belong in the API process, so it is here, behind a jail.

The one answer that justifies the service is a `Location` with `external: true`:
a definition that left the repository and landed in the dependency cache.

## The invariant

**The network and untrusted bytes are never in the same process.**

| | FETCH | SERVE |
|---|---|---|
| runs | `go mod download` — first-party toolchain, download-only | `gopls serve -mode=stdio` — third-party, parses tenant source |
| socket | permitted | **denied** by seccomp (`socket`, `socketpair`, and the io_uring family) |
| tree | writable | read-only |
| dependency cache | writable | read-only |
| namespaces | new user/mount/pid/ipc/uts, minimal chroot, rlimits, `no_new_privs` | same |

The phase is not a field anyone sets — it is `jail.Fetch` or `jail.Serve`, two
functions, so there is no value to get wrong. The only difference between their
seccomp filters is `socket`/`socketpair`, and that is one two-line function
(`denied` in `internal/jail/jail_linux.go`).

Fetches that would run DEPENDENCY-authored code (`uv sync` building an sdist,
`npm install` running postinstall, `cargo build` running build.rs) do not run at
all — see `Fetchable` in `internal/lsp/langs.go`. A language server resolves
definitions from source; build artifacts buy nothing and would be arbitrary code
executing in the one phase that has a network.

## Fail closed

On Linux the jail is REQUIRED. At boot the daemon runs `jail.Probe`, which
builds a real jail in each phase and makes a canary ask the kernel for a socket:
serving must be refused one, fetching must get one. If that does not hold —
no gVisor RuntimeClass, no user namespace — `/readyz` is 503 and every request
that would run a language server is refused. There is no environment variable
that turns the jail off, so there is none that can be set by accident.

Off Linux there is no jail to require, and the daemon says so loudly in the log
and on `/readyz`. The image is linux/amd64, so that case is a developer's
machine.

## Roots are immutable

A root is `(org, repo, rev)` where **rev is a resolved commit** — 40 or 64 hex
digits, refused at the door otherwise. That single rule is the entire
cache-invalidation design: a sha names one tree for all time, a push is a
different key, and there is no subsystem that decides when anything is stale.
The caller resolves refs; it is the one that has the repository.

The daemon holds **no git credential** and makes no git request. The caller
sends the tree. A daemon that could fetch a repository would need a credential
that could reach every repository.

## Wire contract

All bodies are JSON. Every route but the probes requires `X-API-Key`
(constant-time; unset key ⇒ 503, not an open door). `org` is a namespacing key,
not an authorization decision: this daemon does not authenticate tenants, it
isolates them. The caller behind the key — the cloud API — is the authenticator.

### `POST /root`

```json
{ "org": "acme", "repo": "app",
  "rev": "9f2c1e...40 or 64 hex...",
  "files": [ { "path": "go.mod", "content": "module …" },
             { "path": "main.go", "content": "package main…" } ] }
```

→ `200 { "ready": true, "cold": true, "langs": ["go"] }`

Materializes the tree at `/var/lib/lsp/roots/{org}/{repo}/{rev}`, runs the fetch
phase once per module directory, starts one server per language that is both
present in the tree and installed in this image. `cold` is false when the root
was already live. Idempotent: roots are immutable, so re-sending a tree is a
no-op.

Errors: `400` bad key or tree (a path that escapes, a duplicate, an empty tree,
past the 20 000-file / 256 MiB bound), `409` on `/root/warm` only, `503`
sandbox unavailable, `504` build timed out.

### `POST /root/warm`

The same body and the same work, accepted **only if this org already holds a
live root for this repo**. Pre-warming a revision nobody asked about is free
work; it is offered only where a cold start on the same repository has already
been paid for.

→ `409 { "need": "held", "org": …, "repo": … }` otherwise.

### `POST /ask`

```json
{ "org": "acme", "repo": "app", "rev": "9f2c1e…",
  "op": "locate", "relation": "definition",
  "path": "main.go", "line": 5, "character": 9 }
```

`op` ∈ `hover` · `locate` · `symbols` · `diagnostics` · `complete`
`relation` (required for `locate`) ∈ `definition` · `reference` · `type` · `implementation`

**Positions are the LSP's**: `line` and `character` are 0-BASED and `character`
counts UTF-16 code units. An editor's 1-based line must have 1 subtracted before
it is sent. They pass through untouched — re-basing them would corrupt every
line containing a multi-byte character.

→ `200`:

```json
{ "op": "locate", "lang": "go",
  "locations": [ { "path": "example.com/dep@v1.0.0/dep.go",
                   "external": true,
                   "range": { "start": {"line":3,"character":5},
                              "end":   {"line":3,"character":10} } } ] }
```

Exactly one result field is populated: `locations`, `hover`, `symbols`,
`completions` or `diagnostics`. `external: false` (omitted) means `path` is
repo-relative. `external: true` means the answer left the repository and `path`
is its module coordinate — the dependency cache's own layout, which names the
module, its version and the file, and leaks no path belonging to this daemon.

A null result is not an error: "no definition here" is a real answer and comes
back with an empty list.

→ `409 { "need": "tree", "org": …, "repo": …, "rev": … }` when no root is held.
The caller then `POST /root` with the tree and asks again. Two calls cold, one
warm.

Errors: `400` bad key, unknown op or relation, negative position, a path that is
not in the tree, or a file no installed server answers for; `502` the language
server did not answer; `503` sandbox unavailable.

### `GET /healthz` · `GET /readyz`

Liveness answers 200 while the process is up. Readiness answers what the jail
decided: `{ "ready": true, "jail": "jailed", "langs": ["go"] }`, or 503 with the
reason. They are different questions and do not collapse into one.

## Languages

`internal/lsp/langs.go` carries five complete entries — `go`, `rust`,
`typescript`, `python`, `cpp` — with argv, root markers, extensions, cache and
fetch. What decides whether one is SERVED is `Lang.Available()`: whether its
binary is on PATH in the image.

**Phase 1 ships the Go toolchain and gopls, so Go is the only language served.**
The other four are inert in this image and light up the moment their server is
installed in the Dockerfile — no code change. That is deliberate: the table never
promises what the deployment cannot do.

## Bounds

| | |
|---|---|
| live roots | 4, LRU, 20-minute idle TTL |
| concurrent cold starts | 2 |
| one dependency fetch | 10 minutes |
| tree | 20 000 files, 256 MiB, depth 32 |
| serve rlimits | 6 GiB address space, 4096 fds, 256 procs, 2 GiB tmpfs, **no CPU cap** (total-CPU-seconds on a warm server is a scheduled death; the bound is the pod cgroup and the idle TTL) |
| fetch rlimits | 4 GiB address space, 900 CPU seconds, 1024 fds, 128 procs |
| one LSP frame | 32 MiB |
| handshake / query | 120 s / 30 s |

## Configuration

| env | default | |
|---|---|---|
| `LSP_LISTEN` | `:8000` | |
| `LSP_KEY` | *unset* | shared service key, from KMS. Unset ⇒ refuse everything. |
| `LSP_ROOTS` | `/var/lib/lsp/roots` | PVC |
| `LSP_DEPS` | `/var/lib/lsp/deps` | PVC — public, checksum-verified modules only |
| `LSP_STAGE` | `/tmp/jail` | emptyDir; each jail mounts its chroot base here |
| `LSP_PROXY` | `https://proxy.golang.org,direct` | the ONLY host the fetch phase may reach |
| `LSP_SUMDB` | `sum.golang.org` | verification is what makes a shared cache safe |

The dependency cache is shared across orgs on purpose. It holds only public
modules verified against the checksum database, because this daemon carries no
credential and so no private dependency can enter it. Sharing it is most of the
cold-start win.

## Layout

```
main.go                        boot: jail child hook, config, server, shutdown
internal/jail/                 the jailer — COPY of code-exec's, see below
  jail.go                      Spec, Limits, the two phases, the control channel
  jail_linux.go                the child: namespaces, chroot, rlimits, seccomp, exec
  jail_other.go                no jail off Linux, decided by platform not by flag
internal/lsp/
  lsp.go                       types, placing an answer, decoding a server's reply
  conn.go                      the LSP JSON-RPC client   (PORTED, see below)
  langs.go                     the language table        (PORTED, see below)
  root.go                      materialize · fetch · serve
  pool.go                      LRU + idle TTL, single-flight build
  http.go                      the door
```

### Provenance

- `internal/lsp/conn.go` and `langs.go` are PORTED from `hanzoai/cloud` branch
  `lsp` (`apps/lsp/server.go`, `apps/lsp/langs.go`, commit `67975187`), with
  their tests. Two regressions that build pinned are pinned here too: `Close`
  hanging on a server that stopped reading its stdin, and a frame reader that
  would allocate whatever `Content-Length` it was told.
- `internal/jail/` is a COPY of `hanzoai/code-exec`'s jailer
  (`internal/codeexec/jail_linux.go` at `d2794ce`), generalized to two phases.

### CTO call — the jailer should be one module

The seccomp filter now exists in two repositories. A security boundary that
exists twice drifts, and a change has to land in both. It **should** be
published as `github.com/hanzoai/jail` and imported by `code-exec` and `lsp`
alike. Publishing a new shared module is a call to make deliberately, so it is
noted here rather than made in passing.

This copy carries **one fix over the original**: the jail child now calls
`runtime.LockOSThread()` before installing the filter. `no_new_privs` and
`PR_SET_SECCOMP` apply to the CALLING THREAD, and `syscall.Exec` execs the
calling thread — if the Go scheduler moved the goroutine between the two, the
exec'd program would inherit no filter and the sandbox would silently not exist.
The original's sequence is short enough that it has always held in practice.
"In practice" is not a security boundary. **This fix belongs upstream in
code-exec too.**

## Tests

```
go test ./...                     # everything; add gopls to PATH for the acceptance test
```

The acceptance test (`internal/lsp/gopls_test.go`) is hermetic: it publishes a
tiny module into a directory laid out as a Go module proxy and points the fetch
phase at it with `GOPROXY=file://`, so the REAL `go mod download` runs with no
network, and then requires `locate definition` on `dep.Greet` to come back
`external: true` at the module coordinate. It skips where `gopls` is not
installed.

The jail tests interpret the cBPF program the way the kernel would, so the jump
arithmetic — where an off-by-one silently ALLOWS a denied syscall — is checked
on any Linux with no privileges. `TestProbeProvesTheBoundaryOnThisHost` runs the
real thing and skips where a user namespace cannot be created (a plain CI
container; the gVisor target can).

## Phase 2

1. **cloud `apps/lsp` becomes a thin proxy.** The blue monolith on branch `lsp`
   ran language servers inside the fleet pod with its own git checkout — the
   wrong shape, and superseded. Replace it with ~300 lines at
   `/v1/code/lsp/*`: validate the principal, take org from it, resolve the ref
   to a sha, read the tree through `apps/git` `repo.WalkText` (SHARED with
   `apps/code` — one tree read, not a second checkout), `Gate`/`MeterUsage`
   (prepare price on cold, query price on warm), then POST to
   `lsp.hanzo.svc:8000`. On `409 {"need":"tree"}`, POST `/root` and retry once.
2. **universe Deployment.** `ghcr.io/hanzoai/lsp` on a gvisor node pool (scale
   the gvisor-installer DaemonSet up), `runtimeClassName: gvisor`, non-root,
   RO rootfs, all capabilities dropped, no service-account token, a PVC for
   `/var/lib/lsp`, an emptyDir for `/tmp`, and a NetworkPolicy whose egress
   allowlist is the module proxy and nothing else. `LSP_KEY` from a KMSSecret.
3. **MCP.** EXTEND the existing single `lsp` tool (`mcp/rust/src/tools/lsp_tool.rs`,
   `python-sdk/pkg/hanzo-tools-lsp`) with `repo`/`rev` parameters — a file goes
   to the local stdio server, a repo goes to `/v1/code/lsp/*`. Not a new tool.
4. **More languages** = install the server in the Dockerfile. The table entries
   already exist.
