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
| socket | permitted | **denied** by seccomp (`socket` and the io_uring family; `socketpair` is allowed for AF_UNIX only, which is a pipe to your own child and reaches nothing) |
| tree | writable | read-only |
| dependency cache | writable | read-only |
| namespaces | new user/mount/pid/ipc/uts, minimal chroot, rlimits, `no_new_privs` | same |

The phase is not a field anyone sets — it is `jail.Fetch` or `jail.Serve`, two
functions, so there is no value to get wrong. The only difference between their
seccomp filters is `socket`, and that is one two-line function (`denied` in
`internal/jail/jail_linux.go`).

`socketpair` used to be denied beside it and is not any more. It reaches nothing
— both ends come back already connected to each other, in AF_UNIX, inside this
jail's namespaces — but it is how libuv gives a child its stdio, so denying it
did not stop a network, it stopped **Node starting a process**. TypeScript's
server exists to run `tsserver`, so it died with `spawn EPERM` while every other
language kept answering. The filter now decides `socketpair` on its FAMILY, the
one argument it reads, so "no fd to a network" stays a property of the program
rather than a fact about which families the kernel implements
(`TestSocketpairIsDecidedByItsFamily`).

Fetches that would run DEPENDENCY-authored code (`uv sync` building an sdist,
`npm install` running postinstall, `cargo build` running build.rs) do not run at
all — see `Fetchable` in `internal/lsp/langs.go`. A language server resolves
definitions from source; build artifacts buy nothing and would be arbitrary code
executing in the one phase that has a network.

## Fail closed

On Linux the jail is REQUIRED. At boot the daemon runs `jail.Probe`, which
builds a real jail in each phase and **execs** a canary in it — `lsp canary`,
this same binary — which asks the kernel for a socket and says what happened:
serving must be refused one, fetching must get one. Reaching the canary by exec
is the point: a jail that builds perfectly and then cannot exec fails the
self-test instead of passing it from inside the process that built it. If any of
that does not hold — no gVisor RuntimeClass, no user namespace, a masked mount,
a filter that did not take — `/readyz` is 503 and every request that would run a
language server is refused. There is no environment variable that turns the jail
off, so there is none that can be set by accident.

### The mount order is the boundary too

The jail's filesystem is a VALUE — `plan()` in `internal/jail/jail_linux.go` —
ordered shallowest path first, with one mount per path and the jail's own `/tmp`
claiming that path before any caller can.

That ordering is not a detail. A mount whose path is an ancestor of an earlier
one covers it, and nothing fails when it happens: the earlier mount is still
there and simply cannot be seen. The daemon shipped with the writable `/tmp`
mounted AFTER the binds, which erased every bind under `/tmp` — and `/tmp` is
where the staging directory lives. The boot self-test masked its own working
tree, `chdir` returned ENOENT, the child exited 126, and `/readyz` was 503 on
every host. Nothing about the boundary was wrong; the filesystem was built in an
order that hid part of it.

Sorting by depth makes an ancestor-after-descendant order unrepresentable, and
`TestThePlanHidesNothing` asserts it with no kernel and no privileges.

### What the jail brings with it

Three things are the jail's own, present in BOTH phases, and no argument can
replace them (the first claim on a path wins):

| | what | why |
|---|---|---|
| `/tmp` | fresh tmpfs, writable, nosuid+nodev | the only thing a served process can write; dies with the process |
| `/proc` | fresh procfs **in the jail's own PID namespace**, read-only, nosuid+nodev+noexec | shows the jailed process and its children, nothing of the host |
| `/dev/{null,zero,full,random,urandom}` | bound from the host, writable | a user namespace cannot `mknod`; none of them holds state |

`/proc` is not a hole — it is a private one, and without it no Go program starts.
`os.Executable` reads `/proc/self/exe`, `x/telemetry` calls it on init, and gopls
died at startup with `readlink /proc/self/exe: no such file or directory` while
the daemon reported only `server stopped`. `GOTELEMETRY=off` does not prevent it:
x/telemetry reads its mode file, not the environment.

`/dev/null` is required for the same class of reason — Go's `os/exec` opens it
for every subprocess with no stdin, so without it `go list` cannot run. It is
bound writable because a read-only mount makes `open(O_WRONLY)` return EROFS.

**hanzoai/code-exec carries the same ordering, and it is one change away from
the same bug.** This jailer was copied from its `internal/codeexec/jail_linux.go`,
which also binds first and mounts `/tmp` after. It is not hit TODAY only because
it binds the session tree at a fixed `/work` rather than at the tree's own
absolute path, and its toolchain binds are outside `/tmp`; the day any bind path
falls under `/tmp`, it fails exactly the way this did. That is a property of a
call site, not of the jailer — which is the argument for the CTO call below: a
boundary that exists in two files drifts, and this is what the drift looks like.

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
decided: `{ "ready": true, "jail": "jailed", "langs": [ … ] }`, or 503 with the
reason. `langs` is the table narrowed to the servers this image actually has, so
it is also the honest answer to "what can you speak". They are different
questions and do not collapse into one.

## Languages

`internal/lsp/langs.go` carries one entry per language — argv, root markers,
extensions, cache and fetch. What decides whether one is SERVED is
`Lang.Available()`: whether its binary is on PATH in the image. The table never
promises what the deployment cannot do.

| | server | fetch | resolves dependencies from |
|---|---|---|---|
| `go` | gopls | `go mod download all` | the module cache |
| `typescript` (`.ts` `.tsx` `.mts` `.cts` `.js` `.jsx` `.mjs` `.cjs`) | typescript-language-server + tsserver | `npm ci --ignore-scripts` | `node_modules` in the tree |
| `php` | intelephense | `composer install --no-scripts --no-plugins` | `vendor/` in the tree |
| `rust` | rust-analyzer | `cargo fetch --locked` | the cargo registry cache |
| `python` | pyright | none — `uv sync` builds sdists | source + bundled typeshed |
| `ruby` | ruby-lsp | none — `bundle install` compiles | source + the `rbs` core signatures |
| `java` | jdtls | none — every Java resolver is a build tool | source + the JDK |
| `cpp` (`.c` `.h` too) | clangd | none — no resolver exists | `compile_commands.json`, else one file |

The four with no fetch still answer about the tree's own source and its
platform's; what they lose is a definition that crosses into a third-party
package. That is the scripts-off trade, taken deliberately: see `Fetchable`.

A server that fails to start takes only its own language down — `build()` logs
`language server did not start` and the rest of the tree keeps answering.

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

It could not run JAILED until a `file://` GOPROXY was bound into the fetch jail
(`proxyDirs` in `internal/lsp/root.go`). The jail binds an allow-list of host
paths, the proxy was not on it, and `go mod download` reported a module that does
not exist — so on Linux the test skipped via `needJail` and on a Mac it passed
unjailed. That is a real deployment shape too, not only a test's: an air-gapped
mirror on a PVC was a configuration the daemon accepted and could never read.
Verified end to end on the gVisor node: fetch, gopls start, `locate definition`
and `hover` all pass inside the jail.

The jail tests interpret the cBPF program the way the kernel would, so the jump
arithmetic — where an off-by-one silently ALLOWS a denied syscall — is checked
on any Linux with no privileges. `TestThePlanHidesNothing`, `TestThePlanIsThePhase`
and `TestTheJailKeepsItsOwnTmp` check the filesystem half of the boundary the
same way: no kernel, no privileges, no skip.

`TestProbeProvesTheBoundaryOnThisHost` runs the real thing and **skips for
exactly one reason**: this host cannot create the namespaces (`jail.ErrHost`),
which a plain CI container cannot and the gVisor target can. Every other failure
is this repository's and fails the build. It used to skip on any error at all,
so a jail that built and then did not work reported itself as "not the target" —
exit 126 skipped there for as long as it existed. `TestMain` in both test
packages takes the jail-child path, without which a jail re-execs the TEST
BINARY and a self-exec'd test suite proves nothing.

## Phase 2

1. **cloud `apps/lsp` becomes a thin proxy.** The blue monolith on branch `lsp`
   ran language servers inside the fleet pod with its own git checkout — the
   wrong shape, and superseded. Replace it with ~300 lines at
   `/v1/code/lsp/*`: validate the principal, take org from it, resolve the ref
   to a sha, read the tree through `apps/git` `repo.WalkText` (SHARED with
   `apps/code` — one tree read, not a second checkout), `Gate`/`MeterUsage`
   (prepare price on cold, query price on warm), then POST to
   `lsp.hanzo.svc:8000`. On `409 {"need":"tree"}`, POST `/root` and retry once.
2. **universe Deployment.** DECLARED — `hanzoai/universe`
   `charts/app/values/hanzo/lsp.yaml`: `runtimeClassName: gvisor`, non-root at
   uid 65532, RO rootfs, all capabilities dropped, no service-account token,
   seccomp RuntimeDefault, a 20Gi PVC for `/var/lib/lsp`, an emptyDir for
   `/tmp`, and an egress policy. `LSP_KEY` comes from `hanzo/lsp/LSP_KEY@prod`
   through the `lsp-env-kms-sync` KMSSecret; the same secret is read by cloud,
   so the proxy's `X-API-Key` and the daemon's key are one value, not a pair.
   Devs do not `kubectl apply` it — cd.hanzo.ai syncs that file.

   TWO THINGS GATE IT RUNNING, and neither is code here:

   * **The pool is too small.** `runtimeClassName: gvisor` resolves now —
     `code-exec-pool` is two s-4vcpu-8gb nodes labelled `workload=code-exec`,
     tainted `dedicated=code-exec`, with runsc installed and the RuntimeClass
     merging both into this pod at admission. But ~6.2Gi allocatable against the
     8Gi this daemon asks for means Pending on `Insufficient memory` until the
     pool is resized. One `doctl` resize, no code.
   * **The image.** CI is `.hanzo/workflows/cicd.yml` → `hanzoai/ci` on the
     git.hanzo.ai runners, publishing `ghcr.io/hanzoai/lsp`. The values file
     carries tag AND digest, bumped in a reviewed commit.

   Note what the values file does NOT say: which nodes. The pool went from not
   existing to two tainted nodes while that file was being written, and it did
   not have to change, because naming the RuntimeClass names the node set by
   reference. A file that had copied the selector would now be wrong — and a
   nodeSelector that conflicts with the RuntimeClass's does not misplace a pod,
   it rejects it.

   Note what does NOT gate it: a wrong node, a missing RuntimeClass or a kernel
   that will not make a user namespace are all survivable, because the boot-time
   probe refuses to be ready and the Service keeps no endpoints. The daemon
   never parses tenant bytes outside a jail it has watched work.
3. **MCP.** EXTEND the existing single `lsp` tool (`mcp/rust/src/tools/lsp_tool.rs`,
   `python-sdk/pkg/hanzo-tools-lsp`) with `repo`/`rev` parameters — a file goes
   to the local stdio server, a repo goes to `/v1/code/lsp/*`. Not a new tool.
4. **More languages** = install the server in the Dockerfile and add its entry.
   DONE for the nine above, and verified on the gVisor node at 0.1.6: Go,
   Python, Rust, C, C++, Java, PHP and Ruby all answered `locate definition`
   jailed, Ruby into the interpreter's own library with `external: true`.
   TypeScript and JavaScript did not, for the `socketpair` reason above — one
   language's server failing is one language, which is the graceful-degrade
   design doing its job and the reason the other eight shipped anyway.

   Two things a repo needs before its dependencies resolve, neither a bug:
   `cargo fetch --locked` wants a committed `Cargo.lock`, and `npm ci` wants a
   `package-lock.json`. Without one the fetch is skipped, logged, and the server
   still answers about the tree's own source.
