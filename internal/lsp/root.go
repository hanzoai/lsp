package lsp

// root.go builds one root: materialize the tree the caller sent, run the FETCH
// phase, then start the language servers under the SERVE phase.
//
// The order is the security model. Fetch has a network and runs first-party
// toolchain code over a list of dependency names. Serve has no socket and parses
// what fetch downloaded. They are two processes, never one, and they are built by
// two functions in package jail that cannot be confused for each other.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/hanzoai/lsp/internal/jail"
)

// Budgets. A root is a tree plus one process per language, so the bounds are on
// memory, file descriptors and wall clock, not on rows.
const (
	fetchWait = 10 * time.Minute // one module directory's dependency fetch
	warmMost  = 4                // roots held live at once
	warmTTL   = 20 * time.Minute // idle before eviction
	coldMost  = 2                // roots being built at once
)

// The tree a caller may send. These are the bounds on ONE root; the pool bounds
// how many roots exist.
const (
	fileMost  = 20000
	byteMost  = 256 << 20 // 256 MiB across the whole tree
	depthMost = 32
)

// jailPATH is the PATH inside the jail, for a toolchain's own subprocess lookups
// — `go` invoking the compiler, gopls invoking `go list`. Every argv[0] this
// daemon passes is already absolute; this is for what those programs then do.
const jailPATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin"

// toolPATH is the PATH a jailed toolchain runs with. Inside the jail it is the
// IMAGE's layout, because only the bound paths exist there. Where there is no
// jail — a developer's machine — the process runs on the host and gets the
// host's PATH, since the image layout would name nothing. The platform decides,
// which is the same predicate that decides whether this daemon may serve at all.
func toolPATH() string {
	if jail.Supported() {
		return jailPATH
	}
	return os.Getenv("PATH")
}

// toolchainRead is the read-only bind list: the ALLOW-LIST of host paths a jailed
// process can see. The daemon's own rootfs is NOT chrooted into — only these are
// bound, so /etc/shadow, a mounted KMS secret and the service-account token are
// absent rather than defended against.
//
// Missing paths are skipped, so an image that lacks /lib64 still jails. The list
// is the superset across the toolchains langs.go can run.
var toolchainRead = []string{
	"/usr/bin", // the compiler drivers, node, python
	"/usr/lib", // shared libraries
	"/usr/libexec",
	"/usr/include",
	"/usr/share",
	"/usr/local", // /usr/local/go, /usr/local/bin/gopls
	"/lib",       // ld-linux and libc on merged-usr and split layouts
	"/lib64",
	"/bin",
	"/sbin",
	"/etc/alternatives",
	"/etc/ssl",         // the CA store — the fetch phase speaks TLS
	"/etc/ld.so.cache", // a file bind
	"/etc/nsswitch.conf",
	"/etc/resolv.conf", // the fetch phase resolves the proxy's name
	"/etc/hosts",
	"/etc/passwd", // uid → name; hashes live in shadow, which is NOT bound
	"/etc/group",
}

// Config is the daemon's deployment: where roots and dependency caches live, and
// which module proxy the fetch phase is allowed to talk to.
type Config struct {
	// Roots is the directory materialized trees live under, one PVC path.
	Roots string
	// Deps is the directory dependency caches live under, shared across orgs.
	// It holds only PUBLIC, checksum-verified modules: this daemon carries no
	// credential, so no private dependency can enter it.
	Deps string
	// Stage is the writable directory each jail mounts its chroot base over.
	Stage string
	// Proxy is GOPROXY for the fetch phase. The Deployment's egress policy
	// allows this host and nothing else.
	Proxy string
	// Sumdb is GOSUMDB. Verification is what makes a shared cache safe.
	Sumdb string
}

// live is one language server attached to one root.
type live struct {
	lang Lang
	conn *Conn
	// deps are every spelling of the cache an external answer is named against.
	deps []string
}

// Root is one immutable (org, repo, rev) tree with its servers attached.
//
// ready is closed when it is usable. A Root is put in the pool BEFORE the slow
// work starts, so a second request for the same key waits for the first build
// rather than starting a competing one into the same directory.
type Root struct {
	key   key
	dir   string
	dirs  []string // every spelling of dir
	langs map[string]*live
	used  time.Time
	ready chan struct{}
	err   error

	// busy counts the queries currently using this root. A root in use is never
	// evicted, so a query can never have its servers killed and its tree removed
	// out from under it. Every hold is paired with a release.
	busy atomic.Int32
}

// release ends one query's use of a root.
func (r *Root) release() { r.busy.Add(-1) }

// Langs is the languages this root actually serves, sorted.
func (r *Root) Langs() []string {
	out := make([]string, 0, len(r.langs))
	for _, name := range names {
		if r.langs[name] != nil {
			out = append(out, name)
		}
	}
	return out
}

func (r *Root) close() {
	if r == nil {
		return
	}
	for _, l := range r.langs {
		l.conn.Close()
	}
	if r.dir != "" {
		_ = os.RemoveAll(r.dir)
	}
}

// build is the cold path, and it runs in the order the security model requires:
// materialize, fetch, serve.
func (s *Service) build(ctx context.Context, k key, files []File) (*Root, error) {
	dir := filepath.Join(s.cfg.Roots, k.org, k.repo, k.rev)
	// A root is immutable, so anything already at this path is the debris of a
	// build that did not finish. Start from nothing.
	if err := os.RemoveAll(dir); err != nil {
		return nil, fmt.Errorf("clear root: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create root: %w", err)
	}
	paths, err := materialize(dir, files)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}

	r := &Root{key: k, dir: dir, dirs: spellings(dir), langs: map[string]*live{}}
	for _, name := range names {
		l := table[name]
		if !l.Available() || !l.Speaks(paths) {
			continue
		}
		// FETCH — network, first-party toolchain, one run per module directory.
		// A failure is NOT fatal: a server still answers about the tree's own
		// source with nothing resolved, and a dependency we cannot reach is a
		// degraded answer rather than a dead root.
		if Fetchable(l) {
			for _, mod := range l.Modules(paths) {
				if err := s.fetch(ctx, l, dir, mod); err != nil {
					s.log.Warn("dependency fetch failed",
						"org", k.org, "repo", k.repo, "lang", l.Name, "module", mod, "err", err)
				}
			}
		}
		// SERVE — no socket, everything read-only.
		conn, err := s.serve(ctx, l, dir)
		if err != nil {
			s.log.Warn("language server did not start",
				"org", k.org, "repo", k.repo, "lang", l.Name, "err", err)
			continue
		}
		r.langs[l.Name] = &live{lang: l, conn: conn, deps: spellings(s.cache(l))}
	}
	return r, nil
}

// cache is where l's dependencies live on this deployment.
func (s *Service) cache(l Lang) string {
	if l.Cache == "" {
		return ""
	}
	return filepath.Join(s.cfg.Deps, l.Cache)
}

// fetch runs l's dependency fetch in one module directory, WITH a network and
// WITHOUT any dependency's own code — see langs.go on scripts-off.
func (s *Service) fetch(ctx context.Context, l Lang, dir, mod string) error {
	argv, err := absolute(l.Fetch)
	if err != nil {
		return err
	}
	cache := s.cache(l)
	if cache != "" {
		if err := os.MkdirAll(cache, 0o755); err != nil {
			return fmt.Errorf("dependency cache: %w", err)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, fetchWait)
	defer cancel()

	cmd := jail.Fetch(ctx, jail.Spec{
		Root:  s.cfg.Stage,
		Work:  dir,
		Dir:   filepath.Join(dir, filepath.FromSlash(mod)),
		Read:  append(append([]string{}, toolchainRead...), proxyDirs(s.cfg.Proxy)...),
		Write: []string{cache},
		Argv:  argv,
		Env:   s.env(l, l.FetchEnv),
		Limits: jail.Limits{
			AddrMiB: 4096, CPU: 900, FsizeMiB: 2048,
			Nofile: 1024, Nproc: 128, TmpMiB: 512,
		},
	})
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", strings.Join(l.Fetch, " "), err, trim(string(out), 512))
	}
	return nil
}

// serve starts l's language server over the root, in a jail with no socket.
//
// The PROCESS is tied to context.Background(), not to ctx: a server outlives the
// request that warmed it, which is the entire point of the pool. ctx still bounds
// the HANDSHAKE, so a server that never finishes initializing does not hold a
// request open forever.
func (s *Service) serve(ctx context.Context, l Lang, dir string) (*Conn, error) {
	argv, err := absolute(l.Start)
	if err != nil {
		return nil, err
	}
	read := append(append([]string{}, toolchainRead...), s.cache(l))
	cmd := jail.Serve(context.Background(), jail.Spec{
		Root: s.cfg.Stage,
		Work: dir,
		Read: read,
		Argv: argv,
		Env:  s.env(l, l.ServeEnv),
		Limits: jail.Limits{
			// No CPU ceiling: RLIMIT_CPU is total seconds, and on a warm server
			// that is a scheduled death. The bound on a runaway server is the
			// pod's cgroup and the idle TTL.
			AddrMiB: 6144, FsizeMiB: 256,
			Nofile: 4096, Nproc: 256, TmpMiB: 2048,
		},
	})
	return attach(ctx, cmd, l, dir)
}

// env is the environment a jailed toolchain process runs under. It is BUILT,
// never inherited: this daemon holds the service key, and a language server is a
// third-party binary parsing tenant source — the two must not meet.
func (s *Service) env(l Lang, phase []string) []string {
	expand := func(v string) string {
		return os.Expand(v, func(name string) string {
			switch name {
			case "cache":
				return s.cache(l)
			case "proxy":
				return s.cfg.Proxy
			case "sumdb":
				return s.cfg.Sumdb
			}
			return ""
		})
	}
	out := []string{
		"PATH=" + toolPATH(),
		"HOME=/tmp",
		"TMPDIR=/tmp",
		"LANG=C.UTF-8",
		// A toolchain that shells out to git must not be able to prompt, to read
		// an inherited credential helper, or to follow an insteadOf rewrite.
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
	}
	for _, v := range append(append([]string{}, l.Env...), phase...) {
		out = append(out, expand(v))
	}
	return out
}

// proxyDirs are the directories a file:// GOPROXY names, to be bound read-only
// into the fetch jail.
//
// Without them a file:// proxy is a configuration the daemon ACCEPTS and can
// never read: the jail binds an allow-list of host paths, the proxy is not on
// it, and `go mod download` reports a module that does not exist. That is a real
// deployment — an air-gapped mirror on a PVC — and it is also what the hermetic
// acceptance test uses, which is why that test could only ever pass unjailed.
//
// GOPROXY is a comma-separated list and may name several.
func proxyDirs(goproxy string) []string {
	var out []string
	for _, p := range strings.Split(goproxy, ",") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(p), "file://"); ok && rest != "" {
			out = append(out, filepath.FromSlash(rest))
		}
	}
	return out
}

// absolute resolves argv[0] on PATH here, in the parent, where PATH means
// something. Inside the jail there is no shell and no lookup: execve is given a
// path or it fails.
func absolute(argv []string) ([]string, error) {
	if len(argv) == 0 {
		return nil, errors.New("empty argv")
	}
	bin, err := exec.LookPath(argv[0])
	if err != nil {
		return nil, fmt.Errorf("%s not installed: %w", argv[0], err)
	}
	out := append([]string{bin}, argv[1:]...)
	return out, nil
}

// ── materializing the tree ───────────────────────────────────────────────────

// File is one file of the tree the caller sends. Content is the whole file: this
// daemon holds no git credential and makes no git request, so the caller — which
// already has the repository — is the only thing that can produce the tree. That
// is deliberate: a daemon that could fetch a repository would need a credential
// that could reach every repository.
type File struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// materialize writes the tree into dir and returns the paths it wrote.
//
// Every path is narrowed BEFORE anything is created, and every file is created
// with O_EXCL|O_NOFOLLOW into a directory this function made itself. No symlink
// is ever created, so no later step can be walked out of the tree through one;
// combined with the chroot, a path outside the root is not reachable rather than
// refused.
func materialize(dir string, files []File) ([]string, error) {
	if len(files) == 0 {
		return nil, errors.New("a tree needs at least one file")
	}
	if len(files) > fileMost {
		return nil, fmt.Errorf("tree has %d files, at most %d", len(files), fileMost)
	}
	total := 0
	paths := make([]string, 0, len(files))
	for _, f := range files {
		rel, err := narrow(f.Path)
		if err != nil {
			return nil, err
		}
		if total += len(f.Content); total > byteMost {
			return nil, fmt.Errorf("tree exceeds %d bytes", byteMost)
		}
		abs := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
			return nil, fmt.Errorf("%s: %w", rel, err)
		}
		fh, err := os.OpenFile(abs, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", rel, err)
		}
		_, werr := fh.WriteString(f.Content)
		if cerr := fh.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return nil, fmt.Errorf("%s: %w", rel, werr)
		}
		paths = append(paths, rel)
	}
	return paths, nil
}

// narrow reduces a caller's path to a slash-separated tree-relative one, or
// refuses it. It is lexical and total: absolute paths, parent traversal, NUL,
// and absurd depth are all named here rather than discovered later.
func narrow(p string) (string, error) {
	if p == "" {
		return "", errors.New("empty path")
	}
	if strings.ContainsRune(p, 0) {
		return "", errors.New("path contains NUL")
	}
	if strings.HasPrefix(p, "/") || filepath.IsAbs(p) {
		return "", fmt.Errorf("%s: path must be tree-relative", p)
	}
	// filepath.Clean on a slash path: the tree's wire format is slashes, and the
	// daemon runs on Linux, so this is one conversion and not two spellings.
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(p)))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("%s: path escapes the tree", p)
	}
	if strings.Count(clean, "/") > depthMost {
		return "", fmt.Errorf("%s: path is deeper than %d", p, depthMost)
	}
	return clean, nil
}

// clean narrows a tree-relative path to a location PROVEN to be inside dir, and
// returns it under DIR'S OWN SPELLING.
//
// Two different jobs, and they need two different paths. The PROOF is done on the
// resolved path, and that is the part that matters: refusing ".." is not
// sufficient, because a tree is tenant content that a dependency fetch writes
// into, so a link could exist that names /etc, a KMS mount, or another org's
// directory one level up. Only resolving and then proving containment refuses
// that — lexical checks first, since they refuse the cheap attacks without a
// syscall, then EvalSymlinks, then containment.
//
// What is RETURNED is the unresolved join, because that path is about to become a
// file: URI sent to a language server that was rooted at dir. A server told its
// root is /var/x and then handed a document at /private/var/x does not consider
// the document to be in its workspace, and answers null to every question about
// it — which is not an error anywhere, just a service that never works. The
// spelling has to match the root's, so it is the root's.
func clean(dir, p string) (string, error) {
	rel, err := narrow(p)
	if err != nil {
		return "", err
	}
	root, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", fmt.Errorf("resolve root: %w", err)
	}
	abs, err := filepath.EvalSymlinks(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		return "", errors.New("no such file in the tree")
	}
	if abs != root && !strings.HasPrefix(abs, root+string(filepath.Separator)) {
		return "", errors.New("path escapes the tree")
	}
	if info, err := os.Stat(abs); err != nil || info.IsDir() {
		return "", errors.New("no such file in the tree")
	}
	return filepath.Join(dir, filepath.FromSlash(rel)), nil
}

func trim(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
