package lsp

// http.go is the door: three POSTs and two probes.
//
// The shape follows from roots being immutable and expensive. A caller cannot
// ask a question about a tree the daemon does not hold, and the daemon cannot go
// and get one — it has no git credential and no reason to have one. So /ask
// answers 409 {"need":"tree"} and the caller, which already has the repository,
// sends it to /root and asks again. Two calls on a cold root, one on a warm one,
// and no path by which this daemon reaches out to anything.

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/hanzoai/lsp/internal/jail"
)

// diagSettle is how long diagnostics must stay unchanged before the snapshot is
// taken. See Conn.Diagnostics — LSP has no completion signal for them.
const diagSettle = 400 * time.Millisecond

// bodyMost bounds a request body. /root carries a whole tree, so the cap is the
// tree cap plus the room JSON escaping needs.
const bodyMost = byteMost + (32 << 20)

// Service is the daemon.
type Service struct {
	cfg  Config
	key  string
	log  *slog.Logger
	pool *pool

	// cold bounds how many roots are built at once. A cold start is a dependency
	// fetch and a language server's first index, which is where all the memory
	// and all the CPU are.
	cold chan struct{}

	// ready is the jail's verdict, and it is why /readyz can be believed. On
	// Linux it is set only after Probe watched a served process be refused a
	// socket; when it is false every request that would run anything is refused.
	ready atomic.Bool
	why   atomic.Pointer[string]
}

// New builds the daemon. key is the shared service key the caller presents; an
// empty key fails every guarded route closed.
func New(cfg Config, key string, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	return &Service{
		cfg:  cfg,
		key:  strings.TrimSpace(key),
		log:  log,
		pool: newPool(),
		cold: make(chan struct{}, coldMost),
	}
}

// Prove runs the jail's boot self-test and decides whether this daemon may serve.
//
// On Linux the jail is REQUIRED: a pod without the gVisor runtime class, or one
// where the namespaces cannot be created, fails here and then refuses every
// request. That is the fail-closed spine, and it has no override — there is no
// environment variable that turns the jail off, so there is none that can be set
// by accident on the thing that matters.
//
// Off Linux there is no jail to require. The image is linux/amd64, so that case
// is a developer's machine; it is loud in the log and visible on /readyz.
func (s *Service) Prove(ctx context.Context) {
	if !jail.Supported() {
		s.log.Warn("NO JAIL ON THIS PLATFORM — development only. " +
			"Language servers will run unconfined: never do this anywhere real.")
		s.note("unjailed: this platform has no namespaces")
		s.ready.Store(true)
		return
	}
	if err := jail.Probe(ctx, s.cfg.Stage+"/probe", s.cfg.Stage); err != nil {
		s.log.Error("JAIL SELF-TEST FAILED — refusing every request", "err", err)
		s.note("jail did not initialize: " + err.Error())
		s.ready.Store(false)
		return
	}
	s.log.Info("jail proven on this host",
		"boundary", "gVisor + userns + minimal chroot + seccomp(socket denied when serving) + rlimits")
	s.note("jailed")
	s.ready.Store(true)
}

func (s *Service) note(v string) { s.why.Store(&v) }

func (s *Service) status() string {
	if v := s.why.Load(); v != nil {
		return *v
	}
	return "not yet probed"
}

// Close releases every live root and its servers.
func (s *Service) Close() { s.pool.closeAll() }

// Routes is the whole surface. The stdlib router does method and wildcards, so
// there is no third-party mux in a process whose dependency count is the point.
func (s *Service) Routes() http.Handler {
	mux := http.NewServeMux()
	// The probes are unauthenticated: they are the kubelet's, and they disclose
	// nothing a caller could not learn by connecting.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", s.handleReady)

	mux.Handle("POST /root", s.guard(http.HandlerFunc(s.handleRoot)))
	mux.Handle("POST /root/warm", s.guard(http.HandlerFunc(s.handleWarm)))
	mux.Handle("POST /ask", s.guard(http.HandlerFunc(s.handleAsk)))
	return mux
}

// guard is the constant-time shared-key check, and it fails CLOSED twice over:
// an unset key means the daemon is misconfigured, which is a 503 and not an open
// door; a wrong key is a 401 that took the same time to compute as a right one.
//
// This is authorization to REACH the daemon, not authentication of a tenant. The
// caller behind this key is the cloud API, and it is what turns a user into the
// org this daemon isolates by.
func (s *Service) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.key == "" {
			writeErr(w, http.StatusServiceUnavailable, "daemon not configured")
			return
		}
		got := strings.TrimSpace(r.Header.Get("X-API-Key"))
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.key)) != 1 {
			writeErr(w, http.StatusUnauthorized, "invalid api key")
			return
		}
		if !s.ready.Load() {
			writeErr(w, http.StatusServiceUnavailable, "sandbox unavailable")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Service) handleReady(w http.ResponseWriter, _ *http.Request) {
	code := http.StatusOK
	if !s.ready.Load() {
		code = http.StatusServiceUnavailable
	}
	writeJSON(w, code, map[string]any{
		"ready":  s.ready.Load(),
		"jail":   s.status(),
		"langs":  served(),
		"status": http.StatusText(code),
	})
}

// served is the languages this IMAGE can run — the table narrowed to the
// toolchains actually installed. It is what makes the table a claim the
// deployment keeps.
func served() []string {
	out := make([]string, 0, len(table))
	for _, name := range names {
		if table[name].Available() {
			out = append(out, name)
		}
	}
	return out
}

// ── /root ────────────────────────────────────────────────────────────────────

// Tree is the body of /root: a whole working tree, sent by the caller.
type Tree struct {
	Org   string `json:"org"`
	Repo  string `json:"repo"`
	Rev   string `json:"rev"`
	Files []File `json:"files"`
}

// Ready is what /root answers.
type Ready struct {
	Ready bool     `json:"ready"`
	Cold  bool     `json:"cold"`
	Langs []string `json:"langs"`
}

func (s *Service) handleRoot(w http.ResponseWriter, r *http.Request) { s.root(w, r, false) }

// handleWarm is /root with one extra rule: it is only accepted when this org
// already holds a root for this repo.
//
// Warming a revision nobody has asked about is work the caller has not paid for,
// and an unguarded door for it is a way to make this daemon fetch and index
// anything. Requiring a live root for the same repository means a warm request
// can only ever follow a cold start the caller already paid for.
func (s *Service) handleWarm(w http.ResponseWriter, r *http.Request) { s.root(w, r, true) }

func (s *Service) root(w http.ResponseWriter, r *http.Request, warm bool) {
	var in Tree
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	k, err := keyOf(in.Org, in.Repo, in.Rev)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if warm && !s.pool.holds(k.org, k.repo) {
		writeJSON(w, http.StatusConflict, map[string]any{
			"need": "held", "org": k.org, "repo": k.repo,
			"error": "warming is only accepted for a repository that already has a live root",
		})
		return
	}

	root, cold, err := s.open(r.Context(), k, in.Files)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			writeErr(w, http.StatusGatewayTimeout, "root build timed out")
			return
		}
		s.log.Warn("root build failed", "org", k.org, "repo", k.repo, "err", err)
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, Ready{Ready: true, Cold: cold, Langs: root.Langs()})
}

// open returns the live root for k, building it from files if it is not held.
// The bool reports a COLD start: the tree write, the dependency fetch and each
// server's first index.
func (s *Service) open(ctx context.Context, k key, files []File) (*Root, bool, error) {
	root, mine := s.pool.claim(k)
	if !mine {
		select {
		case <-root.ready:
		case <-ctx.Done():
			return nil, false, ctx.Err()
		}
		return root, false, root.err
	}

	// Bound how many cold starts run at once. Excess requests WAIT — a cold start
	// is minutes of a dependency fetch and an index, and letting them pile up is
	// how one pod OOMs for everybody.
	select {
	case s.cold <- struct{}{}:
		defer func() { <-s.cold }()
	case <-ctx.Done():
		s.pool.settle(root, nil, ctx.Err())
		return nil, true, ctx.Err()
	}

	built, err := s.build(ctx, k, files)
	s.pool.settle(root, built, err)
	if err != nil {
		return nil, true, err
	}
	return root, true, nil
}

// ── /ask ─────────────────────────────────────────────────────────────────────

// Ask is one question about one position in one root.
type Ask struct {
	Org  string `json:"org"`
	Repo string `json:"repo"`
	Rev  string `json:"rev"`

	// Op is hover, locate, symbols, diagnostics or complete.
	Op string `json:"op"`
	// Relation refines locate: definition, reference, type or implementation.
	Relation string `json:"relation,omitempty"`

	// Path is tree-relative.
	Path string `json:"path"`
	// Line is 0-based, per the LSP specification.
	Line int `json:"line"`
	// Character is a 0-based UTF-16 code-unit offset within Line, per the LSP
	// specification — not a byte offset and not a rune index.
	Character int `json:"character"`
}

// Answer carries whichever result the op produces. Exactly one result field is
// populated, so a client reads the field its op names and never discriminates a
// union.
type Answer struct {
	Op   string `json:"op"`
	Lang string `json:"lang"`

	Locations   []Location   `json:"locations,omitempty"`
	Hover       string       `json:"hover,omitempty"`
	Symbols     []Symbol     `json:"symbols,omitempty"`
	Completions []Completion `json:"completions,omitempty"`
	Diagnostics []Diagnostic `json:"diagnostics,omitempty"`
}

// ops and relations are CLOSED sets. The door names what it serves, so an
// unknown string is a 400 here rather than an arbitrary method handed to a
// language server.
var (
	ops       = []string{"hover", "locate", "symbols", "diagnostics", "complete"}
	relations = []string{"definition", "reference", "type", "implementation"}
)

func (s *Service) handleAsk(w http.ResponseWriter, r *http.Request) {
	var in Ask
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	k, err := keyOf(in.Org, in.Repo, in.Rev)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !slices.Contains(ops, in.Op) {
		writeErr(w, http.StatusBadRequest, "op must be one of "+strings.Join(ops, ", "))
		return
	}
	if in.Op == "locate" && !slices.Contains(relations, in.Relation) {
		writeErr(w, http.StatusBadRequest, "locate needs a relation: "+strings.Join(relations, ", "))
		return
	}
	if in.Line < 0 || in.Character < 0 {
		writeErr(w, http.StatusBadRequest, "line and character are 0-based and cannot be negative")
		return
	}

	root, held, err := s.pool.hold(r.Context(), k)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "root unavailable")
		return
	}
	if held {
		defer root.release()
	} else {
		// The daemon holds no credential and makes no git request, so it cannot
		// go and get the tree. The caller has it; this says so precisely.
		writeJSON(w, http.StatusConflict, map[string]any{
			"need": "tree", "org": k.org, "repo": k.repo, "rev": k.rev,
			"error": "no root for this revision — POST /root with the tree, then ask again",
		})
		return
	}

	l, ok := langOf(root, in.Path)
	if !ok {
		writeErr(w, http.StatusBadRequest, "no language server in this image answers for "+in.Path)
		return
	}
	abs, err := clean(root.dir, in.Path)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	uri, err := l.conn.Open(l.lang, abs)
	if err != nil {
		s.log.Warn("didOpen failed", "org", k.org, "repo", k.repo, "err", err)
		writeErr(w, http.StatusBadGateway, "language server did not accept the document")
		return
	}

	out, err := resolve(r.Context(), root, l, uri, &in)
	if err != nil {
		s.log.Warn("query failed", "org", k.org, "repo", k.repo, "op", in.Op, "err", err)
		writeErr(w, http.StatusBadGateway, "language server did not answer")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// langOf picks the live server that answers for path.
func langOf(r *Root, path string) (*live, bool) {
	l, ok := langFor(path)
	if !ok {
		return nil, false
	}
	got := r.langs[l.Name]
	return got, got != nil
}

// resolve asks the server the one question and folds the reply into an Answer.
//
// diagnostics is the outlier and is handled first: it is not a request at all in
// LSP but an unsolicited notification the server publishes after didOpen, so it
// is collected rather than called.
func resolve(ctx context.Context, r *Root, l *live, uri string, in *Ask) (*Answer, error) {
	ctx, cancel := context.WithTimeout(ctx, callWait)
	defer cancel()

	out := &Answer{Op: in.Op, Lang: l.lang.Name}
	if in.Op == "diagnostics" {
		out.Diagnostics = l.conn.Diagnostics(ctx, uri, diagSettle)
		if out.Diagnostics == nil {
			out.Diagnostics = []Diagnostic{}
		}
		return out, nil
	}

	doc := map[string]any{"uri": uri}
	params := map[string]any{
		"textDocument": doc,
		"position":     map[string]any{"line": in.Line, "character": in.Character},
	}
	var method string
	switch in.Op {
	case "hover":
		method = "textDocument/hover"
	case "complete":
		method = "textDocument/completion"
	case "symbols":
		method = "textDocument/documentSymbol"
		params = map[string]any{"textDocument": doc} // no position: the whole file
	case "locate":
		switch in.Relation {
		case "definition":
			method = "textDocument/definition"
		case "type":
			method = "textDocument/typeDefinition"
		case "implementation":
			method = "textDocument/implementation"
		case "reference":
			method = "textDocument/references"
			params["context"] = map[string]any{"includeDeclaration": true}
		}
	}

	raw, err := l.conn.Call(ctx, method, params)
	if err != nil {
		return nil, err
	}
	// A null result is not an error: "nothing here" is a real answer and it
	// arrives as JSON null. Every branch leaves the field empty rather than
	// failing, so a caller tells "nothing found" from "the server broke" by
	// status code and not by guesswork.
	if len(raw) == 0 || string(raw) == "null" {
		return out, nil
	}
	switch in.Op {
	case "hover":
		out.Hover = hover(raw)
	case "symbols":
		out.Symbols = symbols(raw)
	case "complete":
		out.Completions = completions(raw)
	case "locate":
		out.Locations = locations(raw, r.dirs, l.deps)
	}
	return out, nil
}

// ── narrowing the key ────────────────────────────────────────────────────────

var (
	// org and repo are path segments under the daemon's data directory, so they
	// carry no slash and no leading dot: a key cannot climb out of its own tenant
	// or name another one.
	orgRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	repoRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,99}$`)
	// rev is a RESOLVED commit and nothing else. That single rule is what makes a
	// root immutable, and therefore what removes cache invalidation from this
	// service: a branch name would move, a sha never does. The caller resolves
	// refs; it is the one that has the repository.
	revRe = regexp.MustCompile(`^[0-9a-f]{40}$|^[0-9a-f]{64}$`)
)

func keyOf(org, repo, rev string) (key, error) {
	k := key{
		org:  strings.TrimSpace(org),
		repo: strings.TrimSpace(repo),
		rev:  strings.ToLower(strings.TrimSpace(rev)),
	}
	switch {
	case !orgRe.MatchString(k.org):
		return key{}, errors.New("org must be a lowercase slug")
	case !repoRe.MatchString(k.repo):
		return key{}, errors.New("repo must be a repository name")
	case !revRe.MatchString(k.rev):
		return key{}, errors.New("rev must be a resolved commit sha (40 or 64 hex digits)")
	}
	return k, nil
}

// ── small helpers ────────────────────────────────────────────────────────────

func decode(r *http.Request, v any) error {
	return json.NewDecoder(http.MaxBytesReader(nil, r.Body, bodyMost)).Decode(v)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeErr answers with a message chosen HERE. A language server's own error text
// echoes tenant source and this daemon's paths, so it goes to the log and never
// to the wire.
func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"status": status, "error": msg})
}
