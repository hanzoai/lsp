// Package lsp is the daemon: immutable roots, a live language server per root,
// and five questions you can ask one.
//
// # What this exists to answer that an index cannot
//
// A static symbol index knows what a repository says about itself. It does not
// know what `dep.Greet` resolves to, because the answer is in a module the
// repository only NAMES. Resolving that means fetching the dependency and
// running a real type-checker over both — which means running a third-party
// binary over untrusted bytes, which is why this is a separate daemon behind a
// jail and not a library inside the API.
//
// So the one answer that justifies the whole service is a Location with
// External true: a definition that left the repository and landed in the
// dependency cache.
//
// # Roots are immutable
//
// A root is (org, repo, rev) where rev is a resolved commit — 40 or 64 hex
// digits, never a branch name. That is the entire cache-invalidation design: a
// sha names one tree for all time, so a root can never be stale, a push is
// simply a different key, and there is no subsystem that decides when to throw
// anything away. The caller resolves refs; this daemon only knows revisions.
//
// # Positions are the protocol's
//
// line and character are 0-BASED, and character counts UTF-16 code units, per
// the LSP specification. That is deliberately not the 1-based line an editor
// shows a human: the callers here already speak LSP, and a service that
// silently re-based positions would corrupt every line containing a multi-byte
// character — an emoji before the cursor is one UTF-16 unit in the protocol's
// arithmetic and two in Go's. Positions pass through untouched.
//
// # Isolation, and who does it
//
// This daemon does not AUTHENTICATE anyone. It holds one shared key, and the
// caller behind it — the cloud API — is what turns a user into an org. What this
// daemon does is ISOLATE: org is the first segment of every root key and every
// root path, so two tenants naming the same repo at the same revision get two
// roots, two directories and two servers, and no warm server is ever handed
// across the boundary.
package lsp

import (
	"encoding/json"
	"path/filepath"
	"strings"
)

// Position is the LSP's: 0-based line, 0-based UTF-16 character.
type Position struct {
	Line      int `json:"line"`
	Character int `json:"character"`
}

// Range is a half-open span between two positions.
type Range struct {
	Start Position `json:"start"`
	End   Position `json:"end"`
}

// Location is one place a question resolved to.
//
// External is the field the service exists for. False means Path is
// repo-relative — a place in the caller's own tree. True means the answer left
// the repository, and Path is then the module coordinate it landed in
// ("golang.org/x/mod@v0.14.0/semver/semver.go"): the dependency cache's own
// layout, which names the module, its version and the file, and which leaks no
// path belonging to this daemon.
type Location struct {
	Path     string `json:"path"`
	External bool   `json:"external,omitempty"`
	Range    Range  `json:"range"`
}

// Symbol is one entry in a file's outline.
type Symbol struct {
	Name   string `json:"name"`
	Kind   int    `json:"kind"`
	Detail string `json:"detail,omitempty"`
	Range  Range  `json:"range"`
}

// Completion is one candidate at a position.
type Completion struct {
	Label  string `json:"label"`
	Kind   int    `json:"kind,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// Diagnostic is one problem a server reported. Severity is the LSP's: 1 error,
// 2 warning, 3 information, 4 hint.
type Diagnostic struct {
	Range    Range  `json:"range"`
	Severity int    `json:"severity,omitempty"`
	Code     any    `json:"code,omitempty"`
	Source   string `json:"source,omitempty"`
	Message  string `json:"message"`
}

// ── placing an answer ────────────────────────────────────────────────────────

// place turns an absolute path a language server reported into the pair a caller
// can use: a name, and whether that name left the repository.
//
// roots and deps are each given in EVERY spelling they have. A server reports
// paths as the OS handed them to it, and a directory reached through a symlink —
// /var → /private/var on a Mac, a mounted volume in the cluster — gives one file
// two absolute names. Comparing one spelling against the other puts every answer
// "outside" the tree, and the caller then receives this daemon's own filesystem
// layout for files that were in their own repository all along.
//
// This is presentation. The security boundary is the chroot the server runs in
// and [clean], which proves a REQUESTED path is inside the tree.
func place(abs string, roots, deps []string) (string, bool) {
	if abs == "" {
		return "", false
	}
	if rel, ok := under(abs, roots); ok {
		return rel, false
	}
	if rel, ok := under(abs, deps); ok {
		return rel, true
	}
	// Outside both. Under the jail there is nowhere else to be, so this is the
	// unjailed development path; report it honestly rather than pretend.
	return abs, true
}

func under(abs string, dirs []string) (string, bool) {
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		rel, err := filepath.Rel(dir, abs)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		return filepath.ToSlash(rel), true
	}
	return "", false
}

// spellings returns every absolute name dir has: the one given, and the one with
// symlinks resolved when they differ.
func spellings(dir string) []string {
	out := []string{dir}
	if resolved, err := filepath.EvalSymlinks(dir); err == nil && resolved != dir {
		out = append(out, resolved)
	}
	return out
}

// ── decoding what a server answered ──────────────────────────────────────────

// locations decodes the three shapes a location-returning request may answer
// with: a single Location, an array of them, or an array of LocationLink (the
// linkSupport form, whose target range lives under different keys). All three
// are in the specification and gopls, rust-analyzer and tsserver do not agree on
// which to send, so all three are read.
func locations(raw json.RawMessage, roots, deps []string) []Location {
	var many []struct {
		URI       string `json:"uri"`
		Range     Range  `json:"range"`
		TargetURI string `json:"targetUri"`
		Target    Range  `json:"targetSelectionRange"`
	}
	if json.Unmarshal(raw, &many) != nil {
		var one struct {
			URI   string `json:"uri"`
			Range Range  `json:"range"`
		}
		if json.Unmarshal(raw, &one) != nil || one.URI == "" {
			return []Location{}
		}
		path, ext := place(uriPath(one.URI), roots, deps)
		return []Location{{Path: path, External: ext, Range: one.Range}}
	}

	out := make([]Location, 0, len(many))
	for _, m := range many {
		uri, rng := m.URI, m.Range
		if uri == "" { // a LocationLink
			uri, rng = m.TargetURI, m.Target
		}
		p := uriPath(uri)
		if p == "" {
			continue // a jar: or zipfile: target names no path of ours
		}
		path, ext := place(p, roots, deps)
		out = append(out, Location{Path: path, External: ext, Range: rng})
	}
	return out
}

// hover decodes MarkupContent, a MarkedString, or an array of either.
func hover(raw json.RawMessage) string {
	var h struct {
		Contents json.RawMessage `json:"contents"`
	}
	if json.Unmarshal(raw, &h) != nil || len(h.Contents) == 0 {
		return ""
	}
	var markup struct {
		Value string `json:"value"`
	}
	if json.Unmarshal(h.Contents, &markup) == nil && markup.Value != "" {
		return markup.Value
	}
	var plain string
	if json.Unmarshal(h.Contents, &plain) == nil {
		return plain
	}
	var list []json.RawMessage
	if json.Unmarshal(h.Contents, &list) != nil {
		return ""
	}
	parts := make([]string, 0, len(list))
	for _, item := range list {
		if json.Unmarshal(item, &markup) == nil && markup.Value != "" {
			parts = append(parts, markup.Value)
			continue
		}
		if json.Unmarshal(item, &plain) == nil && plain != "" {
			parts = append(parts, plain)
		}
	}
	return strings.Join(parts, "\n\n")
}

// symbols decodes DocumentSymbol or SymbolInformation, which carry the range
// under different keys.
func symbols(raw json.RawMessage) []Symbol {
	var list []struct {
		Name     string `json:"name"`
		Kind     int    `json:"kind"`
		Detail   string `json:"detail"`
		Range    Range  `json:"range"`
		Location struct {
			Range Range `json:"range"`
		} `json:"location"`
	}
	if json.Unmarshal(raw, &list) != nil {
		return []Symbol{}
	}
	out := make([]Symbol, 0, len(list))
	for _, s := range list {
		rng := s.Range
		if rng == (Range{}) {
			rng = s.Location.Range
		}
		out = append(out, Symbol{Name: s.Name, Kind: s.Kind, Detail: s.Detail, Range: rng})
	}
	return out
}

// completions decodes CompletionList or a bare CompletionItem array, and bounds
// the reply: a server offering every identifier in a large dependency tree can
// answer with tens of thousands of items, which is not an answer anybody reads.
func completions(raw json.RawMessage) []Completion {
	const most = 200
	type item struct {
		Label  string `json:"label"`
		Kind   int    `json:"kind"`
		Detail string `json:"detail"`
	}
	var list struct {
		Items []item `json:"items"`
	}
	var items []item
	if json.Unmarshal(raw, &list) == nil && list.Items != nil {
		items = list.Items // CompletionList
	} else if json.Unmarshal(raw, &items) != nil {
		return []Completion{} // neither shape
	}
	if len(items) > most {
		items = items[:most]
	}
	out := make([]Completion, 0, len(items))
	for _, i := range items {
		out = append(out, Completion{Label: i.Label, Kind: i.Kind, Detail: i.Detail})
	}
	return out
}
