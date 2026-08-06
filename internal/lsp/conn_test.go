package lsp

// conn_test.go drives the real client against a FAKE language server.
//
// PORTED from hanzoai/cloud branch `lsp` (apps/lsp/server_test.go, 67975187),
// including the two regressions it pins: Close hanging on a wedged server, and a
// frame reader that would allocate whatever Content-Length it was told.
//
// The fake speaks the actual wire protocol — Content-Length framing, JSON-RPC 2.0
// — over an in-process pipe, so these tests need no gopls, no toolchain and no
// network, and still exercise the same code attach hands a real subprocess.
// newConn is what makes that possible; nothing here reimplements the client under
// test.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fake is a language server: it records the methods it is asked, in order, and
// answers from a table of canned replies.
type fake struct {
	mu   sync.Mutex
	seen []string

	reply map[string]any // method → result
	// push, when set, is published as a diagnostics notification after didOpen,
	// which is how a real server delivers them: unsolicited, not as a response.
	push map[string]any
}

// serve reads frames from r and writes answers to w until r closes.
func (f *fake) serve(r io.Reader, w io.WriteCloser) {
	defer w.Close()
	br := bufio.NewReader(r)
	for {
		body, err := readFrame(br)
		if err != nil {
			return
		}
		var m struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if json.Unmarshal(body, &m) != nil {
			continue
		}

		f.mu.Lock()
		f.seen = append(f.seen, m.Method)
		f.mu.Unlock()

		if m.Method == "exit" {
			return
		}
		if len(m.ID) > 0 { // a request: answer it
			result, ok := f.reply[m.Method]
			if !ok {
				result = map[string]any{}
			}
			f.write(w, map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": result})
		}
		if m.Method == "textDocument/didOpen" && f.push != nil {
			f.write(w, map[string]any{
				"jsonrpc": "2.0",
				"method":  "textDocument/publishDiagnostics",
				"params":  f.push,
			})
		}
	}
}

func (f *fake) write(w io.Writer, v any) {
	b, _ := json.Marshal(v)
	fmt.Fprintf(w, "Content-Length: %d\r\n\r\n", len(b))
	w.Write(b)
}

func (f *fake) methods() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.seen...)
}

// dial puts a Conn on a fake over two pipes.
func dial(t *testing.T, f *fake) *Conn {
	t.Helper()
	toServer, fromClient := io.Pipe()
	toClient, fromServer := io.Pipe()
	go f.serve(toServer, fromServer)

	c := newConn(fromClient, toClient, func() {})
	t.Cleanup(c.Close)
	return c
}

// sample writes a file into a temp dir and returns the dir and the abs path.
func sample(t *testing.T, name, body string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	abs := filepath.Join(dir, name)
	if err := os.WriteFile(abs, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return dir, abs
}

// TestDefinitionDrivesTheProtocol is the core claim: given a position, the client
// performs initialize → initialized → didOpen → definition, in that order, and
// parses the Location the server answered with.
func TestDefinitionDrivesTheProtocol(t *testing.T) {
	dir, abs := sample(t, "main.go", "package main\n\nfunc main() {}\n")
	target := filepath.Join(dir, "other.go")

	f := &fake{reply: map[string]any{
		"initialize": map[string]any{"capabilities": map[string]any{}},
		"textDocument/definition": []any{map[string]any{
			"uri": pathURI(target),
			"range": map[string]any{
				"start": map[string]any{"line": 41, "character": 8},
				"end":   map[string]any{"line": 41, "character": 16},
			},
		}},
	}}
	c := dial(t, f)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	l := table["go"]
	if err := c.handshake(ctx, l, dir); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	uri, err := c.Open(l, abs)
	if err != nil {
		t.Fatalf("didOpen: %v", err)
	}
	raw, err := c.Call(ctx, "textDocument/definition", map[string]any{
		"textDocument": map[string]any{"uri": uri},
		"position":     map[string]any{"line": 2, "character": 5},
	})
	if err != nil {
		t.Fatalf("definition: %v", err)
	}

	// The ORDER is the contract: a server asked before initialize completes is
	// entitled to refuse, and one asked about a document it was never told about
	// answers null.
	want := []string{"initialize", "initialized", "textDocument/didOpen", "textDocument/definition"}
	got := f.methods()
	if len(got) != len(want) {
		t.Fatalf("methods = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("method %d = %q, want %q", i, got[i], want[i])
		}
	}

	locs := locations(raw, spellings(dir), nil)
	if len(locs) != 1 {
		t.Fatalf("locations = %d, want 1", len(locs))
	}
	if locs[0].Path != "other.go" || locs[0].External {
		t.Errorf("location = %+v, want other.go inside the tree", locs[0])
	}
	// Positions pass through untouched — 0-based line, 0-based UTF-16 character.
	if locs[0].Range.Start.Line != 41 || locs[0].Range.Start.Character != 8 {
		t.Errorf("start = %+v, want {41 8} (LSP positions must not be re-based)", locs[0].Range.Start)
	}
}

// TestServerRequestIsAnswered pins the deadlock this client is built to avoid: a
// server→client request (workspace/configuration, client/registerCapability)
// BLOCKS the server until it is answered. A client that only reads responses
// hangs here.
func TestServerRequestIsAnswered(t *testing.T) {
	toServer, fromClient := io.Pipe()
	toClient, fromServer := io.Pipe()

	answered := make(chan struct{})
	go func() {
		defer fromServer.Close()
		br := bufio.NewReader(toServer)
		f := &fake{}
		// Read the client's initialize, then turn around and ASK it something
		// before answering — exactly what rust-analyzer does.
		body, err := readFrame(br)
		if err != nil {
			return
		}
		var m struct {
			ID json.RawMessage `json:"id"`
		}
		json.Unmarshal(body, &m)
		f.write(fromServer, map[string]any{
			"jsonrpc": "2.0", "id": 9001, "method": "client/registerCapability",
			"params": map[string]any{"registrations": []any{}},
		})
		if _, err := readFrame(br); err != nil { // the client's reply
			return
		}
		close(answered)
		f.write(fromServer, map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": map[string]any{}})
		for {
			if _, err := readFrame(br); err != nil {
				return
			}
		}
	}()

	c := newConn(fromClient, toClient, func() {})
	t.Cleanup(c.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.handshake(ctx, table["go"], t.TempDir()); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	select {
	case <-answered:
	default:
		t.Fatal("client never answered the server's request — a real server would still be blocked")
	}
}

// TestDiagnosticsAreCollectedFromNotifications: diagnostics are published, not
// returned, so they only arrive if the reader routes notifications.
func TestDiagnosticsAreCollectedFromNotifications(t *testing.T) {
	dir, abs := sample(t, "main.go", "package main\n")
	uri := pathURI(abs)

	f := &fake{
		reply: map[string]any{"initialize": map[string]any{}},
		push: map[string]any{
			"uri": uri,
			"diagnostics": []any{map[string]any{
				"range": map[string]any{
					"start": map[string]any{"line": 0, "character": 0},
					"end":   map[string]any{"line": 0, "character": 7},
				},
				"severity": 1,
				"source":   "compiler",
				"message":  "undefined: x",
			}},
		},
	}
	c := dial(t, f)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	l := table["go"]
	if err := c.handshake(ctx, l, dir); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if _, err := c.Open(l, abs); err != nil {
		t.Fatalf("didOpen: %v", err)
	}

	got := c.Diagnostics(ctx, uri, 100*time.Millisecond)
	if len(got) != 1 {
		t.Fatalf("diagnostics = %d, want 1", len(got))
	}
	if got[0].Message != "undefined: x" || got[0].Severity != 1 {
		t.Errorf("diagnostic = %+v, want severity 1 'undefined: x'", got[0])
	}
}

// TestCallFailsWhenTheServerDies proves the client fails CLOSED: a dead server is
// an error, never a hang until the request's own deadline and never a silently
// empty answer that reads as "no definition found".
func TestCallFailsWhenTheServerDies(t *testing.T) {
	toServer, fromClient := io.Pipe()
	toClient, fromServer := io.Pipe()
	go func() {
		br := bufio.NewReader(toServer)
		readFrame(br)      // take the request
		fromServer.Close() // then die without answering
	}()

	c := newConn(fromClient, toClient, func() {})
	t.Cleanup(c.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := c.Call(ctx, "textDocument/hover", map[string]any{}); err == nil {
		t.Fatal("Call succeeded against a dead server")
	} else if ctx.Err() != nil {
		t.Fatalf("Call waited for its own deadline instead of noticing the server: %v", err)
	}
}

// TestCloseDoesNotHangOnAWedgedServer is the regression this suite found: Close
// used to write a polite `shutdown` unconditionally, and a server that had
// stopped reading its stdin left that write with nowhere to go — Close never
// returned, holding a pool slot and, at shutdown, the whole binary.
func TestCloseDoesNotHangOnAWedgedServer(t *testing.T) {
	toServer, fromClient := io.Pipe()
	toClient, fromServer := io.Pipe()
	// A server that reads NOTHING and answers nothing. Writes to it block.
	_ = toServer

	c := newConn(fromClient, toClient, func() {})

	done := make(chan struct{})
	go func() { defer close(done); c.Close() }()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("Close hung on a server that stopped reading its stdin")
	}
	fromServer.Close()
}

// TestFrameRejectsAnOversizeLength: Content-Length is attacker-influenced (a
// server parsing tenant source emits it), so an absurd one must be refused rather
// than allocated.
func TestFrameRejectsAnOversizeLength(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("Content-Length: 999999999999\r\n\r\n"))
	if _, err := readFrame(r); err == nil {
		t.Fatal("readFrame accepted a length past maxFrame")
	}
}

// TestFrameRejectsAMissingLength: a frame with no Content-Length has no boundary,
// so continuing to read desynchronizes the stream.
func TestFrameRejectsAMissingLength(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("Content-Type: application/vscode-jsonrpc\r\n\r\n"))
	if _, err := readFrame(r); err == nil {
		t.Fatal("readFrame accepted a frame with no Content-Length")
	}
}

// TestURIRoundTrip: paths with characters that must be escaped survive both
// directions, so a definition in a directory with a space is still findable.
func TestURIRoundTrip(t *testing.T) {
	for _, p := range []string{"/tmp/x/main.go", "/tmp/a b/c#d/main.go", "/tmp/100%/x.go"} {
		if got := uriPath(pathURI(p)); got != p {
			t.Errorf("round trip %q → %q", p, got)
		}
	}
	if got := uriPath("jar:file:///x.jar!/A.class"); got != "" {
		t.Errorf("non-file URI resolved to a path %q — it names nothing on our disk", got)
	}
}

// TestExternalIsWhatLeftTheTree pins the field this whole service exists for: a
// target inside the tree is repo-relative and internal, one inside the dependency
// cache is named by its module coordinate and marked external.
func TestExternalIsWhatLeftTheTree(t *testing.T) {
	tree := t.TempDir()
	deps := t.TempDir()
	raw := json.RawMessage(fmt.Sprintf(`[
	  {"uri":%q,"range":{"start":{"line":1,"character":2},"end":{"line":1,"character":7}}},
	  {"uri":%q,"range":{"start":{"line":3,"character":0},"end":{"line":3,"character":5}}}
	]`,
		pathURI(filepath.Join(tree, "pkg", "a.go")),
		pathURI(filepath.Join(deps, "example.com", "dep@v1.0.0", "dep.go"))))

	got := locations(raw, spellings(tree), spellings(deps))
	if len(got) != 2 {
		t.Fatalf("locations = %d, want 2", len(got))
	}
	if got[0].Path != "pkg/a.go" || got[0].External {
		t.Errorf("in-tree = %+v, want pkg/a.go internal", got[0])
	}
	if got[1].Path != "example.com/dep@v1.0.0/dep.go" || !got[1].External {
		t.Errorf("in-cache = %+v, want the module coordinate marked external", got[1])
	}
}
