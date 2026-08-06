package lsp

// conn.go is a JSON-RPC 2.0 client speaking the Language Server Protocol over a
// server's stdio: Content-Length framing, one multiplexed connection,
// initialize → didOpen → ask.
//
// PORTED from hanzoai/cloud branch `lsp` (apps/lsp/server.go, 67975187),
// unchanged in substance including its two fixes — the Close that used to hang on
// a wedged server, and the frame reader that refuses an oversize Content-Length.
// What changed is where the process comes from: there it spawned one itself, here
// it is handed an already-jailed *exec.Cmd, because building the jail is root.go's
// concern and speaking the protocol is this file's. Nothing here knows what a
// namespace is.
//
// The one structural decision: a SINGLE reader goroutine owns the stdout side and
// demultiplexes it. LSP is not request/response — a server interleaves responses,
// its own requests, and unsolicited notifications on the same stream, and
// diagnostics are only ever the third kind. Reading inline from Call drops every
// message that is not the response being waited for, which is why a client that
// does that cannot report diagnostics without a second read path. One reader,
// three destinations, no second path.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// maxFrame bounds one inbound message. A language server is a subprocess we
// spawned, but it is parsing a tenant's tree, and a hostile input that makes it
// emit an enormous frame must not become an allocation the pod dies on.
const maxFrame = 32 << 20 // 32 MiB

// Handshake, request and shutdown budgets. A cold gopls indexes before it
// answers, so initialize is generous where a point query is not.
const (
	initWait  = 120 * time.Second
	callWait  = 30 * time.Second
	closeWait = 3 * time.Second
)

// Conn is one live language server: a process (or, in a test, a pipe) plus the
// bookkeeping to route its stream. Safe for concurrent use — Call may be entered
// from several requests against the same warm root.
type Conn struct {
	w    io.WriteCloser
	stop func() // releases the transport (kills the process)

	wmu sync.Mutex // serializes frame writes; a torn frame desynchronizes the stream
	seq atomic.Int64

	mu   sync.Mutex
	wait map[int64]chan msg

	dmu  sync.Mutex
	diag map[string][]Diagnostic

	omu  sync.Mutex
	open map[string]bool // documents already declared to the server

	done chan struct{} // closed when the reader stops
	err  error         // why it stopped; read only after done
	once sync.Once
}

// msg is any JSON-RPC frame in either direction. Which of the four kinds it is
// follows from which fields are present, which is what [Conn.read] switches on.
type msg struct {
	ID     json.RawMessage `json:"id,omitempty"`
	Method string          `json:"method,omitempty"`
	Params json.RawMessage `json:"params,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *rpcError) Error() string { return fmt.Sprintf("lsp: rpc %d: %s", e.Code, e.Message) }

// attach starts cmd — which the caller has already jailed — and completes the
// handshake against a server rooted at root.
//
// The process is deliberately NOT tied to a request's context: a Conn outlives
// the request that warmed it, which is the entire point of the pool. [Conn.Close]
// is what ends it.
func attach(ctx context.Context, cmd *exec.Cmd, l Lang, root string) (*Conn, error) {
	// The server's stderr is its own log, not ours to relay: it is chatty and it
	// echoes tenant source. Dropping it keeps both out of our logs.
	cmd.Stderr = io.Discard

	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("lsp: stdin: %w", err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("lsp: stdout: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("lsp: start %s: %w", l.Start[0], err)
	}

	c := newConn(in, out, func() {
		if cmd.Process != nil {
			// The jailed process is PID 1 of its own PID namespace, so this one
			// kill takes every `go list` it forked with it.
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	})
	if err := c.handshake(ctx, l, root); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// newConn puts a Conn on an already-open transport and starts its reader. attach
// uses it for a real process; a test uses it for a pipe, and both then drive the
// identical client.
func newConn(w io.WriteCloser, r io.Reader, stop func()) *Conn {
	c := &Conn{
		w:    w,
		stop: stop,
		wait: make(map[int64]chan msg),
		diag: make(map[string][]Diagnostic),
		open: make(map[string]bool),
		done: make(chan struct{}),
	}
	go c.read(bufio.NewReaderSize(r, 64<<10))
	return c
}

// handshake performs initialize → initialized. initializationOptions (langs.go:
// Init) is where a server that would otherwise compile project code at load time
// is told not to.
func (c *Conn) handshake(ctx context.Context, l Lang, root string) error {
	ctx, cancel := context.WithTimeout(ctx, initWait)
	defer cancel()

	uri := pathURI(root)
	params := map[string]any{
		"processId": os.Getpid(),
		"rootUri":   uri,
		"rootPath":  root,
		"capabilities": map[string]any{
			"workspace": map[string]any{"workspaceFolders": true, "applyEdit": false},
			"textDocument": map[string]any{
				"synchronization":    map[string]any{"dynamicRegistration": true, "didSave": true},
				"completion":         map[string]any{"completionItem": map[string]any{"snippetSupport": true}},
				"hover":              map[string]any{"contentFormat": []string{"markdown", "plaintext"}},
				"definition":         map[string]any{"dynamicRegistration": true, "linkSupport": true},
				"references":         map[string]any{"dynamicRegistration": true},
				"publishDiagnostics": map[string]any{"relatedInformation": false},
			},
		},
		"workspaceFolders": []map[string]any{{"uri": uri, "name": filepath.Base(root)}},
	}
	if l.Init != nil {
		params["initializationOptions"] = l.Init
	}
	if _, err := c.Call(ctx, "initialize", params); err != nil {
		return fmt.Errorf("lsp: initialize: %w", err)
	}
	return c.Notify("initialized", map[string]any{})
}

// Call issues a request and waits for the response with that id.
func (c *Conn) Call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	id := c.seq.Add(1)
	ch := make(chan msg, 1)

	c.mu.Lock()
	c.wait[id] = ch
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.wait, id)
		c.mu.Unlock()
	}()

	if err := c.send(map[string]any{
		"jsonrpc": "2.0", "id": id, "method": method, "params": params,
	}); err != nil {
		return nil, err
	}

	select {
	case m := <-ch:
		if m.Error != nil {
			return nil, m.Error
		}
		return m.Result, nil
	case <-c.done:
		return nil, c.stopped()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Notify sends a notification — no id, so no response is expected or waited for.
func (c *Conn) Notify(method string, params any) error {
	return c.send(map[string]any{"jsonrpc": "2.0", "method": method, "params": params})
}

// Open makes the server willing to answer about a file, ONCE.
//
// didOpen is not idempotent in LSP: it declares that the CLIENT now owns the
// document and is the authority on its contents, and a second one for the same
// URI is a protocol violation the server is entitled to reject — which gopls
// does, by then answering null to everything about that document. Once is also
// all that is ever needed here, because a root is immutable: the file cannot
// change for as long as this server exists.
//
// Content is read from disk: the root is the source of truth, and accepting
// caller-supplied text would let one request answer about a file the tenant's
// repository does not have.
func (c *Conn) Open(l Lang, abs string) (string, error) {
	uri := pathURI(abs)

	c.omu.Lock()
	defer c.omu.Unlock()
	if c.open[uri] {
		return uri, nil
	}
	text, err := os.ReadFile(abs)
	if err != nil {
		return "", fmt.Errorf("lsp: read %s: %w", filepath.Base(abs), err)
	}
	if err := c.Notify("textDocument/didOpen", map[string]any{
		"textDocument": map[string]any{
			"uri": uri, "languageId": l.ID(abs), "version": 1, "text": string(text),
		},
	}); err != nil {
		return "", err
	}
	c.open[uri] = true
	return uri, nil
}

// Diagnostics collects what the server published for uri.
//
// LSP has no "diagnostics complete" signal — publishDiagnostics is unsolicited
// and a server may publish several times as analysis deepens. So this waits for a
// first publication, then for a settle window in which nothing new arrives, and
// reports what it has. A server that publishes nothing (a clean file) is reported
// clean at the deadline, which is the honest reading.
func (c *Conn) Diagnostics(ctx context.Context, uri string, settle time.Duration) []Diagnostic {
	const tick = 50 * time.Millisecond
	var last int
	var quiet time.Duration
	for {
		select {
		case <-ctx.Done():
			return c.published(uri)
		case <-c.done:
			return c.published(uri)
		case <-time.After(tick):
		}
		got := c.published(uri)
		if len(got) != last {
			last, quiet = len(got), 0
			continue
		}
		if last > 0 {
			if quiet += tick; quiet >= settle {
				return got
			}
		}
	}
}

func (c *Conn) published(uri string) []Diagnostic {
	c.dmu.Lock()
	defer c.dmu.Unlock()
	if d, ok := c.diag[uri]; ok {
		return append([]Diagnostic(nil), d...)
	}
	return nil
}

// Close shuts the server down politely, then unconditionally. Idempotent.
//
// Polite first, because a server asked to exit flushes and releases its own
// children. But the polite phase can BLOCK: a server that has stopped reading its
// stdin — crashed, or wedged mid-index — leaves our write with nowhere to go, and
// Close would then never return. It would hold a pool slot, a process handle and,
// at shutdown, the whole binary.
//
// So the courtesy runs off to the side and this waits on a clock, never on the
// server. Closing the writer afterwards is what releases that goroutine: a blocked
// write to a closed pipe returns rather than waits.
func (c *Conn) Close() {
	c.once.Do(func() {
		select {
		case <-c.done:
			// Already dead. There is nobody to say goodbye to, and saying it
			// anyway is exactly how this used to hang.
		default:
			polite := make(chan struct{})
			go func() {
				defer close(polite)
				ctx, cancel := context.WithTimeout(context.Background(), closeWait)
				defer cancel()
				_, _ = c.Call(ctx, "shutdown", nil)
				_ = c.Notify("exit", nil)
			}()
			select {
			case <-polite:
			case <-time.After(closeWait):
			}
		}

		_ = c.w.Close()
		select {
		case <-c.done:
		case <-time.After(closeWait):
		}
		if c.stop != nil {
			c.stop()
		}
	})
}

// send frames one message. The write lock spans header and body: two goroutines
// interleaving there would produce a frame whose length does not match its
// payload, and the stream never recovers from that.
func (c *Conn) send(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("lsp: encode: %w", err)
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if _, err := fmt.Fprintf(c.w, "Content-Length: %d\r\n\r\n", len(b)); err != nil {
		return fmt.Errorf("lsp: write header: %w", err)
	}
	if _, err := c.w.Write(b); err != nil {
		return fmt.Errorf("lsp: write body: %w", err)
	}
	return nil
}

// read is the sole owner of the inbound stream. Every frame is exactly one of
// four kinds, and each has exactly one destination.
func (c *Conn) read(r *bufio.Reader) {
	defer close(c.done)
	for {
		body, err := readFrame(r)
		if err != nil {
			c.err = err
			return
		}
		var m msg
		if json.Unmarshal(body, &m) != nil {
			continue // a frame we cannot parse is not a reason to drop the session
		}

		switch {
		case m.Method != "" && len(m.ID) > 0:
			// A server→client REQUEST (workspace/configuration,
			// client/registerCapability). It BLOCKS the server until answered, so
			// silence here is a hang, not a no-op. A null result is a valid answer
			// to every one of them and commits us to nothing.
			_ = c.send(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": nil})

		case m.Method != "" && len(m.ID) == 0:
			if m.Method == "textDocument/publishDiagnostics" {
				c.publish(m.Params)
			}

		case len(m.ID) > 0:
			var id int64
			if json.Unmarshal(m.ID, &id) != nil {
				continue // a response to an id we never issued
			}
			c.mu.Lock()
			ch := c.wait[id]
			c.mu.Unlock()
			if ch != nil {
				ch <- m // buffered, and the waiter is the only receiver
			}
		}
	}
}

func (c *Conn) publish(params json.RawMessage) {
	var p struct {
		URI         string       `json:"uri"`
		Diagnostics []Diagnostic `json:"diagnostics"`
	}
	if json.Unmarshal(params, &p) != nil || p.URI == "" {
		return
	}
	c.dmu.Lock()
	c.diag[p.URI] = p.Diagnostics
	c.dmu.Unlock()
}

func (c *Conn) stopped() error {
	if c.err != nil && !errors.Is(c.err, io.EOF) {
		return fmt.Errorf("lsp: server stopped: %w", c.err)
	}
	return errors.New("lsp: server stopped")
}

// readFrame reads one Content-Length-framed message.
//
// Content-Length is REQUIRED and is the only header that matters; Content-Type is
// accepted and ignored, as the spec allows. A frame is refused rather than
// truncated when it exceeds maxFrame, because a truncated read leaves the stream
// pointing at the middle of a message.
func readFrame(r *bufio.Reader) ([]byte, error) {
	n := -1
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break // end of headers
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(k), "Content-Length") {
			continue
		}
		if n, err = strconv.Atoi(strings.TrimSpace(v)); err != nil {
			return nil, fmt.Errorf("lsp: bad Content-Length %q", v)
		}
	}
	if n < 0 {
		return nil, errors.New("lsp: frame without Content-Length")
	}
	if n > maxFrame {
		return nil, fmt.Errorf("lsp: frame of %d bytes exceeds %d", n, maxFrame)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return body, nil
}

// pathURI renders an absolute path as a file: URI. url.URL does the escaping, so
// a path with a space or a percent survives the round trip.
func pathURI(p string) string {
	return (&url.URL{Scheme: "file", Path: p}).String()
}

// uriPath is pathURI's inverse for a file: URI, and the empty string for anything
// else — a server may cite a definition inside a jar: or zipfile: URI, which names
// no path on our disk.
func uriPath(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "file" {
		return ""
	}
	return u.Path
}
