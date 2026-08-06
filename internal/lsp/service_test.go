package lsp

// service_test.go is the shared rig: a real Service behind a real HTTP server,
// with real directories. Nothing here is a mock — the tests that use it drive the
// same handlers a caller does.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const testKey = "test-service-key"

// rig is a running daemon and the directories it was given.
type rig struct {
	http  *httptest.Server
	cfg   Config
	svc   *Service
	ready bool // the jail proved out (or this platform has none)
}

// launch starts a daemon whose fetch phase resolves modules from proxy — a
// directory in the module-proxy layout, so a test exercises the REAL `go mod
// download` with no network at all.
func launch(t *testing.T, proxy string) *rig {
	t.Helper()
	base := t.TempDir()
	cfg := Config{
		Roots: filepath.Join(base, "roots"),
		Deps:  filepath.Join(base, "deps"),
		Stage: filepath.Join(base, "stage"),
		Proxy: proxy,
		// off, because the modules a test publishes are not in anybody's
		// transparency log. Production sets a real one; see Config.
		Sumdb: "off",
	}
	svc := New(cfg, testKey, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(svc.Close)
	// The Go module cache is deliberately read-only — that is the toolchain
	// protecting verified content, and production wants it. It also means the
	// test framework cannot remove its own temp directory, so unlock it first.
	// Cleanups run last-registered-first, and t.TempDir registered before this.
	t.Cleanup(func() { unlock(cfg.Deps) })

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	svc.Prove(ctx)
	cancel()

	srv := httptest.NewServer(svc.Routes())
	t.Cleanup(srv.Close)
	return &rig{http: srv, cfg: cfg, svc: svc, ready: svc.ready.Load()}
}

// post sends a JSON body to path with the service key and returns the status and
// the decoded body.
func (r *rig) post(t *testing.T, path string, body any) (int, map[string]any) {
	t.Helper()
	return r.postKey(t, path, body, testKey)
}

func (r *rig) postKey(t *testing.T, path string, body any, key string) (int, map[string]any) {
	t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, r.http.URL+path, bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("X-API-Key", key)
	}
	resp, err := r.http.Client().Do(req)
	if err != nil {
		t.Fatalf("post %s: %v", path, err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// needJail skips when the daemon refused to serve because the jail did not
// initialize here. That is the fail-closed path working, not a test failure: a
// plain CI container cannot create a user namespace, and the gVisor target can.
func (r *rig) needJail(t *testing.T) {
	t.Helper()
	if !r.ready {
		t.Skipf("daemon refused to serve — the jail did not initialize here (%s)", r.svc.status())
	}
}

// sha is a synthetic resolved commit. The daemon requires one because a root is
// keyed by an immutable revision; what the digits mean is the caller's business.
func sha(seed byte) string {
	out := make([]byte, 40)
	for i := range out {
		out[i] = "0123456789abcdef"[(int(seed)+i)%16]
	}
	return string(out)
}

// unlock makes a tree removable. See launch.
func unlock(dir string) {
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			_ = os.Chmod(path, 0o755)
		} else {
			_ = os.Chmod(path, 0o644)
		}
		return nil
	})
}
