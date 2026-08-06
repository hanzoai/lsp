package lsp

// gopls_test.go is THE acceptance test, and it asserts the one thing that
// justifies this daemon existing.
//
// A static symbol index over a repository can tell you where `Greet` is written
// in that repository. It structurally cannot tell you where `dep.Greet` is
// DEFINED, because the definition is in a module the repository only names — and
// finding it means downloading that module and type-checking both halves. This
// test does exactly that, end to end through the real HTTP door, and requires the
// answer to come back with External true and a module coordinate.
//
// It is hermetic. The dependency is published into a directory laid out as a Go
// module proxy and fetched through GOPROXY=file://, so the FETCH phase runs the
// real `go mod download` — writing a real go.sum into the tree and a real module
// into GOMODCACHE — with no network and no dependency on anybody's uptime.

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The tiny dependency and the tiny module that imports it.
const (
	depPath    = "example.com/dep"
	depVersion = "v1.0.0"

	depMod = "module example.com/dep\n\ngo 1.21\n"
	depGo  = `package dep

// Greet returns a greeting for name.
func Greet(name string) string { return "hello " + name }
`

	appMod = "module example.com/app\n\ngo 1.21\n\nrequire example.com/dep v1.0.0\n"
	appGo  = `package main

import "example.com/dep"

func main() {
	_ = dep.Greet("world")
}
`
)

func TestDefinitionCrossesIntoTheDependency(t *testing.T) {
	needTool(t, "go")
	needTool(t, "gopls")

	proxy := t.TempDir()
	publish(t, proxy, depPath, depVersion, map[string]string{
		"go.mod": depMod,
		"dep.go": depGo,
	})

	r := launch(t, "file://"+filepath.ToSlash(proxy))
	r.needJail(t)

	rev := sha(1)
	code, body := r.post(t, "/root", Tree{
		Org: "acme", Repo: "app", Rev: rev,
		Files: []File{
			{Path: "go.mod", Content: appMod},
			{Path: "main.go", Content: appGo},
		},
	})
	if code != 200 {
		t.Fatalf("POST /root = %d %v", code, body)
	}
	if got := body["cold"]; got != true {
		t.Errorf("first /root reported cold=%v, want true", got)
	}
	if !hasLang(body, "go") {
		t.Fatalf("/root served no Go server: %v", body)
	}

	// The dependency must really be in the cache: if the fetch phase did not run,
	// the definition below could only ever resolve inside the tree, and the test
	// would be asserting nothing.
	cached := filepath.Join(r.cfg.Deps, "go", depPath+"@"+depVersion, "dep.go")
	if _, err := os.Stat(cached); err != nil {
		t.Fatalf("the fetch phase did not populate the module cache (%s): %v", cached, err)
	}

	line, char := find(appGo, "Greet")

	t.Run("locate definition", func(t *testing.T) {
		body := r.ask(t, Ask{
			Org: "acme", Repo: "app", Rev: rev,
			Op: "locate", Relation: "definition",
			Path: "main.go", Line: line, Character: char,
		}, func(b map[string]any) bool { return len(locs(b)) > 0 })

		got := locs(body)
		if len(got) == 0 {
			t.Fatalf("no location for dep.Greet: %v", body)
		}
		first := got[0]
		if !first.External {
			t.Fatalf("definition = %+v, want External true — it is in a module, not in the repo", first)
		}
		want := path.Join(depPath+"@"+depVersion, "dep.go")
		if first.Path != want {
			t.Fatalf("definition path = %q, want %q (the module coordinate)", first.Path, want)
		}
		if first.Range.Start.Line != 3 {
			t.Errorf("definition line = %d, want 3 (0-based, where Greet is declared)", first.Range.Start.Line)
		}
	})

	t.Run("hover reads the dependency's doc", func(t *testing.T) {
		body := r.ask(t, Ask{
			Org: "acme", Repo: "app", Rev: rev,
			Op: "hover", Path: "main.go", Line: line, Character: char,
		}, func(b map[string]any) bool { return b["hover"] != nil })

		text, _ := body["hover"].(string)
		if !strings.Contains(text, "Greet") {
			t.Fatalf("hover = %q, want it to mention Greet", text)
		}
		if !strings.Contains(text, "returns a greeting") {
			t.Errorf("hover = %q, want the DEPENDENCY's doc comment — that is what resolving through the module buys", text)
		}
	})

	t.Run("second root is warm", func(t *testing.T) {
		code, body := r.post(t, "/root", Tree{
			Org: "acme", Repo: "app", Rev: rev,
			Files: []File{{Path: "go.mod", Content: appMod}, {Path: "main.go", Content: appGo}},
		})
		if code != 200 {
			t.Fatalf("second /root = %d %v", code, body)
		}
		if got := body["cold"]; got != false {
			t.Errorf("second /root reported cold=%v, want false — the root is held", got)
		}
	})

	t.Run("warm is accepted for a repo already held", func(t *testing.T) {
		code, body := r.post(t, "/root/warm", Tree{
			Org: "acme", Repo: "app", Rev: sha(2),
			Files: []File{{Path: "go.mod", Content: appMod}, {Path: "main.go", Content: appGo}},
		})
		if code != 200 {
			t.Fatalf("POST /root/warm = %d %v", code, body)
		}
	})
}

// ask posts a question and retries until done says the answer arrived.
//
// gopls loads a workspace asynchronously and its first answer after a cold start
// can race that load, so a single shot is a flaky assertion about timing rather
// than about resolution. This polls the real door on the real clock and fails with
// the last body it saw.
func (r *rig) ask(t *testing.T, in Ask, done func(map[string]any) bool) map[string]any {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	var last map[string]any
	for {
		code, body := r.post(t, "/ask", in)
		if code != 200 {
			t.Fatalf("POST /ask = %d %v", code, body)
		}
		last = body
		if done(body) {
			return body
		}
		if time.Now().After(deadline) {
			t.Fatalf("gopls never answered %s within the deadline; last body %v", in.Op, last)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// locs decodes the locations out of a raw answer body.
func locs(body map[string]any) []Location {
	raw, err := json.Marshal(body["locations"])
	if err != nil {
		return nil
	}
	var out []Location
	if json.Unmarshal(raw, &out) != nil {
		return nil
	}
	return out
}

func hasLang(body map[string]any, want string) bool {
	list, _ := body["langs"].([]any)
	for _, l := range list {
		if s, _ := l.(string); s == want {
			return true
		}
	}
	return false
}

// find returns the 0-based line and character of the first occurrence of needle.
// The fixtures are ASCII, so a byte index is also a UTF-16 code-unit index —
// which is what the protocol counts, and what the daemon passes through untouched.
func find(src, needle string) (int, int) {
	for i, line := range strings.Split(src, "\n") {
		if col := strings.Index(line, needle); col >= 0 {
			return i, col
		}
	}
	return -1, -1
}

func needTool(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s is not installed here; the image ships it", name)
	}
}

// publish writes one module version into a directory laid out as a Go module
// proxy: the .info, .mod and .zip a `GOPROXY=file://` fetch reads.
func publish(t *testing.T, proxy, module, version string, files map[string]string) {
	t.Helper()
	dir := filepath.Join(proxy, filepath.FromSlash(module), "@v")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("proxy dir: %v", err)
	}
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	write("list", version+"\n")
	write(version+".info", fmt.Sprintf(`{"Version":%q,"Time":"2024-01-01T00:00:00Z"}`, version))
	write(version+".mod", files["go.mod"])

	var buf strings.Builder
	zw := zip.NewWriter(&stringWriter{&buf})
	for name, body := range files {
		// Every entry is prefixed module@version, which is the layout the module
		// zip format requires and how the cache lays the module out on disk.
		w, err := zw.Create(module + "@" + version + "/" + name)
		if err != nil {
			t.Fatalf("zip entry %s: %v", name, err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatalf("zip write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	write(version+".zip", buf.String())
}

// stringWriter adapts a strings.Builder to io.Writer for archive/zip.
type stringWriter struct{ b *strings.Builder }

func (w *stringWriter) Write(p []byte) (int, error) { return w.b.Write(p) }
