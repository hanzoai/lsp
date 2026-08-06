package lsp

// http_test.go drives the door itself: what it refuses, and what it says when it
// refuses. Nothing here needs a language server — these are the answers that must
// hold before one is ever started.

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestKeyIsRequiredAndConstantTime(t *testing.T) {
	r := launch(t, "")
	body := Ask{Org: "acme", Repo: "app", Rev: sha(1), Op: "hover", Path: "main.go"}

	if code, _ := r.postKey(t, "/ask", body, ""); code != http.StatusUnauthorized {
		t.Errorf("no key = %d, want 401", code)
	}
	if code, _ := r.postKey(t, "/ask", body, "wrong"); code != http.StatusUnauthorized {
		t.Errorf("wrong key = %d, want 401", code)
	}
	// A key that is a PREFIX of the real one must fare no better: the comparison
	// is over the whole value, in constant time.
	if code, _ := r.postKey(t, "/ask", body, testKey[:4]); code != http.StatusUnauthorized {
		t.Errorf("prefix key = %d, want 401", code)
	}
}

// An unconfigured daemon is not an open one. With no key it refuses everything
// with 503 rather than serving whoever asks.
func TestUnconfiguredDaemonRefuses(t *testing.T) {
	svc := New(Config{Roots: t.TempDir(), Deps: t.TempDir(), Stage: t.TempDir()}, "",
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(svc.Close)
	svc.Prove(context.Background())
	srv := httptest.NewServer(svc.Routes())
	t.Cleanup(srv.Close)

	r := &rig{http: srv, svc: svc, ready: svc.ready.Load()}
	if code, _ := r.post(t, "/ask", Ask{}); code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured daemon = %d, want 503", code)
	}
}

// The 409 is the whole cold protocol: the daemon holds no credential and cannot
// go and get a tree, so it says precisely what it needs and from whom.
func TestAskWithoutARootAsksForTheTree(t *testing.T) {
	r := launch(t, "")
	r.needJail(t)

	code, body := r.post(t, "/ask", Ask{
		Org: "acme", Repo: "app", Rev: sha(3),
		Op: "hover", Path: "main.go", Line: 0, Character: 0,
	})
	if code != http.StatusConflict {
		t.Fatalf("/ask with no root = %d %v, want 409", code, body)
	}
	if body["need"] != "tree" {
		t.Errorf("need = %v, want \"tree\"", body["need"])
	}
	if body["rev"] != sha(3) {
		t.Errorf("the 409 must echo the revision to send: %v", body)
	}
}

// Warming is free work, so it is only offered where a cold start has already been
// paid for on the same repository.
func TestWarmIsRefusedForARepoNotHeld(t *testing.T) {
	r := launch(t, "")
	r.needJail(t)

	code, body := r.post(t, "/root/warm", Tree{
		Org: "acme", Repo: "app", Rev: sha(4),
		Files: []File{{Path: "notes.txt", Content: "hi"}},
	})
	if code != http.StatusConflict {
		t.Fatalf("/root/warm with nothing held = %d %v, want 409", code, body)
	}
	if body["need"] != "held" {
		t.Errorf("need = %v, want \"held\"", body["need"])
	}
}

// A revision must be a resolved commit. That single rule is what makes a root
// immutable — and therefore what removes cache invalidation from this daemon — so
// it is refused at the door rather than coped with later.
func TestRevisionMustBeAResolvedCommit(t *testing.T) {
	r := launch(t, "")
	r.needJail(t)

	for _, rev := range []string{"main", "v1.2.3", "HEAD", "", "abc", sha(1) + "0", "../" + sha(1)[3:]} {
		code, _ := r.post(t, "/ask", Ask{
			Org: "acme", Repo: "app", Rev: rev, Op: "hover", Path: "main.go",
		})
		if code != http.StatusBadRequest {
			t.Errorf("rev %q = %d, want 400 — only a resolved sha names an immutable tree", rev, code)
		}
	}
	// Hex is case-insensitive and both spellings name the SAME commit, so the
	// revision is folded before it is a key. Two roots for one tree would be two
	// gopls processes and two answers to one question.
	upper := strings.ToUpper(sha(1))
	code, body := r.post(t, "/ask", Ask{
		Org: "acme", Repo: "app", Rev: upper, Op: "hover", Path: "main.go",
	})
	if code != http.StatusConflict {
		t.Fatalf("uppercase sha = %d %v, want 409 (accepted, no root yet)", code, body)
	}
	if body["rev"] != sha(1) {
		t.Errorf("the 409 echoed %v, want the folded %q", body["rev"], sha(1))
	}
}

func TestTenantNamesAreNarrowed(t *testing.T) {
	r := launch(t, "")
	r.needJail(t)

	cases := []struct{ org, repo string }{
		{"../other", "app"},
		{"acme/evil", "app"},
		{".hidden", "app"},
		{"acme", "../../etc"},
		{"acme", "a/b"},
		{"ACME", "app"}, // orgs are lowercase slugs
		{"", "app"},
		{"acme", ""},
	}
	for _, c := range cases {
		code, _ := r.post(t, "/ask", Ask{
			Org: c.org, Repo: c.repo, Rev: sha(1), Op: "hover", Path: "main.go",
		})
		if code != http.StatusBadRequest {
			t.Errorf("org=%q repo=%q = %d, want 400", c.org, c.repo, code)
		}
	}
}

// A tree is tenant content. A path that climbs out of it is refused BEFORE
// anything is written, so there is no window in which a file lands outside the
// root and is then cleaned up.
func TestTreePathsCannotEscape(t *testing.T) {
	r := launch(t, "")
	r.needJail(t)

	for _, p := range []string{"../evil", "/etc/passwd", "a/../../evil", ".."} {
		code, body := r.post(t, "/root", Tree{
			Org: "acme", Repo: "app", Rev: sha(5),
			Files: []File{{Path: p, Content: "x"}},
		})
		if code != http.StatusBadRequest {
			t.Errorf("tree path %q = %d %v, want 400", p, code, body)
		}
	}
}

func TestOpsAndRelationsAreClosedSets(t *testing.T) {
	r := launch(t, "")
	r.needJail(t)

	base := Ask{Org: "acme", Repo: "app", Rev: sha(1), Path: "main.go"}

	for _, op := range []string{"", "definition", "textDocument/definition", "rename", "exec"} {
		in := base
		in.Op = op
		if code, _ := r.post(t, "/ask", in); code != http.StatusBadRequest {
			t.Errorf("op %q = %d, want 400 — the door names what it serves", op, code)
		}
	}
	// locate without a relation is not a question.
	in := base
	in.Op = "locate"
	if code, _ := r.post(t, "/ask", in); code != http.StatusBadRequest {
		t.Errorf("locate with no relation = %d, want 400", code)
	}
	in.Relation = "callers"
	if code, _ := r.post(t, "/ask", in); code != http.StatusBadRequest {
		t.Errorf("unknown relation = %d, want 400", code)
	}
	// A negative position is a caller that re-based a 1-based editor line.
	in.Relation = "definition"
	in.Line = -1
	if code, _ := r.post(t, "/ask", in); code != http.StatusBadRequest {
		t.Errorf("negative line = %d, want 400", code)
	}
}

// A root whose files no installed server answers for still builds — it just
// serves nothing, and says so, rather than failing.
func TestRootWithNoServableLanguage(t *testing.T) {
	r := launch(t, "")
	r.needJail(t)

	code, body := r.post(t, "/root", Tree{
		Org: "acme", Repo: "docs", Rev: sha(6),
		Files: []File{{Path: "README.txt", Content: "nothing to see"}},
	})
	if code != http.StatusOK {
		t.Fatalf("/root = %d %v", code, body)
	}
	if langs, _ := body["langs"].([]any); len(langs) != 0 {
		t.Errorf("langs = %v, want none", langs)
	}
	code, body = r.post(t, "/ask", Ask{
		Org: "acme", Repo: "docs", Rev: sha(6),
		Op: "hover", Path: "README.txt",
	})
	if code != http.StatusBadRequest {
		t.Fatalf("/ask on an unserved file = %d %v, want 400", code, body)
	}
}

// An empty tree is not a root.
func TestEmptyTreeIsRefused(t *testing.T) {
	r := launch(t, "")
	r.needJail(t)
	if code, _ := r.post(t, "/root", Tree{Org: "acme", Repo: "app", Rev: sha(7)}); code != http.StatusBadRequest {
		t.Fatalf("empty tree = %d, want 400", code)
	}
}

// Liveness answers while the process is up; readiness answers what the jail
// decided. They are different questions and must not collapse into one.
func TestProbesAreUnauthenticated(t *testing.T) {
	r := launch(t, "")

	resp, err := http.Get(r.http.URL + "/healthz")
	if err != nil {
		t.Fatalf("healthz: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("healthz = %d, want 200 while the process is up", resp.StatusCode)
	}

	resp, err = http.Get(r.http.URL + "/readyz")
	if err != nil {
		t.Fatalf("readyz: %v", err)
	}
	resp.Body.Close()
	want := http.StatusServiceUnavailable
	if r.ready {
		want = http.StatusOK
	}
	if resp.StatusCode != want {
		t.Errorf("readyz = %d, want %d", resp.StatusCode, want)
	}
}
