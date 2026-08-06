package lsp

// root_test.go pins the tree: what a caller may name, what lands on disk, and
// what the language table concludes about it.

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestNarrowRefusesEverythingButATreePath(t *testing.T) {
	bad := []string{
		"", "..", "../x", "a/../../x", "/etc/passwd", "/", "\x00", "a\x00b",
		strings.Repeat("a/", depthMost+2) + "x",
	}
	for _, p := range bad {
		if got, err := narrow(p); err == nil {
			t.Errorf("narrow(%q) = %q, want an error", p, got)
		}
	}
	good := map[string]string{
		"main.go":            "main.go",
		"./main.go":          "main.go",
		"a/b/c.go":           "a/b/c.go",
		"a//b.go":            "a/b.go",
		"a/./b.go":           "a/b.go",
		"a/b/../c.go":        "a/c.go",
		".hidden/config.yml": ".hidden/config.yml",
	}
	for in, want := range good {
		got, err := narrow(in)
		if err != nil {
			t.Errorf("narrow(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("narrow(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMaterializeWritesTheTree(t *testing.T) {
	dir := t.TempDir()
	paths, err := materialize(dir, []File{
		{Path: "go.mod", Content: "module x\n"},
		{Path: "pkg/deep/a.go", Content: "package deep\n"},
	})
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	if !slices.Equal(paths, []string{"go.mod", "pkg/deep/a.go"}) {
		t.Errorf("paths = %v", paths)
	}
	body, err := os.ReadFile(filepath.Join(dir, "pkg", "deep", "a.go"))
	if err != nil || string(body) != "package deep\n" {
		t.Errorf("nested file = %q %v", body, err)
	}
}

// The same path twice is a caller that cannot be trusted about the rest of the
// tree either. O_EXCL turns it into an error rather than a silent last-wins.
func TestMaterializeRefusesADuplicatePath(t *testing.T) {
	dir := t.TempDir()
	_, err := materialize(dir, []File{
		{Path: "a.go", Content: "first"},
		{Path: "a.go", Content: "second"},
	})
	if err == nil {
		t.Fatal("materialize accepted the same path twice")
	}
}

// A tree cannot smuggle a write past its own root through a path it also names
// as a directory.
func TestMaterializeRefusesAFileUsedAsADirectory(t *testing.T) {
	dir := t.TempDir()
	_, err := materialize(dir, []File{
		{Path: "a", Content: "file"},
		{Path: "a/b", Content: "under a file"},
	})
	if err == nil {
		t.Fatal("materialize accepted a path whose parent is a file")
	}
}

// clean proves containment on the RESOLVED path, because a tree is tenant
// content and a dependency fetch writes into it: a link planted there must not
// become a read of anything outside.
func TestCleanRefusesASymlinkOutOfTheTree(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("KEY"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "real.go"), []byte("package x"), 0o600); err != nil {
		t.Fatalf("write real: %v", err)
	}
	if err := os.Symlink(secret, filepath.Join(dir, "escape.go")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	if _, err := clean(dir, "real.go"); err != nil {
		t.Errorf("clean refused a genuine file: %v", err)
	}
	if got, err := clean(dir, "escape.go"); err == nil {
		t.Fatalf("clean FOLLOWED a symlink out of the tree: %q", got)
	}
	if _, err := clean(dir, "missing.go"); err == nil {
		t.Error("clean accepted a file that is not there")
	}
	// A directory is not a document.
	if err := os.Mkdir(filepath.Join(dir, "pkg"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if _, err := clean(dir, "pkg"); err == nil {
		t.Error("clean accepted a directory")
	}
}

func TestLangForPicksByExtension(t *testing.T) {
	cases := map[string]string{
		"main.go":      "go",
		"a/b/main.go":  "go",
		"lib.rs":       "rust",
		"index.tsx":    "typescript",
		"setup.py":     "python",
		"util.hpp":     "cpp",
		"README.md":    "",
		"Makefile":     "",
		"main.GO":      "go", // extensions are matched case-insensitively
		"noextension/": "",
	}
	for path, want := range cases {
		l, ok := langFor(path)
		if want == "" {
			if ok {
				t.Errorf("langFor(%q) = %q, want none", path, l.Name)
			}
			continue
		}
		if !ok || l.Name != want {
			t.Errorf("langFor(%q) = %q %v, want %q", path, l.Name, ok, want)
		}
	}
}

func TestModulesAreWhereTheFetchRuns(t *testing.T) {
	paths := []string{
		"go.mod", "main.go",
		"service/go.mod", "service/main.go",
		"web/package.json", "web/index.ts",
		"docs/readme.md",
	}
	got := table["go"].Modules(paths)
	if !slices.Equal(got, []string{".", "service"}) {
		t.Errorf("go modules = %v, want [. service]", got)
	}
	if got := table["typescript"].Modules(paths); !slices.Equal(got, []string{"web"}) {
		t.Errorf("typescript modules = %v, want [web]", got)
	}
	if got := table["rust"].Modules(paths); len(got) != 0 {
		t.Errorf("rust modules = %v, want none", got)
	}
}

func TestSpeaksIsAboutFilesNotMarkers(t *testing.T) {
	// A repository with Go source but no go.mod is still a Go repository to a
	// language server; it just has nothing to fetch.
	paths := []string{"scratch/main.go"}
	if !table["go"].Speaks(paths) {
		t.Error("go must speak for a tree of .go files with no go.mod")
	}
	if len(table["go"].Modules(paths)) != 0 {
		t.Error("with no go.mod there is nothing to fetch")
	}
	if table["rust"].Speaks(paths) {
		t.Error("rust claimed a tree with no .rs file")
	}
}

// The four dialects TypeScript's server distinguishes are a property of the FILE.
func TestTypeScriptDialects(t *testing.T) {
	ts := table["typescript"]
	cases := map[string]string{
		"a.ts": "typescript", "a.tsx": "typescriptreact",
		"a.js": "javascript", "a.jsx": "javascriptreact",
	}
	for path, want := range cases {
		if got := ts.ID(path); got != want {
			t.Errorf("ID(%q) = %q, want %q", path, got, want)
		}
	}
	if got := table["go"].ID("a.go"); got != "go" {
		t.Errorf("go ID = %q", got)
	}
}

// The scripts-off policy is one predicate, and this is what it currently says.
func TestFetchableRefusesEveryFetchThatRunsDependencyCode(t *testing.T) {
	for name, l := range table {
		if l.Executes && Fetchable(l) {
			t.Errorf("%s: a fetch that runs dependency code is fetchable", name)
		}
		if len(l.Fetch) == 0 && Fetchable(l) {
			t.Errorf("%s: a language with no fetch is fetchable", name)
		}
	}
	if !Fetchable(table["go"]) {
		t.Error("go's fetch downloads and verifies without running anything; it must be fetchable")
	}
	if Fetchable(table["python"]) {
		t.Error("uv sync builds sdists, which is dependency code; it must not be fetchable")
	}
}
