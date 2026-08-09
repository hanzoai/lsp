package lsp

// langs.go is the language table — the ONE place that answers four questions
// about a language: how to RECOGNIZE it in a tree, how to START its server, how
// to FETCH its dependencies, and WHERE those dependencies land.
//
// PORTED from hanzoai/cloud branch `lsp` (apps/lsp/langs.go, 67975187), whose
// servers and argv were themselves ported from the Python tool
// (hanzo/python-sdk/pkg/hanzo-tools-lsp). A second opinion about how to spawn
// gopls is a second bug surface, so there is not one.
//
// # A table entry is a claim, and Available is what makes it true
//
// Every language below is complete: argv, markers, extensions, cache, fetch. What
// decides whether one is SERVED is whether its binary is on PATH in the image
// (Available), so the table never promises what the deployment cannot do, and
// adding a language to production is adding a toolchain to the Dockerfile — no
// code change, no entry to remember to write.
//
// The image ships every server here. An entry is therefore a claim the
// deployment keeps, and a server that cannot start takes only its own language
// down: build() logs it and the others go on answering.
//
// # Scripts-off, and why the fetch phase does not weaken it
//
// Fetching dependencies is the dangerous half. `npm install` runs postinstall;
// `cargo build` runs build.rs; `pip install` of an sdist runs setup.py. Each is
// third-party code executing as us, triggered by whatever tree the caller sent —
// and it would be executing in the ONE phase that has a network. That is exactly
// the pairing the whole daemon exists to prevent.
//
// It is also UNNECESSARY. A language server resolves definitions, references and
// types from SOURCE — the dependency's .go/.d.ts/.pyi/.rs files — not from what a
// build script produces. Turning scripts off costs some generated code and some
// proc-macro expansion; it does not cost go-to-definition.
//
// So Executes marks the fetches that run dependency-authored code, and Fetchable
// is the ONE predicate that reads it. Today it refuses them all, and no
// configuration turns it on: a switch here would only be a way to lose the
// argument at three in the morning.

import (
	"os/exec"
	"path"
	"slices"
	"strings"
)

// Lang is one language this daemon can speak.
type Lang struct {
	// Name is BOTH the table key and the LSP languageId sent on didOpen. One
	// string, so a language cannot be called one thing here and another on the
	// wire. (The per-file refinement TypeScript needs — tsx vs jsx vs plain js —
	// is a property of the FILE, not the language, and lives in ID.)
	Name string

	// Start is the argv that runs the server speaking JSON-RPC on its stdio.
	Start []string

	// Roots are the marker files that make a directory a module of this
	// language. They locate the FETCH; the server itself is rooted at the tree.
	Roots []string

	// Exts are the file extensions this server answers for.
	Exts []string

	// Cache is this language's dependency cache, as a subdirectory of the
	// daemon's dependency root. It is bound writable during Fetch and read-only
	// during Serve, and it is the origin a definition OUTSIDE the tree is named
	// against — so for Go it is GOMODCACHE itself, which makes an external path
	// read as the module coordinate it is.
	Cache string

	// Fetch is the argv that populates Cache, run once per module directory.
	// Nil means the language has nothing to fetch.
	Fetch []string

	// Executes reports that Fetch runs code authored by the DEPENDENCIES rather
	// than only downloading them. It is the whole of the scripts-off policy's
	// input; Fetchable is the policy.
	Executes bool

	// Env is the environment both phases share. ${cache}, ${proxy} and ${sumdb}
	// are substituted from the daemon's configuration.
	Env []string

	// FetchEnv is added during Fetch, ServeEnv during Serve. This is where the
	// module proxy is named in one and turned off in the other.
	FetchEnv []string
	ServeEnv []string

	// Init is initializationOptions on the initialize request. It is where a
	// server that would otherwise run project code at load time is told not to.
	Init map[string]any
}

// table is every language this daemon speaks, keyed by Lang.Name.
var table = map[string]Lang{
	"go": {
		Name:  "go",
		Start: []string{"gopls", "serve", "-mode=stdio"},
		Roots: []string{"go.work", "go.mod"},
		Exts:  []string{".go"},
		Cache: "go",
		// `go mod download` resolves and verifies modules against the checksum
		// database. It does NOT build them, so no module's code runs: the Go
		// toolchain has no install-time hook to abuse. Executes stays false, and
		// this is the one fetch phase 1 actually performs.
		//
		// `all`, not the bare form, and that word is load-bearing. Bare `go mod
		// download` in a module at go1.17+ records only each dependency's
		// go.mod hash in go.sum — NOT the module zip's. The serve phase then
		// loads with -mod=readonly and no network, hits "missing go.sum entry",
		// and gopls answers null to every question with no error anywhere: a
		// service that silently never works. `all` records both hashes, for the
		// test closure too, which is what makes a _test.go file answerable.
		Fetch: []string{"go", "mod", "download", "all"},
		Env: []string{
			// GOTOOLCHAIN=local: a tenant's go.mod can name any Go version, and
			// the default would go and DOWNLOAD that toolchain — an unbounded
			// fetch in the fetch phase and an impossible one in the serve phase.
			// A repo that needs a newer Go degrades to unresolved imports, which
			// is the honest failure.
			"GOTOOLCHAIN=local",
			"GOMODCACHE=${cache}",
			// GOPATH and GOCACHE are ephemeral by design: /tmp is the only thing
			// a served process can write, and it dies with the process.
			"GOPATH=/tmp/gopath",
			"GOCACHE=/tmp/gocache",
			"GOENV=off",
			// GOROOT is set explicitly because the shipped `go` is built -trimpath,
			// so it carries no compiled-in root, and the jail gives it no way to
			// find one: os.Executable reads /proc/self/exe, and /proc is not bound
			// in (toolchainRead is a host allow-list, not a full filesystem). Without
			// this, `go` and every gopls subprocess die with "cannot find GOROOT
			// directory". /usr/local is bound (toolchainRead), so /usr/local/go — the
			// image's Go — is present at this path inside the jail.
			"GOROOT=/usr/local/go",
			// GOTELEMETRY=off stops the toolchain from spawning its counter child,
			// which also calls os.Executable and logs a failure against the absent
			// /proc. Telemetry is best-effort and never blocks a command, but the
			// jail has nothing to send and no reason to try.
			"GOTELEMETRY=off",
		},
		FetchEnv: []string{"GOPROXY=${proxy}", "GOSUMDB=${sumdb}", "GOFLAGS=-mod=mod"},
		// GOPROXY=off and -mod=readonly are belt to the seccomp braces: the serve
		// phase could not reach a proxy if it tried, and it cannot write the tree
		// to record having tried.
		ServeEnv: []string{"GOPROXY=off", "GOFLAGS=-mod=readonly"},
	},
	"rust": {
		Name:  "rust",
		Start: []string{"rust-analyzer"},
		Roots: []string{"Cargo.toml"},
		Exts:  []string{".rs"},
		Cache: "cargo",
		// `cargo fetch` downloads and unpacks; it does not compile, so no build.rs
		// runs. `cargo build` would, which is why the fetch is not that.
		Fetch: []string{"cargo", "fetch", "--locked"},
		// No RUSTUP_TOOLCHAIN, because there is no rustup: the image installs the
		// component tarballs, so `cargo` and `rustc` are the real binaries and
		// read no rust-toolchain.toml. A tenant cannot name a compiler this
		// deployment would then go and download — the Rust reading of
		// GOTOOLCHAIN=local above.
		Env: []string{"CARGO_HOME=${cache}"},
		// Offline is belt to the seccomp braces, exactly as GOPROXY=off is: the
		// serve phase can obtain no socket, and saying so gets a clean "not
		// downloaded" out of cargo instead of a connection that cannot be made.
		ServeEnv: []string{"CARGO_NET_OFFLINE=true"},
		// The fetch being safe is not enough: rust-analyzer COMPILES AND RUNS
		// build.rs and expands proc macros at workspace load, by default. That is
		// the same code execution the fetch was careful to avoid, arriving through
		// the server instead. Both are turned off here — scripts-off has to hold
		// for the server or it does not hold at all.
		Init: map[string]any{
			"cargo":     map[string]any{"buildScripts": map[string]any{"enable": false}},
			"procMacro": map[string]any{"enable": false},
		},
	},
	"typescript": {
		Name:  "typescript",
		Start: []string{"typescript-language-server", "--stdio"},
		Roots: []string{"tsconfig.json", "package.json"},
		Exts:  []string{".ts", ".tsx", ".js", ".jsx"},
		Cache: "npm",
		// --ignore-scripts is the whole reason this fetch is allowed: it is npm's
		// own switch for "place the tree, run none of its lifecycle hooks". The
		// .d.ts files under node_modules are what the server actually reads, and
		// they land in the TREE, so node_modules is reported repo-relative.
		Fetch: []string{"npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"},
		Env:   []string{"npm_config_cache=${cache}", "npm_config_update_notifier=false"},
		// And this is the other half of that bargain. Left alone,
		// typescript-language-server prefers the TREE's own
		// node_modules/typescript over the one beside it — it would load and RUN
		// dependency-authored JavaScript in the serve phase, which is precisely
		// the execution --ignore-scripts declined to perform one phase earlier.
		// Naming the path takes the user setting, which wins over the workspace
		// lookup, so the server is the image's pinned TypeScript and two
		// identical requests cannot be answered by two different compilers.
		Init: map[string]any{
			"tsserver": map[string]any{"path": "/usr/local/lib/node_modules/typescript/lib/tsserver.js"},
		},
	},
	"python": {
		Name:  "python",
		Start: []string{"pyright-langserver", "--stdio"},
		Roots: []string{"pyproject.toml", "setup.py", "requirements.txt", "pyrightconfig.json"},
		Exts:  []string{".py", ".pyi"},
		Cache: "uv",
		// uv sync BUILDS any dependency published only as an sdist, which runs
		// that dependency's setup.py / PEP-517 backend as us. --no-install-project
		// spares us the TREE's own build, not its dependencies'. So this one
		// executes, and therefore does not run: pyright reads .py/.pyi source and
		// resolves the stdlib and any vendored packages without it.
		Fetch:    []string{"uv", "sync", "--frozen", "--no-install-project"},
		Executes: true,
		Env:      []string{"UV_CACHE_DIR=${cache}", "UV_NO_PROGRESS=1"},
	},
	"cpp": {
		Name:  "cpp",
		Start: []string{"clangd"},
		Roots: []string{"compile_commands.json", "CMakeLists.txt"},
		Exts:  []string{".cpp", ".cc", ".cxx", ".c", ".h", ".hpp"},
		// No fetch: C++ has no dependency resolver to run. clangd answers from
		// compile_commands.json when the tree carries one, and degrades to
		// single-file mode when it does not.
	},
	"java": {
		Name: "java",
		// The project's own launcher rather than a hand-written `java -jar`. It
		// already asks Equinox for a CASCADED configuration, which is the one
		// thing an OSGi application needs to run from a read-only installation,
		// and copying that incantation here would be a second copy to keep right.
		//
		// What it does not do is name the WRITABLE half, and Equinox's fallback
		// for that is the home directory out of /etc/passwd — not $HOME, which is
		// why setting HOME does not contain it. In this image that is /home/lsp,
		// a path the jail does not bind, so the bundle cache would be written
		// nowhere. Naming it puts the cache and the workspace index on the jail's
		// own /tmp, where they die with the process that wrote them.
		//
		// -Xms256m overrides the launcher's hardcoded -Xms1G: a JVM per Java root
		// under a 6 GiB address-space ceiling is no place to commit a gigabyte
		// before the first question. The last -Xms wins and the launcher appends
		// these after its own.
		Start: []string{"jdtls",
			"--jvm-arg=-Xms256m",
			"--jvm-arg=-Xmx1G",
			"--jvm-arg=-Dosgi.configuration.area=/tmp/jdtls/config",
			// jdtls writes .project, .classpath and .settings/ into the PROJECT by
			// default. The tree is read-only while serving, so that is a failed
			// import rather than a modified tree; this keeps them in the workspace
			// metadata, which is where a server's bookkeeping belongs anyway.
			"--jvm-arg=-Djava.import.generatesMetadataFilesAtProjectRoot=false",
			"-data", "/tmp/jdtls/data",
		},
		Roots: []string{"pom.xml", "build.gradle", "build.gradle.kts"},
		Exts:  []string{".java"},
		// No fetch, and unlike C++ it is not for want of a resolver — Java has
		// two. It is that both of them ARE build tools. Maven resolves in-process
		// through m2e and runs the pom's plugins; Gradle runs the build script
		// itself, and its wrapper first downloads whichever distribution the tree
		// names. Every Java dependency fetch is dependency code executing, so
		// there is none, and jdtls answers from the tree's source and the JDK's.
		Env: []string{"JAVA_HOME=/usr/local/jdk"},
		// The same execution arriving through the SERVER instead of the fetch —
		// the shape rust's Init refuses. Both importers off, the Gradle wrapper's
		// download off, and autobuild off because a build is where an annotation
		// processor on the classpath would run. Name resolution needs none of
		// them: JDT indexes source, and that index is what answers.
		//
		// FLAT dotted keys, all of them. jdtls looks the literal dotted key up
		// first and only then walks nested maps, so either spelling works alone —
		// but a half-nested one matches nothing and says so nowhere.
		Init: map[string]any{
			"settings": map[string]any{
				"java.import.maven.enabled":          false,
				"java.import.gradle.enabled":         false,
				"java.import.gradle.wrapper.enabled": false,
				"java.maven.downloadSources":         false,
				"java.eclipse.downloadSources":       false,
				"java.autobuild.enabled":             false,
			},
		},
	},
	"php": {
		Name:  "php",
		Start: []string{"intelephense", "--stdio"},
		Roots: []string{"composer.json"},
		Exts:  []string{".php"},
		Cache: "composer",
		// --no-scripts --no-plugins is composer's own spelling of scripts-off, and
		// it is the bargain npm's --ignore-scripts makes: vendor/ is placed, none
		// of its authors' code runs. vendor/ lands in the TREE, so an answer
		// inside a dependency is reported repo-relative.
		Fetch: []string{"composer", "install", "--no-scripts", "--no-plugins", "--no-interaction"},
		Env:   []string{"COMPOSER_HOME=${cache}"},
		// intelephense keeps its index on disk and defaults it under the home
		// directory. /tmp is the jail's own tmpfs, so naming it makes the index
		// per-process and it dies with the server — and there is nothing to
		// invalidate, because a root is immutable.
		Init: map[string]any{
			"storagePath":       "/tmp/intelephense/workspace",
			"globalStoragePath": "/tmp/intelephense/global",
		},
	},
	"ruby": {
		Name:  "ruby",
		Start: []string{"ruby-lsp"},
		Roots: []string{"Gemfile"},
		Exts:  []string{".rb", ".rake", ".gemspec"},
		Cache: "bundle",
		// `bundle install` COMPILES: a gem with a native extension runs its
		// extconf.rb and then make, as us. So this one executes and therefore does
		// not run, the same answer python gets. ruby-lsp indexes the interpreter's
		// own library directory and the core signatures shipped inside the rbs
		// gem, so the standard library resolves without any of it.
		Fetch:    []string{"bundle", "install"},
		Executes: true,
		// BUNDLE_GEMFILE IS LOAD-BEARING, and not for what it names. ruby-lsp's
		// launcher asks only whether this variable is SET; when it is not, it
		// creates a .ruby-lsp directory in the tree and shells out to `bundle
		// install` before the server starts — a write to a read-only tree and a
		// download in the phase that has no socket. Any value at all takes that
		// path off the table, and this one names nothing, so what gets indexed is
		// the workspace and the interpreter, never a half-installed bundle.
		Env: []string{"BUNDLE_GEMFILE=/nonexistent/Gemfile", "BUNDLE_PATH=${cache}"},
	},
}

// Fetchable reports whether l's dependency fetch may run. See the scripts-off
// note at the top of this file: it is one predicate, in one place, read by the
// one caller that runs a fetch.
func Fetchable(l Lang) bool { return len(l.Fetch) > 0 && !l.Executes }

// Available reports whether this image can actually run l's server. It is what
// keeps the table from promising more than the deployment ships.
func (l Lang) Available() bool {
	if len(l.Start) == 0 {
		return false
	}
	_, err := exec.LookPath(l.Start[0])
	return err == nil
}

// Speaks reports whether any file in the tree is one l answers for.
func (l Lang) Speaks(paths []string) bool {
	for _, p := range paths {
		if slices.Contains(l.Exts, strings.ToLower(path.Ext(p))) {
			return true
		}
	}
	return false
}

// Modules are the directories in the tree that carry one of l's markers — where
// a dependency fetch has to run. Slash-separated and tree-relative; "." is the
// tree root. A monorepo with several modules gets several fetches, and a tree
// with no marker gets none, which is the right answer for a language server
// asked about a loose file.
func (l Lang) Modules(paths []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range paths {
		if !slices.Contains(l.Roots, path.Base(p)) {
			continue
		}
		dir := path.Dir(p)
		if !seen[dir] {
			seen[dir] = true
			out = append(out, dir)
		}
	}
	slices.Sort(out)
	return out
}

// ID is the LSP languageId for one FILE. It is Name for every language but
// TypeScript, whose server distinguishes four dialects that share one toolchain —
// and gets the wrong answer for a React file told it is plain TypeScript.
func (l Lang) ID(p string) string {
	if l.Name != "typescript" {
		return l.Name
	}
	switch strings.ToLower(path.Ext(p)) {
	case ".tsx":
		return "typescriptreact"
	case ".jsx":
		return "javascriptreact"
	case ".js":
		return "javascript"
	default:
		return "typescript"
	}
}

// langFor picks the language for a tree-relative path by extension.
//
// Extension, not markers, decides — the question is "which server answers about
// THIS file", and a polyglot repo (a Go service with a TypeScript console) has
// several right answers at once, one per file.
func langFor(p string) (Lang, bool) {
	ext := strings.ToLower(path.Ext(p))
	if ext == "" {
		return Lang{}, false
	}
	// Deterministic: map iteration is randomized, and a file that resolved to a
	// different server between two identical requests would answer differently
	// for no reason the caller can see. Names are walked in sorted order.
	for _, name := range names {
		if l := table[name]; slices.Contains(l.Exts, ext) {
			return l, true
		}
	}
	return Lang{}, false
}

// names is table's keys in sorted order — the tie-break that makes langFor a
// function of its argument alone.
var names = func() []string {
	out := make([]string, 0, len(table))
	for name := range table {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}()
