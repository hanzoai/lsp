// Command lsp is the jailed language-server daemon.
//
// It holds immutable per-(org, repo, commit) working trees on a volume, runs a
// language server over each one inside a jail with no network, and answers
// position questions about them: hover, locate, symbols, diagnostics, complete.
//
// The answer it exists for is a definition that leaves the repository and lands
// in a dependency — which requires fetching that dependency and type-checking
// both, which requires running a third-party binary over untrusted bytes, which
// is why this is a separate daemon behind a jail. See internal/jail for the two
// phases and the invariant between them, and LLM.md for the wire contract.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/hanzoai/lsp/internal/jail"
	"github.com/hanzoai/lsp/internal/lsp"
)

func main() {
	// FIRST. If this invocation is a jail child — a re-exec of ourselves inside
	// new namespaces — it builds its jail and execs the language server, and
	// never returns. In the daemon process this does nothing. It must precede
	// every other line so the child stays minimal.
	jail.Child()

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg := lsp.Config{
		Roots: env("LSP_ROOTS", "/var/lib/lsp/roots"),
		Deps:  env("LSP_DEPS", "/var/lib/lsp/deps"),
		Stage: env("LSP_STAGE", "/tmp/jail"),
		Proxy: env("LSP_PROXY", "https://proxy.golang.org,direct"),
		Sumdb: env("LSP_SUMDB", "sum.golang.org"),
	}
	for _, dir := range []string{cfg.Roots, cfg.Deps, cfg.Stage} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			log.Error("prepare directory", "dir", dir, "err", err)
			os.Exit(1)
		}
	}

	svc := lsp.New(cfg, os.Getenv("LSP_KEY"), log)
	defer svc.Close()

	// Prove the jail on THIS host before accepting anything. A pod where it does
	// not initialize still boots — the probes must answer — but every request
	// that would run a language server is refused. This daemon never parses
	// tenant bytes outside a jail it has watched work.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	svc.Prove(ctx)
	cancel()

	listen := env("LSP_LISTEN", ":8000")
	srv := &http.Server{
		Addr:              listen,
		Handler:           svc.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
		// No WriteTimeout: a cold root is a dependency fetch and a first index,
		// legitimately minutes. The bounds on that work are in the daemon —
		// per-fetch deadlines, a cold-start semaphore and the jail's rlimits —
		// not in a socket timeout that would cut an honest request in half.
	}

	stop, done := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer done()

	errs := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", listen, "roots", cfg.Roots, "deps", cfg.Deps)
		errs <- srv.ListenAndServe()
	}()

	select {
	case err := <-errs:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("serve", "err", err)
			os.Exit(1)
		}
	case <-stop.Done():
		log.Info("shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Error("shutdown", "err", err)
			os.Exit(1)
		}
	}
}

func env(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}
