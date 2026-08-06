module github.com/hanzoai/lsp

// Jailed language-server daemon.
//
// STDLIB ONLY by design: this process runs third-party language servers over
// tenant source, so the dependency surface it can be attacked through is kept at
// zero (net/http, encoding/json, os/exec, syscall, crypto/subtle). The isolation
// is a Go-native jailer — namespaces + minimal chroot + seccomp — running under
// gVisor; there is no external jailer binary, the daemon re-execs itself.
go 1.26.4
