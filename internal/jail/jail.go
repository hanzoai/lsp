// Package jail runs a process with the kernel taken away from it: new
// user/mount/pid/ipc/uts namespaces, a chroot holding nothing but the paths it
// was handed, rlimits, no_new_privs, and a seccomp-bpf filter.
//
// # Provenance — this is a copy, and it should not stay one
//
// This is hanzoai/code-exec's jailer (internal/codeexec/jail_linux.go at
// d2794ce), lifted here and generalized from "one short exec" to "either phase
// of a language-server root", plus one fix: the child now locks its OS thread
// before installing seccomp (see jail_linux.go).
//
// Two services now carry the same seccomp filter in two files, which is one file
// too many. It SHOULD be published as github.com/hanzoai/jail and imported by
// both — the filter is a security boundary, and a boundary that exists twice
// drifts. Publishing a shared module is a CTO call and is not made here. Until
// it is, a change to the filter must land in BOTH repos.
//
// # Two phases, and the invariant between them
//
// A jailed process is in exactly one of two phases, and the difference between
// them is the whole security model of this daemon:
//
//	Fetch — MAY open sockets, and MAY write the paths in Spec.Write and
//	        Spec.Work. It runs FIRST-PARTY toolchain code in a download-only
//	        mode (`go mod download`) over a manifest of dependency names. No
//	        dependency's own code runs: the Go toolchain has no install hook.
//
//	Serve — may NOT open a socket, by construction: seccomp denies
//	        socket/socketpair and the io_uring family, so there is no call that
//	        returns a socket fd and therefore no egress, no loopback and no DNS.
//	        EVERY bind is read-only, including the working tree. It parses
//	        UNTRUSTED bytes — the tenant's source and its dependencies'.
//
// The invariant is the separation itself: THE NETWORK AND UNTRUSTED BYTES ARE
// NEVER IN THE SAME PROCESS. Phase is not a field a caller fills in; it is which
// function the caller called, so there is no value to get wrong and no
// configuration that can weaken it.
package jail

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
)

// phase is Fetch or Serve. Unexported: it is chosen by which constructor ran.
type phase string

const (
	fetch phase = "fetch"
	serve phase = "serve"
)

// Spec is one jailed process.
type Spec struct {
	// Root is the directory the jail mounts a tmpfs over and chroots into. It
	// is the process's new "/" and contains nothing but mountpoints — the
	// daemon's own rootfs, /etc/shadow and any mounted secret are absent.
	Root string

	// Work is the working tree, bound into the jail AT ITS OWN ABSOLUTE PATH.
	Work string

	// Dir is the working directory, and must be inside one of the binds. Empty
	// means Work. It is separate because a dependency fetch runs in ONE module
	// directory while needing the whole tree bound around it.
	Dir string

	// Read are paths bound read-only, each AT ITS OWN ABSOLUTE PATH: the
	// toolchain, the dependency cache, the CA store. A path that does not exist
	// is skipped, so one image layout does not break another.
	Read []string

	// Write are paths the Fetch phase may write — the dependency cache it is
	// populating. Serve binds them read-only along with everything else.
	Write []string

	// Argv is the program and its arguments. argv[0] is an absolute path: PATH
	// lookup happens in the parent, where PATH means something.
	Argv []string

	// Env is the environment the program runs under. It is BUILT by the caller,
	// never inherited — this daemon's own environment holds its service key.
	Env []string

	Limits Limits
}

// Limits are the per-process ceilings. A zero field is NOT applied, which is how
// a long-lived language server opts out of RLIMIT_CPU: a total-CPU-seconds cap
// is a bound on a batch job, and on a warm server it is a scheduled execution.
type Limits struct {
	AddrMiB  uint64 // RLIMIT_AS, MiB — virtual address space per process
	CPU      uint64 // RLIMIT_CPU, seconds — zero for a long-lived server
	FsizeMiB uint64 // RLIMIT_FSIZE, MiB — one file's size
	Nofile   uint64 // RLIMIT_NOFILE
	Nproc    uint64 // RLIMIT_NPROC, per-uid — the fork-bomb bound
	TmpMiB   uint64 // size of the tmpfs mounted at /tmp inside the jail
}

// Fetch builds the command for the network phase: sockets permitted, Work and
// Write writable. What runs under it must be first-party toolchain code in a
// download-only mode — see the package comment.
func Fetch(ctx context.Context, s Spec) *exec.Cmd { return command(ctx, fetch, s) }

// Serve builds the command for the untrusted phase: no socket, everything
// read-only. What runs under it parses tenant bytes.
func Serve(ctx context.Context, s Spec) *exec.Cmd { return command(ctx, serve, s) }

// ── the control channel between parent and jail child ────────────────────────
//
// The parent hands the child its instructions through the environment, and the
// child strips every one of them before exec'ing the program, so none reaches
// the jailed process.

const (
	envPhase  = "HANZO_JAIL"        // "fetch" | "serve"; absent ⇒ not a jail child
	envRoot   = "HANZO_JAIL_ROOT"   //
	envWork   = "HANZO_JAIL_WORK"   //
	envDir    = "HANZO_JAIL_DIR"    //
	envRead   = "HANZO_JAIL_READ"   // unit-separated
	envWrite  = "HANZO_JAIL_WRITE"  // unit-separated
	envArgv   = "HANZO_JAIL_ARGV"   // unit-separated
	envAddr   = "HANZO_JAIL_AS"     //
	envCPU    = "HANZO_JAIL_CPU"    //
	envFsize  = "HANZO_JAIL_FSIZE"  //
	envNofile = "HANZO_JAIL_NOFILE" //
	envNproc  = "HANZO_JAIL_NPROC"  //
	envTmp    = "HANZO_JAIL_TMP"    //
)

// envPrefix is what the child strips: one prefix covers every control variable,
// so adding one above cannot leak it into a jailed process by omission.
const envPrefix = "HANZO_JAIL"

// unit joins a list into one environment variable. It is the ASCII unit
// separator, a control character that cannot occur in a path and that — unlike
// NUL — an environment accepts.
const unit = "\x1f"

// control renders a Spec as the child's control environment.
func control(p phase, s Spec) []string {
	return []string{
		envPhase + "=" + string(p),
		envRoot + "=" + s.Root,
		envWork + "=" + s.Work,
		envDir + "=" + s.Dir,
		envRead + "=" + strings.Join(s.Read, unit),
		envWrite + "=" + strings.Join(s.Write, unit),
		envArgv + "=" + strings.Join(s.Argv, unit),
		envAddr + "=" + strconv.FormatUint(s.Limits.AddrMiB, 10),
		envCPU + "=" + strconv.FormatUint(s.Limits.CPU, 10),
		envFsize + "=" + strconv.FormatUint(s.Limits.FsizeMiB, 10),
		envNofile + "=" + strconv.FormatUint(s.Limits.Nofile, 10),
		envNproc + "=" + strconv.FormatUint(s.Limits.Nproc, 10),
		envTmp + "=" + strconv.FormatUint(s.Limits.TmpMiB, 10),
	}
}

// setupFailed is the exit code the child uses when it could not build the jail.
// It is distinct from anything the jailed program would return, so a sandbox
// failure is never read as a program result.
const setupFailed = 126

// ── the canary ───────────────────────────────────────────────────────────────

// canary is the single argument that makes this binary report whether the kernel
// would hand it a socket, and then exit. Probe jails it and reads what it says.
//
// AN ARGUMENT, NOT A VARIABLE, and that is forced: the child STRIPS every
// HANZO_JAIL variable before exec'ing, so nothing in the control environment can
// survive into the program. The canary has to be reachable the way the program
// is reached — through argv — which is the point. It is exec'd across the same
// boundary a language server crosses, so it proves the exec, not just the filter.
const canary = "canary"

// canaryOK is what the canary prints when it could open a socket, and canaryDeny
// what it prints when the kernel refused. Probe reads exactly these.
const (
	canaryOK   = "socket=open"
	canaryDeny = "socket=denied"
)
