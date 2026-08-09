//go:build linux

package jail

import (
	"context"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestMain gives the test binary the daemon's own first line.
//
// WITHOUT IT NO JAIL TEST CAN PASS. A jail re-execs `self`, and under `go test`
// self is the TEST BINARY, whose main is testing's rather than the daemon's — so
// the child re-ran the whole suite, printed "PASS", and the canary compared
// "PASS" against "socket=denied". Probe then reported that the phase boundary
// was not in force, and the test skipped, blaming the host.
//
// That is the worst shape a security test can have: honest-looking environmental
// scepticism that is structurally incapable of running. main() calls Child()
// first thing for this exact reason; the test binary has to do the same.
func TestMain(m *testing.M) {
	Child()
	os.Exit(m.Run())
}

// TestFilterIsTheBoundary interprets the cBPF program exactly as the kernel's
// engine would and pins, for BOTH phases, the three things the filter exists to
// say. It enters no seccomp mode and needs no privilege, so it runs in any Linux
// CI — which matters, because the arithmetic it checks is where an off-by-one
// would silently ALLOW a denied syscall and nothing else would notice.
func TestFilterIsTheBoundary(t *testing.T) {
	for _, p := range []phase{serve, fetch} {
		prog := filter(p)
		eval := interpreter(t, prog)

		// A different audit arch is KILLed whatever the number: the i386 ABI's
		// numbers mean other things and would sail past the compares below.
		const auditArchI386 = 0x40000003
		if got := eval(call{arch: auditArchI386, nr: 41}); got != retKill {
			t.Fatalf("%s: i386 arch = 0x%x, want KILL", p, got)
		}
		// Every denied number reaches the ERRNO terminal, and its x32 spelling is
		// KILLed rather than slipping past the numeric compare.
		for _, nr := range denied(p) {
			if got := eval(call{arch: auditArchAMD64, nr: nr}); got != retErrno {
				t.Fatalf("%s: denied nr %d = 0x%x, want ERRNO", p, nr, got)
			}
			if got := eval(call{arch: auditArchAMD64, nr: nr | x32Bit}); got != retKill {
				t.Fatalf("%s: x32 of denied nr %d = 0x%x, want KILL", p, nr, got)
			}
		}
		// The x32 ABI is refused wholesale, not only for the denied numbers.
		if got := eval(call{arch: auditArchAMD64, nr: 0 | x32Bit}); got != retKill {
			t.Fatalf("%s: x32 read = 0x%x, want KILL", p, got)
		}
		// read(0) and openat(257) are not denied — a toolchain's surface is wide
		// and the filter must not become an allow-list of everything.
		for _, nr := range []uint32{0, 257} {
			if got := eval(call{arch: auditArchAMD64, nr: nr}); got != retAllow {
				t.Fatalf("%s: nr %d = 0x%x, want ALLOW", p, nr, got)
			}
		}
		// io_uring is denied in BOTH phases: a socket-only deny is not egress
		// containment, because IORING_OP_SOCKET issues no socket() syscall.
		for _, nr := range []uint32{sysIoUringSetup, sysIoUringEnter, sysIoUringRegister} {
			if got := eval(call{arch: auditArchAMD64, nr: nr}); got != retErrno {
				t.Fatalf("%s: io_uring nr %d = 0x%x, want ERRNO", p, nr, got)
			}
		}
	}
}

// TestSocketpairIsDecidedByItsFamily pins the one place this filter reads an
// ARGUMENT, in both phases.
//
// AF_UNIX has to pass or Node cannot start a child at all — libuv gives a child
// its stdio through a socketpair, so denying it cost TypeScript its server
// rather than costing anyone a network. Every other family has to fail, or the
// claim that no fd to a network exists stops being a property of this program
// and becomes a fact about which families the kernel implements.
//
// The two edges of that compare are the whole test: they are hand-computed
// offsets over a list whose length changes with the phase, so an off-by-one
// here reads as ALLOW for a family that should be refused.
func TestSocketpairIsDecidedByItsFamily(t *testing.T) {
	for _, p := range []phase{serve, fetch} {
		eval := interpreter(t, filter(p))

		if got := eval(call{arch: auditArchAMD64, nr: syscall.SYS_SOCKETPAIR, arg0: afUnix}); got != retAllow {
			t.Errorf("%s: socketpair(AF_UNIX) = 0x%x, want ALLOW — a language server cannot fork without it", p, got)
		}
		// AF_INET, AF_INET6, AF_NETLINK, AF_PACKET, and a family nobody named.
		for _, family := range []uint32{0, 2, 10, 16, 17, 40} {
			if got := eval(call{arch: auditArchAMD64, nr: syscall.SYS_SOCKETPAIR, arg0: family}); got != retErrno {
				t.Errorf("%s: socketpair(family %d) = 0x%x, want ERRNO", p, family, got)
			}
		}
		// The carve-out is for socketpair alone: socket() is still how a network
		// fd is obtained, and the serve phase still refuses it whatever it names.
		if got := eval(call{arch: auditArchAMD64, nr: syscall.SYS_SOCKET, arg0: afUnix}); p == serve && got != retErrno {
			t.Errorf("serve: socket(AF_UNIX) = 0x%x, want ERRNO — the carve-out must not have widened to socket", got)
		}
	}
}

// TestPhasesDifferOnlyByTheNetwork is the invariant stated as a test: Serve can
// obtain no socket, Fetch can, and that is the ONLY thing that separates them.
// If someone ever adds a second difference, or removes this one, this fails.
func TestPhasesDifferOnlyByTheNetwork(t *testing.T) {
	serveEval := interpreter(t, filter(serve))
	fetchEval := interpreter(t, filter(fetch))

	for _, nr := range network {
		if got := serveEval(call{arch: auditArchAMD64, nr: nr}); got != retErrno {
			t.Fatalf("serve: nr %d = 0x%x, want ERRNO — an untrusted process could open a socket", nr, got)
		}
		if got := fetchEval(call{arch: auditArchAMD64, nr: nr}); got != retAllow {
			t.Fatalf("fetch: nr %d = 0x%x, want ALLOW — the fetch phase could not download", nr, got)
		}
	}
	// Everything else agrees.
	for _, nr := range escape {
		if serveEval(call{arch: auditArchAMD64, nr: nr}) != retErrno ||
			fetchEval(call{arch: auditArchAMD64, nr: nr}) != retErrno {
			t.Fatalf("nr %d is not denied in both phases", nr)
		}
	}
}

// TestThePlanHidesNothing is the bug this daemon shipped with, as an assertion
// that needs no kernel and no privileges at all.
//
// A mount whose path is an ANCESTOR of an earlier one covers it. Nothing fails
// when it happens — the earlier mount is still there and simply cannot be seen —
// so the child dies later, on chdir or exec, with ENOENT on a path that plainly
// exists outside the jail. The writable /tmp used to be mounted AFTER the binds,
// which erased every bind under /tmp; the staging directory lives under /tmp, and
// so does a `go test` binary, so the self-test masked its own working tree,
// exited 126, and took the whole daemon out of service.
//
// The cases below are the real shapes: a working tree under /tmp, a cache under
// /tmp, and paths at every depth. If anyone reorders plan() so that a later mount
// can swallow an earlier one, this fails here rather than on a node.
func TestThePlanHidesNothing(t *testing.T) {
	for _, p := range []phase{serve, fetch} {
		for _, work := range []string{"/tmp/jail/work", "/var/lib/lsp/roots/x", "/tmp"} {
			ms := plan(p, work,
				[]string{"/usr/local/go", "/etc/ssl/certs", "/tmp/toolchain", "/lib"},
				[]string{"/tmp/deps/go", "/var/lib/lsp/deps"}, 16)
			for i, m := range ms {
				for _, before := range ms[:i] {
					if covers(m.path, before.path) {
						t.Fatalf("%s work=%s: %s is mounted after %s and hides it",
							p, work, m.path, before.path)
					}
				}
			}
		}
	}
}

// TestThePlanIsThePhase pins the filesystem half of the invariant the two phases
// exist to keep, and the one path that is not optional.
func TestThePlanIsThePhase(t *testing.T) {
	const work, cache, tool = "/var/lib/lsp/roots/x", "/var/lib/lsp/deps/go", "/usr/local/go"
	for _, c := range []struct {
		p     phase
		write bool
	}{{serve, false}, {fetch, true}} {
		var sawWork, sawTmp bool
		for _, m := range plan(c.p, work, []string{tool}, []string{cache}, 16) {
			// The jail's OWN entries — its filesystems and its device nodes — are
			// the same in both phases and are pinned by
			// TestTheJailBringsItsOwnFilesystems. This test is about the paths a
			// CALLER supplied.
			if m.fs != "" && m.path != "/tmp" || strings.HasPrefix(m.path, "/dev/") {
				continue
			}
			switch m.path {
			case "/tmp":
				// The jail's own scratch: writable in BOTH phases, and it is the
				// only thing a served process may write to that survives a syscall.
				sawTmp = true
				if !m.write || m.src != "" {
					t.Fatalf("%s: /tmp must be a writable tmpfs, got %+v", c.p, m)
				}
			case work:
				sawWork = true
				if !m.must {
					t.Fatalf("%s: the working tree must be required, not skipped when absent", c.p)
				}
				fallthrough
			case cache:
				if m.write != c.write {
					t.Fatalf("%s: %s writable = %v, want %v", c.p, m.path, m.write, c.write)
				}
			default:
				if m.write {
					t.Fatalf("%s: %s is writable and nothing but the tree and the cache may be",
						c.p, m.path)
				}
			}
		}
		if !sawWork || !sawTmp {
			t.Fatalf("%s: plan is missing the working tree or /tmp", c.p)
		}
	}
}

// TestTheJailBringsItsOwnFilesystems pins the two filesystems the jail creates
// rather than borrows, and the fact that no argument can reach them.
//
// /tmp is a private tmpfs that dies with the process and is the only thing a
// served program may write. /proc is a private procfs mounted inside the jail's
// own PID namespace — it shows the jailed process and its children and nothing
// of the host, and it is read-only. A caller naming either as a tree or a cache
// must not be able to swap a host directory in for it: a boundary that an
// argument can replace is not a boundary.
func TestTheJailBringsItsOwnFilesystems(t *testing.T) {
	for _, p := range []phase{serve, fetch} {
		var tmp, proc bool
		for _, m := range plan(p, "/tmp", []string{"/proc", "/tmp"}, []string{"/proc"}, 16) {
			switch m.path {
			case "/tmp":
				tmp = true
				if m.fs != "tmpfs" || m.src != "" {
					t.Fatalf("%s: a caller replaced the jail's /tmp with %+v", p, m)
				}
				if !m.write {
					t.Fatalf("%s: the jail's /tmp must be writable", p)
				}
			case "/proc":
				proc = true
				if m.fs != "proc" || m.src != "" {
					t.Fatalf("%s: a caller replaced the jail's /proc with %+v", p, m)
				}
				// Read-only, and never a place to execute from. os.Executable
				// needs to READ /proc/self/exe; nothing needs to write /proc.
				if m.write {
					t.Fatalf("%s: /proc must be read-only", p)
				}
				if m.flag&syscall.MS_NOEXEC == 0 || m.flag&syscall.MS_NOSUID == 0 ||
					m.flag&syscall.MS_NODEV == 0 {
					t.Fatalf("%s: /proc must be nosuid+nodev+noexec, flags=%#x", p, m.flag)
				}
			}
		}
		if !tmp || !proc {
			t.Fatalf("%s: the jail must bring its own /tmp and /proc", p)
		}

		// The device nodes, in BOTH phases. Bound (a userns cannot mknod) and
		// writable, because Go's os/exec opens /dev/null for every subprocess
		// with no stdin and a read-only mount makes that EROFS. Required, so a
		// host without them fails at the cause rather than inside a toolchain.
		want := map[string]bool{
			"/dev/null": false, "/dev/zero": false, "/dev/full": false,
			"/dev/random": false, "/dev/urandom": false,
		}
		for _, m := range plan(p, "/roots/x", nil, nil, 16) {
			if _, ok := want[m.path]; !ok {
				continue
			}
			want[m.path] = true
			if m.src != m.path || !m.write || !m.must {
				t.Fatalf("%s: %s must be a required writable bind of itself, got %+v", p, m.path, m)
			}
		}
		for dev, saw := range want {
			if !saw {
				t.Fatalf("%s: the jail must bring %s — Go opens it for every subprocess", p, dev)
			}
		}
	}
}

// TestProbeProvesTheBoundaryOnThisHost runs the REAL jail in both phases, EXECS
// the canary inside it, and makes it report whether the kernel handed it a
// socket. It is the difference between a sandbox and a comment about one.
//
// IT SKIPS FOR EXACTLY ONE REASON: this host cannot create the namespaces, which
// a plain CI container cannot and gVisor's sentry can. Every other failure is
// this repository's and FAILS. That distinction is the test — it used to skip on
// any error at all, so a jail that built and then did not work reported itself as
// "not the target" and nobody ever saw it. Exit 126 skipped here for weeks.
//
// TestMain above is what lets it run: the jail re-execs `self`, which under
// `go test` is the test binary, and self-exec'ing a test suite proves nothing.
// Both `self` and the canary's working tree are under /tmp here, so this is also
// the on-target guard against the masking bug TestThePlanHidesNothing pins.
func TestProbeProvesTheBoundaryOnThisHost(t *testing.T) {
	if !Supported() {
		t.Skip("no jail on this build")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := Probe(ctx, t.TempDir()); err != nil {
		if errors.Is(err, ErrHost) {
			t.Skipf("this host cannot create namespaces, as expected off the gVisor target: %v", err)
		}
		t.Fatalf("the jail built on this host and did not work: %v", err)
	}
}

// covers reports whether a is b or an ancestor of it. Paths are cleaned by
// plan(), so this is a path comparison and not a string one: /ab is not under /a.
func covers(a, b string) bool {
	return a == b || strings.HasPrefix(b, strings.TrimSuffix(a, "/")+"/")
}

// call is one synthetic seccomp_data — the kernel's input to the filter, named
// rather than passed as a growing list of positions, because the filter now
// reads an ARGUMENT and a caller that got arch and arg0 the wrong way round
// would still compile.
type call struct {
	arch uint32
	nr   uint32
	arg0 uint32
}

// interpreter returns a function that runs prog against one call the way the
// kernel's cBPF engine does, for the four opcodes this filter uses.
func interpreter(t *testing.T, prog []insn) func(call) uint32 {
	t.Helper()
	return func(c call) uint32 {
		var a uint32
		for pc := 0; pc < len(prog); {
			f := prog[pc]
			switch f.code {
			case 0x20: // BPF_LD|BPF_W|BPF_ABS
				switch f.k {
				case 0:
					a = c.nr
				case 4:
					a = c.arch
				case 16:
					a = c.arg0
				default:
					t.Fatalf("load from unmodelled seccomp_data offset %d", f.k)
				}
				pc++
			case 0x15: // BPF_JMP|BPF_JEQ|BPF_K
				if a == f.k {
					pc += 1 + int(f.jt)
				} else {
					pc += 1 + int(f.jf)
				}
			case 0x45: // BPF_JMP|BPF_JSET|BPF_K
				if a&f.k != 0 {
					pc += 1 + int(f.jt)
				} else {
					pc += 1 + int(f.jf)
				}
			case 0x06: // BPF_RET|BPF_K
				return f.k
			default:
				t.Fatalf("unexpected opcode 0x%x at pc=%d", f.code, pc)
			}
		}
		t.Fatal("filter fell through without a RET")
		return 0
	}
}
