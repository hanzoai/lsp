//go:build linux

package jail

import (
	"context"
	"errors"
	"os"
	"strings"
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
		if got := eval(auditArchI386, 41); got != retKill {
			t.Fatalf("%s: i386 arch = 0x%x, want KILL", p, got)
		}
		// Every denied number reaches the ERRNO terminal, and its x32 spelling is
		// KILLed rather than slipping past the numeric compare.
		for _, nr := range denied(p) {
			if got := eval(auditArchAMD64, nr); got != retErrno {
				t.Fatalf("%s: denied nr %d = 0x%x, want ERRNO", p, nr, got)
			}
			if got := eval(auditArchAMD64, nr|x32Bit); got != retKill {
				t.Fatalf("%s: x32 of denied nr %d = 0x%x, want KILL", p, nr, got)
			}
		}
		// The x32 ABI is refused wholesale, not only for the denied numbers.
		if got := eval(auditArchAMD64, 0|x32Bit); got != retKill {
			t.Fatalf("%s: x32 read = 0x%x, want KILL", p, got)
		}
		// read(0) and openat(257) are not denied — a toolchain's surface is wide
		// and the filter must not become an allow-list of everything.
		for _, nr := range []uint32{0, 257} {
			if got := eval(auditArchAMD64, nr); got != retAllow {
				t.Fatalf("%s: nr %d = 0x%x, want ALLOW", p, nr, got)
			}
		}
		// io_uring is denied in BOTH phases: a socket-only deny is not egress
		// containment, because IORING_OP_SOCKET issues no socket() syscall.
		for _, nr := range []uint32{sysIoUringSetup, sysIoUringEnter, sysIoUringRegister} {
			if got := eval(auditArchAMD64, nr); got != retErrno {
				t.Fatalf("%s: io_uring nr %d = 0x%x, want ERRNO", p, nr, got)
			}
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
		if got := serveEval(auditArchAMD64, nr); got != retErrno {
			t.Fatalf("serve: nr %d = 0x%x, want ERRNO — an untrusted process could open a socket", nr, got)
		}
		if got := fetchEval(auditArchAMD64, nr); got != retAllow {
			t.Fatalf("fetch: nr %d = 0x%x, want ALLOW — the fetch phase could not download", nr, got)
		}
	}
	// Everything else agrees.
	for _, nr := range escape {
		if serveEval(auditArchAMD64, nr) != retErrno || fetchEval(auditArchAMD64, nr) != retErrno {
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
			switch m.path {
			case "/tmp":
				// The jail's own scratch: writable in BOTH phases, and it is the
				// only thing a served process may write.
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

// TestTheJailKeepsItsOwnTmp pins a boundary that must not be reachable from an
// argument. The jail's /tmp is a private tmpfs that dies with the process and is
// the only thing a served program may write; a caller naming /tmp as a tree or a
// cache must not be able to swap the host's directory in for it.
func TestTheJailKeepsItsOwnTmp(t *testing.T) {
	for _, m := range plan(fetch, "/tmp", []string{"/tmp"}, []string{"/tmp"}, 16) {
		if m.path == "/tmp" && m.src != "" {
			t.Fatalf("a caller replaced the jail's private /tmp with a bind of %s", m.src)
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

// interpreter returns a function that runs prog against a synthetic (arch, nr)
// the way the kernel's cBPF engine does, for the four opcodes this filter uses.
func interpreter(t *testing.T, prog []insn) func(arch, nr uint32) uint32 {
	t.Helper()
	return func(arch, nr uint32) uint32 {
		var a uint32
		for pc := 0; pc < len(prog); {
			f := prog[pc]
			switch f.code {
			case 0x20: // BPF_LD|BPF_W|BPF_ABS
				if f.k == 0 {
					a = nr
				} else {
					a = arch
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
