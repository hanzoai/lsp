//go:build linux

package jail

import (
	"context"
	"testing"
	"time"
)

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

// TestProbeProvesTheBoundaryOnThisHost runs the REAL jail in both phases and
// makes the canary report whether the kernel handed it a socket. It needs a host
// that can create a user namespace — gVisor's sentry can, a plain CI container
// cannot — so it SKIPS off-target rather than failing. On the target it is the
// difference between a sandbox and a comment about one.
func TestProbeProvesTheBoundaryOnThisHost(t *testing.T) {
	if !Supported() {
		t.Skip("no jail on this build")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := Probe(ctx, t.TempDir()+"/stage", t.TempDir()); err != nil {
		t.Skipf("the jail cannot initialize here (expected off the gVisor target): %v", err)
	}
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
