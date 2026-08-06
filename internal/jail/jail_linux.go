//go:build linux

package jail

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// ── how the jail is entered ──────────────────────────────────────────────────
//
// The daemon RE-EXECS ITSELF. command() builds an *exec.Cmd that runs this same
// binary with the control environment set and SysProcAttr asking the kernel for
// new user/mount/pid/ipc/uts namespaces. main() calls Child() first thing, so the
// re-exec'd process takes the child path below, builds its jail, and execs the
// real program as its last act.
//
// WHY NOT nsjail: nsjail is incompatible with gVisor. It calls
// prctl(PR_SET_SECUREBITS) unconditionally during uid setup, which the gVisor
// sentry does not implement, so the child never launches; it also creates a
// cgroup namespace and a netlink-configured net namespace that gVisor rejects,
// and no flag turns those off. Proven on-target. A small auditable Go component
// avoids all three and keeps this repo dependency-free.
//
// WHY NO NET NAMESPACE: the same gVisor incompatibility. The network boundary is
// therefore at the SYSCALL layer — seccomp denies socket/socketpair and the
// io_uring family, so the served process can obtain no socket fd at all. That is
// the property an empty net namespace would give, achieved where gVisor allows.

// self is this binary, re-exec'd as the jail child.
var self, selfErr = os.Executable()

// Supported reports whether a jail can be built on this platform and binary.
// On Linux it is true whenever the executable path resolved: whether the HOST
// can actually create the namespaces is what Probe answers.
func Supported() bool { return selfErr == nil && self != "" }

// command builds the re-exec. The child's environment is the control variables
// plus the clean environment the caller built for the program; this process's
// own environment — which holds the service key — is not passed.
func command(ctx context.Context, p phase, s Spec) *exec.Cmd {
	c := exec.CommandContext(ctx, self)
	c.Env = append(control(p, s), s.Env...)
	c.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS |
			syscall.CLONE_NEWPID | syscall.CLONE_NEWIPC | syscall.CLONE_NEWUTS,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		GidMappingsEnableSetgroups: false,
		// No Pdeathsig: in Go it fires when the CREATING OS THREAD exits, not the
		// process, and the runtime retires threads freely — it would kill warm
		// language servers at random. The child is PID 1 of a new PID namespace,
		// so killing it already takes everything it forked with it; that is the
		// reaping guarantee, and it is the kernel's rather than a signal's.
	}
	return c
}

// Child runs the jail-child path and never returns, if this process IS a jail
// child. In the daemon process it does nothing. main() calls it first, before any
// server setup, so the child stays minimal.
func Child() {
	p := phase(os.Getenv(envPhase))
	if p != fetch && p != serve {
		return
	}
	if err := run(p); err != nil {
		fmt.Fprintln(os.Stderr, "jail:", err)
		os.Exit(setupFailed)
	}
	os.Exit(setupFailed) // run() execs on success; arriving here means exec failed
}

// run executes inside the new namespaces, as root within its own user namespace
// and as the daemon's non-root uid outside it. It builds the chroot, applies the
// limits, installs the filter, and execs.
func run(p phase) error {
	// LOCK THE THREAD FIRST. no_new_privs and PR_SET_SECCOMP apply to the
	// CALLING THREAD, and syscall.Exec execs the calling thread. If the Go
	// scheduler moved this goroutine between installing the filter and exec'ing,
	// the exec'd program would inherit NO filter and the sandbox would silently
	// not exist. This is the fix over the code-exec original, where the sequence
	// is short enough that it has always held in practice — "in practice" not
	// being a security boundary.
	runtime.LockOSThread()

	root := os.Getenv(envRoot)
	work := os.Getenv(envWork)
	if root == "" || work == "" {
		return errors.New("missing root or work")
	}
	argv := split(os.Getenv(envArgv))
	canary := os.Getenv(envCanary) == "1"
	if len(argv) == 0 && !canary {
		return errors.New("empty argv")
	}

	// (a) A private mount tree, so nothing built here propagates back out.
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make-rprivate: %w", err)
	}
	// A tmpfs as the chroot base. It holds only mountpoints, so it can be tiny —
	// and it must be, since a tmpfs is charged to the pod's memory.
	if err := os.MkdirAll(root, 0o755); err != nil {
		return fmt.Errorf("mkdir root: %w", err)
	}
	if err := syscall.Mount("tmpfs", root, "tmpfs", 0, "mode=0755,size=8m"); err != nil {
		return fmt.Errorf("mount root: %w", err)
	}

	// (b) Bind what the caller allowed, EACH AT ITS OWN ABSOLUTE PATH.
	//
	// Same-path is not a convenience. A language server reports every answer as a
	// file: URI of a path it was given, so a jail that renamed /roots/x to /work
	// would hand the caller paths that name nothing — or would need a translation
	// table, which is a second place for the two sides to disagree. There is no
	// translation here because there is nothing to translate.
	//
	// Serve binds EVERYTHING read-only, including the working tree: a root is
	// immutable and a language server has no business writing to one. Fetch binds
	// Work and Write read-write, because populating a dependency cache is
	// precisely what it is for.
	for _, path := range split(os.Getenv(envRead)) {
		if err := bind(path, root, false); err != nil {
			return err
		}
	}
	writable := p == fetch
	for _, path := range split(os.Getenv(envWrite)) {
		if err := bind(path, root, writable); err != nil {
			return err
		}
	}
	if err := bind(work, root, writable); err != nil {
		return err
	}
	// A writable tmpfs /tmp: the ONLY thing a served process can write, and it
	// dies with the process. Build caches live here for exactly that reason.
	tmp := filepath.Join(root, "tmp")
	if err := os.MkdirAll(tmp, 0o1777); err != nil {
		return fmt.Errorf("mkdir /tmp: %w", err)
	}
	size := num(envTmp, 256)
	if err := syscall.Mount("tmpfs", tmp, "tmpfs", 0,
		fmt.Sprintf("mode=1777,size=%dm", size)); err != nil {
		return fmt.Errorf("mount /tmp: %w", err)
	}

	// (c) Enter it. The old root is gone; work is reachable at the same path it
	// had outside.
	if err := syscall.Chroot(root); err != nil {
		return fmt.Errorf("chroot: %w", err)
	}
	dir := os.Getenv(envDir)
	if dir == "" {
		dir = work
	}
	if err := syscall.Chdir(dir); err != nil {
		return fmt.Errorf("chdir %s: %w", dir, err)
	}

	// (d) Ceilings, then no_new_privs, then the filter. Order matters:
	// SECCOMP_MODE_FILTER requires no_new_privs for a non-root caller.
	if err := limits(); err != nil {
		return err
	}
	if _, _, e := syscall.Syscall6(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0, 0, 0, 0); e != 0 {
		return fmt.Errorf("no_new_privs: %w", e)
	}
	if err := seccomp(p); err != nil {
		return err
	}

	// (e) Either prove the boundary to ourselves, or become the program.
	if canary {
		probe()
		os.Exit(0)
	}
	if err := syscall.Exec(argv[0], argv, clean()); err != nil {
		return fmt.Errorf("exec %s: %w", argv[0], err)
	}
	return nil // unreachable
}

// bind mounts src inside the staging root at src's own path. A missing source is
// skipped: the bind list is the superset across image layouts, and a host that
// lacks /lib64 must not fail to jail.
func bind(src, root string, write bool) error {
	fi, err := os.Stat(src)
	if err != nil {
		return nil
	}
	dst := filepath.Join(root, src)
	if fi.IsDir() {
		err = os.MkdirAll(dst, 0o755)
	} else {
		if err = os.MkdirAll(filepath.Dir(dst), 0o755); err == nil {
			var f *os.File
			if f, err = os.OpenFile(dst, os.O_CREATE, 0o644); err == nil {
				err = f.Close()
			}
		}
	}
	if err != nil {
		return fmt.Errorf("bind target %s: %w", src, err)
	}
	if err := syscall.Mount(src, dst, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
		return fmt.Errorf("bind %s: %w", src, err)
	}
	if write {
		return nil
	}
	// A bind acquires read-only only on a second, remounting call.
	if err := syscall.Mount("", dst, "", syscall.MS_BIND|syscall.MS_REC|syscall.MS_REMOUNT|syscall.MS_RDONLY, ""); err != nil {
		return fmt.Errorf("seal %s: %w", src, err)
	}
	return nil
}

// limits applies the ceilings the parent chose. A zero is not applied — that is
// how a long-lived server declines RLIMIT_CPU, which would otherwise kill it
// after a fixed amount of work.
func limits() error {
	set := func(res int, v uint64, name string) error {
		if v == 0 {
			return nil
		}
		if err := syscall.Setrlimit(res, &syscall.Rlimit{Cur: v, Max: v}); err != nil {
			return fmt.Errorf("rlimit %s: %w", name, err)
		}
		return nil
	}
	if err := set(syscall.RLIMIT_AS, num(envAddr, 0)*1024*1024, "as"); err != nil {
		return err
	}
	if err := set(syscall.RLIMIT_CPU, num(envCPU, 0), "cpu"); err != nil {
		return err
	}
	if err := set(syscall.RLIMIT_FSIZE, num(envFsize, 0)*1024*1024, "fsize"); err != nil {
		return err
	}
	if err := set(syscall.RLIMIT_NOFILE, num(envNofile, 0), "nofile"); err != nil {
		return err
	}
	return set(rlimitNproc, num(envNproc, 0), "nproc")
}

// clean is the environment handed to the jailed program: this child's own
// environment minus every control variable, so none of them reaches it.
func clean() []string {
	out := make([]string, 0, len(os.Environ()))
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); strings.HasPrefix(k, envPrefix) {
			continue
		}
		out = append(out, kv)
	}
	return out
}

func split(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, unit)
}

func num(key string, def uint64) uint64 {
	if v, err := strconv.ParseUint(os.Getenv(key), 10, 64); err == nil {
		return v
	}
	return def
}

// ── the canary ───────────────────────────────────────────────────────────────

// probe runs INSIDE a fully built jail, after the filter is installed, on the
// thread the filter was installed on (run() locked it). It asks the kernel for a
// socket and reports what happened. That is the daemon proving the invariant
// about ITSELF on THIS host, rather than asserting it in a comment.
func probe() {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		fmt.Println(canaryDeny, err)
		return
	}
	syscall.Close(fd)
	fmt.Println(canaryOK)
}

// Probe builds a real jail in each phase and makes the canary tell it whether a
// socket was obtainable. It is the boot self-test, and it is the reason /readyz
// can be trusted: a host where the namespaces cannot be created, or where the
// filter did not take, fails here and the daemon then refuses every request
// rather than serving untrusted bytes next to a network.
//
// root and work are scratch directories the caller owns.
func Probe(ctx context.Context, root, work string) error {
	if !Supported() {
		return errors.New("jail: unsupported on this build")
	}
	for _, c := range []struct {
		p    phase
		want string
	}{
		{serve, canaryDeny},
		{fetch, canaryOK},
	} {
		spec := Spec{
			Root: root, Work: work,
			Env:    []string{envCanary + "=1"},
			Limits: Limits{AddrMiB: 1024, CPU: 10, Nofile: 64, Nproc: 32, TmpMiB: 16},
		}
		out, err := command(ctx, c.p, spec).Output()
		if err != nil {
			return fmt.Errorf("jail: %s canary did not run: %w", c.p, err)
		}
		got := strings.TrimSpace(string(out))
		if !strings.HasPrefix(got, c.want) {
			return fmt.Errorf("jail: %s canary reported %q, want %q — the phase boundary is not in force",
				c.p, got, c.want)
		}
	}
	return nil
}

// ── seccomp-bpf ──────────────────────────────────────────────────────────────
//
// A classic BPF program installed with prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER).
// It:
//   - KILLs any audit arch that is not x86_64, which stops the i386 ABI whose
//     syscall numbers differ entirely and would sail past a numeric filter;
//   - KILLs any syscall carrying the x32 bit (0x40000000), since x32 shares
//     AUDIT_ARCH_X86_64 with amd64 — the arch check alone does not catch it, yet
//     every x32 number is ORed with that bit and would dodge the numeric deny;
//   - returns ERRNO(EPERM) for the denied numbers;
//   - ALLOWs everything else, because a toolchain's syscall surface is wide and
//     an allow-list of it would be a list of everything.

// escape is denied in BOTH phases. Neither a module download nor a language
// server has any use for these, and each is a documented container-escape or
// sandbox-bypass primitive.
var escape = []uint32{
	// io_uring — the OTHER way to get a socket. Its ops (IORING_OP_SOCKET,
	// CONNECT, SEND, OPENAT …) do network and filesystem work WITHOUT issuing
	// socket()/connect(), so a socket-only deny would not be the whole boundary.
	// Denying the ring's setup means no ring exists to issue them from.
	sysIoUringSetup, sysIoUringEnter, sysIoUringRegister,
	// kernel keyring (container-escape CVEs)
	syscall.SYS_ADD_KEY, syscall.SYS_REQUEST_KEY, syscall.SYS_KEYCTL,
	// cross-process memory and ptrace
	syscall.SYS_PTRACE, sysProcessVMReadv, sysProcessVMWritev,
	// eBPF
	sysBPF,
	// mount / pivot / chroot: the program is already chrooted into a minimal
	// root, and a second chroot is an escape primitive, never a need.
	syscall.SYS_MOUNT, syscall.SYS_UMOUNT2, syscall.SYS_PIVOT_ROOT, syscall.SYS_CHROOT,
	sysMoveMount, sysOpenTree, sysFsopen, sysFsconfig, sysFsmount, sysFspick,
	// new namespaces from inside
	syscall.SYS_UNSHARE, sysSetns,
	// kernel code load
	syscall.SYS_INIT_MODULE, sysFinitModule, syscall.SYS_DELETE_MODULE,
	syscall.SYS_KEXEC_LOAD, sysKexecFileLoad,
}

// network is denied in the SERVE phase only. With no call that returns a socket
// fd, connect/sendto/recvfrom are unreachable: egress is impossible by
// construction rather than filtered by policy.
var network = []uint32{syscall.SYS_SOCKET, syscall.SYS_SOCKETPAIR}

// denied is the deny-list for p. The ONE difference between the phases lives
// here, in a two-line function, so "what does Fetch have that Serve does not"
// has a single answer that can be read in full.
func denied(p phase) []uint32 {
	if p == fetch {
		return escape
	}
	return append(append([]uint32{}, network...), escape...)
}

// x86_64 numbers absent from Go's syscall package. These are a STABLE kernel ABI
// on amd64 — the target arch, and the only one the image is built for — so
// hardcoding them is correct and dependency-free.
const (
	sysProcessVMReadv  = 310
	sysProcessVMWritev = 311
	sysBPF             = 321
	sysSetns           = 308
	sysFsopen          = 430
	sysFsconfig        = 431
	sysFsmount         = 432
	sysFspick          = 433
	sysOpenTree        = 428
	sysMoveMount       = 429
	sysFinitModule     = 313
	sysKexecFileLoad   = 320
	sysIoUringSetup    = 425
	sysIoUringEnter    = 426
	sysIoUringRegister = 427

	rlimitNproc     = 6  // RLIMIT_NPROC, absent from Go's syscall package
	prSetNoNewPrivs = 38 // PR_SET_NO_NEW_PRIVS
)

// Filter return actions and arch markers. Package-level so the builder and its
// structural test share ONE definition of each security-critical number.
const (
	retAllow       = 0x7FFF0000     // SECCOMP_RET_ALLOW
	retErrno       = 0x00050000 | 1 // SECCOMP_RET_ERRNO | EPERM
	retKill        = 0x80000000     // SECCOMP_RET_KILL_PROCESS
	auditArchAMD64 = 0xC000003E     // AUDIT_ARCH_X86_64
	x32Bit         = 0x40000000     // __X32_SYSCALL_BIT, set on every x32 number
)

// filter is the cBPF program for p. It is built here rather than inline so its
// jump arithmetic — where an off-by-one would silently ALLOW a denied syscall —
// is unit-tested by interpreting the program, with no need to enter seccomp mode.
func filter(p phase) []insn {
	const (
		ld    = 0x00 | 0x00 | 0x20 // BPF_LD|BPF_W|BPF_ABS
		jeq   = 0x05 | 0x10 | 0x00 // BPF_JMP|BPF_JEQ|BPF_K
		jset  = 0x05 | 0x40 | 0x00 // BPF_JMP|BPF_JSET|BPF_K
		ret   = 0x06 | 0x00        // BPF_RET|BPF_K
		atNR  = 0                  // seccomp_data.nr
		atArc = 4                  // seccomp_data.arch
	)
	nrs := denied(p)
	prog := []insn{
		// 1. Wrong arch ⇒ KILL. This is what stops the i386 ABI.
		{code: ld, k: atArc},
		{code: jeq, jt: 1, k: auditArchAMD64},
		{code: ret, k: retKill},
		// 2. Load the number, then refuse the x32 ABI wholesale: it shares this
		// audit arch but ORs 0x40000000 into every number, so the numeric compares
		// below would miss its socket. No toolchain on an amd64 image uses x32.
		{code: ld, k: atNR},
		{code: jset, jt: 0, jf: 1, k: x32Bit},
		{code: ret, k: retKill},
	}
	// 3. Each denied number jumps forward to the shared ERRNO terminal, over the
	// remaining compares and over the ALLOW. jt is an offset from the NEXT
	// instruction and is 8 bits; the list is far below 250 long.
	for i, nr := range nrs {
		prog = append(prog, insn{code: jeq, jt: uint8(len(nrs)-1-i) + 1, k: nr})
	}
	// 4. The two terminals.
	return append(prog, insn{code: ret, k: retAllow}, insn{code: ret, k: retErrno})
}

// insn mirrors struct sock_filter { u16 code; u8 jt; u8 jf; u32 k; }.
type insn struct {
	code uint16
	jt   uint8
	jf   uint8
	k    uint32
}

// program mirrors struct sock_fprog { u16 len; sock_filter *filter; }.
type program struct {
	len uint16
	_   [6]byte // pad to the pointer's 8-byte alignment on amd64
	f   *insn
}

// seccomp installs filter(p) on the calling thread — which run() has locked, and
// which is the thread that will exec.
func seccomp(p phase) error {
	const (
		prSetSeccomp = 22 // PR_SET_SECCOMP
		modeFilter   = 2  // SECCOMP_MODE_FILTER
	)
	prog := filter(p)
	fp := program{len: uint16(len(prog)), f: &prog[0]}
	if _, _, e := syscall.Syscall6(syscall.SYS_PRCTL, prSetSeccomp, modeFilter,
		uintptr(unsafe.Pointer(&fp)), 0, 0, 0); e != 0 {
		return fmt.Errorf("prctl(PR_SET_SECCOMP): %w", e)
	}
	return nil
}
