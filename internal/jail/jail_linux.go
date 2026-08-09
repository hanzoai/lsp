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
	"sort"
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
// child or the canary. In the daemon process it does nothing. main() calls it
// first, before any server setup, so the child stays minimal.
func Child() {
	// The canary, which a jail EXECS. It reports whether the kernel would hand it
	// a socket and exits. Because it is reached by exec — the same way a language
	// server is reached — a jail that builds perfectly and then cannot exec fails
	// the self-test, instead of passing it from inside the process that built it.
	if len(os.Args) == 2 && os.Args[1] == canary {
		if fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0); err != nil {
			fmt.Println(canaryDeny, err)
		} else {
			syscall.Close(fd)
			fmt.Println(canaryOK)
		}
		os.Exit(0)
	}
	p := phase(os.Getenv(envPhase))
	if p != fetch && p != serve {
		return
	}
	if err := run(p); err != nil {
		fmt.Fprintln(os.Stderr, "jail:", err)
	}
	os.Exit(setupFailed) // run() execs on success; arriving here means it did not
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
	if len(argv) == 0 {
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

	// (b) Fill it, in the order plan() put things in.
	for _, m := range plan(p, work, split(os.Getenv(envRead)),
		split(os.Getenv(envWrite)), num(envTmp, 256)) {
		if err := m.make(root); err != nil {
			return err
		}
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

	// (e) Become the program. There is no other ending — the canary is a program
	// like any other, so the exec is on the path the self-test proves.
	if err := syscall.Exec(argv[0], argv, clean()); err != nil {
		return fmt.Errorf("exec %s: %w", argv[0], err)
	}
	return nil // unreachable
}

// ── what the jail's filesystem is ────────────────────────────────────────────

// mount is one line of that filesystem, as a value: what appears at path inside
// the jail, and whether the program may write it. fs names a filesystem to
// create fresh; empty fs means a bind of src.
//
// path is ALWAYS the source's own absolute path. Same-path is not a convenience:
// a language server reports every answer as a file: URI of a path it was given,
// so a jail that renamed /roots/x to /work would hand the caller paths that name
// nothing — or would need a translation table, which is a second place for the
// two sides to disagree. There is nothing to translate here.
//
// write is the ONE truth about read-only-ness, for a bind and a fresh filesystem
// alike: MS_RDONLY is derived from it rather than carried beside it, so the two
// cannot disagree.
type mount struct {
	src   string  // the host path to bind; empty when fs is set
	fs    string  // "tmpfs" | "proc": a fresh filesystem; empty ⇒ a bind of src
	opt   string  // mount options for fs
	flag  uintptr // mount flags for fs, minus MS_RDONLY — see write
	path  string  // absolute, and the same inside the jail as outside
	write bool    // may the jailed program write it
	must  bool    // a missing source is an error rather than a skip
}

// plan is the whole filesystem the jail will have, ORDERED SHALLOWEST PATH
// FIRST — and that ordering is the reason this is a value rather than a run of
// mount calls.
//
// A mount whose path is an ANCESTOR of an earlier one covers it. Nothing fails
// at the time: the earlier mount is still there, and simply cannot be seen. The
// child fails much later, on chdir or exec, with ENOENT on a path that plainly
// exists outside the jail. That was this daemon's boot self-test — the writable
// /tmp was mounted AFTER the binds, so every bind under /tmp was placed and then
// erased, and /tmp is where the staging directory lives. The pod reported `exit
// status 126` and refused every request, correctly, for a filesystem bug.
//
// Sorting by depth makes an ancestor-after-descendant order unrepresentable, so
// the rule is enforced rather than remembered. TestThePlanHidesNothing asserts
// it directly, needs no privileges, and would have caught this before it shipped.
func plan(p phase, work string, read, write []string, tmp uint64) []mount {
	// The two filesystems the jail brings with it, shallowest of all so
	// everything binds ON them.
	ms := []mount{
		// The jail's own writable /tmp: the ONLY thing a served process can
		// write, and it dies with the process. Build caches live here for
		// exactly that reason. nosuid/nodev because a scratch directory has no
		// business holding a setuid binary or a device node; NOT noexec, since
		// the go command compiles and runs out of $TMPDIR.
		{fs: "tmpfs", path: "/tmp", write: true,
			opt:  fmt.Sprintf("mode=1777,size=%dm", tmp),
			flag: syscall.MS_NOSUID | syscall.MS_NODEV},

		// A PRIVATE procfs, and it is not a hole in the jail — it is this jail's
		// own, mounted inside this jail's PID namespace, so it shows the jailed
		// process and its children and NOTHING of the host. Read-only, nosuid,
		// nodev, noexec.
		//
		// It is here because a Go program cannot start without it. os.Executable
		// reads /proc/self/exe, and x/telemetry calls it on init, so gopls died
		// at startup with
		//
		//   failed to start telemetry sidecar: os.Executable: readlink
		//   /proc/self/exe: no such file or directory
		//   gopls cannot access its persistent index: can't hash gopls executable
		//
		// and the daemon reported only "server stopped". GOTELEMETRY=off does not
		// prevent it: x/telemetry reads its mode file, not the environment. Every
		// language server this daemon runs is a Go, Node or Python binary that
		// expects a /proc, so giving the jail its own is the general answer and
		// removes the reason GOROOT had to be pinned by hand.
		{fs: "proc", path: "/proc",
			flag: syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC},
	}

	// The device nodes every toolchain assumes exist. They are BOUND from the
	// host rather than created, because a user namespace cannot mknod a device —
	// that is the one thing CAP_MKNOD inside a userns does not buy.
	//
	// They are writable in BOTH phases, and that is not a hole in the serve
	// phase: none of them holds state. Writes to null and zero are discarded,
	// full returns ENOSPC, and a write to random or urandom cannot credit
	// entropy without CAP_SYS_ADMIN in the initial namespace. Read-only would
	// break them for their actual purpose — `open("/dev/null", O_WRONLY)` on a
	// read-only mount is EROFS, and Go's os/exec opens exactly that for every
	// subprocess with no stdin, so `go list` could not run at all.
	//
	// REQUIRED, not skipped when absent: a jail without /dev/null fails later and
	// obscurely, which is the same shape of bug as a mount that hides another.
	for _, dev := range []string{
		"/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom",
	} {
		ms = append(ms, mount{src: dev, path: dev, write: true, must: true})
	}

	// Serve binds EVERYTHING read-only, including the working tree: a root is
	// immutable and a language server has no business writing to one. Fetch binds
	// Work and Write read-write, because populating a dependency cache is
	// precisely what it is for. That is the ONE difference, and it is this line.
	writable := p == fetch
	for _, src := range read {
		ms = append(ms, mount{src: src, path: src})
	}
	for _, src := range write {
		ms = append(ms, mount{src: src, path: src, write: writable})
	}
	// The working tree is the one path that is NOT optional. The read list is a
	// superset across image layouts — a host without /lib64 must still jail — but
	// a jail whose working tree is missing has nothing to chdir into, and saying
	// so HERE names the cause instead of leaving a chdir to report the symptom.
	ms = append(ms, mount{src: work, path: work, write: writable, must: true})

	// ONE MOUNT PER PATH, and the first claim wins. Two mounts at one path are
	// the same hiding as an ancestor mounted late, and the order above decides it
	// the safe way: the jail's own /tmp is first, so a caller that asks to bind
	// /tmp gets the private tmpfs that dies with the process rather than the
	// host's directory. A boundary must not be overridable by an argument.
	seen := make(map[string]bool, len(ms))
	out := ms[:0]
	for _, m := range ms {
		if m.path == "" {
			continue // an unconfigured cache is spelled ""
		}
		m.path = filepath.Clean(m.path)
		if seen[m.path] {
			continue
		}
		seen[m.path] = true
		out = append(out, m)
	}
	sort.SliceStable(out, func(i, j int) bool { return depth(out[i].path) < depth(out[j].path) })
	return out
}

// depth is how many separators a cleaned absolute path has. An ancestor always
// has strictly fewer than its descendants, which is all the sort needs.
func depth(p string) int { return strings.Count(p, string(filepath.Separator)) }

// make performs one line of the plan, inside the staging root.
func (m mount) make(root string) error {
	dst := filepath.Join(root, m.path)
	if m.fs != "" {
		if err := os.MkdirAll(dst, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", m.path, err)
		}
		flag := m.flag
		if !m.write {
			flag |= syscall.MS_RDONLY
		}
		if err := syscall.Mount(m.fs, dst, m.fs, flag, m.opt); err != nil {
			return fmt.Errorf("mount %s %s: %w", m.fs, m.path, err)
		}
		return nil
	}
	fi, err := os.Stat(m.src)
	if err != nil {
		if m.must {
			return fmt.Errorf("bind %s: %w", m.src, err)
		}
		return nil
	}
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
		return fmt.Errorf("bind target %s: %w", m.src, err)
	}
	if err := syscall.Mount(m.src, dst, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
		return fmt.Errorf("bind %s: %w", m.src, err)
	}
	if m.write {
		return nil
	}
	// A bind acquires read-only only on a second, remounting call.
	if err := syscall.Mount("", dst, "", syscall.MS_BIND|syscall.MS_REC|syscall.MS_REMOUNT|syscall.MS_RDONLY, ""); err != nil {
		return fmt.Errorf("seal %s: %w", m.src, err)
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

// ── the boot self-test ───────────────────────────────────────────────────────

// ErrHost reports that this host cannot create the namespaces a jail needs: the
// child never started. Every OTHER Probe failure means the child DID start and
// the jail itself is wrong, and the two must never be read as one — a caller
// that tolerates the first would otherwise tolerate the second and certify
// nothing. On the target, both are fatal; only a test may skip on this one.
var ErrHost = errors.New("jail: this host cannot create namespaces")

// Probe builds a real jail in each phase, EXECS the canary in it, and makes it
// say whether a socket was obtainable. It is the boot self-test, and it is the
// reason /readyz can be trusted: a host where the namespaces cannot be created,
// where a mount is masked, where the exec cannot happen or where the filter did
// not take fails here, and the daemon then refuses every request rather than
// serving untrusted bytes next to a network.
//
// root is the staging base, and it is the ONLY path this takes. The canary's
// working tree is the directory the canary lives in, so there is no second
// directory to get into the wrong relationship with the first — which is exactly
// the mistake that made this self-test fail on every host it ran on.
func Probe(ctx context.Context, root string) error {
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
		out, err := command(ctx, c.p, Spec{
			Root: root,
			Work: filepath.Dir(self),
			Argv: []string{self, canary},
			// GENEROUS ON PURPOSE. A ceiling that stops the canary starting takes
			// the daemon out of service without any boundary having failed, which
			// is the worst answer a self-test can give. RLIMIT_NPROC especially:
			// it is per-UID, so the jailed process shares its budget with the
			// daemon's own threads — measured on the target, 32 leaves a Go
			// program unable to start a third thread, and that reads exactly like
			// a broken jail. Ceilings are proven by the phases that use them.
			Limits: Limits{AddrMiB: 4096, CPU: 10, Nofile: 256, Nproc: 256, TmpMiB: 16},
		}).Output()
		if err != nil {
			var ee *exec.ExitError
			if !errors.As(err, &ee) {
				return fmt.Errorf("%w: %v", ErrHost, err)
			}
			// THE CHILD ALREADY SAID WHY. run() writes "jail: <reason>" to stderr
			// and exits 126; Output() parks that on ExitError.Stderr, and this
			// function used to drop it and report only "exit status 126".
			//
			// That number is not a diagnosis. It is the same code for a missing
			// mount, an unmappable uid, a chroot that failed and a chdir into a
			// masked path — and it was all an operator got for a pod that would
			// not go ready. Never report an exit status without the words beside it.
			return fmt.Errorf("jail: %s canary did not run: %w: %s",
				c.p, err, strings.TrimSpace(string(ee.Stderr)))
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
//   - allows socketpair for AF_UNIX ONLY, and refuses every other family — see
//     the note on it below;
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

// network is denied in the SERVE phase only. socket() is the only call that
// hands out a fd to a NETWORK, so with it denied connect/sendto/recvfrom are
// unreachable: egress is impossible by construction rather than filtered by
// policy.
//
// socketpair is NOT here, and that is a correction rather than a concession.
// It was, and the cost was TypeScript: a socketpair is how libuv gives a child
// its stdio, so denying it does not stop a network — it stops Node starting a
// process at all, and typescript-language-server exists to run tsserver. It
// failed with `spawn EPERM` and every other language kept working, which is the
// graceful-degrade design telling the truth about a boundary drawn in the wrong
// place.
//
// A socketpair reaches nothing. Both ends come back already connected to each
// other, in AF_UNIX, inside this jail's own namespaces; it cannot be connect()ed
// elsewhere, and a peer that could pass a network fd over it would have to be
// outside the jail, where nothing is. Filtering it to AF_UNIX (filter, below)
// keeps the claim above exact — no INET fd by construction — rather than resting
// on the fact that the kernel implements socketpair for no other family.
var network = []uint32{syscall.SYS_SOCKET}

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
	afUnix          = 1  // AF_UNIX, the only family socketpair may name here
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
		// seccomp_data.args[0] is 64 bits at offset 16; cBPF loads 32, and on a
		// little-endian machine that offset IS the low half. That half is the
		// whole of the answer here: sys_socketpair takes an `int family`, so the
		// kernel truncates the register to exactly these bits, and the filter and
		// the kernel therefore read the same number.
		atArg0 = 16
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
		// 3. socketpair, decided on its FAMILY rather than its number — the one
		// place this filter reads an argument. AF_UNIX is a pipe between a process
		// and its own child and reaches nothing (see network, above); every other
		// family is refused, so "no fd to a network" stays a property of the
		// program and not a fact about which families the kernel bothered to
		// implement.
		//
		// Reading args[0] CLOBBERS the accumulator, so this arm never falls
		// through — both edges are terminals. A number that is not socketpair
		// skips both instructions with the number still loaded.
		{code: jeq, jt: 0, jf: 2, k: syscall.SYS_SOCKETPAIR},
		{code: ld, k: atArg0},
		{code: jeq, jt: uint8(len(nrs)), jf: uint8(len(nrs)) + 1, k: afUnix},
	}
	// 4. Each denied number jumps forward to the shared ERRNO terminal, over the
	// remaining compares and over the ALLOW. jt is an offset from the NEXT
	// instruction and is 8 bits; the list is far below 250 long.
	for i, nr := range nrs {
		prog = append(prog, insn{code: jeq, jt: uint8(len(nrs)-1-i) + 1, k: nr})
	}
	// 5. The two terminals. Everything above that jumps forward is measured to
	// land on one of these two, which is why they are appended last and once.
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
