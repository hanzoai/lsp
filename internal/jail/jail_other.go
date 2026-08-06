//go:build !linux

package jail

import (
	"context"
	"errors"
	"os/exec"
)

// The jail is namespaces + chroot + seccomp, so it exists only on Linux. Off it —
// a developer's Mac — there is no jail child, no re-exec, and no boundary: the
// program simply runs.
//
// That is safe ONLY because the platform decides, not a flag. The image is
// linux/amd64, so in production Supported() is always true and a pod where the
// namespaces cannot be created fails Probe and refuses every request. There is no
// environment variable that turns the jail off, and therefore none that can be
// set by accident on the thing that matters.

// Supported reports whether a jail can be built here. It cannot.
func Supported() bool { return false }

// command runs the program directly. The caller's clean environment and working
// directory still apply; the kernel boundary does not exist to apply.
func command(ctx context.Context, _ phase, s Spec) *exec.Cmd {
	c := exec.CommandContext(ctx, s.Argv[0], s.Argv[1:]...)
	c.Dir = s.Dir
	if c.Dir == "" {
		c.Dir = s.Work
	}
	c.Env = s.Env
	return c
}

// Child is a no-op: nothing re-execs, so nothing is ever a jail child.
func Child() {}

// Probe cannot prove a boundary that is not there.
func Probe(context.Context, string, string) error {
	return errors.New("jail: unsupported on this platform")
}
