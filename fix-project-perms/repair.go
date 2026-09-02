package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// resolveTarget turns a validated fileset name into the one directory this
// binary may touch, and checks it is what deployment says it should be. The
// checks can only deny.
func resolveTarget(fileset string) (string, error) {
	if !nameRE.MatchString(fileset) {
		return "", fmt.Errorf("fileset %q is not a valid fileset name", fileset)
	}
	target := filepath.Join(projectsRoot, fileset)

	// Lstat, not Stat: a symlink at the fileset path must be refused, not
	// followed. Wherever it points is not what the token authorised.
	info, err := os.Lstat(target)
	if err != nil {
		return "", fmt.Errorf("fileset %s: %w", target, err)
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return "", fmt.Errorf("fileset %s is a symlink; refusing to follow it", target)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("fileset %s is not a directory", target)
	}
	return target, nil
}

// repairArgv is the repair, exactly as the proven celery path runs it, minus
// the -uid filter -- the authority a token attests is over the project root,
// so the walk is the whole fileset. Both operations are idempotent: a second
// run sets the same values the first did, which is why replay costs nothing
// but a walk and the lock, not this, bounds it.
//
// -xdev keeps the walk on the projects device: a mount point inside a fileset
// is not something a project token authorises. Absolute paths for chmod and
// chown so find never consults PATH for them.
func repairArgv(target, fileset string) []string {
	return []string{
		findBin, target,
		"-xdev",
		"!", "-type", "l",
		"-exec", chmodBin, "g+rwXs", "{}", "+",
		"-exec", chownBin, ":" + posixGroupPrefix + fileset, "{}", "+",
	}
}

// shellWords renders argv the way a human would type it, for the dry-run
// line and the log. Display only; nothing here is ever passed to a shell.
func shellWords(argv []string) string {
	out := make([]string, len(argv))
	for i, a := range argv {
		if a == "" || strings.ContainsAny(a, " \t'\"!{}$") {
			out[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		} else {
			out[i] = a
		}
	}
	return strings.Join(out, " ")
}

// runRepair executes argv with no shell, a scrubbed environment and a tight
// umask. ctx cancellation kills find, which is how a SIGTERM to this process
// stops the walk rather than orphaning it under the lock.
func runRepair(ctx context.Context, argv []string, stdout, stderr *os.File) error {
	syscall.Umask(0o077)
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	// find still needs *a* PATH to exec chmod and chown, even given absolute
	// paths, on some implementations. This one is the minimum and is ours.
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return fmt.Errorf("interrupted: %w", ctx.Err())
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return fmt.Errorf("find exited %d", exitErr.ExitCode())
	}
	return err
}
