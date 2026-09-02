// fix-project-perms repairs group ownership and permissions on one GPFS project
// fileset, on the strength of a signed attestation from ColdFront and nothing
// else.
//
// The design, and the reasoning behind every refusal below, is ARC/coldfront
// issue 162. The short version of the trust model:
//
//   - The token on stdin is the only input that carries authority. It is
//     verified offline against a public key on local disk; nothing is fetched
//     and nothing calls back to ColdFront.
//   - The path is derived from the token's fileset claim. A caller cannot name
//     a path, and a positional argument of any kind is refused.
//   - This binary is invoked through sudo by a service that has already
//     established the caller's identity from SO_PEERCRED. It therefore CANNOT
//     cross-check the invoking uid against the token's sub -- its own uid is
//     the service account's -- and it does not pretend to. What still binds
//     it is the token: one fileset, obtainable only with that user's own
//     ColdFront credential.
//   - The repair is done on file descriptors, never on paths, so a project
//     member swapping a file for a symlink mid-walk changes nothing. See
//     repair.go for why `find -exec chmod` cannot be made safe.
//   - One cluster-wide lock per fileset bounds duplicate work. Not a jti
//     replay store: the repair is idempotent and the holder can mint a fresh
//     token at will, so replay protection would restrict the authorised party
//     and nobody else.
//
// It runs synchronously. The invoking service is what makes the call
// non-blocking, and it verifies at submission, so a token never has to outlive
// a walk.
//
// Dry-run is the default. Nothing is changed on disk without -apply.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// repairTestHook is threaded into the repairer so tests can attack the
// check-to-act window. Nil in the shipped binary.
var repairTestHook func(dirfd int, name string)

// foreignUIDs renders the capped uid histogram for the audit line.
func foreignUIDs(m map[uint32]int) string {
	if len(m) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(m))
	for uid, n := range m {
		parts = append(parts, fmt.Sprintf("%d(x%d)", uid, n))
		if len(parts) == 8 {
			parts = append(parts, "...")
			break
		}
	}
	return strings.Join(parts, ",")
}

// lookupGroupFn is indirected so tests can hand the walker a gid and member
// set without a resolvable group on the box.
var lookupGroupFn = lookupGroup

// isTerminal asks the kernel, not the file mode. /dev/null is a character
// device too, and a service handing us an empty stdin must not be told it is
// sitting at a terminal.
func isTerminal(fd uintptr) bool {
	var t syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCGETS, uintptr(unsafe.Pointer(&t)))
	return errno == 0
}

func main() {
	apply := flag.Bool("apply", false, "actually run the repair (default: verify, lock, print, exit)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: fix-project-perms [-apply] < token\n\nThe token is read from stdin. No other input is accepted.\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	stdinIsTTY := isTerminal(os.Stdin.Fd())

	audit := newAuditor(os.Stderr)
	defer audit.close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	os.Exit(run(ctx, os.Stdin, stdinIsTTY, *apply, flag.Args(), os.Stdout, os.Stderr, audit))
}

// run is main without the process-level plumbing, so tests can drive every
// path against a temporary tree and read the exit status back.
func run(ctx context.Context, stdin io.Reader, stdinIsTTY, apply bool, args []string, stdout, stderr *os.File, audit *auditor) int {
	started := time.Now()

	// A path from the caller is the one thing this binary refuses always.
	// There is nothing an argument could legitimately say.
	if len(args) != 0 {
		fmt.Fprintf(stderr, "fix-project-perms takes no arguments; the token goes on stdin\n")
		return exitUsage
	}
	if stdinIsTTY {
		fmt.Fprintf(stderr, "refusing to read a token from a terminal; pipe it on stdin\n")
		return exitUsage
	}

	raw, err := readToken(stdin)
	if err != nil {
		audit.warn("denied", map[string]any{"reason": "no-token", "error": err})
		return exitRefused
	}

	c, err := verifyToken(raw)
	if err != nil {
		audit.warn("denied", map[string]any{"reason": "token-rejected", "error": err})
		return exitRefused
	}
	fields := map[string]any{
		"jti": c.ID, "sub": c.Subject, "fileset": c.Fileset, "role": c.Role, "project_id": c.ProjectID,
	}

	group := posixGroupPrefix + c.Fileset
	gid, members, err := lookupGroupFn(group)
	if err != nil {
		fields["reason"], fields["error"] = "group-unresolvable", err
		audit.warn("denied", fields)
		return exitConfig
	}
	fields["group"], fields["gid"], fields["members"] = group, gid, len(members)

	root, rootSt, err := openTarget(c.Fileset)
	if err != nil {
		fields["reason"], fields["error"] = "bad-target", err
		audit.warn("denied", fields)
		return exitConfig
	}
	defer root.Close()

	lock, err := acquireLock(c.Fileset)
	if err != nil {
		if errors.Is(err, errLockHeld) {
			fields["reason"] = "already-running"
			audit.warn("denied", fields)
			return exitBusy
		}
		fields["reason"], fields["error"] = "lock-unavailable", err
		audit.warn("denied", fields)
		return exitConfig
	}
	defer lock.release()

	hbCtx, stopHB := context.WithCancel(ctx)
	defer stopHB()
	go lock.heartbeat(hbCtx, heartbeatInterval)

	fields["target"] = root.Name()

	mode := "apply"
	if !apply {
		mode = "dry-run"
	}
	fields["mode"] = mode
	audit.info("granted", fields)

	// Dry-run walks too, read-only. A dry-run that only printed a plan would
	// tell an operator nothing about what the legitimacy rule is going to
	// refuse on a real fileset, and that is precisely what phase 3 exists to
	// find out before anything is enabled.
	r := &repairer{gid: gid, members: members, dryRun: !apply, testHook: repairTestHook}
	err = r.run(ctx, root, rootSt)
	fields["duration"] = since(started)
	fields["stats"] = r.stats.String()
	if r.stats.foreign > 0 {
		// Loud and separate: foreign-owned entries under a project root are
		// either drift worth a ticket or someone staging files, and both
		// deserve to be seen.
		audit.warn("foreign-owned", map[string]any{
			"jti": c.ID, "sub": c.Subject, "fileset": c.Fileset,
			"count": r.stats.foreign, "uids": foreignUIDs(r.stats.foreignUID),
		})
	}
	if err != nil {
		fields["outcome"], fields["error"] = "interrupted", err
		audit.warn("completed", fields)
		return exitRepair
	}
	if !apply {
		fmt.Fprintf(stdout, "DRY-RUN %s: would change %d of %d entries (group -> %s gid %d, mode g+rwXs); "+
			"skipped %d symlinks/special/other-device, %d foreign-owned, %d hardlinked; %d errors\n",
			root.Name(), r.stats.changed, r.stats.seen+1, group, gid,
			r.stats.skipped, r.stats.foreign, r.stats.hardlinked, r.stats.errors)
		fields["outcome"] = "dry-run"
		audit.info("completed", fields)
		return exitOK
	}
	if r.stats.errors > 0 {
		fields["outcome"] = "partial"
		audit.warn("completed", fields)
		return exitRepair
	}
	fields["outcome"] = "ok"
	audit.info("completed", fields)
	return exitOK
}
