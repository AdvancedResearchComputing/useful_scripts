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
	"syscall"
	"time"
	"unsafe"
)

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

	target, err := resolveTarget(c.Fileset)
	if err != nil {
		fields["reason"], fields["error"] = "bad-target", err
		audit.warn("denied", fields)
		return exitConfig
	}

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

	argv := repairArgv(target, c.Fileset)
	fields["command"] = shellWords(argv)

	if !apply {
		fields["mode"] = "dry-run"
		audit.info("granted", fields)
		fmt.Fprintf(stdout, "DRY-RUN would run: %s\n", shellWords(argv))
		return exitOK
	}

	fields["mode"] = "apply"
	audit.info("granted", fields)
	err = runRepair(ctx, argv, stdout, stderr)
	fields["duration"] = since(started)
	if err != nil {
		fields["outcome"], fields["error"] = "failed", err
		audit.warn("completed", fields)
		return exitRepair
	}
	fields["outcome"] = "ok"
	audit.info("completed", fields)
	return exitOK
}
