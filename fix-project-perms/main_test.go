package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func drive(t *testing.T, stdin string, tty, apply bool, args []string) (code int, stdout, stderr string) {
	t.Helper()
	out, errf := tempFile(t), tempFile(t)
	var mirror bytes.Buffer
	audit := &auditor{mirror: &mirror} // no syslog in tests
	code = run(context.Background(), strings.NewReader(stdin), tty, apply, args, out, errf, audit)
	return code, readBack(t, out), readBack(t, errf) + mirror.String()
}

func lockExists() bool {
	_, err := os.Lstat(filepath.Join(lockDir, "arcadm"))
	return err == nil
}

func TestArgumentsAreRefused(t *testing.T) {
	tr := setup(t)
	code, _, stderr := drive(t, tr.valid(t), false, false, []string{"/gpfs/fs1/projects/arcadm"})
	if code != exitUsage || !strings.Contains(stderr, "no arguments") {
		t.Fatalf("code %d, stderr %q", code, stderr)
	}
}

func TestTerminalStdinIsRefused(t *testing.T) {
	tr := setup(t)
	if code, _, _ := drive(t, tr.valid(t), true, false, nil); code != exitUsage {
		t.Fatalf("code %d", code)
	}
}

func TestBadTokenIsRefusedAndLogged(t *testing.T) {
	setup(t)
	code, _, stderr := drive(t, "not.a.token", false, false, nil)
	if code != exitRefused {
		t.Fatalf("code %d", code)
	}
	if !strings.Contains(stderr, "decision=denied") || !strings.Contains(stderr, "reason=token-rejected") {
		t.Fatalf("denial not audited: %q", stderr)
	}
	if lockExists() {
		t.Fatal("lock taken for a rejected token")
	}
}

func TestDryRunVerifiesLocksPrintsAndTouchesNothing(t *testing.T) {
	tr := setup(t)
	useTestGID(t)
	f := treeFile(t, "f", 0o600)

	code, stdout, stderr := drive(t, tr.valid(t), false, false, nil)
	if code != exitOK {
		t.Fatalf("code %d, stderr %s", code, stderr)
	}
	if !strings.Contains(stdout, "DRY-RUN would walk") || !strings.Contains(stdout, filepath.Join(projectsRoot, "arcadm")) {
		t.Fatalf("dry-run output: %q", stdout)
	}
	if permOf(t, f) != 0o600 {
		t.Fatal("dry-run modified a file")
	}
	if !strings.Contains(stderr, "decision=granted") || !strings.Contains(stderr, "mode=dry-run") || !strings.Contains(stderr, "jti=0f1c0f1c0f1c") {
		t.Fatalf("grant not audited with jti: %q", stderr)
	}
	if lockExists() {
		t.Fatal("lock not released after dry-run")
	}
}

func TestApplyRunsTheRepairAndReleasesTheLock(t *testing.T) {
	requireRoot(t)
	tr := setup(t)
	useTestGID(t)
	f := treeFile(t, "f", 0o640)

	code, _, stderr := drive(t, tr.valid(t), false, true, nil)
	if code != exitOK {
		t.Fatalf("code %d, stderr %s", code, stderr)
	}
	if got := permOf(t, f); got != 0o2660 {
		t.Fatalf("mode %#o after apply", got)
	}
	if got := gidOf(t, f); got != testGID {
		t.Fatalf("gid %d after apply", got)
	}
	if !strings.Contains(stderr, "decision=completed") || !strings.Contains(stderr, "outcome=ok") || !strings.Contains(stderr, "changed=") {
		t.Fatalf("completion not audited: %q", stderr)
	}
	if lockExists() {
		t.Fatal("lock not released after apply")
	}
}

func TestApplyReportsPartialFailureAndStillReleases(t *testing.T) {
	requireRoot(t)
	tr := setup(t)
	useTestGID(t)
	treeDir(t, "dswap", 0o700)
	treeFile(t, "dswap/child", 0o600)
	prev := repairTestHook
	repairTestHook = func(dirfd int, name string) {
		if name == "dswap" {
			base := fmt.Sprintf("/proc/self/fd/%d/", dirfd)
			_ = os.Rename(base+"dswap", base+"dswap.moved")
			_ = os.Mkdir(base+"dswap", 0o700)
		}
	}
	t.Cleanup(func() { repairTestHook = prev })

	code, _, stderr := drive(t, tr.valid(t), false, true, nil)
	if code != exitRepair {
		t.Fatalf("code %d, stderr %s", code, stderr)
	}
	if !strings.Contains(stderr, "outcome=partial") {
		t.Fatalf("partial outcome not audited: %q", stderr)
	}
	if lockExists() {
		t.Fatal("lock leaked after a partial repair")
	}
}

func TestBusyFilesetIsRefusedWithoutWalking(t *testing.T) {
	tr := setup(t)
	useTestGID(t)
	f := treeFile(t, "f", 0o600)
	held, err := acquireLock("arcadm")
	if err != nil {
		t.Fatal(err)
	}
	defer held.release()

	code, _, stderr := drive(t, tr.valid(t), false, true, nil)
	if code != exitBusy || !strings.Contains(stderr, "reason=already-running") {
		t.Fatalf("code %d, stderr %q", code, stderr)
	}
	if permOf(t, f) != 0o600 {
		t.Fatal("walked a fileset that was already locked")
	}
	if !lockExists() {
		t.Fatal("refused invocation released someone else's lock")
	}
}

func TestUnresolvableGroupIsAConfigFailureBeforeAnyLock(t *testing.T) {
	tr := setup(t)
	prev := lookupGroupGID
	lookupGroupGID = func(g string) (uint32, error) { return 0, fmt.Errorf("no such group %s", g) }
	t.Cleanup(func() { lookupGroupGID = prev })

	code, _, stderr := drive(t, tr.valid(t), false, true, nil)
	if code != exitConfig || !strings.Contains(stderr, "reason=group-unresolvable") {
		t.Fatalf("code %d, stderr %q", code, stderr)
	}
	if lockExists() {
		t.Fatal("lock taken before the group resolved")
	}
}

func TestMissingLockDirIsAConfigFailure(t *testing.T) {
	tr := setup(t)
	useTestGID(t)
	lockDir = filepath.Join(t.TempDir(), "absent")
	if code, _, _ := drive(t, tr.valid(t), false, true, nil); code != exitConfig {
		t.Fatalf("code %d", code)
	}
}

func TestMissingFilesetIsAConfigFailure(t *testing.T) {
	tr := setup(t)
	useTestGID(t)
	c := baseClaims()
	c.Fileset = "nosuchfileset"
	if code, _, _ := drive(t, tr.sign(t, c, testKID), false, true, nil); code != exitConfig {
		t.Fatalf("code %d", code)
	}
}

// /dev/null and a pipe are both non-terminals, and /dev/null is the one a
// naive ModeCharDevice check gets wrong.
func TestIsTerminalIsFalseForDevNullAndPipes(t *testing.T) {
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devnull.Close()
	if isTerminal(devnull.Fd()) {
		t.Fatal("/dev/null reported as a terminal")
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if isTerminal(r.Fd()) {
		t.Fatal("pipe reported as a terminal")
	}
}
