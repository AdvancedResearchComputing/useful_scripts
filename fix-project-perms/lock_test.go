package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLockIsTakenAndReleased(t *testing.T) {
	setup(t)
	l, err := acquireLock("arcadm")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(lockDir, "arcadm"))
	if err != nil || len(b) == 0 {
		t.Fatalf("lock file not written: %v", err)
	}
	l.release()
	if _, err := os.Lstat(filepath.Join(lockDir, "arcadm")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("lock not released")
	}
	l.release() // idempotent
}

func TestSecondAcquireIsRefusedWhileHeld(t *testing.T) {
	setup(t)
	l, err := acquireLock("arcadm")
	if err != nil {
		t.Fatal(err)
	}
	defer l.release()
	if _, err := acquireLock("arcadm"); !errors.Is(err, errLockHeld) {
		t.Fatalf("second acquire: got %v, want errLockHeld", err)
	}
}

func TestDifferentFilesetsDoNotContend(t *testing.T) {
	setup(t)
	a, err := acquireLock("arcadm")
	if err != nil {
		t.Fatal(err)
	}
	defer a.release()
	b, err := acquireLock("other")
	if err != nil {
		t.Fatalf("unrelated fileset blocked: %v", err)
	}
	b.release()
}

// A lock whose heartbeat has stopped is breakable -- from any host, because
// the test is mtime, not a pid.
func TestStaleLockIsBroken(t *testing.T) {
	setup(t)
	p := filepath.Join(lockDir, "arcadm")
	if err := os.WriteFile(p, []byte("host=dead pid=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-staleAfter - time.Minute)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	l, err := acquireLock("arcadm")
	if err != nil {
		t.Fatalf("stale lock not broken: %v", err)
	}
	l.release()
}

func TestQuietButFreshLockIsNotBroken(t *testing.T) {
	setup(t)
	p := filepath.Join(lockDir, "arcadm")
	if err := os.WriteFile(p, []byte("host=alive pid=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	recent := time.Now().Add(-staleAfter / 2)
	_ = os.Chtimes(p, recent, recent)
	if _, err := acquireLock("arcadm"); !errors.Is(err, errLockHeld) {
		t.Fatalf("fresh lock broken or wrong error: %v", err)
	}
}

func TestHeartbeatAdvancesMtime(t *testing.T) {
	setup(t)
	l, err := acquireLock("arcadm")
	if err != nil {
		t.Fatal(err)
	}
	defer l.release()
	old := time.Now().Add(-time.Hour)
	_ = os.Chtimes(l.path, old, old)

	ctx, cancel := contextWithTimeout(t, 500*time.Millisecond)
	defer cancel()
	go l.heartbeat(ctx, 20*time.Millisecond)
	<-ctx.Done()

	info, _ := os.Lstat(l.path)
	if !info.ModTime().After(old.Add(time.Minute)) {
		t.Fatal("heartbeat did not touch the lock")
	}
}

// Deployment creates the directory; the binary never does. A missing
// directory is a refusal, because a binary that self-provisions can have
// every lock evaporated by deleting the directory.
func TestMissingLockDirRefuses(t *testing.T) {
	setup(t)
	lockDir = filepath.Join(t.TempDir(), "does-not-exist")
	_, err := acquireLock("arcadm")
	if err == nil {
		t.Fatal("acquired a lock with no lock directory")
	}
	if _, statErr := os.Lstat(lockDir); statErr == nil {
		t.Fatal("binary created the lock directory")
	}
}

func TestLockDirThatIsAFileRefuses(t *testing.T) {
	setup(t)
	f := filepath.Join(t.TempDir(), "file")
	_ = os.WriteFile(f, nil, 0o600)
	lockDir = f
	if _, err := acquireLock("arcadm"); err == nil {
		t.Fatal("acquired a lock inside a regular file")
	}
}
