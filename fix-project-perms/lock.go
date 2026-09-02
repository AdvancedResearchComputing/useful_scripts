package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

var errLockHeld = errors.New("another repair of this fileset is already running")

// filesetLock is one cluster-wide lock per fileset, held for the length of a
// walk. It is what bounds duplicate work -- a PI who clicks twice, a second
// manager acting at once, or a replayed token all collide here.
type filesetLock struct {
	path string
}

// acquireLock takes the lock with O_CREAT|O_EXCL, which GPFS makes atomic
// across nodes through its distributed lock manager. That single property is
// what the whole mechanism rests on.
//
// The lock DIRECTORY must already exist. It is created by deployment, never
// here: a binary that self-provisions hands an attacker the bypass directly,
// because deleting the directory would evaporate every held lock. A missing
// directory is a refusal, not a condition to repair.
func acquireLock(fileset string) (*filesetLock, error) {
	info, err := os.Lstat(lockDir)
	if err != nil {
		return nil, fmt.Errorf("lock directory %s: %w (deployment creates it; this binary never does)", lockDir, err)
	}
	if !info.IsDir() || info.Mode()&fs.ModeSymlink != 0 {
		return nil, fmt.Errorf("lock directory %s is not a directory", lockDir)
	}

	l := &filesetLock{path: filepath.Join(lockDir, fileset)}
	for attempt := 0; attempt < 2; attempt++ {
		f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			host, _ := os.Hostname()
			fmt.Fprintf(f, "host=%s pid=%d since=%s\n", host, os.Getpid(), time.Now().UTC().Format(time.RFC3339))
			f.Close()
			return l, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("taking lock %s: %w", l.path, err)
		}
		// Held. Whether it is held by a live walk or by a worker that died
		// mid-walk is a question only the heartbeat can answer -- a pid
		// written by another host means nothing here.
		if !l.stale() || attempt > 0 {
			return nil, errLockHeld
		}
		if err := os.Remove(l.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("breaking stale lock %s: %w", l.path, err)
		}
		// Loud on purpose. Breaking a lock is the unsafe direction; if this
		// happens often something is killing walks.
		fmt.Fprintf(os.Stderr, "broke stale lock %s (no heartbeat for over %s)\n", l.path, staleAfter)
	}
	return nil, errLockHeld
}

// stale reports whether the holder has stopped heartbeating. Prefer wedging
// to duplicate walks: a lock that is merely quiet is treated as held.
func (l *filesetLock) stale() bool {
	info, err := os.Lstat(l.path)
	if err != nil {
		return false
	}
	return time.Since(info.ModTime()) > staleAfter
}

// heartbeat touches the lock's mtime until ctx is done. This is the liveness
// signal that lets a different host break the lock if this process dies.
func (l *filesetLock) heartbeat(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			now := time.Now()
			_ = os.Chtimes(l.path, now, now)
		}
	}
}

// release is the holder's last act, on every path including error and
// signal. Idempotent, so it is safe to defer and also call explicitly.
func (l *filesetLock) release() {
	if l == nil {
		return
	}
	_ = os.Remove(l.path)
}
