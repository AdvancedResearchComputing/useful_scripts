package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestWantModeIsGroupRWXS(t *testing.T) {
	for in, want := range map[uint32]uint32{
		syscall.S_IFREG | 0o640:  0o2660, // no execute anywhere: X adds nothing
		syscall.S_IFREG | 0o750:  0o2770, // owner executes: X grants group execute
		syscall.S_IFREG | 0o601:  0o2671, // other executes: still counts as "any"
		syscall.S_IFDIR | 0o700:  0o2770, // directories always get X
		syscall.S_IFDIR | 0o2770: 0o2770, // already right: unchanged
		syscall.S_IFREG | 0o4755: 0o6775, // setuid preserved
	} {
		if got := wantMode(in); got != want {
			t.Errorf("wantMode(%#o) = %#o, want %#o", in, got, want)
		}
	}
}

func TestRepairBringsATreeToTheIntendedState(t *testing.T) {
	requireRoot(t)
	setup(t)
	f640 := treeFile(t, "f640", 0o640)
	f750 := treeFile(t, "f750", 0o750)
	d700 := treeDir(t, "d700", 0o700)
	inner := treeFile(t, "d700/inner", 0o600)
	root := filepath.Join(projectsRoot, "arcadm")

	r := repairArcadm(t, nil)

	for p, want := range map[string]uint32{f640: 0o2660, f750: 0o2770, d700: 0o2770, inner: 0o2660, root: 0o2770} {
		if got := permOf(t, p); got != want {
			t.Errorf("%s mode %#o, want %#o", p, got, want)
		}
		if got := gidOf(t, p); got != testGID {
			t.Errorf("%s gid %d, want %d", p, got, testGID)
		}
	}
	if r.stats.errors != 0 {
		t.Errorf("stats %s", r.stats)
	}
}

func TestAlreadyCorrectEntriesAreNotTouched(t *testing.T) {
	requireRoot(t)
	setup(t)
	ok := treeFile(t, "ok", 0o2660)
	if err := os.Lchown(ok, -1, testGID); err != nil {
		t.Fatal(err)
	}
	before := lstatOf(t, ok)

	r := repairArcadm(t, nil)

	after := lstatOf(t, ok)
	if after.Ctim != before.Ctim {
		t.Error("an already-correct file was written to")
	}
	// root dir + ok: root changes, ok does not
	if r.stats.changed != 1 {
		t.Errorf("changed=%d, want 1 (the root only)", r.stats.changed)
	}
}

func TestSymlinksAreSkippedAndNeverFollowed(t *testing.T) {
	requireRoot(t)
	setup(t)
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(projectsRoot, "arcadm", "link")); err != nil {
		t.Fatal(err)
	}
	before := lstatOf(t, victim)

	r := repairArcadm(t, nil)

	after := lstatOf(t, victim)
	if after.Mode != before.Mode || after.Gid != before.Gid {
		t.Fatalf("symlink target touched: mode %#o gid %d", after.Mode&0o7777, after.Gid)
	}
	if r.stats.skipped != 1 {
		t.Errorf("skipped=%d, want 1", r.stats.skipped)
	}
}

// The attack this design exists to defeat. A regular file is inspected, then
// swapped for a symlink to a victim before the action. With path-based
// chmod/chown the victim would be modified; on a pinned descriptor the swap
// changes what the name points at and nothing else.
func TestSwappingAFileForASymlinkMidWalkDoesNotReachTheTarget(t *testing.T) {
	requireRoot(t)
	setup(t)
	victim := filepath.Join(t.TempDir(), "shadow")
	if err := os.WriteFile(victim, []byte("root:x"), 0o600); err != nil {
		t.Fatal(err)
	}
	treeFile(t, "swapme", 0o640)
	before := lstatOf(t, victim)

	swapped := false
	repairArcadm(t, func(dirfd int, name string) {
		if name != "swapme" {
			return
		}
		// Through the directory descriptor, exactly as an attacker racing the
		// walk from a shell would see the same directory.
		p := fmt.Sprintf("/proc/self/fd/%d/%s", dirfd, name)
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(victim, p); err != nil {
			t.Fatal(err)
		}
		swapped = true
	})

	if !swapped {
		t.Fatal("hook never fired")
	}
	after := lstatOf(t, victim)
	if after.Mode != before.Mode || after.Gid != before.Gid {
		t.Fatalf("VICTIM MODIFIED: mode %#o -> %#o, gid %d -> %d", before.Mode&0o7777, after.Mode&0o7777, before.Gid, after.Gid)
	}
}

// Same attack one level up: a directory swapped out between its O_PATH
// inspection and the O_DIRECTORY reopen for descent. The reopen sees a
// different inode and the walker refuses to descend.
func TestSwappingADirectoryMidWalkIsDetectedAndSkipped(t *testing.T) {
	requireRoot(t)
	setup(t)
	treeDir(t, "dswap", 0o700)
	hidden := treeFile(t, "dswap/child", 0o600)
	before := lstatOf(t, hidden)

	r := repairArcadm(t, func(dirfd int, name string) {
		if name != "dswap" {
			return
		}
		base := fmt.Sprintf("/proc/self/fd/%d/", dirfd)
		if err := os.Rename(base+"dswap", base+"dswap.moved"); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(base+"dswap", 0o700); err != nil {
			t.Fatal(err)
		}
	})

	if r.stats.errors != 1 {
		t.Errorf("errors=%d, want 1 (the swapped directory, reported loudly)", r.stats.errors)
	}
	moved := filepath.Join(projectsRoot, "arcadm", "dswap.moved", "child")
	after := lstatOf(t, moved)
	if after.Mode != before.Mode {
		t.Fatal("walker descended into a directory that had moved underneath it")
	}
}

func TestFifosAndOtherSpecialFilesAreSkipped(t *testing.T) {
	requireRoot(t)
	setup(t)
	fifo := filepath.Join(projectsRoot, "arcadm", "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	// If the walker opened this O_RDONLY it would block here forever.
	r := repairArcadm(t, nil)
	if permOf(t, fifo) != 0o600 {
		t.Fatal("fifo was modified")
	}
	if r.stats.skipped != 1 {
		t.Errorf("skipped=%d, want 1", r.stats.skipped)
	}
}

func TestEntriesOnAnotherDeviceAreSkipped(t *testing.T) {
	requireRoot(t)
	setup(t)
	f := treeFile(t, "f", 0o600)
	root, st, err := openTarget("arcadm")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	// Pretend the root is on some other device: everything under it is then
	// "across a mount" and must be left alone.
	r := &repairer{gid: testGID}
	r.rootDev = uint64(st.Dev) + 1
	r.apply(int(root.Fd()), st, root.Name()) // root itself, as run() would
	if err := r.walk(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	if permOf(t, f) != 0o600 {
		t.Fatal("crossed a device boundary")
	}
	if r.stats.skipped != 1 {
		t.Errorf("skipped=%d, want 1", r.stats.skipped)
	}
}

func TestCancellationStopsTheWalk(t *testing.T) {
	requireRoot(t)
	setup(t)
	treeFile(t, "a", 0o600)
	root, st, err := openTarget("arcadm")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := &repairer{gid: testGID}
	if err := r.run(ctx, root, st); err == nil {
		t.Fatal("cancelled walk reported success")
	}
}

func TestOpenTargetRefusals(t *testing.T) {
	setup(t)
	_ = os.WriteFile(filepath.Join(projectsRoot, "notadir"), nil, 0o600)
	_ = os.Symlink(filepath.Join(projectsRoot, "arcadm"), filepath.Join(projectsRoot, "alias"))

	for name, tc := range map[string]struct{ fileset, want string }{
		"missing":     {"nosuch", "no such file"},
		"regularfile": {"notadir", "not a directory"},
		"symlink":     {"alias", "symlink"},
		"pathshaped":  {"../etc", "not a valid fileset"},
		"empty":       {"", "not a valid fileset"},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := openTarget(tc.fileset)
			if err == nil {
				t.Fatalf("opened %q, must refuse", tc.fileset)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refused for the wrong reason: %v (want %q)", err, tc.want)
			}
		})
	}
}

func TestParseGetentGroup(t *testing.T) {
	if gid, err := parseGetentGroup([]byte("arc.arcadm:*:31337:alice,bob\n"), "arc.arcadm"); err != nil || gid != 31337 {
		t.Fatalf("got %d, %v", gid, err)
	}
	for _, bad := range []string{"", "arc.other:*:1:", "arc.arcadm:*:notanumber:", "garbage"} {
		if _, err := parseGetentGroup([]byte(bad), "arc.arcadm"); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}
