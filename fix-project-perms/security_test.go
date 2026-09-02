package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// These tests are the proof for the cross-project staging escalation bsandbro
// raised on ARC/coldfront#162 -- run as root (the golang container is), skipped
// otherwise. They deliberately use real uids and a real setuid child rather
// than argue the attack in prose.

const (
	victimUID   = 5001 // a user in project B; never in project A
	attackerUID = 5002 // PI/manager of A, and a member of B
)

// TestCrossProjectStagingEscalation demonstrates the hole, against the real
// repairer, with the fd-based rewrite in place. It is not a race: the file is
// simply present under the fileset root when the repair runs.
//
//   - victim owns a 0600 file, unreadable by anyone else.
//   - it is renamed into project A (inode preserved: owner and mode unchanged).
//   - the repair of A runs.
//
// Afterwards the file is group arc.A with g+rw -- so any member of arc.A, which
// the requester controls, can now read a file that was 0600 and owned by
// someone who was never in project A. The repair upgraded access to a file its
// requester had no claim on.
func TestCrossProjectStagingEscalation(t *testing.T) {
	requireRoot(t)
	setup(t) // projectsRoot/arcadm is "project A"

	// Project B, a sibling on the same device.
	projB := filepath.Join(projectsRoot, "projB")
	if err := os.MkdirAll(projB, 0o2770); err != nil {
		t.Fatal(err)
	}
	victimFile := filepath.Join(projB, "private")
	if err := os.WriteFile(victimFile, []byte("victim secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(victimFile, victimUID, victimUID); err != nil {
		t.Fatal(err)
	}

	// The staging step: the file is moved into A. (Whether the attacker CAN
	// do this is the next test; here we grant it and show the consequence.)
	staged := filepath.Join(projectsRoot, "arcadm", "loot")
	if err := os.Rename(victimFile, staged); err != nil {
		t.Fatal(err)
	}

	// Sanity: before the repair, the staged file is still victim-owned and
	// 0600 -- inaccessible to the group.
	if before := lstatOf(t, staged); before.Uid != victimUID || before.Mode&0o7777 != 0o600 {
		t.Fatalf("staging changed the file: uid %d mode %#o", before.Uid, before.Mode&0o7777)
	}

	repairArcadm(t, nil)

	after := lstatOf(t, staged)
	escalated := after.Gid == testGID && after.Mode&(syscall.S_IRGRP|syscall.S_IWGRP) == (syscall.S_IRGRP|syscall.S_IWGRP)
	if !escalated {
		t.Fatalf("expected the documented escalation; got gid %d mode %#o", after.Gid, after.Mode&0o7777)
	}
	if after.Uid != victimUID {
		t.Fatalf("owner changed too (uid %d) -- the repair only regroups, so this is unexpected", after.Uid)
	}
	t.Logf("ESCALATION CONFIRMED: victim's 0600 file is now gid=%d(arc.A) mode=%#o -- readable by arc.A", after.Gid, after.Mode&0o7777)
}

// TestStickyBitBlocksTheStagingRename proves the mitigation with a real setuid
// child, instead of asserting it. In a directory a user can write to, whether
// they may rename *another user's* file turns entirely on the sticky bit:
//
//   - non-sticky (2770): the attacker renames the victim's file out. Staging
//     works, and the escalation above is reachable.
//   - sticky (3770): the kernel refuses the rename with EPERM. Staging fails,
//     and the escalation is unreachable regardless of what the repair does.
//
// So the defense lives in how project directories are provisioned, not in the
// binary -- which is the point worth landing on #162.
func TestStickyBitBlocksTheStagingRename(t *testing.T) {
	requireRoot(t)

	// A helper that attempts the cross-user rename as the attacker and returns
	// the kernel's verdict, so the assertion is on an errno, not an inference.
	run := func(t *testing.T, sticky bool) (renamed bool, why string) {
		// Under /tmp (1777, world-traversable) rather than t.TempDir(), whose
		// 0700 parents the attacker uid cannot traverse -- which would fail the
		// rename for a reason that has nothing to do with the sticky bit. That
		// mistake is why an earlier version of this test "passed" for the wrong
		// reason.
		base, err := os.MkdirTemp("/tmp", "stage")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(base) })
		if err := os.Chmod(base, 0o755); err != nil {
			t.Fatal(err)
		}
		srcDir := filepath.Join(base, "shared")
		mode := os.FileMode(0o0777)
		if sticky {
			mode |= os.ModeSticky
		}
		if err := os.Mkdir(srcDir, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(srcDir, mode); err != nil { // defeat umask
			t.Fatal(err)
		}
		victim := filepath.Join(srcDir, "private")
		if err := os.WriteFile(victim, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(victim, victimUID, victimUID); err != nil {
			t.Fatal(err)
		}
		dstDir := filepath.Join(base, "out")
		if err := os.Mkdir(dstDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(dstDir, attackerUID, attackerUID); err != nil {
			t.Fatal(err)
		}
		dst := filepath.Join(dstDir, "loot")

		cmd := exec.Command("/bin/mv", victim, dst)
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{Uid: attackerUID, Gid: attackerUID},
		}
		out, err := cmd.CombinedOutput()
		if _, statErr := os.Lstat(dst); statErr == nil {
			return true, ""
		}
		return false, strings.TrimSpace(string(out)) + errStr(err)
	}

	if ok, why := run(t, false); !ok {
		t.Errorf("non-sticky dir: cross-user rename was blocked, so this test proves nothing about +t. reason: %s", why)
	} else {
		t.Log("non-sticky: attacker renamed the victim's file (staging possible)")
	}
	if ok, why := run(t, true); ok {
		t.Error("sticky dir: cross-user rename SUCCEEDED; +t did not block staging")
	} else {
		t.Logf("sticky (+t): kernel refused the attacker's rename (staging blocked): %s", why)
	}
}

// TestStickyBitDoesNotStopMovingAnAttackerOwnedDirectory is the reason sticky
// is necessary but not sufficient. Sticky checks the entry being renamed, not
// what is inside it. If a victim's file sits inside a directory the ATTACKER
// owns -- which happens whenever an attacker makes a group-writable subdir and
// another member drops a file in it -- the attacker can move the whole
// directory, victim's file and all, even out of a sticky parent.
func TestStickyBitDoesNotStopMovingAnAttackerOwnedDirectory(t *testing.T) {
	requireRoot(t)
	base, err := os.MkdirTemp("/tmp", "stage")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	_ = os.Chmod(base, 0o755)

	// A sticky shared area, as the mitigation would provision it.
	shared := filepath.Join(base, "shared")
	if err := os.Mkdir(shared, 0o1777); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(shared, os.ModeSticky|0o777)

	// A subdirectory the attacker owns, holding a victim's private file.
	adir := filepath.Join(shared, "adir")
	if err := os.Mkdir(adir, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(adir, attackerUID, attackerUID); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(adir, "private")
	if err := os.WriteFile(victim, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(victim, victimUID, victimUID); err != nil {
		t.Fatal(err)
	}

	dstDir := filepath.Join(base, "out")
	_ = os.Mkdir(dstDir, 0o700)
	_ = os.Chown(dstDir, attackerUID, attackerUID)

	// Attacker moves their OWN directory; sticky permits it because they own
	// the entry being renamed. The victim file rides along.
	cmd := exec.Command("/bin/mv", adir, filepath.Join(dstDir, "adir"))
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: attackerUID, Gid: attackerUID}}
	out, _ := cmd.CombinedOutput()

	moved := filepath.Join(dstDir, "adir", "private")
	st := syscall.Stat_t{}
	if err := syscall.Lstat(moved, &st); err != nil {
		t.Fatalf("directory move blocked (%s); if GPFS behaves this way the vector is narrower than expected: %v", strings.TrimSpace(string(out)), err)
	}
	if st.Uid != victimUID {
		t.Fatalf("moved file not victim-owned: uid %d", st.Uid)
	}
	t.Log("sticky BYPASSED: attacker moved their own directory carrying the victim's file; sticky is necessary but not sufficient")
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return " (" + err.Error() + ")"
}

var _ = context.Background
