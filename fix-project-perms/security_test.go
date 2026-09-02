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

// TestForeignOwnedFileIsNotUpgraded is the escalation bsandbro raised, now
// asserted CLOSED. A victim's 0600 file, owned by someone never in project A,
// is renamed under A's root (inode preserved) and the repair runs. It comes
// out untouched: the legitimacy rule refuses it -- its group is not
// arc.<fileset> and its owner is not a member -- and both of those are facts
// the attacker cannot forge on a file they do not own. An earlier version of
// this test confirmed the escalation; this one confirms the fix.
func TestForeignOwnedFileIsNotUpgraded(t *testing.T) {
	requireRoot(t)
	setup(t)

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
	staged := filepath.Join(projectsRoot, "arcadm", "loot")
	if err := os.Rename(victimFile, staged); err != nil {
		t.Fatal(err)
	}
	before := lstatOf(t, staged)

	r := repairArcadm(t, nil)

	after := lstatOf(t, staged)
	if after.Gid != before.Gid || after.Mode != before.Mode || after.Uid != victimUID {
		t.Fatalf("ESCALATION: staged foreign file was modified: uid %d gid %d mode %#o", after.Uid, after.Gid, after.Mode&0o7777)
	}
	if r.stats.foreign != 1 || r.stats.foreignUID[victimUID] != 1 {
		t.Fatalf("foreign file not counted and named: %s %v", r.stats, r.stats.foreignUID)
	}
	t.Logf("closed: victim's file untouched (gid %d mode %#o), reported as foreign uid %d", after.Gid, after.Mode&0o7777, victimUID)
}

// The rule must not break the primary use case: a DEPARTED member's files,
// which carry the project group from setgid inheritance, are still repaired.
func TestDepartedMembersFileIsStillRepaired(t *testing.T) {
	requireRoot(t)
	setup(t)
	f := treeFile(t, "old-data", 0o600)
	own(t, f, departedUID, testGID) // not a member any more; group is the project's

	repairArcadm(t, nil)

	if got := permOf(t, f); got != 0o2660 {
		t.Fatalf("departed member's project file not opened up: mode %#o", got)
	}
}

// A current member's file whose group drifted -- bad umask, group rename --
// is repaired on the strength of its owner.
func TestCurrentMembersFileWithDriftedGroupIsRepaired(t *testing.T) {
	requireRoot(t)
	setup(t)
	f := treeFile(t, "drifted", 0o640)
	own(t, f, memberUID, 9999)

	repairArcadm(t, nil)

	if gidOf(t, f) != testGID || permOf(t, f) != 0o2660 {
		t.Fatalf("member's drifted file not repaired: gid %d mode %#o", gidOf(t, f), permOf(t, f))
	}
}

// The one legitimate case the rule refuses, stated rather than hidden: a
// departed member's file whose group has ALSO drifted has neither signal. It
// is rare -- removal-time repair handled departed users when they left -- and
// the complete fix is a members claim in the token (proposed on #162). Until
// then, refusing is the right failure: the alternative is the escalation.
func TestDepartedMembersFileWithDriftedGroupIsRefusedKnownCost(t *testing.T) {
	requireRoot(t)
	setup(t)
	f := treeFile(t, "orphan", 0o640)
	own(t, f, departedUID, 9999)

	r := repairArcadm(t, nil)

	if gidOf(t, f) != 9999 || permOf(t, f) != 0o640 {
		t.Fatalf("modified a file with neither legitimacy signal: gid %d mode %#o", gidOf(t, f), permOf(t, f))
	}
	if r.stats.foreign != 1 {
		t.Fatalf("not reported: %s", r.stats)
	}
}

// A regular file with a second link is reachable by another name, possibly
// outside the fileset; acting on the inode acts on every name. Skipped, so the
// hardlink staging variant does not depend on fs.protected_hardlinks.
func TestHardlinkedFileIsSkipped(t *testing.T) {
	requireRoot(t)
	setup(t)
	f := treeFile(t, "linked", 0o640)
	own(t, f, memberUID, 9999)
	if err := os.Link(f, filepath.Join(projectsRoot, "elsewhere")); err != nil {
		t.Fatal(err)
	}

	r := repairArcadm(t, nil)

	if gidOf(t, f) != 9999 || permOf(t, f) != 0o640 {
		t.Fatal("touched a hardlinked inode")
	}
	if r.stats.hardlinked != 1 {
		t.Fatalf("not reported: %s", r.stats)
	}
}

// The residual no ownership rule can close, proven rather than assumed: a
// victim who is themselves a current member of A. Their staged private file
// is indistinguishable from their own project data, and is repaired. This is
// what the provisioning layer -- sticky directories, independent filesets --
// is for, and why the two sticky tests below still matter.
func TestCoMemberVictimIsTheDocumentedResidual(t *testing.T) {
	requireRoot(t)
	setup(t)
	projB := filepath.Join(projectsRoot, "projB")
	_ = os.MkdirAll(projB, 0o2770)
	f := filepath.Join(projB, "private")
	_ = os.WriteFile(f, []byte("x"), 0o600)
	own(t, f, memberUID, memberUID) // a member of A, whose file lived in B
	staged := filepath.Join(projectsRoot, "arcadm", "loot")
	_ = os.Rename(f, staged)

	repairArcadm(t, nil)

	if gidOf(t, staged) != testGID {
		t.Fatal("expected the documented residual; a co-member's staged file was refused")
	}
	t.Log("residual confirmed: a co-member's staged file is repaired; bounded by sticky dirs / independent filesets, not by this binary")
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
