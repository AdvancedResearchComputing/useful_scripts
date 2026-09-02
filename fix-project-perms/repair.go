package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// The repair, done on file descriptors rather than paths.
//
// The obvious implementation -- `find … -exec chmod … -exec chown …` -- has a
// hole that is fatal for a binary that runs as root on demand inside a tree
// users can write to. find lstat()s a path, decides it is a regular file, and
// hands the PATH to chmod and chown, which follow symlinks. Between the check
// and the action -- a wide window, because `-exec {} +` batches hundreds of
// paths per exec -- a project member swaps the file for a symlink to
// /etc/shadow, and root has just handed the project group read-write on it.
// No shell tool closes this: there is no lchmod on Linux, so chmod always
// follows.
//
// So nothing here ever acts on a path after checking it. Every entry is
// opened with O_NOFOLLOW and pinned to an inode by its descriptor; fstat on
// that descriptor is the only check; fchownat with AT_EMPTY_PATH and chmod via
// /proc/self/fd/N are the only actions, and both address the descriptor. A
// swap after the open changes what the name points at and nothing else.
//
// Directories get the same treatment one level up: opened O_DIRECTORY|
// O_NOFOLLOW, entries read from the descriptor, and a subdirectory is
// re-opened and its dev/ino compared to the O_PATH fstat before we descend,
// so a directory swapped underneath us is skipped -- loudly -- not trusted.

const (
	atEmptyPath = 0x1000 // AT_EMPTY_PATH; the syscall package does not export it

	// g+rwXs, as the celery command spelled it: group read, write, setgid,
	// and execute only where something already executes or it is a directory.
	groupRW    = syscall.S_IRGRP | syscall.S_IWGRP
	anyExecute = 0o111
)

// repairer walks one fileset. gid and the member set are resolved before the
// lock is taken, so a lookup failure is a refusal rather than a half-finished
// walk.
type repairer struct {
	gid     uint32
	members map[string]bool // current members of arc.<fileset>, by username
	rootDev uint64
	stats   repairStats
	dryRun  bool // count what would change; touch nothing

	uids map[uint32]passwdEntry // uid -> resolved once per walk

	// testHook, when set, runs after an entry has been opened and inspected
	// and before it is acted on -- the window an attacker aims at. Tests use
	// it to swap the entry out from under the walker and then prove nothing
	// happened to the swapped-in target. Nil outside tests.
	testHook func(dirfd int, name string)
}

type repairStats struct {
	seen, changed, skipped, errors int
	// foreign counts entries the legitimacy rule refused to touch; the uids
	// are kept (capped) because a non-zero count is a signal worth a Splunk
	// alert, and "which uid" is the first question anyone will ask.
	foreign    int
	foreignUID map[uint32]int
	hardlinked int
}

func (s repairStats) String() string {
	return fmt.Sprintf("seen=%d changed=%d skipped=%d foreign=%d hardlinked=%d errors=%d",
		s.seen, s.changed, s.skipped, s.foreign, s.hardlinked, s.errors)
}

type passwdEntry struct {
	name       string
	primaryGID uint32
}

// openTarget opens the fileset root the way the walk will use it. Not a
// stat-then-open, which would be the same race in miniature: the descriptor
// IS the check. O_NOFOLLOW makes a symlink at the root ELOOP; O_DIRECTORY
// makes anything else ENOTDIR.
func openTarget(fileset string) (*os.File, *syscall.Stat_t, error) {
	if !nameRE.MatchString(fileset) {
		return nil, nil, fmt.Errorf("fileset %q is not a valid fileset name", fileset)
	}
	target := filepath.Join(projectsRoot, fileset)
	fd, err := syscall.Open(target, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.ENOTDIR) {
			// The refusal is already decided by the open. This lstat is only
			// so the operator is told "symlink" rather than "not a directory"
			// -- with O_DIRECTORY set, the kernel reports a symlink as
			// ENOTDIR before it gets to ELOOP.
			var st syscall.Stat_t
			if syscall.Lstat(target, &st) == nil && st.Mode&syscall.S_IFMT == syscall.S_IFLNK {
				return nil, nil, fmt.Errorf("fileset %s is a symlink; refusing to follow it", target)
			}
			return nil, nil, fmt.Errorf("fileset %s is not a directory", target)
		}
		return nil, nil, fmt.Errorf("fileset %s: %w", target, err)
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		syscall.Close(fd)
		return nil, nil, fmt.Errorf("fstat %s: %w", target, err)
	}
	return os.NewFile(uintptr(fd), target), &st, nil
}

// run repairs root and everything under it on the same device. It returns an
// error only for interruption; per-entry problems are counted and reported,
// because one unreadable entry must not abandon the other ten million.
func (r *repairer) run(ctx context.Context, root *os.File, rootSt *syscall.Stat_t) error {
	r.rootDev = uint64(rootSt.Dev)
	// The root itself is part of the repair, as find's starting point is.
	r.apply(int(root.Fd()), rootSt, root.Name())
	return r.walk(ctx, root)
}

func (r *repairer) walk(ctx context.Context, dir *os.File) error {
	dirfd := int(dir.Fd())
	names, err := dir.Readdirnames(-1)
	if err != nil {
		r.stats.errors++
		fmt.Fprintf(os.Stderr, "readdir %s: %v\n", dir.Name(), err)
		return nil
	}
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return err
		}
		r.stats.seen++
		if err := r.entry(ctx, dirfd, dir.Name(), name); err != nil {
			return err
		}
	}
	return nil
}

func (r *repairer) entry(ctx context.Context, dirfd int, dirName, name string) error {
	display := filepath.Join(dirName, name)

	// O_PATH: a descriptor to the inode with no side effects at all. Opening
	// a planted FIFO for reading would block forever; opening a device node
	// could do anything. O_PATH does neither, and fstat on it is enough.
	fd, err := syscall.Openat(dirfd, name, syscall.O_PATH|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		r.stats.errors++
		fmt.Fprintf(os.Stderr, "open %s: %v\n", display, err)
		return nil
	}
	defer syscall.Close(fd)

	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		r.stats.errors++
		fmt.Fprintf(os.Stderr, "fstat %s: %v\n", display, err)
		return nil
	}

	// O_PATH|O_NOFOLLOW on a symlink opens the LINK, not the target, so this
	// is where `! -type l` lives. Skipped, never followed.
	switch st.Mode & syscall.S_IFMT {
	case syscall.S_IFLNK:
		r.stats.skipped++
		return nil
	case syscall.S_IFREG, syscall.S_IFDIR:
	default:
		// FIFOs, sockets, device nodes. find's command would chmod them;
		// a project repair needs nothing from them and a root process has
		// no business touching them.
		r.stats.skipped++
		return nil
	}

	// -xdev. A mount point inside a fileset is not what the token authorised.
	if uint64(st.Dev) != r.rootDev {
		r.stats.skipped++
		return nil
	}

	if r.testHook != nil {
		r.testHook(dirfd, name)
	}

	// A regular file with more than one link is also reachable by some other
	// name -- possibly outside this fileset -- and acting on the inode acts
	// on every name. Skip it rather than depend on fs.protected_hardlinks.
	if st.Mode&syscall.S_IFMT == syscall.S_IFREG && uint64(st.Nlink) > 1 {
		r.stats.hardlinked++
		fmt.Fprintf(os.Stderr, "skipping %s: %d links; not touching a shared inode\n", display, st.Nlink)
	} else if !r.legitimate(&st) {
		// See legitimate(). Counted and named, never touched. The directory
		// is still descended, because what is inside it is judged on its
		// own merits.
		r.stats.foreign++
		if r.stats.foreignUID == nil {
			r.stats.foreignUID = map[uint32]int{}
		}
		r.stats.foreignUID[st.Uid]++
	} else {
		r.apply(fd, &st, display)
	}

	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return nil
	}
	// Descend. This is a second open by name, so it is a second place a swap
	// can land: re-open as a directory and require the same inode we just
	// inspected. Different means it moved under us. Skip it and say so.
	sub, err := syscall.Openat(dirfd, name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		r.stats.errors++
		fmt.Fprintf(os.Stderr, "open dir %s: %v\n", display, err)
		return nil
	}
	var st2 syscall.Stat_t
	if err := syscall.Fstat(sub, &st2); err != nil || st2.Dev != st.Dev || st2.Ino != st.Ino {
		syscall.Close(sub)
		r.stats.errors++
		fmt.Fprintf(os.Stderr, "directory %s changed underneath the walk; skipping it\n", display)
		return nil
	}
	subFile := os.NewFile(uintptr(sub), display)
	defer subFile.Close()
	return r.walk(ctx, subFile)
}

// apply brings one inode to the intended state, touching only what is
// wrong. chown first, then chmod: root's chown clears setgid on a
// group-executable file, so the celery command's order (chmod, then chown)
// quietly loses the s bit on every executable it touches.
func (r *repairer) apply(fd int, st *syscall.Stat_t, display string) {
	changed := false

	if st.Gid != r.gid {
		if r.dryRun {
			r.stats.changed++
			return
		}
		if err := syscall.Fchownat(fd, "", -1, int(r.gid), atEmptyPath); err != nil {
			r.stats.errors++
			fmt.Fprintf(os.Stderr, "chgrp %s: %v\n", display, err)
			return
		}
		changed = true
	}

	want := wantMode(st.Mode)
	if st.Mode&0o7777 != want {
		if r.dryRun {
			r.stats.changed++
			return
		}
		// fchmod refuses an O_PATH descriptor and the login-node kernels
		// predate fchmodat2, so this is glibc's own technique: the magic
		// link resolves to the pinned inode, whatever the name now says.
		if err := syscall.Chmod(fmt.Sprintf("/proc/self/fd/%d", fd), want); err != nil {
			r.stats.errors++
			fmt.Fprintf(os.Stderr, "chmod %s: %v\n", display, err)
			return
		}
		changed = true
	}
	if changed {
		r.stats.changed++
	}
}

// wantMode is chmod g+rwXs applied to an existing mode.
func wantMode(mode uint32) uint32 {
	perm := mode & 0o7777
	perm |= groupRW | syscall.S_ISGID
	if mode&syscall.S_IFMT == syscall.S_IFDIR || perm&anyExecute != 0 {
		perm |= syscall.S_IXGRP
	}
	return perm
}

// legitimate is the rule that closes the cross-project staging escalation
// (ARC/coldfront#162, bsandbro). The repair widens group access on every
// inode it touches, so it must only touch inodes that are genuinely this
// project's data. The filesystem carries no provenance, but it carries two
// facts an attacker cannot forge on a file they do not own -- they cannot
// chgrp it and they cannot change its uid -- and either one is enough:
//
//   - the group is already arc.<fileset>: it was created inside the project
//     (setgid inheritance) or repaired before. A departed member's files
//     qualify, which is the primary use case.
//   - the owner is a current member of arc.<fileset>: their file, whatever
//     drift did to its group.
//
// A victim's file renamed in from another project has neither, and is left
// exactly as it was. The one legitimate case this refuses is a DEPARTED
// member's file whose group has ALSO drifted -- rare, since removal-time
// repair handled departed users when they left -- and the complete fix for
// it is provenance in the token (a members claim from ColdFront), proposed on
// #162. Until then, refusing it is the right failure.
//
// The residual no ownership rule can close: a victim who is themselves a
// current member of this project. Their staged file is indistinguishable from
// their own project data. That case is bounded by provisioning -- sticky
// directories and independent filesets -- and is documented, not hidden.
func (r *repairer) legitimate(st *syscall.Stat_t) bool {
	if st.Gid == r.gid {
		return true
	}
	if r.uids == nil {
		r.uids = map[uint32]passwdEntry{}
	}
	pw, ok := r.uids[st.Uid]
	if !ok {
		var err error
		pw, err = lookupPasswdFn(st.Uid)
		if err != nil {
			// An unresolvable owner is not a member of anything we know.
			pw = passwdEntry{}
		}
		r.uids[st.Uid] = pw
	}
	return pw.primaryGID == r.gid || (pw.name != "" && r.members[pw.name])
}

// lookupPasswdFn is indirected for tests; the real one goes through getent so
// that sssd-backed accounts resolve.
var lookupPasswdFn = lookupPasswdByUID

func lookupPasswdByUID(uid uint32) (passwdEntry, error) {
	cmd := exec.Command(getentBin, "passwd", strconv.FormatUint(uint64(uid), 10))
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	out, err := cmd.Output()
	if err != nil {
		return passwdEntry{}, fmt.Errorf("uid %d: %w", uid, err)
	}
	f := strings.Split(strings.TrimSpace(string(out)), ":")
	if len(f) < 4 {
		return passwdEntry{}, fmt.Errorf("uid %d: unexpected getent output", uid)
	}
	pgid, err := parseGID(f[3])
	if err != nil {
		return passwdEntry{}, err
	}
	return passwdEntry{name: f[0], primaryGID: pgid}, nil
}

// lookupGroup resolves arc.<fileset> to a gid and its current members before
// anything is locked or touched. os/user is pure Go under CGO_ENABLED=0 and reads only /etc/group,
// which these groups are not in; getent goes through NSS and sssd the way
// chown itself would have.
func lookupGroup(group string) (uint32, map[string]bool, error) {
	// os/user is pure Go under CGO_ENABLED=0 and reads only /etc/group, which
	// these groups are not in; getent goes through NSS and sssd. Try the cheap
	// one first for the case where it is there.
	if g, err := user.LookupGroup(group); err == nil {
		gid, err := parseGID(g.Gid)
		if err == nil {
			// os/user does not expose members; fall through to getent for
			// those, but keep the gid if getent then fails.
			if _, members, gerr := lookupGroupViaGetent(group); gerr == nil {
				return gid, members, nil
			}
			return gid, map[string]bool{}, nil
		}
	}
	return lookupGroupViaGetent(group)
}

func lookupGroupViaGetent(group string) (uint32, map[string]bool, error) {
	cmd := exec.Command(getentBin, "group", group)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	out, err := cmd.Output()
	if err != nil {
		return 0, nil, fmt.Errorf("group %s: not resolvable through getent: %w", group, err)
	}
	return parseGetentGroup(out, group)
}

func parseGetentGroup(out []byte, group string) (uint32, map[string]bool, error) {
	line := string(bytes.TrimSpace(out))
	fields := strings.Split(line, ":")
	if len(fields) < 3 || fields[0] != group {
		return 0, nil, fmt.Errorf("group %s: unexpected getent output %q", group, line)
	}
	gid, err := parseGID(fields[2])
	if err != nil {
		return 0, nil, err
	}
	members := map[string]bool{}
	if len(fields) > 3 {
		for _, m := range strings.Split(fields[3], ",") {
			if m = strings.TrimSpace(m); m != "" {
				members[m] = true
			}
		}
	}
	return gid, members, nil
}

func parseGID(s string) (uint32, error) {
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("gid %q: %w", s, err)
	}
	return uint32(n), nil
}
