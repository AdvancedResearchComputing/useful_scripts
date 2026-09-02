package main

import "time"

// Everything the binary trusts or writes is a fixed path. None of these can be
// supplied by the caller: the token is the only input that carries authority,
// and argv is refused outright (see main). They are variables rather than
// constants only so tests can point them at a temporary tree.
var (
	// The trust anchor. Local disk, never the shared /apps tree: whoever can
	// write the public key can mint tokens this binary accepts, so it must
	// not share a writer with the thing it validates.
	authzKeyDir = "/etc/arc/authz"

	// The only device this binary will ever act on. The path is derived from
	// the token's fileset claim by concatenation onto this root and nothing
	// else -- a token cannot name a path.
	projectsRoot = "/gpfs/fs1/projects"

	// On the same GPFS device as the data so the lock is cluster-wide: a lock
	// under /run would be per-host, and two hosts would happily walk one
	// fileset together. A sibling of the projects tree, not inside any
	// fileset, because a lock a user can see is a lock a user can delete.
	// Created by deployment, never by this binary -- see acquireLock.
	lockDir = "/gpfs/fs1/.arc-authz-locks"

	findBin  = "/usr/bin/find"
	chmodBin = "/usr/bin/chmod"
	chownBin = "/usr/bin/chown"
)

const (
	// What a valid token must say about itself. aud names this binary, not a
	// host, so a token minted for some future second consumer is not
	// replayable here; ver is pinned so a changed claim set fails closed
	// instead of being half-understood.
	expectedIssuer   = "coldfront.arc.vt.edu"
	expectedAudience = "fix-project-perms"
	expectedVersion  = 1

	// Tolerated skew between ColdFront's clock and this host's, in both
	// directions. A token's whole life is the HTTP hop plus a fork, so this is
	// generous already.
	clockLeeway = 30 * time.Second

	// The POSIX group a fileset's files are handed to: arc.<fileset>. Matches
	// tasks.gpfs.add_project_dir on the ColdFront side, which provisions the
	// fileset as root:arc.<group> in the first place.
	posixGroupPrefix = "arc."

	// A walk runs for hours, so the lock has to outlive any plausible run, but
	// a worker killed mid-walk leaves a lock nothing will release. Liveness is
	// the lock's mtime, which the holder touches every heartbeatInterval; a
	// lock that has not moved for staleAfter is breakable from any host. A pid
	// check would not do -- a pid written by host A means nothing on host B.
	heartbeatInterval = 60 * time.Second
	staleAfter        = 5 * heartbeatInterval

	// More than any real token, less than anything worth reading into memory
	// from an untrusted caller.
	maxTokenBytes = 16 * 1024
)

// Fileset and key-id names are concatenated into paths, so they are validated
// before they get anywhere near one. No slashes, no leading dash, nothing that
// resolves upwards. Lowercase because the fileset on disk is the lowercased
// Storage_Group_Name -- add_project_dir lowercases before it creates anything.
const nameRegexp = `^[a-z0-9][a-z0-9._-]{0,63}$`

// Exit statuses are distinct on purpose: the invoking service renders them, and
// "already running" and "bad token" deserve different messages.
const (
	exitOK      = 0
	exitRefused = 2 // the token did not verify, or does not name this binary
	exitBusy    = 3 // another repair of this fileset is in flight
	exitConfig  = 4 // trust dir, lock dir or target path is not as deployed
	exitRepair  = 5 // find ran and failed
	exitUsage   = 64
)
