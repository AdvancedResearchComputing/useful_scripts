# fix-project-perms

Repairs group ownership and permissions on one GPFS project fileset, on the
strength of a signed attestation from ColdFront and nothing else.

The design and threat model are **ARC/coldfront#162** (GitLab, internal). This
README is the operator's view: how to build it, what it refuses, and what
deployment owes it before it can do anything.

## What it does

```
<token on stdin>  ->  verify offline  ->  lock the fileset  ->  find/chmod/chown  ->  syslog
```

1. Reads a JWT from **stdin**. Never argv -- argv is world-readable in `/proc`
   for the life of the process, and a walk runs for hours.
2. Resolves the token's `kid` to `/etc/arc/authz/<kid>.pem` on **local disk**
   and verifies RS256, `iss`, `aud`, `ver`, `nbf`/`exp` (30s leeway). No
   callback to ColdFront; it works when ColdFront is down.
3. Derives the one path it may touch from the token's `fileset` claim:
   `/gpfs/fs1/projects/<fileset>`. Refuses a symlink or a non-directory there.
4. Takes `/gpfs/fs1/.arc-authz-locks/<fileset>` with `O_CREAT|O_EXCL`, which
   GPFS makes atomic cluster-wide. Heartbeats its mtime while it runs; a lock
   nobody has touched for five minutes is breakable from any host.
5. Walks the fileset **on file descriptors, never on paths**, and brings every
   regular file and directory on the same device to `:arc.<fileset>` and
   `g+rwXs` -- the same end state the removal-triggered celery command has
   produced for years, proven equal by test, touching only entries that are
   not already right. Symlinks, FIFOs, sockets and device nodes are skipped;
   nothing is ever followed. See *Why not `find`* below.
6. Logs one `key=value` line per decision to syslog, carrying the token's
   `jti`. ColdFront logs the same `jti` when it mints, and Splunk joins the two.

**Dry-run is the default.** Without `-apply` it verifies, takes the lock, walks
the fileset **read-only**, and prints what it would change and what it would
refuse -- how many entries, how many foreign-owned, how many hardlinked -- then
exits 0 having touched nothing. That is phase 3 of the rollout, and it is not
optional: a verifier that has never been observed rejecting a bad token has not
been tested, and a repair that has never been observed refusing a foreign file
on a real fileset has not been either.

## Why not `find -exec chmod … -exec chown …`

Because it is a root compromise waiting for a project member to request a
repair. `find` lstat()s a path, decides it is a regular file, and hands the
*path* to `chmod` and `chown` -- which follow symlinks. Between the check and
the action, a member of the project swaps `data/foo` for a symlink to
`/etc/shadow`, and root has just handed the project group read-write on it.
`-exec {} +` batches hundreds of paths per exec, so the window is wide, and
this binary runs **on demand**, so the attacker chooses when. No shell tool
closes it: there is no `lchmod` on Linux, so `chmod` always follows.

So the walk never acts on a path after checking it. Every entry is opened
`O_PATH|O_NOFOLLOW` and pinned to its inode by the descriptor; `fstat` on that
descriptor is the only check; `fchownat(AT_EMPTY_PATH)` and `chmod` via
`/proc/self/fd/N` are the only actions, and both address the descriptor. A
subdirectory is re-opened `O_DIRECTORY|O_NOFOLLOW` and its `dev`/`ino` compared
against the inspection before the walk descends; one that moved underneath is
skipped, loudly. `go test` includes both attacks -- a file swapped for a
symlink mid-walk, and a directory swapped mid-walk -- and asserts the target
is untouched.

Two deliberate differences from the celery command, both improvements:
`chown` runs before `chmod`, because root's `chown` clears setgid on a
group-executable file and the old order lost the `s` bit on every executable
it touched; and special files are skipped rather than chmod'ed, since a project
repair needs nothing from a FIFO and a root process has no business opening
one (it would block forever).

## What it will not touch: the legitimacy rule

The repair widens group access on every inode it touches, so it must only
touch inodes that are genuinely this project's data. The filesystem carries no
provenance -- but it carries two facts an attacker **cannot forge on a file
they do not own**: they cannot `chgrp` it, and they cannot change its uid.
Either one is enough:

- **the group is already `arc.<fileset>`** -- it was created inside the project
  (setgid inheritance) or repaired before. A *departed* member's files
  qualify, which is the primary use case.
- **the owner is a current member of `arc.<fileset>`** -- their file, whatever
  drift did to its group.

Anything with neither is counted, named by uid in a separate audit line, and
left exactly as it was. This is what closes the cross-project staging
escalation on #162: a victim's `0600` file renamed in from another project the
requester is merely a member of has neither signal, and comes out untouched.
`go test` proves it, along with the cases the rule must not break.

Also skipped: a regular file with more than one link. It is reachable by
another name, possibly outside the fileset, and acting on the inode acts on
every name.

**The one legitimate case this refuses**, stated rather than hidden: a departed
member's file whose group has *also* drifted. Rare -- removal-time repair
handled departed users when they left -- and the complete fix is provenance in
the token (a members claim from ColdFront), proposed on #162. Until then,
refusing is the right failure; the alternative is the escalation.

**The residual no ownership rule can close:** a victim who is themselves a
current member of this project. Their staged file is indistinguishable from
their own project data. That is bounded by provisioning -- sticky directories,
and project filesets being independent GPFS filesets so a cross-project rename
is `EXDEV` -- and both of those are proven and documented in the tests rather
than assumed.

## What it refuses, always

- Any positional argument. There is nothing a caller could legitimately say.
- A token from a terminal.
- `alg` other than RS256 -- including `none`, and including HS256 signed with
  the public key as the secret.
- An unknown or path-shaped `kid`; a fileset that is not `^[a-z0-9][a-z0-9._-]{0,63}$`.
- A `ver` other than the one it was built for. Newer fails closed.
- A fileset path that is a symlink, a file, or absent.
- A missing lock directory. **The binary never creates it** -- a binary that
  self-provisions can have every held lock evaporated by deleting the
  directory.
- A file whose group is not the project's and whose owner is not a current
  member, or a regular file with more than one link -- see the legitimacy rule.

## What it deliberately does not check

**The invoking uid against `sub`.** This binary is invoked through sudo by a
service that has already established the caller's identity from
`SO_PEERCRED`, so its own real uid is the service account's -- comparing that
to `sub` would compare the wrong thing and either no-op or deny everything.
The identity check belongs to the service. What still binds this binary is the
token: one fileset, obtainable only with that user's own ColdFront credential.

## Exit status

| code | meaning | the service should say |
| --- | --- | --- |
| 0 | done, or dry-run walked and reported | |
| 2 | token rejected | not authorised |
| 3 | another repair of this fileset is running | try again later |
| 4 | trust dir, lock dir or fileset path not as deployed | tell an admin |
| 5 | `find` ran and failed | tell an admin; see syslog |
| 64 | usage: an argument was passed, or stdin is a terminal | bug in the caller |

## Building

Needs Go 1.24. Without a local toolchain:

```sh
podman run --rm -v "$PWD:/src" -w /src docker.io/library/golang:1.24 \
    sh -c 'go vet ./... && go test ./... && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/fix-project-perms .'
```

With one: `make vet test build`. The result is static; on the host it needs
`/proc` mounted and `/usr/bin/getent` (the `arc.*` groups come from sssd,
which a static binary cannot reach through `os/user`). The tests that chown
need root, and skip cleanly otherwise -- run them in the container.

## Installing -- read this part

**It is not on `admin/deploy_useful_scripts.sh`'s list, on purpose.** That
script copies into the shared `/apps/common/useful_scripts` tree and sets new
files to mode `775`. This is a root sudo target, and a group-writable sudo
target on a shared mount means whoever can write the file -- or whoever
controls the export -- is root on every host carrying the rule.

`make install` puts it on **local disk**, `root:root 0750`, at
`/usr/local/sbin/fix-project-perms`. Point the sudoers rule at that path, and
grant it to the **invoking service's account** -- never to `%ood_users` or any
group an interactive user is in.

Deployment (ansible) still owes each host, before the first run:

| path | what | mode |
| --- | --- | --- |
| `/etc/arc/authz/<kid>.pem` | the public key(s); rotate by overlap | root `0644` |
| `/gpfs/fs1/.arc-authz-locks/` | the lock directory, on the **shared** device | root `0700` |
| sudoers | one binary, no wildcards, one service-account grantee | |

## Testing the verifier

`go test` covers every rejection above with keys generated per run. To test a
deployed binary against tokens signed by the **real** key, ColdFront's
`arc_authz_mint <pid> <fileset> --verify <pubkey> --negatives DIR` writes a
bundle; every file but `valid.jwt` must exit 2:

```sh
for f in DIR/*.jwt; do printf '%-28s' "$(basename "$f")"; fix-project-perms < "$f" >/dev/null 2>&1; echo "exit $?"; done
```
