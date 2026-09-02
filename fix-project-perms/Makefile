# fix-project-perms -- see README.md and ARC/coldfront#162.
#
# The binary is NOT on admin/deploy_useful_scripts.sh's list, on purpose. That
# script installs into the shared /apps tree with mode 775, and this is a root
# sudo target: it goes on local disk, root-owned, group-unwritable, on each
# host that runs it. `make install` does that; deployment owns the rest (trust
# directory, public key, lock directory, sudoers).

BIN     := bin/fix-project-perms
PREFIX  := /usr/local
SBIN    := $(PREFIX)/sbin

GOFLAGS := -trimpath -ldflags="-s -w"

.PHONY: build test vet fmt clean install

build:
	CGO_ENABLED=0 go build $(GOFLAGS) -o $(BIN) .

test:
	go test ./...

vet:
	go vet ./...
	@test -z "$$(gofmt -l .)" || { echo "gofmt:"; gofmt -l .; exit 1; }

fmt:
	gofmt -w .

clean:
	rm -rf bin

# Root-owned, group-unwritable, on LOCAL disk. If you find yourself pointing
# PREFIX at /apps, stop and read the sudo-target discussion in #162 first.
install: build
	install -d -m 0755 $(SBIN)
	install -o root -g root -m 0750 $(BIN) $(SBIN)/fix-project-perms
	@echo
	@echo "Installed $(SBIN)/fix-project-perms (root:root 0750)."
	@echo "Still needed on this host, from deployment, not from here:"
	@echo "  /etc/arc/authz/<kid>.pem        the public key(s), root:root 0644"
	@echo "  /gpfs/fs1/.arc-authz-locks/     the lock directory, root 0700"
	@echo "  a sudoers rule naming $(SBIN)/fix-project-perms, granted to the"
	@echo "  invoking service account -- NOT to a user group"
