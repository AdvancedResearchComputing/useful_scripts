package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testKID = "authz-test"

// trust stands up a temporary trust directory holding one public key, and
// points every path the binary uses at temporary space. Package globals are
// restored on cleanup; the tests do not run in parallel.
type trust struct {
	priv   *rsa.PrivateKey
	pubPEM []byte
}

func setup(t *testing.T) *trust {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	keyDir, root, locks := t.TempDir(), t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(keyDir, testKID+".pem"), pubPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "arcadm"), 0o770); err != nil {
		t.Fatal(err)
	}

	prev := [3]string{authzKeyDir, projectsRoot, lockDir}
	authzKeyDir, projectsRoot, lockDir = keyDir, root, locks
	t.Cleanup(func() { authzKeyDir, projectsRoot, lockDir = prev[0], prev[1], prev[2] })
	return &trust{priv: priv, pubPEM: pubPEM}
}

func baseClaims() *claims {
	now := time.Now()
	return &claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    expectedIssuer,
			Audience:  jwt.ClaimStrings{expectedAudience},
			Subject:   "abc123",
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
			ID:        "0f1c0f1c0f1c",
		},
		Fileset:   "arcadm",
		ProjectID: 12,
		Role:      "pi",
		Version:   expectedVersion,
	}
}

// sign mints a token the way ColdFront does: RS256, kid in the header.
func (tr *trust) sign(t *testing.T, c *claims, kid string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(tr.priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (tr *trust) valid(t *testing.T) string {
	return tr.sign(t, baseClaims(), testKID)
}

// requireRoot skips a test that needs to chown. The golang container runs
// as root; a developer running go test unprivileged gets a skip, not a lie.
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root to chown")
	}
}

// The gid every repair in these tests targets, and the cast of uids. All
// arbitrary and unresolvable on purpose: the walker takes a gid and a member
// set, the passwd lookup is stubbed, and resolving names is tested apart.
const (
	testGID     = 4242
	victimUID   = 5001 // in project B only; never in A
	attackerUID = 5002 // PI/manager of A, member of B
	memberUID   = 5003 // an ordinary current member of A
	departedUID = 5004 // was in A once; no longer in arc.<fileset>
)

var testPasswd = map[uint32]passwdEntry{
	0:           {name: "root", primaryGID: 0},
	victimUID:   {name: "victim", primaryGID: victimUID},
	attackerUID: {name: "attacker", primaryGID: attackerUID},
	memberUID:   {name: "member", primaryGID: memberUID},
	departedUID: {name: "departed", primaryGID: departedUID},
}

func testMembers() map[string]bool { return map[string]bool{"attacker": true, "member": true} }

// useTestGroup stubs both lookups: arc.<fileset> -> testGID with the current
// members above, and uid -> passwd for the cast. Nothing touches NSS.
func useTestGroup(t *testing.T) {
	t.Helper()
	prevG, prevP := lookupGroupFn, lookupPasswdFn
	lookupGroupFn = func(string) (uint32, map[string]bool, error) { return testGID, testMembers(), nil }
	lookupPasswdFn = func(uid uint32) (passwdEntry, error) {
		if e, ok := testPasswd[uid]; ok {
			return e, nil
		}
		return passwdEntry{}, fmt.Errorf("uid %d: unknown", uid)
	}
	t.Cleanup(func() { lookupGroupFn, lookupPasswdFn = prevG, prevP })
}

// treeFile creates a regular file under the arcadm fileset with the given
// raw mode bits (setgid included); group is whatever the test process's is.
func treeFile(t *testing.T, rel string, mode uint32) string {
	t.Helper()
	p := filepath.Join(projectsRoot, "arcadm", rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// syscall.Chmod, not os.Chmod: os.FileMode keeps setgid in a high bit,
	// so os.Chmod(p, 0o2660) silently drops it and a fixture meant to be
	// "already correct" is not.
	if err := syscall.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	own(t, p, memberUID, memberUID)
	return p
}

// own sets owner and group without following symlinks. Skips silently when
// not root, so non-chown tests still run unprivileged.
func own(t *testing.T, p string, uid, gid int) {
	t.Helper()
	if os.Geteuid() != 0 {
		return
	}
	if err := os.Lchown(p, uid, gid); err != nil {
		t.Fatal(err)
	}
}

func treeDir(t *testing.T, rel string, mode uint32) string {
	t.Helper()
	p := filepath.Join(projectsRoot, "arcadm", rel)
	if err := os.MkdirAll(p, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	own(t, p, memberUID, memberUID)
	return p
}

func lstatOf(t *testing.T, p string) syscall.Stat_t {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Lstat(p, &st); err != nil {
		t.Fatal(err)
	}
	return st
}

func permOf(t *testing.T, p string) uint32 { return lstatOf(t, p).Mode & 0o7777 }
func gidOf(t *testing.T, p string) uint32  { return lstatOf(t, p).Gid }

// repairArcadm runs the walker over the fixture fileset with an optional hook.
func repairArcadm(t *testing.T, hook func(dirfd int, name string)) *repairer {
	t.Helper()
	useTestGroup(t)
	root, st, err := openTarget("arcadm")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	r := &repairer{gid: testGID, members: testMembers(), testHook: hook}
	if err := r.run(context.Background(), root, st); err != nil {
		t.Fatal(err)
	}
	return r
}

func tempFile(t *testing.T) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func readBack(t *testing.T, f *os.File) string {
	t.Helper()
	b, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// setupKeyOnly makes a second key pair that is NOT in the trust directory.
func setupKeyOnly(t *testing.T) *trust {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &trust{priv: priv}
}

func contextWithTimeout(t *testing.T, d time.Duration) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), d)
}
