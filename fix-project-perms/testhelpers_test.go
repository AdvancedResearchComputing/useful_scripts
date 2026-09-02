package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
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

// fakeFind installs a stand-in for /usr/bin/find that records its argv to
// recordPath and exits with code. The environment is scrubbed by runRepair,
// so the record path is baked into the script rather than read from env.
func fakeFind(t *testing.T, code int) (recordPath string) {
	t.Helper()
	dir := t.TempDir()
	recordPath = filepath.Join(dir, "argv")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + recordPath + "\nexit " + itoa(code) + "\n"
	bin := filepath.Join(dir, "find")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	prev := findBin
	findBin = bin
	t.Cleanup(func() { findBin = prev })
	return recordPath
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	s := ""
	for i > 0 {
		s = string(rune('0'+i%10)) + s
		i /= 10
	}
	return s
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
