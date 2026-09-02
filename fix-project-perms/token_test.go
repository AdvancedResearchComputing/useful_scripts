package main

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// These are the fixture bundle from ColdFront's `arc_authz_mint --negatives`,
// reproduced here so the verifier is seen rejecting each one in CI rather
// than only on the day someone runs the bundle by hand.

func TestValidTokenIsAccepted(t *testing.T) {
	tr := setup(t)
	c, err := verifyToken(tr.valid(t))
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if c.Subject != "abc123" || c.Fileset != "arcadm" || c.Role != "pi" || c.ID == "" {
		t.Fatalf("claims not carried through: %+v", c)
	}
}

func TestRejections(t *testing.T) {
	tr := setup(t)
	now := time.Now()

	cases := map[string]struct {
		token string
		want  string // substring of the error
	}{
		"expired": {tr.sign(t, func() *claims {
			c := baseClaims()
			c.ExpiresAt = jwt.NewNumericDate(now.Add(-2 * clockLeeway))
			return c
		}(), testKID), "expired"},
		"not-yet-valid": {tr.sign(t, func() *claims {
			c := baseClaims()
			c.NotBefore = jwt.NewNumericDate(now.Add(time.Hour))
			c.ExpiresAt = jwt.NewNumericDate(now.Add(2 * time.Hour))
			return c
		}(), testKID), "not valid yet"},
		"wrong-audience": {tr.sign(t, func() *claims {
			c := baseClaims()
			c.Audience = jwt.ClaimStrings{"some-other-service"}
			return c
		}(), testKID), "audience"},
		"wrong-issuer": {tr.sign(t, func() *claims {
			c := baseClaims()
			c.Issuer = "not-coldfront.example.edu"
			return c
		}(), testKID), "issuer"},
		"future-version": {tr.sign(t, func() *claims {
			c := baseClaims()
			c.Version = expectedVersion + 1
			return c
		}(), testKID), "ver"},
		"unknown-kid":     {tr.sign(t, baseClaims(), "no-such-key"), "unknown kid"},
		"path-shaped-kid": {tr.sign(t, baseClaims(), "../etc/evil"), "not a valid key id"},
		"no-expiry": {tr.sign(t, func() *claims {
			c := baseClaims()
			c.ExpiresAt = nil
			return c
		}(), testKID), "exp"},
		"no-subject": {tr.sign(t, func() *claims {
			c := baseClaims()
			c.Subject = ""
			return c
		}(), testKID), "sub"},
		"no-jti": {tr.sign(t, func() *claims {
			c := baseClaims()
			c.ID = ""
			return c
		}(), testKID), "jti"},
		"path-shaped-fileset": {tr.sign(t, func() *claims {
			c := baseClaims()
			c.Fileset = "../../etc"
			return c
		}(), testKID), "fileset"},
		"uppercase-fileset": {tr.sign(t, func() *claims {
			c := baseClaims()
			c.Fileset = "ArcAdm"
			return c
		}(), testKID), "fileset"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := verifyToken(tc.token)
			if err == nil {
				t.Fatalf("%s: ACCEPTED, must be rejected", name)
			}
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.want)) {
				t.Fatalf("%s: rejected for the wrong reason: %v (wanted %q)", name, err, tc.want)
			}
		})
	}
}

func TestMissingKidIsRejected(t *testing.T) {
	tr := setup(t)
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, baseClaims())
	s, _ := tok.SignedString(tr.priv) // no kid header at all
	if _, err := verifyToken(s); err == nil || !strings.Contains(err.Error(), "kid") {
		t.Fatalf("token without kid accepted or wrong reason: %v", err)
	}
}

func TestAlgNoneIsRejected(t *testing.T) {
	setup(t)
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, baseClaims())
	tok.Header["kid"] = testKID
	s, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyToken(s); err == nil {
		t.Fatal("alg:none token ACCEPTED")
	}
}

// The classic confusion attack: HMAC-sign with the PUBLIC key as the secret.
// A verifier that honours the token's own alg header accepts this.
func TestHS256WithPublicKeyIsRejected(t *testing.T) {
	tr := setup(t)
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, baseClaims())
	tok.Header["kid"] = testKID
	s, err := tok.SignedString(tr.pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyToken(s); err == nil {
		t.Fatal("HS256-with-public-key token ACCEPTED")
	}
}

func TestSignedByADifferentKeyIsRejected(t *testing.T) {
	setup(t)
	other := setupKeyOnly(t)
	// Same kid, so the verifier loads the deployed key and the signature
	// simply does not match.
	if _, err := verifyToken(other.sign(t, baseClaims(), testKID)); err == nil {
		t.Fatal("token signed by an unknown key ACCEPTED")
	}
}

func TestOversizedTokenIsRefused(t *testing.T) {
	if _, err := readToken(strings.NewReader(strings.Repeat("x", maxTokenBytes+1))); err == nil {
		t.Fatal("oversized token read")
	}
}

func TestEmptyStdinIsRefused(t *testing.T) {
	if _, err := readToken(strings.NewReader("  \n")); err == nil {
		t.Fatal("empty stdin accepted")
	}
}
