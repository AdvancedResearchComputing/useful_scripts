package main

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

var nameRE = regexp.MustCompile(nameRegexp)

// claims is the attestation ColdFront mints: who the caller is and what they
// hold. It attests; it does not grant. There is no action verb, because this
// binary holds its own privilege and does one thing.
type claims struct {
	jwt.RegisteredClaims
	Fileset   string `json:"fileset"`
	ProjectID int64  `json:"project_id"`
	Role      string `json:"role"`
	Version   int    `json:"ver"`
}

// verifyToken returns the claims of a token this binary may act on, or an
// error saying why not. Every check here is one the fixture bundle from
// ColdFront's arc_authz_mint --negatives exercises; the two that the library
// does not do for you -- ver, and kid resolution -- are the ones that matter
// most, because a verifier built around jwt.Parse alone accepts both.
func verifyToken(raw string) (*claims, error) {
	c := &claims{}
	_, err := jwt.ParseWithClaims(
		raw, c, keyForToken,
		// The confusion attack: re-sign HS256 using the public key as the HMAC
		// secret, which is by definition not secret. Pinning the method is
		// what defeats it; so does refusing alg:none, which this also does.
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithIssuer(expectedIssuer),
		jwt.WithAudience(expectedAudience),
		jwt.WithLeeway(clockLeeway),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)
	if err != nil {
		return nil, fmt.Errorf("token rejected: %w", err)
	}

	// A custom claim. The library has never heard of it, so nothing above
	// looked at it. Anything but the version we know is refused outright --
	// a newer claim set must fail closed, not be read optimistically.
	if c.Version != expectedVersion {
		return nil, fmt.Errorf("token rejected: ver %d, this binary understands %d",
			c.Version, expectedVersion)
	}
	if c.Subject == "" {
		return nil, errors.New("token rejected: no sub")
	}
	if !nameRE.MatchString(c.Fileset) {
		return nil, fmt.Errorf("token rejected: fileset %q is not a valid fileset name", c.Fileset)
	}
	if c.ID == "" {
		return nil, errors.New("token rejected: no jti")
	}
	return c, nil
}

// keyForToken resolves the header's kid to a public key on local disk.
//
// This happens before the signature is checked and is the whole of the
// rotation story: the trust directory holds every key currently accepted, and
// a token says which one signed it. Handing jwt.Parse a key you already chose
// would make kid decorative -- both keys would be equally acceptable regardless
// of which the token asked for.
func keyForToken(t *jwt.Token) (any, error) {
	// Belt and braces alongside WithValidMethods above. Neither is optional.
	if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
		return nil, fmt.Errorf("alg %q is not RS256", t.Header["alg"])
	}

	kidRaw, present := t.Header["kid"]
	kid, isString := kidRaw.(string)
	if !present || !isString || kid == "" {
		return nil, errors.New("no kid in token header")
	}
	// kid becomes a filename. The same rule as filesets keeps it a bare name.
	if !nameRE.MatchString(kid) {
		return nil, fmt.Errorf("kid %q is not a valid key id", kid)
	}
	return loadPublicKey(kid)
}

func loadPublicKey(kid string) (*rsa.PublicKey, error) {
	path := filepath.Join(authzKeyDir, kid+".pem")
	pem, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("unknown kid %q: no %s", kid, path)
		}
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	key, err := jwt.ParseRSAPublicKeyFromPEM(pem)
	if err != nil {
		return nil, fmt.Errorf("%s is not an RSA public key: %w", path, err)
	}
	return key, nil
}

// readToken takes the token from stdin. Never argv: argv is world-readable in
// /proc for the life of the process, and a walk runs for hours.
func readToken(in io.Reader) (string, error) {
	buf, err := io.ReadAll(io.LimitReader(in, maxTokenBytes+1))
	if err != nil {
		return "", fmt.Errorf("reading token from stdin: %w", err)
	}
	if len(buf) > maxTokenBytes {
		return "", fmt.Errorf("token exceeds %d bytes", maxTokenBytes)
	}
	tok := strings.TrimSpace(string(buf))
	if tok == "" {
		return "", errors.New("no token on stdin")
	}
	return tok, nil
}
