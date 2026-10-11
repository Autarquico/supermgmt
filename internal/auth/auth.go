// Package auth turns bearer credentials into authenticated callers (spec
// §11.1, §11.5, §23; ADR-0017): opaque tokens minted from 32 random bytes and
// stored only as SHA-256 hashes, the database-backed credential status that
// the request path and the job claim both consult, and the resolver that
// admits an HTTPS request.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/autarquico/supermgmt/internal/audit"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// Kind is the one-letter tag after "sm" in a token, so a token pasted into
// the wrong place is refused before any lookup: "sms_…" is a session.
type Kind byte

const (
	KindSession   Kind = 's'
	KindAPIToken  Kind = 't'
	KindBootstrap Kind = 'b'
	KindJoin      Kind = 'j'
)

const (
	tokenPrefix = "sm"
	tokenBytes  = 32
	tokenHead   = len(tokenPrefix) + 2 // "sm" + kind + "_"
)

var tokenEncoding = base64.RawURLEncoding

func (k Kind) valid() bool {
	switch k {
	case KindSession, KindAPIToken, KindBootstrap, KindJoin:
		return true
	}
	return false
}

// Mint returns a new token of kind k ("sm<k>_" + base64url of 32 bytes from
// crypto/rand) and the hash to store. The plaintext is shown once and never
// stored.
func Mint(k Kind) (plaintext audit.Secret, hash string, err error) {
	if !k.valid() {
		return "", "", fmt.Errorf("mint token: unknown kind %q", byte(k))
	}
	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("mint token: %w", err)
	}
	token := tokenPrefix + string(rune(k)) + "_" + tokenEncoding.EncodeToString(raw)
	return audit.Secret(token), hashOf(token), nil
}

// Hash parses a presented token and returns its kind and storage hash. A
// malformed token is UNAUTHENTICATED without touching the database.
func Hash(token string) (Kind, string, error) {
	if len(token) <= tokenHead || !strings.HasPrefix(token, tokenPrefix) || token[tokenHead-1] != '_' {
		return 0, "", malformedToken()
	}
	kind := Kind(token[len(tokenPrefix)])
	if !kind.valid() {
		return 0, "", malformedToken()
	}
	body, err := tokenEncoding.DecodeString(token[tokenHead:])
	if err != nil || len(body) != tokenBytes {
		return 0, "", malformedToken()
	}
	return kind, hashOf(token), nil
}

func hashOf(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func malformedToken() error {
	return smerr.New(smerr.CodeUnauthenticated, "", "malformed token")
}
