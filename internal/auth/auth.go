// Package auth turns bearer credentials into authenticated callers (spec
// §11.1, §11.5, §23; ADR-0017): opaque tokens minted from 32 random bytes and
// stored only as SHA-256 hashes, the database-backed credential status that
// the request path and the job claim both consult, and the one-time admin
// bootstrap code.
//
// W0 contract: signatures are frozen; bodies land in M2 task T2.
package auth

import (
	"context"

	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
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

// Mint returns a new token of kind k ("sm<k>_" + base64url of 32 bytes from
// crypto/rand) and the hash to store. The plaintext is shown once and never
// stored.
func Mint(k Kind) (plaintext audit.Secret, hash string, err error) {
	panic("not implemented: M2 T2")
}

// Hash parses a presented token and returns its kind and storage hash. A
// malformed token is UNAUTHENTICATED without touching the database.
func Hash(token string) (Kind, string, error) {
	panic("not implemented: M2 T2")
}

// CredentialStatus is the database-backed app.CredentialStatus: local_socket
// is always active; session and api_token are looked up by id on every call
// (no cache, spec §23); every other kind is refused until its milestone.
type CredentialStatus struct {
	DB *database.DB
}

var _ app.CredentialStatus = CredentialStatus{}

func (s CredentialStatus) Status(ctx context.Context, cred domain.CredentialContext) (app.CredentialState, error) {
	panic("not implemented: M2 T2")
}

// Resolver authenticates an HTTPS request's bearer token. Errors are
// UNAUTHENTICATED, or CREDENTIAL_REVOKED / CREDENTIAL_EXPIRED.
type Resolver interface {
	Resolve(ctx context.Context, bearer string) (app.Caller, error)
}
