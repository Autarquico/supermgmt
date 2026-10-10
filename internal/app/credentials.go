package app

import (
	"context"
	"fmt"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// CredentialState is what a credential store knows about a credential.
type CredentialState string

const (
	CredentialActive  CredentialState = "active"
	CredentialRevoked CredentialState = "revoked"
	CredentialExpired CredentialState = "expired"
)

// CredentialStatus looks up the live state of a credential (spec §11.1). A
// non-nil error means the lookup itself failed, not that the credential is bad.
type CredentialStatus interface {
	Status(ctx context.Context, cred domain.CredentialContext) (CredentialState, error)
}

// LocalSocketCredentials is the only store M0 ships: a local socket connection
// has no token to revoke or expire. Every other kind is refused until its
// token store exists (M2).
type LocalSocketCredentials struct{}

func (LocalSocketCredentials) Status(_ context.Context, cred domain.CredentialContext) (CredentialState, error) {
	if cred.Kind == domain.CredentialLocalSocket {
		return CredentialActive, nil
	}
	return "", smerr.New(smerr.CodeUnauthenticated, "", fmt.Sprintf("no credential store for kind %q", cred.Kind))
}

// requireActive is the check for a live request: the credential must be active.
func (c core) requireActive(ctx context.Context, cred domain.CredentialContext) error {
	state, err := c.cfg.Credentials.Status(ctx, cred)
	if err != nil {
		return statusLookupError(err)
	}
	return stateError(state)
}

// requireStillValid is the check at claim time: a session or GitHub OIDC token
// that expired naturally after a valid submission does not fail the job;
// revocation always does (spec §11.1).
func (c core) requireStillValid(ctx context.Context, cred domain.CredentialContext) error {
	state, err := c.cfg.Credentials.Status(ctx, cred)
	if err != nil {
		return statusLookupError(err)
	}
	if state == CredentialExpired && expiresNaturally(cred.Kind) {
		return nil
	}
	return stateError(state)
}

func expiresNaturally(kind domain.CredentialKind) bool {
	return kind == domain.CredentialSession || kind == domain.CredentialGitHubOIDC
}

// statusLookupError keeps typed errors (a refused kind fails the job) and wraps
// anything else as an infrastructure failure.
func statusLookupError(err error) error {
	if isTyped(err) {
		return err
	}
	return fmt.Errorf("credential status: %w", err)
}

// stateError fails closed on any state it does not know.
func stateError(state CredentialState) error {
	switch state {
	case CredentialActive:
		return nil
	case CredentialRevoked:
		return smerr.FromReason(smerr.ReasonCredentialRevoked, "credential was revoked")
	case CredentialExpired:
		return smerr.FromReason(smerr.ReasonCredentialExpired, "credential expired")
	}
	return smerr.New(smerr.CodeUnauthenticated, "", fmt.Sprintf("unknown credential state %q", state))
}
