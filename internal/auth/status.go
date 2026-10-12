package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// CredentialStatus is the database-backed app.CredentialStatus: local_socket
// is always active; session, api_token and github_oidc are looked up by id on
// every call (no cache, spec §23); every other kind is refused until its
// milestone.
type CredentialStatus struct {
	DB *database.DB
	// Clock defaults to the system clock.
	Clock domain.Clock
}

var _ app.CredentialStatus = CredentialStatus{}

func (s CredentialStatus) Status(ctx context.Context, cred domain.CredentialContext) (app.CredentialState, error) {
	switch cred.Kind {
	case domain.CredentialLocalSocket:
		return app.CredentialActive, nil
	case domain.CredentialSession:
		row, err := database.GetAuthSession(ctx, s.DB.Reader(), domain.ID(cred.ID))
		return s.stateOf(row.RevokedAt, row.ExpiresAt, err)
	case domain.CredentialAPIToken:
		row, err := database.GetAPIToken(ctx, s.DB.Reader(), domain.ID(cred.ID))
		return s.stateOf(row.RevokedAt, row.ExpiresAt, err)
	case domain.CredentialGitHubOIDC:
		return s.githubOIDCState(ctx, cred.ID)
	case domain.CredentialMCPToken, domain.CredentialOAuthAccessToken:
	}
	return "", smerr.New(smerr.CodeUnauthenticated, "", fmt.Sprintf("no credential store for kind %q", cred.Kind))
}

// githubOIDCState: revoked when the row is revoked (unlinking the automation
// identity from its app revokes its open rows), the identity is disabled, or
// the row is gone; otherwise expired from expires_at, which callers treat as
// natural expiry. A credential without an id is malformed, not revoked.
func (s CredentialStatus) githubOIDCState(ctx context.Context, id string) (app.CredentialState, error) {
	if id == "" {
		return "", smerr.New(smerr.CodeUnauthenticated, "", "github_oidc credential has no id")
	}
	row, err := database.GetGithubOIDCCredential(ctx, s.DB.Reader(), id)
	if smerr.CodeOf(err) == smerr.CodeNotFound {
		return app.CredentialRevoked, nil
	}
	if err != nil {
		return "", fmt.Errorf("read credential: %w", err)
	}
	identity, err := database.GetIdentity(ctx, s.DB.Reader(), row.IdentityID)
	if err == nil && identity.DisabledAt != nil {
		return app.CredentialRevoked, nil
	}
	return s.stateOf(row.RevokedAt, row.ExpiresAt, err)
}

// stateOf judges a credential row. Revocation wins over expiry. A row that is
// gone (swept after it expired) fails closed as revoked: it cannot be told
// apart from one that never existed, and an expired session does not fail a
// job while a revoked one must.
func (s CredentialStatus) stateOf(revokedAt *time.Time, expiresAt time.Time, err error) (app.CredentialState, error) {
	if smerr.CodeOf(err) == smerr.CodeNotFound {
		return app.CredentialRevoked, nil
	}
	if err != nil {
		return "", fmt.Errorf("read credential: %w", err)
	}
	return stateAt(clockOrSystem(s.Clock).Now(), revokedAt, expiresAt), nil
}

func stateAt(now time.Time, revokedAt *time.Time, expiresAt time.Time) app.CredentialState {
	switch {
	case revokedAt != nil:
		return app.CredentialRevoked
	case !now.Before(expiresAt):
		return app.CredentialExpired
	}
	return app.CredentialActive
}

func clockOrSystem(c domain.Clock) domain.Clock {
	if c == nil {
		return domain.SystemClock{}
	}
	return c
}
