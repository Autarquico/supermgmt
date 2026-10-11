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
// is always active; session and api_token are looked up by id on every call
// (no cache, spec §23); every other kind is refused until its milestone.
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
	case domain.CredentialMCPToken, domain.CredentialOAuthAccessToken, domain.CredentialGitHubOIDC:
	}
	return "", smerr.New(smerr.CodeUnauthenticated, "", fmt.Sprintf("no credential store for kind %q", cred.Kind))
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
