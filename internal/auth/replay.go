package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/autarquico/supermgmt/internal/auth/oidc"
	"github.com/autarquico/supermgmt/internal/database"
)

// OIDCReplay is the oidc.ReplayStore over the oidc_replay table, so an ID
// token is accepted once even across restarts. A jti seen before reports
// not fresh and the adapter refuses the login as OIDC_REPLAY.
type OIDCReplay struct {
	DB *database.DB
}

var _ oidc.ReplayStore = OIDCReplay{}

func (r OIDCReplay) Remember(ctx context.Context, issuer, jti string, expiresAt time.Time) (bool, error) {
	var fresh bool
	err := r.DB.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		var err error
		fresh, err = database.ClaimOIDCJTI(ctx, tx, issuer, jti, expiresAt)
		return err
	})
	if err != nil {
		return false, fmt.Errorf("remember oidc jti: %w", err)
	}
	return fresh, nil
}
