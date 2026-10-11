package daemon

import (
	"context"
	"fmt"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// EnsureSystemIdentity creates the system identity on the first start, in
// either mode, and leaves an existing one alone. Jobs the scheduler submits
// name it as their actor (spec §11.1).
func EnsureSystemIdentity(ctx context.Context, db *database.DB, clock domain.Clock) error {
	err := db.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		_, err := database.GetIdentity(ctx, tx, SystemIdentityID)
		if err == nil {
			return nil
		}
		if smerr.CodeOf(err) != smerr.CodeNotFound {
			return err
		}
		return database.CreateIdentity(ctx, tx, database.Identity{
			ID: SystemIdentityID, ActorType: domain.ActorSystem, Issuer: systemIssuer, Subject: systemIssuer,
			DisplayName: systemIssuer, CreatedAt: clock.Now(),
		})
	})
	if err != nil {
		return fmt.Errorf("ensure the system identity: %w", err)
	}
	return nil
}
