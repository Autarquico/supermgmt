package daemon

import (
	"context"
	"fmt"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const (
	localIssuer  = "local"
	adminRole    = "admin"
	eventSource  = "daemon"
	eventCreated = "identity.local.created"
)

// LocalIdentityID is the identity of the OS user uid in local mode. The id is
// derived from the uid, in the same UUIDv7-shaped family as the built-in
// roles, so finding it needs no lookup by subject and creating it twice is a
// conflict, not a duplicate.
func LocalIdentityID(uid uint32) domain.ID {
	return domain.ID(fmt.Sprintf("01970000-0000-7000-8001-%012x", uid))
}

// EnsureLocalIdentity creates the `local:<uid>` human identity and binds it to
// admin on the first daemon start (spec §11.5), auditing that once. It never
// touches an identity that exists: a binding an administrator removed stays
// removed.
func EnsureLocalIdentity(ctx context.Context, db *database.DB, clock domain.Clock, ids domain.IDGenerator, uid uint32) (domain.ID, error) {
	id := LocalIdentityID(uid)
	subject := fmt.Sprintf("local:%d", uid)
	emitter := audit.Emitter{Clock: clock, IDs: ids, Source: eventSource}
	err := db.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		_, err := database.GetIdentity(ctx, tx, id)
		if err == nil {
			return nil
		}
		if smerr.CodeOf(err) != smerr.CodeNotFound {
			return err
		}
		if err := createAdmin(ctx, tx, clock, ids, id, subject); err != nil {
			return err
		}
		_, err = emitter.Emit(ctx, database.EventsIn(tx), domain.Event{
			ActorType: domain.ActorSystem, Action: eventCreated,
			ResourceType: domain.ResourceIdentity, ResourceID: id,
			Severity: domain.SeverityInfo, Result: domain.ResultSucceeded,
			Data: map[string]any{"subject": subject, "role": adminRole},
		})
		return err
	})
	if err != nil {
		return "", fmt.Errorf("ensure the local identity: %w", err)
	}
	return id, nil
}

func createAdmin(ctx context.Context, tx *database.Tx, clock domain.Clock, ids domain.IDGenerator, id domain.ID, subject string) error {
	now := clock.Now()
	err := database.CreateIdentity(ctx, tx, database.Identity{
		ID: id, ActorType: domain.ActorHuman, Issuer: localIssuer, Subject: subject, DisplayName: subject, CreatedAt: now,
	})
	if err != nil {
		return err
	}
	role, err := database.GetRoleByName(ctx, tx, adminRole)
	if err != nil {
		return err
	}
	return database.CreateRoleBinding(ctx, tx, database.RoleBinding{ID: ids.NewID(), IdentityID: id, RoleID: role.ID, CreatedAt: now})
}
