package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// revokeClientTokens revokes every token the rig's registered client holds.
func (r *oauthJWTRig) revokeClientTokens() {
	r.t.Helper()
	must(r.t, r.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		_, err := database.RevokeOAuthTokensOfClient(ctx, tx, r.client.ID, r.clock.Now())
		return err
	}), "revoke client tokens")
}

// deleteAndReregister deletes the rig's client and registers a fresh one on
// the same identity, as ADR-0032's re-registration does.
func (r *oauthJWTRig) deleteAndReregister() database.MCPClient {
	r.t.Helper()
	must(r.t, r.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		if _, err := database.DeleteMCPClient(ctx, tx, r.client.ID, r.clock.Now()); err != nil {
			return err
		}
		_, err := database.RevokeOAuthTokensOfClient(ctx, tx, r.client.ID, r.clock.Now())
		return err
	}), "delete")
	r.clock.Advance(time.Hour)
	now := r.clock.Now()
	again := database.MCPClient{
		ID: r.ids.NewID(), IdentityID: r.client.IdentityID, Name: r.client.Name, Origin: database.MCPOriginRemote,
		State: database.MCPClientActive, RequestedBy: r.admin, ApprovedAt: now, CreatedAt: now, UpdatedAt: now,
	}
	must(r.t, r.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		return database.CreateMCPClient(ctx, tx, again)
	}), "re-register")
	return again
}

func TestOAuthReregistration_OldTokensStayDeadAndNewOnesStartWithNoRoles(t *testing.T) {
	r := newOAuthJWTRig(t)
	seen := r.token(nil)
	must(t, r.resolve(seen), "token seen before deletion")
	unseen := r.token(nil) // issued while the first registration was live, never presented

	again := r.deleteAndReregister()

	r.wantRefused(r.resolve(seen), smerr.CodeUnauthenticated, smerr.ReasonCredentialRevoked)
	r.wantRefused(r.resolve(unseen), smerr.CodeUnauthenticated, smerr.ReasonOAuthTokenInvalid)

	fresh := r.fake.AccessToken(r.clock.Now())
	caller, err := r.resolver.Resolve(context.Background(), r.fake.Sign(fresh))
	must(t, err, "token issued after re-registration")
	if caller.ID != again.IdentityID {
		t.Errorf("caller = %q, want the re-registered identity %q", caller.ID, again.IdentityID)
	}
	var bindings int
	must(t, r.db.Reader().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM role_bindings WHERE identity_id = ?`, again.IdentityID).Scan(&bindings), "count bindings")
	if bindings != 0 {
		t.Errorf("re-registered identity holds %d role bindings, want none", bindings)
	}
}

func TestOAuthReregistration_OldIntrospectedTokenIsRefusedByTheIatFloor(t *testing.T) {
	r := newOAuthIntrospectRig(t, introspectSecret)
	old := r.opaque("opaque-old", nil)

	r.deleteAndReregister()

	r.wantRefused(r.resolve(old), smerr.CodeUnauthenticated, smerr.ReasonOAuthTokenInvalid)
	renewed := r.opaque("opaque-new", func(m map[string]any) {
		m["iat"] = r.clock.Now().Unix()
		m["exp"] = r.clock.Now().Add(time.Hour).Unix()
	})
	must(t, r.resolve(renewed), "token issued after re-registration")
}
