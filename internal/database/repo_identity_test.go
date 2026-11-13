package database

import (
	"context"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func TestRevokeIdentityCredentialsRevokesSessionsAndTokensIncludingExpiredOnes(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		alice := f.identity(ctx, q, domain.ActorHuman, "alice")
		bob := f.identity(ctx, q, domain.ActorHuman, "bob")
		session := f.authSession(alice.ID, "s-alice", time.Hour)
		noErr(t, CreateAuthSession(ctx, q, session))
		expired := f.token(alice.ID, "old", "hash-old", time.Hour)
		noErr(t, CreateAPIToken(ctx, q, expired))
		live := f.token(alice.ID, "ci", "hash-ci", 30*24*time.Hour)
		noErr(t, CreateAPIToken(ctx, q, live))
		bobs := f.token(bob.ID, "ci", "hash-bob", 30*24*time.Hour)
		noErr(t, CreateAPIToken(ctx, q, bobs))
		at := testEpoch.Add(24 * time.Hour) // the expired token lapsed a day ago

		n := must(RevokeIdentityCredentials(ctx, q, alice.ID, at))

		if n != 3 {
			t.Fatalf("revoked %d, want the session and both API tokens, the expired one included", n)
		}
		for name, revokedAt := range map[string]*time.Time{
			"session": must(GetAuthSession(ctx, q, session.ID)).RevokedAt,
			"expired": must(GetAPIToken(ctx, q, expired.ID)).RevokedAt,
			"live":    must(GetAPIToken(ctx, q, live.ID)).RevokedAt,
		} {
			if revokedAt == nil || !revokedAt.Equal(at) {
				t.Errorf("%s revoked_at = %v, want %s", name, revokedAt, at)
			}
		}
		if got := must(GetAPIToken(ctx, q, bobs.ID)); got.RevokedAt != nil {
			t.Errorf("another identity's token revoked_at = %v, want none", got.RevokedAt)
		}
		if floor := must(CredentialsNotBefore(ctx, q)); !floor.IsZero() {
			t.Errorf("credentials-not-before = %s, want none: it is global", floor)
		}
	})
}

func TestRevokeIdentityCredentialsReachesAnMCPIdentitysTokenAndItsOAuthTokens(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		alice := f.identity(ctx, q, domain.ActorHuman, "alice")
		local := f.identity(ctx, q, domain.ActorMCP, "local-agent")
		remote := f.identity(ctx, q, domain.ActorMCP, "remote-agent")
		other := f.identity(ctx, q, domain.ActorMCP, "other-agent")
		localClient := f.mcpClientFor(ctx, q, alice.ID, local.ID, "local", MCPOriginLocal)
		must(IssueMCPToken(ctx, q, localClient.ID, "hash-mcp", testEpoch, testEpoch.Add(time.Hour)))
		remoteClient := f.mcpClientFor(ctx, q, alice.ID, remote.ID, "remote", MCPOriginRemote)
		oauth := must(RecordOAuthAccessToken(ctx, q, f.oauthToken(remoteClient.ID, "oat-1")))
		otherClient := f.mcpClientFor(ctx, q, alice.ID, other.ID, "other", MCPOriginRemote)
		otherOAuth := must(RecordOAuthAccessToken(ctx, q, f.oauthToken(otherClient.ID, "oat-2")))
		at := testEpoch.Add(time.Minute)

		if n := must(RevokeIdentityCredentials(ctx, q, local.ID, at)); n != 1 {
			t.Fatalf("local agent: revoked %d, want its MCP token", n)
		}
		if n := must(RevokeIdentityCredentials(ctx, q, remote.ID, at)); n != 1 {
			t.Fatalf("remote agent: revoked %d, want its OAuth token", n)
		}

		if got := must(GetMCPClient(ctx, q, localClient.ID)); got.RevokedAt == nil || !got.RevokedAt.Equal(at) {
			t.Errorf("local client revoked_at = %v, want %s", got.RevokedAt, at)
		}
		if got := must(GetOAuthAccessToken(ctx, q, oauth.ID)); got.RevokedAt == nil || !got.RevokedAt.Equal(at) {
			t.Errorf("OAuth token revoked_at = %v, want %s", got.RevokedAt, at)
		}
		if got := must(GetOAuthAccessToken(ctx, q, otherOAuth.ID)); got.RevokedAt != nil {
			t.Errorf("another identity's OAuth token revoked_at = %v, want none", got.RevokedAt)
		}
	})
}

func TestIdentitiesListOldestFirstAndOnlyEnabledOnesCountAsAdmins(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		admin := must(GetRoleByName(ctx, q, "admin"))
		first := f.identity(ctx, q, domain.ActorHuman, "first")
		second := f.identity(ctx, q, domain.ActorHuman, "second")
		for _, id := range []domain.ID{first.ID, second.ID} {
			noErr(t, CreateRoleBinding(ctx, q, RoleBinding{ID: f.ids.NewID(), IdentityID: id, RoleID: admin.ID, CreatedAt: testEpoch}))
		}
		if n := must(CountEnabledAdmins(ctx, q, "admin")); n != 2 {
			t.Fatalf("enabled admins = %d, want 2", n)
		}

		at := testEpoch.Add(time.Hour)
		noErr(t, SetIdentityDisabled(ctx, q, second.ID, &at))

		if n := must(CountEnabledAdmins(ctx, q, "admin")); n != 1 {
			t.Errorf("enabled admins = %d, want 1 once one is disabled", n)
		}
		listed := must(ListIdentities(ctx, q))
		if len(listed) != 2 || listed[0].ID != first.ID || listed[1].ID != second.ID {
			t.Fatalf("list = %+v, want both identities oldest first", listed)
		}
		if listed[0].DisabledAt != nil || listed[1].DisabledAt == nil || !listed[1].DisabledAt.Equal(at) {
			t.Errorf("disabled_at = %v and %v, want none and %s", listed[0].DisabledAt, listed[1].DisabledAt, at)
		}
		noErr(t, SetIdentityDisabled(ctx, q, second.ID, nil))
		if got := must(GetIdentity(ctx, q, second.ID)); got.DisabledAt != nil {
			t.Errorf("disabled_at after enabling = %v, want none", got.DisabledAt)
		}
		if err := SetIdentityDisabled(ctx, q, "missing", nil); smerr.CodeOf(err) != smerr.CodeNotFound {
			t.Errorf("unknown identity: %v, want NOT_FOUND", err)
		}
	})
}
