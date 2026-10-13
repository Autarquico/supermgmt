package database

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// mcpClient registers a client for a fresh mcp identity, as the apply step does.
func (f *fixture) mcpClient(ctx context.Context, q Querier, requester domain.ID, name string, origin MCPClientOrigin) MCPClient {
	f.t.Helper()
	identity := f.identity(ctx, q, domain.ActorMCP, name+"-"+f.ids.NewID().String())
	return f.mcpClientFor(ctx, q, requester, identity.ID, name, origin)
}

func (f *fixture) mcpClientFor(ctx context.Context, q Querier, requester, identity domain.ID, name string, origin MCPClientOrigin) MCPClient {
	f.t.Helper()
	state := MCPClientPendingToken
	if origin == MCPOriginRemote {
		state = MCPClientActive
	}
	c := MCPClient{
		ID: f.ids.NewID(), IdentityID: identity, Name: name, Origin: origin, State: state,
		RequestedBy: requester, ApprovedAt: testEpoch, CreatedAt: testEpoch, UpdatedAt: testEpoch,
	}
	noErr(f.t, CreateMCPClient(ctx, q, c))
	return c
}

func (f *fixture) oauthToken(client domain.ID, hash string) OAuthAccessToken {
	return OAuthAccessToken{
		ID: f.ids.NewID(), MCPClientID: client, TokenHash: hash, Issuer: "https://issuer.example", JTI: "jti-" + hash,
		IssuedAt: testEpoch, ExpiresAt: testEpoch.Add(time.Hour), FirstSeenAt: testEpoch,
	}
}

func TestMCPClientRoundTrip(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		alice := f.identity(ctx, q, domain.ActorHuman, "alice")
		c := f.mcpClient(ctx, q, alice.ID, "claude-code", MCPOriginLocal)

		got := must(GetMCPClient(ctx, q, c.ID))
		if got.Name != "claude-code" || got.Origin != MCPOriginLocal || got.State != MCPClientPendingToken ||
			got.RequestedBy != alice.ID || got.IdentityID != c.IdentityID || !got.ApprovedAt.Equal(testEpoch) ||
			got.TokenIssuedAt != nil || got.TokenExpiresAt != nil || got.RevokedAt != nil || got.DeletedAt != nil {
			t.Fatalf("got %+v, want the registered pending local client", got)
		}
		live := must(GetLiveMCPClientByIdentity(ctx, q, c.IdentityID))
		if live.ID != c.ID {
			t.Fatalf("live client of the identity = %s, want %s", live.ID, c.ID)
		}
		_, err := GetMCPClient(ctx, q, f.ids.NewID())
		wantError(t, err, smerr.CodeNotFound, "")
	})
}

func TestMCPClientRecordsItsRegistrationJob(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		alice := f.identity(ctx, q, domain.ActorHuman, "alice")
		job := f.job(ctx, q, alice.ID)
		identity := f.identity(ctx, q, domain.ActorMCP, "m")
		c := MCPClient{
			ID: f.ids.NewID(), IdentityID: identity.ID, Name: "n", Origin: MCPOriginLocal, State: MCPClientPendingToken,
			RequestedBy: alice.ID, RegistrationJobID: &job, ApprovedAt: testEpoch, CreatedAt: testEpoch, UpdatedAt: testEpoch,
		}
		noErr(t, CreateMCPClient(ctx, q, c))
		got := must(GetMCPClient(ctx, q, c.ID))
		if got.RegistrationJobID == nil || *got.RegistrationJobID != job {
			t.Fatalf("registration job = %v, want %s", got.RegistrationJobID, job)
		}
	})
}

func TestMCPClientNamesAndIdentitiesAreUniqueWhileLive(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		alice := f.identity(ctx, q, domain.ActorHuman, "alice")
		first := f.mcpClient(ctx, q, alice.ID, "taken", MCPOriginLocal)

		other := f.identity(ctx, q, domain.ActorMCP, "other")
		sameName := MCPClient{
			ID: f.ids.NewID(), IdentityID: other.ID, Name: "taken", Origin: MCPOriginLocal, State: MCPClientPendingToken,
			RequestedBy: alice.ID, ApprovedAt: testEpoch, CreatedAt: testEpoch, UpdatedAt: testEpoch,
		}
		wantError(t, CreateMCPClient(ctx, q, sameName), smerr.CodeConflict, "")

		sameIdentity := sameName
		sameIdentity.ID, sameIdentity.Name, sameIdentity.IdentityID = f.ids.NewID(), "another", first.IdentityID
		wantError(t, CreateMCPClient(ctx, q, sameIdentity), smerr.CodeConflict, "")

		must(DeleteMCPClient(ctx, q, first.ID, testEpoch))
		noErr(t, CreateMCPClient(ctx, q, sameIdentity))
		sameName.ID, sameName.IdentityID = f.ids.NewID(), other.ID
		noErr(t, CreateMCPClient(ctx, q, sameName))
	})
}

func TestMCPClientRequiresAnMCPIdentity(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		alice := f.identity(ctx, q, domain.ActorHuman, "alice")
		c := MCPClient{
			ID: f.ids.NewID(), IdentityID: alice.ID, Name: "n", Origin: MCPOriginLocal, State: MCPClientPendingToken,
			RequestedBy: alice.ID, ApprovedAt: testEpoch, CreatedAt: testEpoch, UpdatedAt: testEpoch,
		}
		if err := CreateMCPClient(ctx, q, c); err == nil {
			t.Fatal("a client on a human identity was accepted")
		}
	})
}

func TestIssueMCPTokenMakesTheClientActiveAndFindableByHash(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		alice := f.identity(ctx, q, domain.ActorHuman, "alice")
		c := f.mcpClient(ctx, q, alice.ID, "local", MCPOriginLocal)
		issuedAt := testEpoch.Add(time.Minute)

		got := must(IssueMCPToken(ctx, q, c.ID, "hash-1", issuedAt, issuedAt.Add(90*24*time.Hour)))

		if got.State != MCPClientActive || got.TokenIssuedAt == nil || !got.TokenIssuedAt.Equal(issuedAt) ||
			got.TokenExpiresAt == nil || !got.TokenExpiresAt.Equal(issuedAt.Add(90*24*time.Hour)) || !got.UpdatedAt.Equal(issuedAt) {
			t.Fatalf("got %+v, want an active client with the token window", got)
		}
		byHash := must(GetMCPClientByTokenHash(ctx, q, "hash-1"))
		if byHash.ID != c.ID {
			t.Fatalf("client by hash = %s, want %s", byHash.ID, c.ID)
		}
		_, err := GetMCPClientByTokenHash(ctx, q, "unknown")
		wantError(t, err, smerr.CodeNotFound, "")
	})
}

func TestIssueMCPTokenWorksOnce(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		alice := f.identity(ctx, q, domain.ActorHuman, "alice")
		c := f.mcpClient(ctx, q, alice.ID, "local", MCPOriginLocal)
		must(IssueMCPToken(ctx, q, c.ID, "hash-1", testEpoch, testEpoch.Add(time.Hour)))

		_, err := IssueMCPToken(ctx, q, c.ID, "hash-2", testEpoch, testEpoch.Add(time.Hour))
		wantError(t, err, smerr.CodeConflict, smerr.ReasonInvalidTransition)
		if got := must(GetMCPClient(ctx, q, c.ID)); got.State != MCPClientActive {
			t.Fatalf("state = %s after a refused second issue", got.State)
		}
		if _, err := GetMCPClientByTokenHash(ctx, q, "hash-2"); err == nil {
			t.Fatal("a second token hash was stored")
		}
	})
}

func TestIssueMCPTokenRefusals(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		alice := f.identity(ctx, q, domain.ActorHuman, "alice")
		remote := f.mcpClient(ctx, q, alice.ID, "remote", MCPOriginRemote)
		deleted := f.mcpClient(ctx, q, alice.ID, "gone", MCPOriginLocal)
		must(DeleteMCPClient(ctx, q, deleted.ID, testEpoch))
		pending := f.mcpClient(ctx, q, alice.ID, "pending", MCPOriginLocal)

		cases := []struct {
			name    string
			id      domain.ID
			expires time.Duration
			code    smerr.Code
			reason  smerr.Reason
		}{
			{"unknown client", f.ids.NewID(), time.Hour, smerr.CodeNotFound, ""},
			{"remote client is already active", remote.ID, time.Hour, smerr.CodeConflict, smerr.ReasonInvalidTransition},
			{"deleted client", deleted.ID, time.Hour, smerr.CodeConflict, smerr.ReasonInvalidTransition},
			{"expiry not after issuance", pending.ID, 0, smerr.CodeInvalidArgument, ""},
			{"expiry beyond 365 days", pending.ID, MCPTokenMaxLifetime + time.Millisecond, smerr.CodeInvalidArgument, ""},
		}
		for _, tc := range cases {
			_, err := IssueMCPToken(ctx, q, tc.id, "hash-x", testEpoch, testEpoch.Add(tc.expires))
			if !errors.Is(err, smerr.New(tc.code, tc.reason, "")) {
				t.Errorf("%s: err = %v, want %s/%s", tc.name, err, tc.code, tc.reason)
			}
		}
		if got := must(GetMCPClient(ctx, q, pending.ID)); got.State != MCPClientPendingToken {
			t.Errorf("a refused issue changed the pending client: %+v", got)
		}
		must(IssueMCPToken(ctx, q, pending.ID, "hash-ok", testEpoch, testEpoch.Add(MCPTokenMaxLifetime)))
	})
}

func TestIssueMCPTokenRaceHasOneWinner(t *testing.T) {
	f := newFixture(t)
	var client MCPClient
	f.tx(func(ctx context.Context, q Querier) {
		alice := f.identity(ctx, q, domain.ActorHuman, "alice")
		client = f.mcpClient(ctx, q, alice.ID, "local", MCPOriginLocal)
	})

	const contenders = 8
	var wins, losses atomic.Int32
	var wg sync.WaitGroup
	for i := range contenders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := f.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *Tx) error {
				_, err := IssueMCPToken(ctx, tx, client.ID, "hash-"+string(rune('a'+i)), testEpoch, testEpoch.Add(time.Hour))
				return err
			})
			switch {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, smerr.New(smerr.CodeConflict, smerr.ReasonInvalidTransition, "")):
				losses.Add(1)
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()

	if wins.Load() != 1 || losses.Load() != contenders-1 {
		t.Fatalf("wins = %d, losses = %d; want 1 and %d", wins.Load(), losses.Load(), contenders-1)
	}
}

func TestDeleteMCPClientKeepsHistoryAndRevokesTheToken(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		alice := f.identity(ctx, q, domain.ActorHuman, "alice")
		c := f.mcpClient(ctx, q, alice.ID, "local", MCPOriginLocal)
		must(IssueMCPToken(ctx, q, c.ID, "hash-1", testEpoch, testEpoch.Add(time.Hour)))
		at := testEpoch.Add(time.Minute)

		if first := must(DeleteMCPClient(ctx, q, c.ID, at)); !first {
			t.Fatal("first delete reported false")
		}
		if again := must(DeleteMCPClient(ctx, q, c.ID, at.Add(time.Hour))); again {
			t.Fatal("second delete reported true")
		}

		got := must(GetMCPClient(ctx, q, c.ID))
		if got.State != MCPClientDeleted || got.DeletedAt == nil || !got.DeletedAt.Equal(at) ||
			got.RevokedAt == nil || !got.RevokedAt.Equal(at) {
			t.Fatalf("got %+v, want deleted and revoked at %s, row kept", got, at)
		}
		if _, err := GetLiveMCPClientByIdentity(ctx, q, c.IdentityID); err == nil {
			t.Fatal("a deleted client is still the live one of its identity")
		}
		_, err := DeleteMCPClient(ctx, q, f.ids.NewID(), at)
		wantError(t, err, smerr.CodeNotFound, "")
	})
}

func TestReregisteringAfterDeleteKeepsBothRows(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		alice := f.identity(ctx, q, domain.ActorHuman, "alice")
		old := f.mcpClient(ctx, q, alice.ID, "remote", MCPOriginRemote)
		oldToken := must(RecordOAuthAccessToken(ctx, q, f.oauthToken(old.ID, "oat-old")))
		must(DeleteMCPClient(ctx, q, old.ID, testEpoch))
		must(RevokeOAuthTokensOfClient(ctx, q, old.ID, testEpoch))

		fresh := f.mcpClientFor(ctx, q, alice.ID, old.IdentityID, "remote", MCPOriginRemote)

		all := must(ListMCPClients(ctx, q))
		if len(all) != 2 || all[0].ID != old.ID || all[1].ID != fresh.ID {
			t.Fatalf("list = %+v, want the deleted client then the new one", all)
		}
		if live := must(GetLiveMCPClientByIdentity(ctx, q, old.IdentityID)); live.ID != fresh.ID {
			t.Fatalf("live client = %s, want the new one %s", live.ID, fresh.ID)
		}
		if got := must(GetOAuthAccessToken(ctx, q, oldToken.ID)); got.RevokedAt == nil || got.MCPClientID != old.ID {
			t.Fatalf("old token row = %+v, want revoked and still the old client's", got)
		}
		_, err := RecordOAuthAccessToken(ctx, q, f.oauthToken(fresh.ID, "oat-old"))
		wantError(t, err, smerr.CodeConflict, "")
	})
}

func TestTouchMCPClientRecordsLastUse(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		alice := f.identity(ctx, q, domain.ActorHuman, "alice")
		c := f.mcpClient(ctx, q, alice.ID, "local", MCPOriginLocal)
		at := testEpoch.Add(time.Hour)
		noErr(t, TouchMCPClient(ctx, q, c.ID, at))
		if got := must(GetMCPClient(ctx, q, c.ID)); got.LastUsedAt == nil || !got.LastUsedAt.Equal(at) {
			t.Fatalf("last used = %v, want %s", got.LastUsedAt, at)
		}
	})
}

func TestRecordOAuthAccessToken(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		alice := f.identity(ctx, q, domain.ActorHuman, "alice")
		a := f.mcpClient(ctx, q, alice.ID, "a", MCPOriginRemote)
		b := f.mcpClient(ctx, q, alice.ID, "b", MCPOriginRemote)

		first := must(RecordOAuthAccessToken(ctx, q, f.oauthToken(a.ID, "oat-1")))
		if first.MCPClientID != a.ID || first.Issuer != "https://issuer.example" || first.JTI != "jti-oat-1" ||
			!first.ExpiresAt.Equal(testEpoch.Add(time.Hour)) {
			t.Fatalf("stored %+v", first)
		}

		seenAgain := f.oauthToken(a.ID, "oat-1")
		seenAgain.FirstSeenAt = testEpoch.Add(time.Minute)
		again := must(RecordOAuthAccessToken(ctx, q, seenAgain))
		if again.ID != first.ID || !again.FirstSeenAt.Equal(testEpoch) ||
			again.LastUsedAt == nil || !again.LastUsedAt.Equal(testEpoch.Add(time.Minute)) {
			t.Fatalf("second sighting = %+v, want the same row, first seen kept, last use stamped", again)
		}

		_, err := RecordOAuthAccessToken(ctx, q, f.oauthToken(b.ID, "oat-1"))
		wantError(t, err, smerr.CodeConflict, "")
		if got := must(GetOAuthAccessTokenByHash(ctx, q, "oat-1")); got.MCPClientID != a.ID {
			t.Fatalf("hash re-attached to %s", got.MCPClientID)
		}
	})
}

func TestRecordOAuthAccessTokenRefusesARevokedHash(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		alice := f.identity(ctx, q, domain.ActorHuman, "alice")
		a := f.mcpClient(ctx, q, alice.ID, "a", MCPOriginRemote)
		must(RecordOAuthAccessToken(ctx, q, f.oauthToken(a.ID, "oat-1")))
		keep := must(RecordOAuthAccessToken(ctx, q, f.oauthToken(a.ID, "oat-2")))

		if n := must(RevokeOAuthTokensOfClient(ctx, q, a.ID, testEpoch)); n != 2 {
			t.Fatalf("revoked %d, want 2", n)
		}
		if n := must(RevokeOAuthTokensOfClient(ctx, q, a.ID, testEpoch.Add(time.Hour))); n != 0 {
			t.Fatalf("second revoke changed %d rows", n)
		}
		_, err := RecordOAuthAccessToken(ctx, q, f.oauthToken(a.ID, "oat-1"))
		wantError(t, err, smerr.CodeConflict, "")
		if got := must(GetOAuthAccessToken(ctx, q, keep.ID)); got.RevokedAt == nil || !got.RevokedAt.Equal(testEpoch) {
			t.Fatalf("revoked_at = %v, want the first revocation time", got.RevokedAt)
		}
	})
}
