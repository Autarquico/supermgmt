package database

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const dayMillis = int64(24 * time.Hour / time.Millisecond)

func authBaselines() map[string]map[string]any {
	return map[string]map[string]any{
		"sessions": {
			"id": idA, "identity_id": idA, "token_hash": "h", "origin": "oidc", "created_at": 1, "expires_at": 2,
		},
		"api_tokens": {
			"id": idA, "identity_id": idA, "name": "ci", "token_hash": "h", "created_at": 1, "expires_at": 2,
		},
		"bootstrap_codes": {"id": idA, "code_hash": "h", "created_at": 1, "expires_at": 2},
		"oidc_replay":     {"issuer": "https://idp", "jti": "j", "expires_at": 2},
		"join_tokens": {
			"id": idA, "token_hash": "h", "created_by": idA, "created_at": 1, "expires_at": 2,
		},
	}
}

func TestSessionOriginCheckMatchesDomain(t *testing.T) {
	db := migratedTest(t)
	base := authBaselines()["sessions"]
	for _, origin := range AllSessionOrigins() {
		if err := tryInsert(t, db, "sessions", override(base, "origin", string(origin))); err != nil {
			t.Errorf("origin %q rejected: %v", origin, err)
		}
	}
	err := tryInsert(t, db, "sessions", override(base, "origin", "bogus"))
	if err == nil || !strings.Contains(err.Error(), "CHECK constraint failed") {
		t.Fatalf("origin=bogus: err = %v, want CHECK failure", err)
	}
	ddl := scalar[string](t, db.Reader(), `SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'sessions'`)
	var got []string
	for _, m := range checkInList.FindAllStringSubmatch(ddl, -1) {
		for _, item := range strings.Split(m[3], ",") {
			got = append(got, strings.Trim(strings.TrimSpace(item), "'"))
		}
	}
	slices.Sort(got)
	if want := values(AllSessionOrigins()); !slices.Equal(got, slices.Sorted(slices.Values(want))) {
		t.Fatalf("sessions.origin CHECK = %v, want %v", got, want)
	}
}

func TestAPITokenExpiryCheckAllowsAtMostOneYear(t *testing.T) {
	db := migratedTest(t)
	base := authBaselines()["api_tokens"]
	if err := tryInsert(t, db, "api_tokens", override(base, "expires_at", 1+365*dayMillis)); err != nil {
		t.Errorf("exactly 365 days rejected: %v", err)
	}
	err := tryInsert(t, db, "api_tokens", override(base, "expires_at", 1+365*dayMillis+1))
	if err == nil || !strings.Contains(err.Error(), "CHECK constraint failed") {
		t.Fatalf("365 days + 1 ms: err = %v, want CHECK failure", err)
	}
}

func TestM2UniqueConstraints(t *testing.T) {
	db := migratedTest(t)
	b := authBaselines()
	cases := []struct {
		name  string
		table string
		dup   map[string]any
	}{
		{"session token hash", "sessions", override(b["sessions"], "id", idB)},
		{"api token hash", "api_tokens", override(override(b["api_tokens"], "id", idB), "name", "other")},
		{"api token name per identity", "api_tokens", override(b["api_tokens"], "id", idB)},
		{"bootstrap code hash", "bootstrap_codes", override(b["bootstrap_codes"], "id", idB)},
		{"oidc replay issuer+jti", "oidc_replay", b["oidc_replay"]},
		{"join token hash", "join_tokens", override(b["join_tokens"], "id", idB)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var dupErr error
			_ = db.WithWriteTx(context.Background(), func(ctx context.Context, tx *Tx) error {
				if _, err := tx.ExecContext(ctx, `PRAGMA defer_foreign_keys = ON`); err != nil {
					t.Fatal(err)
				}
				if err := insertRow(ctx, tx, tc.table, b[tc.table]); err != nil {
					t.Fatalf("first insert: %v", err)
				}
				dupErr = insertRow(ctx, tx, tc.table, tc.dup)
				return fmt.Errorf("rollback")
			})
			if dupErr == nil || !strings.Contains(dupErr.Error(), "UNIQUE constraint failed") {
				t.Fatalf("duplicate err = %v, want UNIQUE failure", dupErr)
			}
		})
	}
}

func TestSameAPITokenNameIsAllowedForAnotherIdentity(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		alice := f.identity(ctx, q, domain.ActorHuman, "alice")
		bob := f.identity(ctx, q, domain.ActorHuman, "bob")
		noErr(t, CreateAPIToken(ctx, q, f.token(alice.ID, "ci", "h1", time.Hour)))
		noErr(t, CreateAPIToken(ctx, q, f.token(bob.ID, "ci", "h2", time.Hour)))
		wantError(t, CreateAPIToken(ctx, q, f.token(alice.ID, "ci", "h3", time.Hour)), smerr.CodeConflict, "")
	})
}

func TestM2ForeignKeysAreEnforced(t *testing.T) {
	db := migratedTest(t)
	for _, table := range []string{"sessions", "api_tokens", "join_tokens"} {
		err := db.WithWriteTx(context.Background(), func(ctx context.Context, tx *Tx) error {
			return insertRow(ctx, tx, table, authBaselines()[table]) // identity does not exist
		})
		if err == nil || !strings.Contains(err.Error(), "FOREIGN KEY") {
			t.Errorf("%s: err = %v, want FOREIGN KEY failure", table, err)
		}
	}
}

func (f *fixture) token(identity domain.ID, name, hash string, ttl time.Duration) APIToken {
	return APIToken{
		ID: f.ids.NewID(), IdentityID: identity, Name: name, TokenHash: hash,
		CreatedAt: testEpoch, ExpiresAt: testEpoch.Add(ttl),
	}
}

func (f *fixture) authSession(identity domain.ID, hash string, ttl time.Duration) AuthSession {
	return AuthSession{
		ID: f.ids.NewID(), IdentityID: identity, TokenHash: hash, Client: "sm/test", Origin: OriginOIDC,
		CreatedAt: testEpoch, ExpiresAt: testEpoch.Add(ttl),
	}
}

func TestAuthSessionLifecycle(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		alice := f.identity(ctx, q, domain.ActorHuman, "alice")
		s := f.authSession(alice.ID, "hash-1", time.Hour)
		noErr(t, CreateAuthSession(ctx, q, s))

		byHash := must(GetAuthSessionByHash(ctx, q, "hash-1"))
		if byHash != s {
			t.Fatalf("by hash = %+v, want %+v", byHash, s)
		}
		if byID := must(GetAuthSession(ctx, q, s.ID)); byID != s {
			t.Fatalf("by id = %+v, want %+v", byID, s)
		}
		_, err := GetAuthSessionByHash(ctx, q, "unknown")
		wantError(t, err, smerr.CodeNotFound, "")

		noErr(t, TouchAuthSession(ctx, q, s.ID, testEpoch.Add(time.Minute)))
		if got := must(GetAuthSession(ctx, q, s.ID)); got.LastUsedAt == nil || !got.LastUsedAt.Equal(testEpoch.Add(time.Minute)) {
			t.Fatalf("last used = %v", got.LastUsedAt)
		}

		first := must(RevokeAuthSession(ctx, q, s.ID, testEpoch.Add(2*time.Minute)))
		again := must(RevokeAuthSession(ctx, q, s.ID, testEpoch.Add(3*time.Minute)))
		if !first || again {
			t.Fatalf("revoke first/again = %v/%v, want true/false", first, again)
		}
		if got := must(GetAuthSession(ctx, q, s.ID)); got.RevokedAt == nil || !got.RevokedAt.Equal(testEpoch.Add(2*time.Minute)) {
			t.Fatalf("revoked at = %v, want the first revocation time", got.RevokedAt)
		}
		_, err = RevokeAuthSession(ctx, q, f.ids.NewID(), testEpoch)
		wantError(t, err, smerr.CodeNotFound, "")
	})
}

func TestAuthSessionRejectsBadInput(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		alice := f.identity(ctx, q, domain.ActorHuman, "alice")
		bogus := f.authSession(alice.ID, "h", time.Hour)
		bogus.Origin = "bogus"
		wantError(t, CreateAuthSession(ctx, q, bogus), smerr.CodeInvalidArgument, "")

		noErr(t, CreateAuthSession(ctx, q, f.authSession(alice.ID, "same", time.Hour)))
		wantError(t, CreateAuthSession(ctx, q, f.authSession(alice.ID, "same", time.Hour)), smerr.CodeConflict, "")
	})
}

func TestAPITokenLifecycle(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		alice := f.identity(ctx, q, domain.ActorHuman, "alice")
		tok := f.token(alice.ID, "ci", "hash-1", 30*24*time.Hour)
		tok.Scopes = []string{"node.read", "job.read"}
		noErr(t, CreateAPIToken(ctx, q, tok))
		other := f.token(alice.ID, "deploy", "hash-2", time.Hour)
		noErr(t, CreateAPIToken(ctx, q, other))

		got := must(GetAPITokenByHash(ctx, q, "hash-1"))
		if !slices.Equal(got.Scopes, tok.Scopes) || got.ID != tok.ID || got.RevokedAt != nil {
			t.Fatalf("token = %+v", got)
		}
		if empty := must(GetAPIToken(ctx, q, other.ID)); empty.Scopes == nil || len(empty.Scopes) != 0 {
			t.Fatalf("nil scopes stored as %#v, want empty list", empty.Scopes)
		}

		listed := must(ListAPITokens(ctx, q, alice.ID))
		if len(listed) != 2 || listed[0].ID != tok.ID || listed[1].ID != other.ID {
			t.Fatalf("list = %+v", listed)
		}
		if first := must(RevokeAPIToken(ctx, q, tok.ID, testEpoch)); !first {
			t.Fatal("first revoke reported false")
		}
		if again := must(RevokeAPIToken(ctx, q, tok.ID, testEpoch.Add(time.Hour))); again {
			t.Fatal("second revoke reported true")
		}
		noErr(t, TouchAPIToken(ctx, q, other.ID, testEpoch.Add(time.Minute)))
		if used := must(GetAPIToken(ctx, q, other.ID)); used.LastUsedAt == nil {
			t.Fatal("touch left last_used_at empty")
		}
		_, err := GetAPIToken(ctx, q, f.ids.NewID())
		wantError(t, err, smerr.CodeNotFound, "")
	})
}

func TestAPITokenLifetimeBounds(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		alice := f.identity(ctx, q, domain.ActorHuman, "alice")
		noErr(t, CreateAPIToken(ctx, q, f.token(alice.ID, "max", "h1", APITokenMaxLifetime)))
		wantError(t, CreateAPIToken(ctx, q, f.token(alice.ID, "long", "h2", APITokenMaxLifetime+time.Millisecond)),
			smerr.CodeInvalidArgument, "")
		wantError(t, CreateAPIToken(ctx, q, f.token(alice.ID, "none", "h3", 0)), smerr.CodeInvalidArgument, "")
	})
}

func TestBootstrapCodeIsSingleUseAndNewCodeInvalidatesOld(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		admin := f.identity(ctx, q, domain.ActorHuman, "root")
		issue := func(hash string) BootstrapCode {
			c := BootstrapCode{ID: f.ids.NewID(), CodeHash: hash, CreatedAt: testEpoch, ExpiresAt: testEpoch.Add(time.Hour)}
			noErr(t, IssueBootstrapCode(ctx, q, c))
			return c
		}
		old := issue("old")
		fresh := issue("fresh")

		_, err := ConsumeBootstrapCode(ctx, q, "old", admin.ID, testEpoch)
		wantError(t, err, smerr.CodeNotFound, "")
		if got := must(GetBootstrapCode(ctx, q, old.ID)); got.InvalidatedAt == nil {
			t.Fatal("old code was not invalidated")
		}

		used := must(ConsumeBootstrapCode(ctx, q, "fresh", admin.ID, testEpoch.Add(time.Minute)))
		if used.ID != fresh.ID || used.ConsumedAt == nil || used.ConsumedBy == nil || *used.ConsumedBy != admin.ID {
			t.Fatalf("consumed = %+v", used)
		}
		_, err = ConsumeBootstrapCode(ctx, q, "fresh", admin.ID, testEpoch.Add(2*time.Minute))
		wantError(t, err, smerr.CodeNotFound, "")

		issue("third")
		if got := must(GetBootstrapCode(ctx, q, fresh.ID)); got.InvalidatedAt != nil {
			t.Fatal("a consumed code must not be marked invalidated")
		}
	})
}

func TestBootstrapCodeExpires(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		admin := f.identity(ctx, q, domain.ActorHuman, "root")
		noErr(t, IssueBootstrapCode(ctx, q, BootstrapCode{
			ID: f.ids.NewID(), CodeHash: "c", CreatedAt: testEpoch, ExpiresAt: testEpoch.Add(time.Hour),
		}))
		_, err := ConsumeBootstrapCode(ctx, q, "c", admin.ID, testEpoch.Add(time.Hour))
		wantError(t, err, smerr.CodeNotFound, "")
		noErr(t, nilIfNil(ConsumeBootstrapCode(ctx, q, "c", admin.ID, testEpoch.Add(time.Hour-time.Millisecond))))
	})
}

func nilIfNil[T any](_ T, err error) error { return err }

func TestOIDCReplayRecordsEachJTIOnce(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		claim := func(issuer, jti string) bool {
			return must(ClaimOIDCJTI(ctx, q, issuer, jti, testEpoch.Add(time.Hour)))
		}
		if !claim("https://a", "j1") {
			t.Fatal("first claim reported replay")
		}
		if claim("https://a", "j1") {
			t.Fatal("second claim of the same jti was accepted")
		}
		if !claim("https://b", "j1") || !claim("https://a", "j2") {
			t.Fatal("a different issuer or jti was reported as replay")
		}
	})
}

func TestRevokeAllCredentialsLeavesRevokedTimestampsAlone(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		alice := f.identity(ctx, q, domain.ActorHuman, "alice")
		live := f.authSession(alice.ID, "s1", time.Hour)
		gone := f.authSession(alice.ID, "s2", time.Hour)
		tok := f.token(alice.ID, "ci", "t1", time.Hour)
		noErr(t, CreateAuthSession(ctx, q, live))
		noErr(t, CreateAuthSession(ctx, q, gone))
		noErr(t, CreateAPIToken(ctx, q, tok))
		must(RevokeAuthSession(ctx, q, gone.ID, testEpoch))

		later := testEpoch.Add(time.Hour)
		if n := must(RevokeAllCredentials(ctx, q, later)); n != 2 {
			t.Fatalf("revoked %d, want 2 (the live session and the token)", n)
		}
		if got := must(GetAuthSession(ctx, q, gone.ID)); !got.RevokedAt.Equal(testEpoch) {
			t.Fatalf("earlier revocation overwritten: %v", got.RevokedAt)
		}
		if got := must(GetAuthSession(ctx, q, live.ID)); got.RevokedAt == nil {
			t.Fatal("live session still active")
		}
		if got := must(GetAPIToken(ctx, q, tok.ID)); got.RevokedAt == nil {
			t.Fatal("token still active")
		}
		if n := must(RevokeAllCredentials(ctx, q, later)); n != 0 {
			t.Fatalf("second pass revoked %d, want 0", n)
		}
	})
}

func TestInvalidatePendingCodesSkipsConsumed(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		admin := f.identity(ctx, q, domain.ActorHuman, "root")
		consumed := BootstrapCode{ID: f.ids.NewID(), CodeHash: "used", CreatedAt: testEpoch, ExpiresAt: testEpoch.Add(time.Hour)}
		noErr(t, IssueBootstrapCode(ctx, q, consumed))
		must(ConsumeBootstrapCode(ctx, q, "used", admin.ID, testEpoch))
		pending := BootstrapCode{ID: f.ids.NewID(), CodeHash: "pending", CreatedAt: testEpoch, ExpiresAt: testEpoch.Add(time.Hour)}
		noErr(t, IssueBootstrapCode(ctx, q, pending))
		join := JoinToken{
			ID: f.ids.NewID(), TokenHash: "j", CreatedBy: admin.ID, CreatedAt: testEpoch,
			ExpiresAt: testEpoch.Add(time.Hour), Constraints: JoinConstraints{MaxNodes: 1},
		}
		noErr(t, CreateJoinToken(ctx, q, join))

		if n := must(InvalidatePendingCodes(ctx, q, testEpoch.Add(time.Minute))); n != 2 {
			t.Fatalf("invalidated %d, want 2 (pending bootstrap code and join token)", n)
		}
		if got := must(GetBootstrapCode(ctx, q, consumed.ID)); got.InvalidatedAt != nil {
			t.Fatal("consumed code was invalidated")
		}
		_, err := UseJoinToken(ctx, q, join.ID, testEpoch.Add(2*time.Minute))
		wantError(t, err, smerr.CodeConflict, "")
	})
}

func TestSweepAuthRemovesOnlyExpiredRows(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		alice := f.identity(ctx, q, domain.ActorHuman, "alice")
		expiredSession := f.authSession(alice.ID, "s-old", time.Minute)
		liveSession := f.authSession(alice.ID, "s-live", time.Hour)
		revokedLive := f.authSession(alice.ID, "s-revoked", time.Hour)
		for _, s := range []AuthSession{expiredSession, liveSession, revokedLive} {
			noErr(t, CreateAuthSession(ctx, q, s))
		}
		must(RevokeAuthSession(ctx, q, revokedLive.ID, testEpoch))
		noErr(t, CreateAPIToken(ctx, q, f.token(alice.ID, "old", "t-old", time.Minute)))
		noErr(t, CreateAPIToken(ctx, q, f.token(alice.ID, "live", "t-live", time.Hour)))
		noErr(t, IssueBootstrapCode(ctx, q, BootstrapCode{
			ID: f.ids.NewID(), CodeHash: "b", CreatedAt: testEpoch, ExpiresAt: testEpoch.Add(time.Minute),
		}))
		noErr(t, CreateJoinToken(ctx, q, JoinToken{
			ID: f.ids.NewID(), TokenHash: "j", CreatedBy: alice.ID, CreatedAt: testEpoch,
			ExpiresAt: testEpoch.Add(time.Minute), Constraints: JoinConstraints{MaxNodes: 1},
		}))
		must(ClaimOIDCJTI(ctx, q, "https://a", "old", testEpoch.Add(time.Minute)))
		must(ClaimOIDCJTI(ctx, q, "https://a", "live", testEpoch.Add(time.Hour)))

		cutoff := testEpoch.Add(time.Minute)
		got := must(SweepAuth(ctx, q, cutoff))
		want := AuthSwept{Sessions: 1, APITokens: 1, BootstrapCodes: 1, JoinTokens: 1, OIDCReplays: 1}
		if got != want {
			t.Fatalf("swept %+v, want %+v", got, want)
		}
		if again := must(SweepAuth(ctx, q, cutoff)); again != (AuthSwept{}) {
			t.Fatalf("second sweep removed %+v", again)
		}
		for _, id := range []domain.ID{liveSession.ID, revokedLive.ID} {
			noErr(t, nilIfNil(GetAuthSession(ctx, q, id)))
		}
		_, err := GetAuthSession(ctx, q, expiredSession.ID)
		wantError(t, err, smerr.CodeNotFound, "")
		if replay := must(ClaimOIDCJTI(ctx, q, "https://a", "old", testEpoch.Add(time.Hour))); !replay {
			t.Fatal("a swept jti should be claimable again")
		}
	})
}
