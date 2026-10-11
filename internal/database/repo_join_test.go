package database

import (
	"context"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func (f *fixture) joinToken(creator domain.ID, hash string, maxNodes int) JoinToken {
	return JoinToken{
		ID: f.ids.NewID(), TokenHash: hash, CreatedBy: creator,
		Constraints: JoinConstraints{Tags: []string{"edge"}, MaxNodes: maxNodes, SourceCIDRs: []string{"10.0.0.0/8"}},
		CreatedAt:   testEpoch, ExpiresAt: testEpoch.Add(time.Hour),
	}
}

func TestJoinTokenRoundTripsItsConstraints(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		admin := f.identity(ctx, q, domain.ActorHuman, "root")
		tok := f.joinToken(admin.ID, "h", 3)
		noErr(t, CreateJoinToken(ctx, q, tok))

		got := must(GetJoinTokenByHash(ctx, q, "h"))
		if got.ID != tok.ID || got.Uses != 0 || got.ConsumedAt != nil || got.Constraints.MaxNodes != 3 ||
			len(got.Constraints.Tags) != 1 || got.Constraints.SourceCIDRs[0] != "10.0.0.0/8" {
			t.Fatalf("token = %+v", got)
		}
		if byID := must(GetJoinToken(ctx, q, tok.ID)); byID.TokenHash != "h" {
			t.Fatalf("by id = %+v", byID)
		}
		_, err := GetJoinTokenByHash(ctx, q, "unknown")
		wantError(t, err, smerr.CodeNotFound, "")
		wantError(t, CreateJoinToken(ctx, q, f.joinToken(admin.ID, "h", 1)), smerr.CodeConflict, "")
	})
}

func TestJoinTokenValidation(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		admin := f.identity(ctx, q, domain.ActorHuman, "root")
		with := func(mutate func(*JoinToken)) error {
			tok := f.joinToken(admin.ID, "v"+string(f.ids.NewID()), 1)
			mutate(&tok)
			return CreateJoinToken(ctx, q, tok)
		}
		noErr(t, with(func(t *JoinToken) { t.ExpiresAt = t.CreatedAt.Add(JoinTokenMaxLifetime) }))
		wantError(t, with(func(t *JoinToken) { t.ExpiresAt = t.CreatedAt.Add(JoinTokenMaxLifetime + time.Millisecond) }),
			smerr.CodeInvalidArgument, "")
		wantError(t, with(func(t *JoinToken) { t.ExpiresAt = t.CreatedAt }), smerr.CodeInvalidArgument, "")
		wantError(t, with(func(t *JoinToken) { t.Constraints.MaxNodes = 0 }), smerr.CodeInvalidArgument, "")
	})
}

func TestUseJoinTokenTakesSlotsUntilExhausted(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		admin := f.identity(ctx, q, domain.ActorHuman, "root")
		tok := f.joinToken(admin.ID, "h", 2)
		noErr(t, CreateJoinToken(ctx, q, tok))

		first := must(UseJoinToken(ctx, q, tok.ID, testEpoch))
		if first.Uses != 1 || first.ConsumedAt != nil {
			t.Fatalf("after first use = %+v, want 1 use and not consumed", first)
		}
		second := must(UseJoinToken(ctx, q, tok.ID, testEpoch.Add(time.Minute)))
		if second.Uses != 2 || second.ConsumedAt == nil || !second.ConsumedAt.Equal(testEpoch.Add(time.Minute)) {
			t.Fatalf("after second use = %+v, want 2 uses and consumed", second)
		}
		_, err := UseJoinToken(ctx, q, tok.ID, testEpoch.Add(2*time.Minute))
		wantError(t, err, smerr.CodeConflict, "")
		if stored := must(GetJoinToken(ctx, q, tok.ID)); stored.Uses != 2 {
			t.Fatalf("uses = %d after refused use, want 2", stored.Uses)
		}
		_, err = UseJoinToken(ctx, q, f.ids.NewID(), testEpoch)
		wantError(t, err, smerr.CodeNotFound, "")
	})
}

func TestUseJoinTokenRefusesExpiredTokens(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		admin := f.identity(ctx, q, domain.ActorHuman, "root")
		tok := f.joinToken(admin.ID, "h", 1)
		noErr(t, CreateJoinToken(ctx, q, tok))
		_, err := UseJoinToken(ctx, q, tok.ID, tok.ExpiresAt)
		wantError(t, err, smerr.CodeConflict, "")
		noErr(t, nilIfNil(UseJoinToken(ctx, q, tok.ID, tok.ExpiresAt.Add(-time.Millisecond))))
	})
}

func TestEnrolledNodeIsFoundByDigestForReplay(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		admin := f.identity(ctx, q, domain.ActorHuman, "root")
		tokenA, tokenB := f.joinToken(admin.ID, "a", 2), f.joinToken(admin.ID, "b", 1)
		noErr(t, CreateJoinToken(ctx, q, tokenA))
		noErr(t, CreateJoinToken(ctx, q, tokenB))
		digest := JoinRequestDigest("ssh-ed25519 AAAA", "web-1")

		p := f.provider(ctx, q, "static")
		enrolled := must(CreateNode(ctx, q, domain.Node{
			ID: f.ids.NewID(), ProviderID: p.ID, NativeID: "web-1", Name: "web-1", Kind: "host",
			ManagementState: domain.ManagementManaged, Reachability: domain.ReachabilityUnknown,
			Metadata:  map[string]any{JoinMetaTokenID: string(tokenA.ID), JoinMetaRequestDigest: digest},
			CreatedAt: testEpoch, UpdatedAt: testEpoch,
		}))
		f.node(ctx, q, p, "unrelated")

		if got := must(FindEnrolledNode(ctx, q, tokenA.ID, digest)); got != enrolled.ID {
			t.Fatalf("same token and digest found %s, want %s", got, enrolled.ID)
		}
		if got := must(FindEnrolledNode(ctx, q, "", digest)); got != enrolled.ID {
			t.Fatalf("any token found %s, want %s", got, enrolled.ID)
		}
		_, err := FindEnrolledNode(ctx, q, tokenB.ID, digest)
		wantError(t, err, smerr.CodeNotFound, "")
		_, err = FindEnrolledNode(ctx, q, tokenA.ID, JoinRequestDigest("ssh-ed25519 BBBB", "web-1"))
		wantError(t, err, smerr.CodeNotFound, "")
	})
}

func TestJoinRequestDigestSeparatesKeyFromHostname(t *testing.T) {
	if JoinRequestDigest("ab", "c") == JoinRequestDigest("a", "bc") {
		t.Fatal("digest does not separate key from hostname")
	}
	if got := JoinRequestDigest("k", "h"); len(got) != 64 || got != JoinRequestDigest("k", "h") {
		t.Fatalf("digest = %q, want 64 stable hex characters", got)
	}
}
