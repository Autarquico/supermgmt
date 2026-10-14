//go:build stress

package stress

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/auth"
	"github.com/autarquico/supermgmt/internal/auth/oauthfake"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const (
	mcpStressCallers       = 32
	mcpStressRequiredScope = "mcp:read"
)

type mcpStressRig struct {
	db    *database.DB
	clock *domaintest.FakeClock
	ids   *domaintest.SequentialIDs
	admin domain.ID
}

func newMCPStressRig(t *testing.T) *mcpStressRig {
	t.Helper()
	ctx := context.Background()
	r := &mcpStressRig{
		clock: domaintest.NewFakeClock(time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)),
		ids:   domaintest.NewSequentialIDs(),
	}
	var err error
	r.db, err = database.Open(ctx, filepath.Join(t.TempDir(), "sm.db"), database.Options{Clock: r.clock})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = r.db.Close() })
	if err := r.db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	r.admin = r.ids.NewID()
	r.createIdentity(t, database.Identity{ID: r.admin, ActorType: domain.ActorHuman, Subject: "admin"})
	return r
}

func (r *mcpStressRig) createIdentity(t *testing.T, identity database.Identity) {
	t.Helper()
	identity.CreatedAt = r.clock.Now()
	err := r.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		return database.CreateIdentity(ctx, tx, identity)
	})
	if err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}
}

// register stores a client of the given origin and state for an mcp identity.
func (r *mcpStressRig) register(t *testing.T, name string, origin database.MCPClientOrigin, state database.MCPClientState, identity database.Identity) database.MCPClient {
	t.Helper()
	identity.ID, identity.ActorType = r.ids.NewID(), domain.ActorMCP
	r.createIdentity(t, identity)
	now := r.clock.Now()
	client := database.MCPClient{
		ID: r.ids.NewID(), IdentityID: identity.ID, Name: name, Origin: origin, State: state,
		RequestedBy: r.admin, ApprovedAt: now, CreatedAt: now, UpdatedAt: now,
	}
	err := r.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		return database.CreateMCPClient(ctx, tx, client)
	})
	if err != nil {
		t.Fatalf("CreateMCPClient: %v", err)
	}
	return client
}

func (r *mcpStressRig) count(t *testing.T, query string, args ...any) int {
	t.Helper()
	var n int
	if err := r.db.Reader().QueryRowContext(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

func TestMCPStress_ConcurrentTokenIssuanceSucceedsForExactlyOneCaller(t *testing.T) {
	r := newMCPStressRig(t)
	client := r.register(t, "local-agent", database.MCPOriginLocal, database.MCPClientPendingToken, database.Identity{Subject: "local-agent"})
	issuedAt := r.clock.Now()

	hashes := make([]string, mcpStressCallers)
	errs := make([]error, mcpStressCallers)
	var wg sync.WaitGroup
	for i := range mcpStressCallers {
		hashes[i] = fmt.Sprintf("hash-%02d", i)
		wg.Go(func() {
			errs[i] = r.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
				_, err := database.IssueMCPToken(ctx, tx, client.ID, hashes[i], issuedAt, issuedAt.Add(24*time.Hour))
				return err
			})
		})
	}
	wg.Wait()

	winner := -1
	for i, err := range errs {
		switch {
		case err == nil && winner == -1:
			winner = i
		case err == nil:
			t.Errorf("callers %d and %d were both issued the token", winner, i)
		case smerr.CodeOf(err) != smerr.CodeConflict:
			t.Errorf("caller %d got %v; want CONFLICT", i, err)
		}
	}
	if winner == -1 {
		t.Fatal("no caller was issued the token")
	}
	stored, err := database.GetMCPClientByTokenHash(context.Background(), r.db.Reader(), hashes[winner])
	if err != nil || stored.ID != client.ID || stored.State != database.MCPClientActive {
		t.Fatalf("client by the winner's hash = %+v, %v; want the active client", stored, err)
	}
	if n := r.count(t, `SELECT COUNT(*) FROM mcp_clients WHERE token_hash IS NOT NULL`); n != 1 {
		t.Errorf("%d clients hold a token hash, want 1", n)
	}
}

func TestMCPStress_ConcurrentFirstSightingsOfTheSameOAuthTokenStoreOneRow(t *testing.T) {
	r := newMCPStressRig(t)
	client := r.register(t, "remote-a", database.MCPOriginRemote, database.MCPClientActive,
		database.Identity{Issuer: "https://as.test", Subject: "user-a", ClientID: "client-a"})
	other := r.register(t, "remote-b", database.MCPOriginRemote, database.MCPClientActive,
		database.Identity{Issuer: "https://as.test", Subject: "user-b", ClientID: "client-b"})
	now := r.clock.Now()

	record := func(owner domain.ID) error {
		return r.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
			_, err := database.RecordOAuthAccessToken(ctx, tx, database.OAuthAccessToken{
				ID: r.ids.NewID(), MCPClientID: owner, TokenHash: "shared-token-hash", Issuer: "https://as.test",
				JTI: "jti-1", IssuedAt: now, ExpiresAt: now.Add(time.Hour), FirstSeenAt: now,
			})
			return err
		})
	}
	errs := make([]error, mcpStressCallers)
	var wg sync.WaitGroup
	for i := range mcpStressCallers {
		owner := client.ID
		if i%8 == 7 {
			owner = other.ID // a hash is never re-attached to another client
		}
		wg.Go(func() { errs[i] = record(owner) })
	}
	wg.Wait()

	if n := r.count(t, `SELECT COUNT(*) FROM oauth_access_tokens WHERE token_hash = ?`, "shared-token-hash"); n != 1 {
		t.Fatalf("%d rows for one token hash, want 1", n)
	}
	stored, err := database.GetOAuthAccessTokenByHash(context.Background(), r.db.Reader(), "shared-token-hash")
	if err != nil {
		t.Fatalf("GetOAuthAccessTokenByHash: %v", err)
	}
	for i, err := range errs {
		belongsToStored := (i%8 == 7) == (stored.MCPClientID == other.ID)
		switch {
		case belongsToStored && err != nil:
			t.Errorf("caller %d of the owning client got %v", i, err)
		case !belongsToStored && smerr.CodeOf(err) != smerr.CodeConflict:
			t.Errorf("caller %d of the other client got %v; want CONFLICT", i, err)
		}
	}
}

type mcpStressJWKSRig struct {
	*mcpStressRig
	fake     *oauthfake.Server
	resolver *auth.OAuthResolver
}

func newMCPStressJWKSRig(t *testing.T) *mcpStressJWKSRig {
	t.Helper()
	r := &mcpStressJWKSRig{mcpStressRig: newMCPStressRig(t), fake: oauthfake.New()}
	t.Cleanup(r.fake.Close)
	r.register(t, "remote", database.MCPOriginRemote, database.MCPClientActive,
		database.Identity{Issuer: r.fake.Issuer, Subject: r.fake.Subject, ClientID: r.fake.ClientID})
	var err error
	r.resolver, err = auth.NewOAuthResolver(context.Background(), auth.OAuthConfig{
		Issuer: r.fake.Issuer, Resource: r.fake.Resource, JWKSURL: r.fake.JWKSURL(),
		RequiredScopes: []string{mcpStressRequiredScope}, HTTP: r.fake.Client(), Clock: r.clock,
	}, r.db)
	if err != nil {
		t.Fatalf("NewOAuthResolver: %v", err)
	}
	return r
}

// resolveAll resolves one fresh token per caller, concurrently, and returns the errors.
func (r *mcpStressJWKSRig) resolveAll(tokens []string) []error {
	errs := make([]error, len(tokens))
	var wg sync.WaitGroup
	for i, token := range tokens {
		wg.Go(func() {
			_, errs[i] = r.resolver.Resolve(context.Background(), token)
		})
	}
	wg.Wait()
	return errs
}

func (r *mcpStressJWKSRig) tokens(n int, mutate func(*oauthfake.Token)) []string {
	tokens := make([]string, n)
	for i := range tokens {
		tok := r.fake.AccessToken(r.clock.Now())
		if mutate != nil {
			mutate(tok)
		}
		tokens[i] = r.fake.Sign(tok)
	}
	return tokens
}

func TestMCPStress_ConcurrentTokensSignedByARotatedKeyAreAllAdmitted(t *testing.T) {
	r := newMCPStressJWKSRig(t)
	if err := r.resolveAll(r.tokens(1, nil))[0]; err != nil {
		t.Fatalf("warm the key cache: %v", err)
	}
	r.fake.RotateKey()
	tokens := r.tokens(mcpStressCallers, nil)
	before := r.fake.JWKSCalls()

	for i, err := range r.resolveAll(tokens) {
		if err != nil {
			t.Errorf("token %d signed by the rotated key: %v", i, err)
		}
	}
	if calls := r.fake.JWKSCalls() - before; calls < 1 || calls > mcpStressCallers {
		t.Errorf("JWKS fetches to learn the rotated key = %d, want between 1 and %d", calls, mcpStressCallers)
	}
	if n := r.count(t, `SELECT COUNT(*) FROM oauth_access_tokens`); n != mcpStressCallers+1 {
		t.Errorf("%d token rows, want one per distinct token (%d)", n, mcpStressCallers+1)
	}
}

func TestMCPStress_ConcurrentTokensWithAnUnknownKidAreAllRefusedAndKnownOnesStillAdmitted(t *testing.T) {
	r := newMCPStressJWKSRig(t)
	unknown := r.tokens(mcpStressCallers, func(tok *oauthfake.Token) { tok.Unpublished = true })
	known := r.tokens(mcpStressCallers, nil)

	errs := r.resolveAll(append(unknown, known...))

	for i, err := range errs {
		if i < mcpStressCallers {
			if smerr.CodeOf(err) != smerr.CodeUnauthenticated {
				t.Errorf("unknown-kid token %d got %v; want UNAUTHENTICATED", i, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("known-kid token %d: %v", i-mcpStressCallers, err)
		}
	}
}
