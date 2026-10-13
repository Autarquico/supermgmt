package auth_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/auth"
	"github.com/autarquico/supermgmt/internal/auth/oauthfake"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const oauthJWTRequiredScope = "mcp:read"

// oauthJWTRig is a world with a fake authorization server, one registered
// remote client for the fake's default (issuer, subject, client_id) and a
// resolver that validates tokens by JWKS.
type oauthJWTRig struct {
	*world
	fake     *oauthfake.Server
	resolver *auth.OAuthResolver
	client   database.MCPClient
}

func newOAuthJWTRig(t *testing.T) *oauthJWTRig {
	t.Helper()
	r := &oauthJWTRig{world: newWorld(t), fake: oauthfake.New()}
	t.Cleanup(r.fake.Close)
	r.client = r.register(r.fake.Subject, r.fake.ClientID)
	var err error
	r.resolver, err = auth.NewOAuthResolver(context.Background(), auth.OAuthConfig{
		Issuer: r.fake.Issuer, Resource: r.fake.Resource, JWKSURL: r.fake.JWKSURL(),
		RequiredScopes: []string{oauthJWTRequiredScope}, HTTP: r.fake.Client(), Clock: r.clock,
	}, r.db)
	must(t, err, "NewOAuthResolver")
	return r
}

// register creates the identity (no roles) and the active remote client of a triple.
func (r *oauthJWTRig) register(subject, clientID string) database.MCPClient {
	r.t.Helper()
	now := r.clock.Now()
	identity := r.ids.NewID()
	client := database.MCPClient{
		ID: r.ids.NewID(), IdentityID: identity, Name: "remote-" + subject, Origin: database.MCPOriginRemote,
		State: database.MCPClientActive, RequestedBy: r.admin, ApprovedAt: now, CreatedAt: now, UpdatedAt: now,
	}
	must(r.t, r.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		err := database.CreateIdentity(ctx, tx, database.Identity{
			ID: identity, ActorType: domain.ActorMCP, Issuer: r.fake.Issuer, Subject: subject, ClientID: clientID, CreatedAt: now,
		})
		if err != nil {
			return err
		}
		return database.CreateMCPClient(ctx, tx, client)
	}), "register remote client")
	return client
}

func (r *oauthJWTRig) token(mutate func(*oauthfake.Token)) string {
	tok := r.fake.AccessToken(r.clock.Now())
	if mutate != nil {
		mutate(tok)
	}
	return r.fake.Sign(tok)
}

func (r *oauthJWTRig) resolve(token string) error {
	_, err := r.resolver.Resolve(context.Background(), token)
	return err
}

func (r *oauthJWTRig) wantRefused(err error, code smerr.Code, reason smerr.Reason) {
	r.wantCode(err, code, reason)
}

func TestOAuthJWT_ClaimAndHeaderRules(t *testing.T) {
	r := newOAuthJWTRig(t)
	now := r.clock.Now()
	secs := func(d time.Duration) int64 { return now.Add(d).Unix() }

	accepted := smerr.Code("")
	const (
		unauthenticated = smerr.CodeUnauthenticated
		forbidden       = smerr.CodePolicyDenied
		bad             = smerr.ReasonOAuthTokenInvalid
	)

	cases := []struct {
		name   string
		mutate func(*oauthfake.Token)
		code   smerr.Code // accepted: the token is admitted
		reason smerr.Reason
	}{
		{"valid", nil, accepted, ""},
		{"scope as scp array", func(t *oauthfake.Token) {
			delete(t.Claims, "scope")
			t.Claims["scp"] = []string{"other", oauthJWTRequiredScope}
		}, accepted, ""},
		{"audience array with the resource among others", func(t *oauthfake.Token) {
			t.Claims["aud"] = []string{"https://other.test", r.fake.Resource}
		}, accepted, ""},
		{"audience as a bare string", func(t *oauthfake.Token) { t.Claims["aud"] = r.fake.Resource }, accepted, ""},
		{"typ application/at+jwt", func(t *oauthfake.Token) { t.Header["typ"] = "application/at+jwt" }, accepted, ""},
		{"typ case-insensitive", func(t *oauthfake.Token) { t.Header["typ"] = "AT+JWT" }, accepted, ""},
		{"azp equal to client_id", func(t *oauthfake.Token) { t.Claims["azp"] = r.fake.ClientID }, accepted, ""},

		{"wrong issuer", func(t *oauthfake.Token) { t.Claims["iss"] = "https://evil.test" }, unauthenticated, bad},
		{"audience without the resource", func(t *oauthfake.Token) { t.Claims["aud"] = []string{"https://other.test"} }, unauthenticated, bad},
		{"audience is a prefix of the resource", func(t *oauthfake.Token) { t.Claims["aud"] = []string{"https://sm.test"} }, unauthenticated, bad},
		{"no audience", func(t *oauthfake.Token) { delete(t.Claims, "aud") }, unauthenticated, bad},
		{"expired beyond skew", func(t *oauthfake.Token) { t.Claims["exp"] = secs(-61 * time.Second) }, unauthenticated, bad},
		{"expired within skew", func(t *oauthfake.Token) { t.Claims["exp"] = secs(-60 * time.Second) }, accepted, ""},
		{"no exp", func(t *oauthfake.Token) { delete(t.Claims, "exp") }, unauthenticated, bad},
		{"nbf beyond skew", func(t *oauthfake.Token) { t.Claims["nbf"] = secs(61 * time.Second) }, unauthenticated, bad},
		{"nbf within skew", func(t *oauthfake.Token) { t.Claims["nbf"] = secs(60 * time.Second) }, accepted, ""},
		{"missing iat", func(t *oauthfake.Token) { delete(t.Claims, "iat") }, unauthenticated, bad},
		{"iat in the future", func(t *oauthfake.Token) { t.Claims["iat"] = secs(61 * time.Second) }, unauthenticated, bad},
		{"iat before the client existed", func(t *oauthfake.Token) { t.Claims["iat"] = secs(-61 * time.Second) }, unauthenticated, bad},
		{"iat just inside the registration floor", func(t *oauthfake.Token) { t.Claims["iat"] = secs(-60 * time.Second) }, accepted, ""},
		{"no subject", func(t *oauthfake.Token) { delete(t.Claims, "sub") }, unauthenticated, bad},
		{"missing client_id", func(t *oauthfake.Token) { delete(t.Claims, "client_id") }, unauthenticated, bad},
		{"azp different from client_id", func(t *oauthfake.Token) { t.Claims["azp"] = "someone-else" }, unauthenticated, bad},
		{"nonce present", func(t *oauthfake.Token) { t.Claims["nonce"] = "n-0S6_WzA2Mj" }, unauthenticated, bad},

		{"alg none", func(t *oauthfake.Token) { t.Alg = "none" }, unauthenticated, bad},
		{"HS256 keyed with the public key", func(t *oauthfake.Token) { t.Alg = "HS256" }, unauthenticated, bad},
		{"unknown kid", func(t *oauthfake.Token) { t.Unpublished = true }, unauthenticated, bad},
		{"typ absent", func(t *oauthfake.Token) { delete(t.Header, "typ") }, unauthenticated, bad},
		{"typ JWT", func(t *oauthfake.Token) { t.Header["typ"] = "JWT" }, unauthenticated, bad},
		{"nonce-free ID token with otherwise matching claims", func(t *oauthfake.Token) {
			delete(t.Header, "typ")
			t.Claims["aud"] = []string{r.fake.Resource, r.fake.ClientID}
			t.Claims["azp"] = r.fake.ClientID
			t.Claims["email"] = "user@example.com"
		}, unauthenticated, bad},

		{"missing required scope", func(t *oauthfake.Token) { t.Claims["scope"] = "something:else" }, forbidden, smerr.ReasonScopeDenied},
		{"no scope at all", func(t *oauthfake.Token) { delete(t.Claims, "scope") }, forbidden, smerr.ReasonScopeDenied},

		{"unregistered subject", func(t *oauthfake.Token) { t.Claims["sub"] = "stranger" }, forbidden, smerr.ReasonMCPClientUnregistered},
		{"unregistered client_id", func(t *oauthfake.Token) { t.Claims["client_id"] = "other-client" }, forbidden, smerr.ReasonMCPClientUnregistered},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := r.resolve(r.token(c.mutate))
			if c.code == accepted {
				must(t, err, "Resolve")
				return
			}
			r.wantRefused(err, c.code, c.reason)
		})
	}
}

func TestOAuthJWT_AdmittedTokenBecomesTheClientsCaller(t *testing.T) {
	r := newOAuthJWTRig(t)
	token := r.token(nil)

	caller, err := r.resolver.Resolve(context.Background(), token)
	must(t, err, "Resolve")

	cred := caller.Credential
	if caller.ID != r.client.IdentityID || cred.Kind != domain.CredentialOAuthAccessToken || caller.Source != "api" {
		t.Fatalf("caller = %+v", caller)
	}
	if len(cred.Scopes) != 0 {
		t.Errorf("OAuth scopes must not become action scopes: %v", cred.Scopes)
	}
	if cred.ExpiresAt == nil || !cred.ExpiresAt.Equal(r.clock.Now().Add(time.Hour)) {
		t.Errorf("expires at = %v, want the token's exp", cred.ExpiresAt)
	}
	stored, err := database.GetOAuthAccessToken(context.Background(), r.db.Reader(), domain.ID(cred.ID))
	must(t, err, "GetOAuthAccessToken")
	if stored.MCPClientID != r.client.ID || stored.Issuer != r.fake.Issuer || stored.JTI == "" {
		t.Errorf("stored row = %+v", stored)
	}
	if strings.Contains(cred.ID, token) || strings.Contains(stored.TokenHash, token) {
		t.Error("the token itself leaked into the credential id or row")
	}
}

func TestOAuthJWT_StatusOfAnAdmittedTokenIsRecordedOnce(t *testing.T) {
	r := newOAuthJWTRig(t)
	token := r.token(nil)

	first, err := r.resolver.Resolve(context.Background(), token)
	must(t, err, "first Resolve")
	second, err := r.resolver.Resolve(context.Background(), token)
	must(t, err, "second Resolve")

	if first.Credential.ID != second.Credential.ID {
		t.Errorf("credential ids differ: %q vs %q", first.Credential.ID, second.Credential.ID)
	}
	var rows int
	must(t, r.db.Reader().QueryRowContext(context.Background(), `SELECT COUNT(*) FROM oauth_access_tokens`).Scan(&rows), "count")
	if rows != 1 {
		t.Errorf("rows = %d, want 1", rows)
	}
}

func TestOAuthJWT_UnknownKidTriggersExactlyOneRefresh(t *testing.T) {
	r := newOAuthJWTRig(t)
	must(t, r.resolve(r.token(nil)), "warm the key cache")
	before := r.fake.JWKSCalls()

	r.wantRefused(r.resolve(r.token(func(t *oauthfake.Token) { t.Unpublished = true })), smerr.CodeUnauthenticated, smerr.ReasonOAuthTokenInvalid)

	if got := r.fake.JWKSCalls() - before; got != 1 {
		t.Errorf("JWKS calls for an unknown kid = %d, want 1", got)
	}
}

func TestOAuthJWT_RotatedKeyIsPickedUpWithOneRefresh(t *testing.T) {
	r := newOAuthJWTRig(t)
	must(t, r.resolve(r.token(nil)), "token signed by the first key")

	r.fake.RotateKey()
	rotated := r.token(nil)
	before := r.fake.JWKSCalls()
	must(t, r.resolve(rotated), "token signed by the rotated key")
	if got := r.fake.JWKSCalls() - before; got != 1 {
		t.Errorf("JWKS calls to learn the rotated key = %d, want 1", got)
	}
}

func TestOAuthJWT_RevokedTokenIsRefusedWithoutAnyJWKSCall(t *testing.T) {
	r := newOAuthJWTRig(t)
	token := r.token(nil)
	must(t, r.resolve(token), "first use")
	must(t, r.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		_, err := database.RevokeOAuthTokensOfClient(ctx, tx, r.client.ID, r.clock.Now())
		return err
	}), "revoke")
	before := r.fake.JWKSCalls()

	r.wantRefused(r.resolve(token), smerr.CodeUnauthenticated, smerr.ReasonCredentialRevoked)

	if got := r.fake.JWKSCalls() - before; got != 0 {
		t.Errorf("a revoked token cost %d JWKS calls, want 0", got)
	}
}

func TestOAuthJWT_DeletedClientIsUnregistered(t *testing.T) {
	r := newOAuthJWTRig(t)
	must(t, r.resolve(r.token(nil)), "before deletion")
	must(t, r.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		_, err := database.DeleteMCPClient(ctx, tx, r.client.ID, r.clock.Now())
		return err
	}), "delete")

	r.wantRefused(r.resolve(r.token(nil)), smerr.CodePolicyDenied, smerr.ReasonMCPClientUnregistered)
}

func TestOAuthJWT_DisabledIdentityIsUnregistered(t *testing.T) {
	r := newOAuthJWTRig(t)
	must(t, r.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE identities SET disabled_at = ? WHERE id = ?`, r.clock.Now().UnixMilli(), r.client.IdentityID)
		return err
	}), "disable identity")

	r.wantRefused(r.resolve(r.token(nil)), smerr.CodePolicyDenied, smerr.ReasonMCPClientUnregistered)
}

func TestOAuthJWT_LocalAndPendingClientsAreNotRemoteRegistrations(t *testing.T) {
	r := newOAuthJWTRig(t)
	now := r.clock.Now()
	identity := r.ids.NewID()
	must(t, r.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		err := database.CreateIdentity(ctx, tx, database.Identity{
			ID: identity, ActorType: domain.ActorMCP, Issuer: r.fake.Issuer, Subject: "local-look-alike", ClientID: r.fake.ClientID, CreatedAt: now,
		})
		if err != nil {
			return err
		}
		return database.CreateMCPClient(ctx, tx, database.MCPClient{
			ID: r.ids.NewID(), IdentityID: identity, Name: "local-one", Origin: database.MCPOriginLocal,
			State: database.MCPClientPendingToken, RequestedBy: r.admin, ApprovedAt: now, CreatedAt: now, UpdatedAt: now,
		})
	}), "register local look-alike")

	tok := r.token(func(t *oauthfake.Token) { t.Claims["sub"] = "local-look-alike" })
	r.wantRefused(r.resolve(tok), smerr.CodePolicyDenied, smerr.ReasonMCPClientUnregistered)
}

func TestOAuthJWT_OversizedBearerIsRefusedBeforeAnyWork(t *testing.T) {
	r := newOAuthJWTRig(t)
	before := r.fake.JWKSCalls()

	r.wantRefused(r.resolve(strings.Repeat("a", 9<<10)), smerr.CodeUnauthenticated, smerr.ReasonOAuthTokenInvalid)

	if r.fake.JWKSCalls() != before {
		t.Error("an oversized bearer reached the JWKS")
	}
}

func TestOAuthJWT_NonJWTBearerWithoutIntrospectionIsRefused(t *testing.T) {
	r := newOAuthJWTRig(t)
	before := r.fake.JWKSCalls()

	r.wantRefused(r.resolve("opaque-access-token"), smerr.CodeUnauthenticated, smerr.ReasonOAuthTokenInvalid)

	if r.fake.JWKSCalls() != before {
		t.Error("an opaque token reached the JWKS")
	}
}

func TestNewOAuthResolverNeedsWhatItValidatesWith(t *testing.T) {
	w := newWorld(t)
	ok := auth.OAuthConfig{Issuer: "i", Resource: "r", JWKSURL: "http://jwks.test", HTTP: oauthfake.New().Client()}
	for name, mutate := range map[string]func(*auth.OAuthConfig){
		"no http client":     func(c *auth.OAuthConfig) { c.HTTP = nil },
		"no issuer":          func(c *auth.OAuthConfig) { c.Issuer = "" },
		"no resource":        func(c *auth.OAuthConfig) { c.Resource = "" },
		"no validation path": func(c *auth.OAuthConfig) { c.JWKSURL = "" },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := ok
			mutate(&cfg)
			if _, err := auth.NewOAuthResolver(context.Background(), cfg, w.db); err == nil {
				t.Error("want an error")
			}
		})
	}
}
