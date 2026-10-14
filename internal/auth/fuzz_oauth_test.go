package auth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/auth"
	"github.com/autarquico/supermgmt/internal/auth/oauthfake"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
)

// fuzzRegisterRemoteClient creates the identity and active remote MCP client
// of (issuer, subject, clientID), which is what a valid token maps to.
func fuzzRegisterRemoteClient(tb testing.TB, db *database.DB, issuer, subject, clientID string) database.MCPClient {
	tb.Helper()
	ids := domaintest.NewSequentialIDs()
	now := epoch
	requester, identity := ids.NewID(), ids.NewID()
	client := database.MCPClient{
		ID: ids.NewID(), IdentityID: identity, Name: "remote-fuzz", Origin: database.MCPOriginRemote,
		State: database.MCPClientActive, RequestedBy: requester, ApprovedAt: now, CreatedAt: now, UpdatedAt: now,
	}
	err := db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		if err := database.CreateIdentity(ctx, tx, database.Identity{ID: requester, ActorType: domain.ActorHuman, Subject: "root", CreatedAt: now}); err != nil {
			return err
		}
		err := database.CreateIdentity(ctx, tx, database.Identity{
			ID: identity, ActorType: domain.ActorMCP, Issuer: issuer, Subject: subject, ClientID: clientID, CreatedAt: now,
		})
		if err != nil {
			return err
		}
		return database.CreateMCPClient(ctx, tx, client)
	})
	if err != nil {
		tb.Fatalf("register remote client: %v", err)
	}
	return client
}

// Any access token is refused with a typed error, or maps to the registered
// client. Keys are the in-process fake's; nothing leaves the process.
func FuzzOAuthAccessToken(f *testing.F) {
	db, clock := fuzzMigratedDB(f)
	fake := oauthfake.New()
	f.Cleanup(fake.Close)
	client := fuzzRegisterRemoteClient(f, db, fake.Issuer, fake.Subject, fake.ClientID)
	resolver, err := auth.NewOAuthResolver(context.Background(), auth.OAuthConfig{
		Issuer: fake.Issuer, Resource: fake.Resource, JWKSURL: fake.JWKSURL(),
		RequiredScopes: []string{"mcp:read"}, HTTP: fake.Client(), Clock: clock,
	}, db)
	if err != nil {
		f.Fatal(err)
	}
	valid := fake.AccessToken(clock.Now())
	validClaims, err := json.Marshal(valid.Claims)
	if err != nil {
		f.Fatal(err)
	}
	f.Add("", string(validClaims), "at+jwt")
	f.Add("", `{}`, "at+jwt")
	f.Add("", string(validClaims), "JWT")
	f.Add(fake.Sign(valid), "", "")
	f.Add("a.b.c", "", "")
	f.Add("eyJhbGciOiJub25lIn0.e30.", "", "")
	f.Fuzz(func(t *testing.T, raw, claimsJSON, typ string) {
		if raw == "" {
			var claims map[string]any
			if json.Unmarshal([]byte(claimsJSON), &claims) != nil {
				return
			}
			raw = fake.Sign(&oauthfake.Token{Header: map[string]any{"typ": typ}, Claims: claims})
		}
		caller, err := resolver.Resolve(context.Background(), raw)
		if err != nil {
			fuzzWantRefusal(t, caller, err)
			return
		}
		if caller.ID != client.IdentityID || caller.Credential.Kind != domain.CredentialOAuthAccessToken ||
			caller.Credential.ExpiresAt == nil || !caller.Credential.ExpiresAt.After(clock.Now()) {
			t.Fatalf("admitted a token as %+v", caller)
		}
	})
}

// fuzzAnswerTransport answers every request with the current body.
type fuzzAnswerTransport struct{ body []byte }

func (a *fuzzAnswerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(bytes.NewReader(a.body)), Request: req,
	}, nil
}

// Whatever an authorization server answers to an introspection request, the
// bearer is admitted only on an `active: true` answer.
func FuzzIntrospectionAnswer(f *testing.F) {
	db, clock := fuzzMigratedDB(f)
	fake := oauthfake.New()
	f.Cleanup(fake.Close)
	fuzzRegisterRemoteClient(f, db, fake.Issuer, fake.Subject, fake.ClientID)
	answers := &fuzzAnswerTransport{}
	resolver, err := auth.NewOAuthResolver(context.Background(), auth.OAuthConfig{
		Issuer: fake.Issuer, Resource: fake.Resource, IntrospectionURL: "https://issuer.test/introspect",
		ClientID: "sm-introspector", ClientSecret: audit.Secret("secret"), RequiredScopes: []string{"mcp:read"},
		HTTP: &http.Client{Transport: answers}, Clock: clock,
	}, db)
	if err != nil {
		f.Fatal(err)
	}
	active, err := json.Marshal(fake.ActiveResponse(clock.Now()))
	if err != nil {
		f.Fatal(err)
	}
	for _, body := range []string{string(active), `{"active":false}`, `{"active":"true"}`, `{"active":true,"token_type":"refresh_token"}`, `[]`, `null`, ``, `{`} {
		f.Add([]byte(body))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		answers.body = body
		caller, err := resolver.Resolve(context.Background(), "opaque-bearer")
		if err != nil {
			fuzzWantRefusal(t, caller, err)
			return
		}
		var answer struct {
			Active bool `json:"active"`
		}
		if json.Unmarshal(body, &answer) != nil || !answer.Active {
			t.Fatalf("admitted on the answer %q", body)
		}
	})
}
