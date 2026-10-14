package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/auth"
	"github.com/autarquico/supermgmt/internal/auth/oauthfake"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const (
	remoteRequiredScope = "mcp:read"
	remoteMetadataURL   = "https://sm.test/.well-known/oauth-protected-resource/mcp"
	remoteIntrospectID  = "sm-introspect"
	remoteIntrospectPwd = "introspect-secret"
)

// remoteRig is the remote MCP endpoint over a real OAuthResolver, a real
// database and a fake authorization server. The MCP handler behind the gate
// records the caller it was given.
type remoteRig struct {
	t        *testing.T
	db       *database.DB
	clock    *domaintest.FakeClock
	fake     *oauthfake.Server
	handler  http.Handler
	reached  []domain.ID
	identity domain.ID
}

type remoteRigOptions struct {
	scopes        []string
	introspection bool
	proxy         *Proxy
}

func newRemoteRig(t *testing.T, opts ...func(*remoteRigOptions)) *remoteRig {
	t.Helper()
	o := remoteRigOptions{scopes: []string{remoteRequiredScope}}
	for _, f := range opts {
		f(&o)
	}
	ctx := context.Background()
	clock := domaintest.NewFakeClock(time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC))
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "sm.db"), database.Options{Clock: clock})
	must(t, err)
	t.Cleanup(func() { _ = db.Close() })
	must(t, db.Migrate(ctx))
	rig := &remoteRig{t: t, db: db, clock: clock, fake: oauthfake.New()}
	t.Cleanup(rig.fake.Close)

	oauth := auth.OAuthConfig{
		Issuer: rig.fake.Issuer, Resource: rig.fake.Resource, RequiredScopes: o.scopes, HTTP: rig.fake.Client(), Clock: clock,
	}
	if o.introspection {
		rig.fake.EnableIntrospection(remoteIntrospectID, remoteIntrospectPwd)
		oauth.IntrospectionURL, oauth.ClientID, oauth.ClientSecret = rig.fake.IntrospectionURL(), remoteIntrospectID, audit.Secret(remoteIntrospectPwd)
	} else {
		oauth.JWKSURL = rig.fake.JWKSURL()
	}
	resolver, err := auth.NewOAuthResolver(ctx, oauth, db)
	must(t, err)
	rig.handler = NewMCPRemote(MCPRemoteConfig{
		Resolver: resolver, Resource: rig.fake.Resource, Issuer: rig.fake.Issuer, RequiredScopes: o.scopes,
		Proxy: o.proxy, Clock: clock, IDs: domain.UUIDv7Generator{}, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		MCP: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			by, _ := MCPCaller(r)
			rig.reached = append(rig.reached, by.ID)
			w.WriteHeader(http.StatusOK)
		}),
	})
	return rig
}

// registerFakeClient creates the identity and active remote client of the
// fake's default (issuer, subject, client_id) triple.
func (r *remoteRig) registerFakeClient() {
	r.t.Helper()
	ids, now := domain.UUIDv7Generator{}, r.clock.Now()
	admin, identity := ids.NewID(), ids.NewID()
	r.identity = identity
	must(r.t, r.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		for _, i := range []database.Identity{
			{ID: admin, ActorType: domain.ActorHuman, Subject: "local:1", CreatedAt: now},
			{ID: identity, ActorType: domain.ActorMCP, Issuer: r.fake.Issuer, Subject: r.fake.Subject, ClientID: r.fake.ClientID, CreatedAt: now},
		} {
			if err := database.CreateIdentity(ctx, tx, i); err != nil {
				return err
			}
		}
		return database.CreateMCPClient(ctx, tx, database.MCPClient{
			ID: ids.NewID(), IdentityID: identity, Name: "remote-client", Origin: database.MCPOriginRemote,
			State: database.MCPClientActive, RequestedBy: admin, ApprovedAt: now, CreatedAt: now, UpdatedAt: now,
		})
	}))
}

func (r *remoteRig) accessToken() string {
	return r.fake.Sign(r.fake.AccessToken(r.clock.Now()))
}

func (r *remoteRig) do(method, path, bearer string, headers ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(context.Background(), method, "https://sm.test"+path, nil)
	req.RemoteAddr = "198.51.100.7:4000"
	if bearer != "" {
		req.Header.Set(wire.HeaderAuthorization, "Bearer "+bearer)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	rec := httptest.NewRecorder()
	r.handler.ServeHTTP(rec, req)
	return rec
}

func remoteErrorReason(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	body, _ := io.ReadAll(rec.Result().Body)
	var envelope wire.ErrorEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("error body %q: %v", body, err)
	}
	reason, _ := envelope.Error.Details[wire.DetailReason].(string)
	return reason
}

func TestRemote_MetadataBothPaths(t *testing.T) {
	rig := newRemoteRig(t)
	want := map[string]any{
		"resource":                 rig.fake.Resource,
		"authorization_servers":    []any{rig.fake.Issuer},
		"scopes_supported":         []any{remoteRequiredScope},
		"bearer_methods_supported": []any{"header"},
	}
	// The root path is an alias: it serves the document of the path-suffixed
	// one, whose resource is <origin>/mcp (ADR-0033, deviation 1).
	for _, path := range []string{wire.WellKnownProtectedResourceMCP, wire.WellKnownProtectedResource} {
		rec := rig.do(http.MethodGet, path, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d: %s", path, rec.Code, rec.Body)
		}
		var got map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		for key, value := range want {
			if gotJSON, wantJSON := mustJSON(t, got[key]), mustJSON(t, value); gotJSON != wantJSON {
				t.Errorf("%s: %s = %s, want %s", path, key, gotJSON, wantJSON)
			}
		}
	}
}

func TestRemote_ChallengeCarriesThePathSuffixedMetadataURL(t *testing.T) {
	rig := newRemoteRig(t)
	rig.registerFakeClient()
	wantChallenge := `Bearer resource_metadata="` + remoteMetadataURL + `", scope="` + remoteRequiredScope + `"`
	cases := map[string]string{
		"no token":        "",
		"garbage":         "not-a-jwt",
		"wrong issuer":    rig.fake.Sign(withClaim(rig.fake.AccessToken(rig.clock.Now()), "iss", "https://other.test")),
		"local mcp token": "smm_localtoken",
	}
	for name, bearer := range cases {
		rec := rig.do(http.MethodPost, wire.MCPPath, bearer)
		if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") != wantChallenge {
			t.Errorf("%s: status %d challenge %q, want 401 and %q", name, rec.Code, rec.Header().Get("WWW-Authenticate"), wantChallenge)
		}
	}
	if len(rig.reached) != 0 {
		t.Errorf("the MCP handler ran %d times for refused requests", len(rig.reached))
	}
}

func TestRemote_UnregisteredClientIs403WithoutAChallenge(t *testing.T) {
	rig := newRemoteRig(t)
	rec := rig.do(http.MethodPost, wire.MCPPath, rig.accessToken())
	if rec.Code != http.StatusForbidden || remoteErrorReason(t, rec) != string(smerr.ReasonMCPClientUnregistered) {
		t.Errorf("status %d reason %q, want 403 %s", rec.Code, remoteErrorReason(t, rec), smerr.ReasonMCPClientUnregistered)
	}
	if challenge := rec.Header().Get("WWW-Authenticate"); challenge != "" {
		t.Errorf("challenge %q on an unregistered client, want none", challenge)
	}
}

func TestRemote_InsufficientScopeIs403WithTheScopeChallenge(t *testing.T) {
	rig := newRemoteRig(t, func(o *remoteRigOptions) { o.scopes = []string{remoteRequiredScope, "mcp:admin"} })
	rig.registerFakeClient()
	rec := rig.do(http.MethodPost, wire.MCPPath, rig.accessToken())
	want := `Bearer error="insufficient_scope", scope="mcp:read mcp:admin", resource_metadata="` + remoteMetadataURL + `"`
	if rec.Code != http.StatusForbidden || rec.Header().Get("WWW-Authenticate") != want {
		t.Errorf("status %d challenge %q, want 403 and %q", rec.Code, rec.Header().Get("WWW-Authenticate"), want)
	}
}

func TestRemote_AdmittedRequestReachesMCPAsTheRegisteredIdentity(t *testing.T) {
	rig := newRemoteRig(t)
	rig.registerFakeClient()
	rec := rig.do(http.MethodPost, wire.MCPPath, rig.accessToken())
	if rec.Code != http.StatusOK || len(rig.reached) != 1 || rig.reached[0] != rig.identity {
		t.Errorf("status %d reached %v, want 200 once as identity %s", rec.Code, rig.reached, rig.identity)
	}
}

func TestRemote_MCPCallerIsAbsentWithoutAdmission(t *testing.T) {
	if _, ok := MCPCaller(httptest.NewRequestWithContext(context.Background(), http.MethodPost, wire.MCPPath, nil)); ok {
		t.Error("MCPCaller found a caller on a request that was never admitted")
	}
}

func TestRemote_NonBearerAuthorizationIs401(t *testing.T) {
	rig := newRemoteRig(t)
	rec := rig.do(http.MethodPost, wire.MCPPath, rig.accessToken(), wire.HeaderAuthorization, "Basic abc")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status %d, want 401 for a non-bearer Authorization header", rec.Code)
	}
}

func withClaim(t *oauthfake.Token, name string, value any) *oauthfake.Token {
	t.Claims[name] = value
	return t
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	must(t, err)
	return string(b)
}
