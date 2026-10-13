package daemon

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/auth/oauthfake"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/transport/ssh"
)

const (
	remoteToolsListBody = `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`
	remoteListNodesBody = `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"infra_list_nodes","arguments":{}}}`
	remoteMCPVersion    = "2025-11-25"
	remotePublicURL     = "https://sm.test"
)

// remoteBuilder assembles a server-mode builder after its core services. The
// mutation runs on the loaded configuration before anything reads it.
func remoteBuilder(t *testing.T, fake *oauthfake.Server, mutate func(*config.Config)) *builder {
	t.Helper()
	i := newServerInstance(t, "")
	i.cfg.Server.PublicURL = remotePublicURL
	i.cfg.MCP = config.MCP{
		Enabled: true, RemoteEnabled: true,
		OAuth: config.MCPOAuth{Issuer: fake.Issuer, Resource: fake.Resource, JWKSURL: fake.JWKSURL(), RequiredScopes: []string{"mcp:read"}},
	}
	if mutate != nil {
		mutate(i.cfg)
	}
	prepared := prepare(t, i)
	t.Cleanup(func() { _ = prepared.Close() })
	o, err := Options{Config: i.cfg, ConfigFile: i.file}.withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	appCfg, _, err := appConfig(prepared.db, o)
	if err != nil {
		t.Fatal(err)
	}
	b := &builder{o: o, cfg: i.cfg, app: appCfg, db: prepared.db, kit: prepared.kit, oauthHTTP: fake.Client()}
	if err := b.openGate(context.Background()); err != nil {
		t.Fatal(err)
	}
	b.pool = ssh.NewPool(poolConfig(i.cfg), ssh.NewCredentials(prepared.kit.store), o.Clock)
	t.Cleanup(b.pool.Close)
	if err := b.coreServices(); err != nil {
		t.Fatal(err)
	}
	return b
}

func newRemoteFake(t *testing.T) *oauthfake.Server {
	t.Helper()
	fake := oauthfake.New()
	t.Cleanup(fake.Close)
	return fake
}

// registerRemoteClient creates the active remote client of the fake's token
// triple, with no role.
func registerRemoteClient(t *testing.T, b *builder, fake *oauthfake.Server) {
	t.Helper()
	now := b.o.Clock.Now()
	requester, identity := b.o.IDs.NewID(), b.o.IDs.NewID()
	err := b.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		for _, i := range []database.Identity{
			{ID: requester, ActorType: domain.ActorHuman, Issuer: "test", Subject: "admin", CreatedAt: now},
			{ID: identity, ActorType: domain.ActorMCP, Issuer: fake.Issuer, Subject: fake.Subject, ClientID: fake.ClientID, CreatedAt: now},
		} {
			if err := database.CreateIdentity(ctx, tx, i); err != nil {
				return err
			}
		}
		return database.CreateMCPClient(ctx, tx, database.MCPClient{
			ID: b.o.IDs.NewID(), IdentityID: identity, Name: "remote-client", Origin: database.MCPOriginRemote,
			State: database.MCPClientActive, RequestedBy: requester, ApprovedAt: now, CreatedAt: now, UpdatedAt: now,
		})
	})
	if err != nil {
		t.Fatal(err)
	}
}

// serveRemote builds the server of b and serves its handler.
func serveRemote(t *testing.T, b *builder) *httptest.Server {
	t.Helper()
	services, err := b.apiServices()
	if err != nil {
		t.Fatal(err)
	}
	remote, _, err := b.serverServers(context.Background(), services)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(remote.Handler())
	t.Cleanup(srv.Close)
	return srv
}

func remoteCall(t *testing.T, srv *httptest.Server, method, path, token, body string, headers ...string) (int, http.Header, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", remoteMCPVersion)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, resp.Header, string(payload)
}

func accessToken(b *builder, fake *oauthfake.Server) string {
	return fake.Sign(fake.AccessToken(b.o.Clock.Now()))
}

func TestRemoteMCPServesMetadataAndTheTools(t *testing.T) {
	fake := newRemoteFake(t)
	b := remoteBuilder(t, fake, nil)
	registerRemoteClient(t, b, fake)
	srv := serveRemote(t, b)

	status, _, metadata := remoteCall(t, srv, http.MethodGet, "/.well-known/oauth-protected-resource/mcp", "", "")
	if status != http.StatusOK || !strings.Contains(metadata, fake.Resource) {
		t.Errorf("metadata = %d %s, want 200 naming %s", status, metadata, fake.Resource)
	}
	status, header, _ := remoteCall(t, srv, http.MethodPost, "/mcp", "", remoteToolsListBody)
	if status != http.StatusUnauthorized || !strings.Contains(header.Get("WWW-Authenticate"), "resource_metadata=") {
		t.Errorf("no token = %d %q, want 401 with the metadata challenge", status, header.Get("WWW-Authenticate"))
	}

	token := accessToken(b, fake)
	status, _, tools := remoteCall(t, srv, http.MethodPost, "/mcp", token, remoteToolsListBody)
	if status != http.StatusOK || !strings.Contains(tools, "infra_list_nodes") {
		t.Fatalf("tools/list = %d %s, want the read tools", status, tools)
	}
	if strings.Contains(tools, "infra_restart_service") {
		t.Error("a write tool is listed while mcp.write_tools_enabled is false")
	}
	status, _, nodes := remoteCall(t, srv, http.MethodPost, "/mcp", token, remoteListNodesBody)
	if status != http.StatusOK || !strings.Contains(nodes, `"structuredContent":{"items":[]`) {
		t.Errorf("infra_list_nodes in process = %d %s, want a result", status, nodes)
	}
}

func TestRemoteMCPListsWriteToolsOnlyWhenEnabled(t *testing.T) {
	fake := newRemoteFake(t)
	b := remoteBuilder(t, fake, func(c *config.Config) { c.MCP.WriteToolsEnabled = true })
	registerRemoteClient(t, b, fake)
	srv := serveRemote(t, b)

	_, _, tools := remoteCall(t, srv, http.MethodPost, "/mcp", accessToken(b, fake), remoteToolsListBody)

	if !strings.Contains(tools, "infra_restart_service") {
		t.Errorf("tools/list = %s, want the write tools with mcp.write_tools_enabled", tools)
	}
}

func TestRemoteMCPRefusesAnOriginThatIsNotThePublicURL(t *testing.T) {
	fake := newRemoteFake(t)
	b := remoteBuilder(t, fake, nil)
	registerRemoteClient(t, b, fake)
	srv := serveRemote(t, b)

	status, _, _ := remoteCall(t, srv, http.MethodPost, "/mcp", accessToken(b, fake), remoteToolsListBody, "Origin", "https://evil.test")
	if status != http.StatusForbidden {
		t.Errorf("foreign Origin = %d, want 403", status)
	}
	status, _, _ = remoteCall(t, srv, http.MethodPost, "/mcp", accessToken(b, fake), remoteToolsListBody, "Origin", remotePublicURL)
	if status != http.StatusOK {
		t.Errorf("own Origin = %d, want 200", status)
	}
}

func TestAnUnregisteredOAuthSubjectIsRefusedOnMCP(t *testing.T) {
	fake := newRemoteFake(t)
	b := remoteBuilder(t, fake, nil)
	srv := serveRemote(t, b)

	status, _, _ := remoteCall(t, srv, http.MethodPost, "/mcp", accessToken(b, fake), remoteToolsListBody)

	if status != http.StatusForbidden {
		t.Errorf("valid token of no registered client = %d, want 403", status)
	}
}

func TestMCPIsNotMountedWithoutRemoteMCP(t *testing.T) {
	fake := newRemoteFake(t)
	b := remoteBuilder(t, fake, func(c *config.Config) { c.MCP.RemoteEnabled = false })
	srv := serveRemote(t, b)

	for _, path := range []string{"/mcp", "/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"} {
		if status, _, _ := remoteCall(t, srv, http.MethodGet, path, "", ""); status != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404 when remote MCP is off", path, status)
		}
	}
}

func TestMCPIsNotMountedWhenMCPIsDisabled(t *testing.T) {
	fake := newRemoteFake(t)
	b := remoteBuilder(t, fake, func(c *config.Config) { c.MCP.Enabled = false })

	mount, err := b.remoteMCP(context.Background(), nil, nil)

	if err != nil || mount != nil {
		t.Errorf("remoteMCP = %v, %v, want nothing mounted while mcp.enabled is false", mount, err)
	}
}

func TestRemoteMCPRefusesToStartOnAnOAuthSectionItCannotServe(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*config.Config)
	}{
		{"neither jwks nor introspection", func(c *config.Config) { c.MCP.OAuth.JWKSURL = "" }},
		{"introspection without a client", func(c *config.Config) {
			c.MCP.OAuth.IntrospectionURL = "https://auth.test/introspect"
			c.MCP.OAuth.IntrospectionClientSecretRef = "secret://oauth/introspection"
		}},
		{"introspection secret not in the store", func(c *config.Config) {
			c.MCP.OAuth.IntrospectionURL = "https://auth.test/introspect"
			c.MCP.OAuth.IntrospectionClientID = "sm"
			c.MCP.OAuth.IntrospectionClientSecretRef = "secret://oauth/introspection"
		}},
		{"introspection secret is not a reference", func(c *config.Config) {
			c.MCP.OAuth.IntrospectionURL = "https://auth.test/introspect"
			c.MCP.OAuth.IntrospectionClientID = "sm"
			c.MCP.OAuth.IntrospectionClientSecretRef = "hunter2"
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := remoteBuilder(t, newRemoteFake(t), tt.mutate)

			mount, err := b.remoteMCP(context.Background(), nil, nil)

			if err == nil || mount != nil {
				t.Errorf("remoteMCP = %v, %v, want a refusal to start", mount, err)
			}
		})
	}
}

func TestOAuthEndpointsGoThroughNetguard(t *testing.T) {
	fake := newRemoteFake(t)
	b := remoteBuilder(t, fake, nil)
	registerRemoteClient(t, b, fake)
	b.oauthHTTP = nil // the production client: the fake listens on loopback, which is never allowed
	srv := serveRemote(t, b)

	status, _, _ := remoteCall(t, srv, http.MethodPost, "/mcp", accessToken(b, fake), remoteToolsListBody)

	if status != http.StatusUnauthorized {
		t.Errorf("token whose JWKS is on loopback = %d, want 401", status)
	}
	if calls := fake.JWKSCalls(); calls != 0 {
		t.Errorf("the fake saw %d JWKS requests, want 0: netguard must refuse loopback", calls)
	}
}
