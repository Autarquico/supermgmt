//go:build e2e && fixtures

package e2e_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/auth/oauthfake"
	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/test/e2e/harness"
)

const m5RemoteScope = "mcp:read"

// /mcp admits 10 requests a minute per address with a burst of 5 (internal/api/edge.go, authRate),
// before it looks at any token. The tests spend that budget request by request, so they wait for it
// to refill instead of tripping the limit they are not testing.
const m5AddressRefill = 6500 * time.Millisecond

// m5Remote is `sm server` with remote MCP on, an authorization server the server reaches over TLS
// (oauthfake behind a TLS front on the test machine) and one registered remote MCP client.
type m5Remote struct {
	t       *testing.T
	srv     *harness.Server
	admin   *client.Client
	as      *oauthfake.Server
	api     *http.Client // trusts the server's CA
	mcpURL  string
	issuer  string
	subject string
	// containerNow reads the clock the server judges tokens by.
	containerNow func() time.Time
}

func newM5Remote(t *testing.T) *m5Remote {
	t.Helper()
	ctx := context.Background()
	hostIP := m4HostAddress()
	if hostIP == "" {
		t.Skip("the test machine has no address besides loopback; the server container cannot reach the authorization server")
	}
	network, ca, asCA := harness.NewNetwork(t), harness.NewCA(t), harness.NewCA(t)
	srv := harness.StartServer(t, network, ca, harness.ServerOptions{Mode: harness.Direct, TrustCAs: []*harness.CA{asCA}})
	srv.WaitReady(ctx)

	as := oauthfake.New()
	t.Cleanup(as.Close)
	issuer := serveAuthorizationServer(t, as, asCA, hostIP)
	as.Issuer, as.Resource = issuer, srv.URL+"/mcp"

	srv.AppendConfig(ctx, fmt.Sprintf(`security:
    allow_self_approval: true
mcp:
    remote_enabled: true
    oauth:
        issuer: %s
        resource: %s
        jwks_url: %s%s
        required_scopes:
            - %s
`, issuer, as.Resource, issuer, oauthfake.JWKSPath, m5RemoteScope))
	srv.Restart(ctx)

	admin := harness.NewClient(t)
	admin.AddProfile(ctx, "ops", srv.URL, srv.CAFile)
	token := srv.BootstrapAdmin(ctx, admin, "m5 operator")
	httpClient, err := httpClientTrusting(ca)
	if err != nil {
		t.Fatal(err)
	}
	r := &m5Remote{
		t: t, srv: srv, admin: srv.Typed(token), as: as, api: httpClient, mcpURL: as.Resource, issuer: issuer, subject: as.Subject,
		containerNow: func() time.Time { return containerClock(t, srv) },
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("server journal:\n%s", srv.C.Exec(ctx, "", "journalctl", "-u", "supermgmt", "--no-pager", "-n", "60", "-o", "cat").Output())
		}
	})
	return r
}

// serveAuthorizationServer puts a TLS front, with a certificate from ca for hostIP, before the
// fake and returns the issuer URL the server's configuration uses. The fake itself listens on
// loopback only.
func serveAuthorizationServer(t *testing.T, as *oauthfake.Server, ca *harness.CA, hostIP string) string {
	t.Helper()
	target, err := url.Parse(as.URL())
	if err != nil {
		t.Fatal(err)
	}
	leaf := ca.Issue(t, []string{"localhost"}, []string{hostIP})
	certPath, keyPath := leaf.WriteTo(t, t.TempDir(), "as")
	keyPair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewUnstartedServer(httputil.NewSingleHostReverseProxy(target))
	front.Listener.Close()
	front.Listener = listener
	front.TLS = &tls.Config{Certificates: []tls.Certificate{keyPair}, MinVersion: tls.VersionTLS12}
	front.StartTLS()
	t.Cleanup(front.Close)
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	return "https://" + net.JoinHostPort(hostIP, port)
}

func httpClientTrusting(ca *harness.CA) (*http.Client, error) {
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.Pool(), MinVersion: tls.VersionTLS12}},
	}, nil
}

func containerClock(t *testing.T, srv *harness.Server) time.Time {
	t.Helper()
	var seconds int64
	res := srv.C.Exec(context.Background(), "", "date", "+%s")
	if _, err := fmt.Sscan(strings.TrimSpace(res.Stdout), &seconds); err != nil {
		t.Fatalf("read the server clock: %v (%s)", err, res.Output())
	}
	return time.Unix(seconds, 0)
}

// register makes the authorization server's subject and client id a registered remote MCP client.
func (r *m5Remote) register(name, clientID string) {
	r.t.Helper()
	ctx := context.Background()
	direct, err := r.admin.RegisterMCPClient(ctx, wire.RegisterMCPClientRequest{
		Name: name, Origin: wire.MCPOriginRemote, Subject: r.subject, ClientID: clientID,
	})
	if err != nil {
		r.t.Fatalf("register %s: %v", name, err)
	}
	if direct.Pending != nil {
		harness.ApproveJob(ctx, r.t, r.admin, direct.Pending.Job.ID)
	}
	deadline := harness.Now().Add(time.Minute)
	for harness.Now().Before(deadline) {
		page, err := r.admin.ListMCPClients(ctx)
		if err != nil {
			r.t.Fatal(err)
		}
		for _, c := range page.Items {
			if c.Name == name && c.State == wire.MCPClientActive {
				return
			}
		}
		time.Sleep(time.Second)
	}
	r.t.Fatalf("remote MCP client %s did not become active", name)
}

// accessToken is a valid RFC 9068 token issued by the authorization server a moment after the
// client's registration, by the clock the server uses.
func (r *m5Remote) accessToken(mutate func(*oauthfake.Token)) string {
	r.t.Helper()
	token := r.as.AccessToken(r.containerNow())
	token.Claims["scope"] = m5RemoteScope
	if mutate != nil {
		mutate(token)
	}
	return r.as.Sign(token)
}

// pace waits until n more /mcp requests fit in the per-address budget.
func (r *m5Remote) pace(n int) { time.Sleep(time.Duration(n) * m5AddressRefill) }

func (r *m5Remote) do(method, path, bearer, body string) (*http.Response, string) {
	r.t.Helper()
	if strings.HasPrefix(path, "/mcp") || strings.HasPrefix(path, "/.well-known/") {
		r.pace(1)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, r.srv.URL+path, strings.NewReader(body))
	if err != nil {
		r.t.Fatal(err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
	}
	resp, err := r.api.Do(req)
	if err != nil {
		r.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		r.t.Fatal(err)
	}
	return resp, string(raw)
}

const m5InitializeRequest = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e","version":"0"}}}`

// bearerTransport adds the access token the way an MCP client's HTTP layer does.
type bearerTransport struct {
	token string
	next  http.RoundTripper
}

func (b bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+b.token)
	return b.next.RoundTrip(req)
}

// TestE2E_MCPRemoteStreamable
//
// Spec §24 and ADR-0033: the server's /mcp is an OAuth protected resource. Discovery follows
// RFC 9728; a request without a token is challenged; a registered client holding a valid RFC 9068
// access token reaches the read tools over streamable HTTP; a token of an unregistered client, a
// token for another audience and an OAuth token on /api/v1 are refused; the token is in no log.
// The authorization server is a fake: a real one (including RFC 8707 resource indicators) is not
// verified here.
func TestE2E_MCPRemoteStreamable(t *testing.T) {
	r := newM5Remote(t)
	const registeredClient = "client-1"
	r.register("remote-agent", registeredClient)
	time.Sleep(2 * time.Second) // tokens are only honoured when issued after the registration

	t.Run("a request without a token is challenged with the path-suffixed resource metadata", func(t *testing.T) {
		resp, _ := r.do(http.MethodPost, "/mcp", "", m5InitializeRequest)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("POST /mcp without a token = %d, want 401", resp.StatusCode)
		}
		challenge := resp.Header.Get("WWW-Authenticate")
		want := `resource_metadata="` + r.srv.URL + `/.well-known/oauth-protected-resource/mcp"`
		if !strings.HasPrefix(challenge, "Bearer") || !strings.Contains(challenge, want) {
			t.Errorf("WWW-Authenticate = %q, want a Bearer challenge with %s", challenge, want)
		}
	})

	t.Run("the protected resource metadata names the resource and the authorization server", func(t *testing.T) {
		for _, path := range []string{"/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-protected-resource"} {
			resp, body := r.do(http.MethodGet, path, "", "")
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("GET %s = %d: %s", path, resp.StatusCode, body)
			}
			if !strings.Contains(body, `"resource":"`+r.mcpURL+`"`) || !strings.Contains(body, r.issuer) {
				t.Errorf("GET %s = %s, want resource %s and authorization server %s", path, body, r.mcpURL, r.issuer)
			}
		}
	})

	token := r.accessToken(nil)
	t.Run("a registered client with a valid access token lists tools and reads the graph", func(t *testing.T) {
		r.pace(6) // initialize, initialized, tools/list, tools/call and the closing DELETE
		transport := &sdk.StreamableClientTransport{
			Endpoint:             r.mcpURL,
			HTTPClient:           &http.Client{Transport: bearerTransport{token: token, next: r.api.Transport}},
			DisableStandaloneSSE: true,
		}
		session, err := sdk.NewClient(&sdk.Implementation{Name: "sm-e2e-remote", Version: "0"}, nil).Connect(context.Background(), transport, nil)
		if err != nil {
			t.Fatalf("connect to /mcp: %v", err)
		}
		t.Cleanup(func() { _ = session.Close() })
		names := m5ToolNames(t, session)
		if len(names) == 0 {
			t.Fatal("tools/list is empty")
		}
		for _, name := range names {
			if name == "infra_submit_plan" || strings.Contains(name, "shell") || strings.Contains(name, "exec") {
				t.Errorf("tool %q is offered although write tools are off and MCP has no shell", name)
			}
		}
		var outputs mcpOutputs
		var nodes m5Nodes
		if failure := m5Call(t, &outputs, session, "infra_list_nodes", nil, &nodes); failure != "" {
			t.Fatalf("infra_list_nodes failed: %s", failure)
		}
	})

	t.Run("a token of an unregistered client is refused with 403", func(t *testing.T) {
		stranger := r.accessToken(func(tok *oauthfake.Token) { tok.Claims["client_id"] = "client-never-registered" })
		resp, body := r.do(http.MethodPost, "/mcp", stranger, m5InitializeRequest)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("POST /mcp with an unregistered client = %d, want 403: %s", resp.StatusCode, body)
		}
	})

	t.Run("a token for another audience is refused with 401", func(t *testing.T) {
		other := r.accessToken(func(tok *oauthfake.Token) { tok.Claims["aud"] = []string{"https://elsewhere.test/mcp"} })
		if resp, body := r.do(http.MethodPost, "/mcp", other, m5InitializeRequest); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("POST /mcp with another audience = %d, want 401: %s", resp.StatusCode, body)
		}
	})

	t.Run("a request from another origin is refused with 403", func(t *testing.T) {
		r.pace(1)
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, r.mcpURL, strings.NewReader(m5InitializeRequest))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Origin", "https://evil.test")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		resp, err := r.api.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("POST /mcp from a foreign origin = %d, want 403", resp.StatusCode)
		}
	})

	t.Run("an OAuth access token is not accepted on the API", func(t *testing.T) {
		if resp, body := r.do(http.MethodGet, wire.PathMe, token, ""); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("GET %s with an OAuth access token = %d, want 401: %s", wire.PathMe, resp.StatusCode, body)
		}
	})

	t.Run("the access token is in neither the database nor the journal", func(t *testing.T) {
		harness.AssertNoPlaintext(t, r.srv.Evidence(context.Background()), map[string]string{"the OAuth access token": token})
	})
}
