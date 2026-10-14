package daemon

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const selfApproval = "security:\n  allow_self_approval: true\n"

// issueLocalMCPToken registers a local MCP client as the daemon's user,
// approves its registration and takes its one token with the real minter.
func issueLocalMCPToken(t *testing.T, c *client.Client, name string) (wire.MCPClient, string) {
	t.Helper()
	ctx := context.Background()
	registered, err := c.RegisterMCPClient(ctx, wire.RegisterMCPClientRequest{Name: name, Origin: wire.MCPOriginLocal})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if registered.Pending == nil {
		t.Fatalf("register applied without the approval the high-risk floor requires: %+v", registered)
	}
	pending := registered.Pending.Job
	if _, err := c.Approve(ctx, pending.ID, wire.DecisionRequest{PlanHash: pending.PlanHash}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	clientID := waitForMCPClient(t, c, name)
	issued, err := c.IssueMCPToken(ctx, clientID, wire.IssueMCPTokenRequest{ExpiresAt: clockNow().Add(24 * time.Hour)})
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	return issued.Client, issued.Token
}

func waitForMCPClient(t *testing.T, c *client.Client, name string) domain.ID {
	t.Helper()
	deadline := clockNow().Add(waitLimit)
	for clockNow().Before(deadline) {
		page, err := c.ListMCPClients(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for _, listed := range page.Items {
			if listed.Name == name {
				return listed.ID
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the approved registration of %q never produced a client", name)
	return ""
}

func TestALocalMCPTokenMintedByTheDaemonAuthenticatesOnTheSocket(t *testing.T) {
	i := newInstance(t, selfApproval)
	i.start()
	issued, token := issueLocalMCPToken(t, i.client(), "assistant")

	if !strings.HasPrefix(token, "smm_") {
		t.Fatalf("token %q is not an smm_ token", token[:min(len(token), 4)])
	}
	me, err := client.New(client.Options{Socket: i.socket, Token: audit.Secret(token)}).Me(context.Background())
	if err != nil {
		t.Fatalf("me with the MCP token: %v", err)
	}
	if me.ActorType != domain.ActorMCP || me.IdentityID != issued.IdentityID {
		t.Errorf("me = %+v, want the mcp identity %s", me, issued.IdentityID)
	}
	if len(me.Roles) != 0 {
		t.Errorf("an MCP identity holds roles %v", me.Roles)
	}
}

func TestMCPClientsAndTheirTokenSurviveARestart(t *testing.T) {
	i := newInstance(t, selfApproval)
	first := i.start()
	issued, token := issueLocalMCPToken(t, i.client(), "assistant")
	first.stop()
	if err := first.wait(t); err != nil {
		t.Fatal(err)
	}

	i.start()

	page, err := i.client().ListMCPClients(context.Background())
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != issued.ID || page.Items[0].State != wire.MCPClientActive {
		t.Fatalf("clients after restart = %+v, %v, want the one active client", page.Items, err)
	}
	if _, err := client.New(client.Options{Socket: i.socket, Token: audit.Secret(token)}).Me(context.Background()); err != nil {
		t.Errorf("the token after the restart: %v", err)
	}
}

func TestMCPTokensAreRefusedWhenMCPIsDisabled(t *testing.T) {
	i := newInstance(t, selfApproval)
	first := i.start()
	_, token := issueLocalMCPToken(t, i.client(), "assistant")
	first.stop()
	if err := first.wait(t); err != nil {
		t.Fatal(err)
	}
	i.cfg.MCP.Enabled = false

	i.start()

	_, err := client.New(client.Options{Socket: i.socket, Token: audit.Secret(token)}).Me(context.Background())
	if smerr.CodeOf(err) != smerr.CodeUnauthenticated {
		t.Errorf("me with mcp.enabled false = %v, want UNAUTHENTICATED", err)
	}
}

func TestALocalDaemonNeverServesMCPOverHTTP(t *testing.T) {
	i := newInstance(t, "")
	i.start()
	socket := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", i.socket)
	}}}
	t.Cleanup(socket.CloseIdleConnections)

	for _, path := range []string{"/mcp", "/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"} {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://daemon"+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := socket.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s on the socket = %d, want 404", path, resp.StatusCode)
		}
	}
}

func TestTheWritesFlagReachesTheServices(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		i := newInstance(t, "")
		i.cfg.MCP.WriteToolsEnabled = enabled
		o, err := Options{Config: i.cfg}.withDefaults()
		if err != nil {
			t.Fatal(err)
		}
		cfg, _, err := appConfig(nil, o)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.MCPWritesEnabled != enabled {
			t.Errorf("write_tools_enabled %v reached the services as %v", enabled, cfg.MCPWritesEnabled)
		}
	}
}
