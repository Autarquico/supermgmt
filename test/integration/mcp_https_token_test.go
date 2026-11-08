package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api"
	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/auth"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
)

// The HTTPS-token scenarios that the route matrix does not state (ADR-0044,
// spec mcp-https-token): which path an MCP client's events name, and how fast
// a removed or expired token stops. The floor and the equality of results
// across transports are the matrix's third transport.

// mcpSocketClient is the rig's marked client reached over a socket whose
// resolver is the real one, so that the same token travels both paths.
func (rig *mcpRig) mcpSocketClient() *http.Client {
	rig.t.Helper()
	server, err := api.New(api.Options{
		Services: rig.services, IDs: rig.ids, Identity: rig.admin.ID, DB: rig.db, Clock: rig.clock,
		MCPResolver: auth.MCPResolver{DB: rig.db, Clock: rig.clock, Enabled: true},
	})
	mcpRigMust(rig.t, err)
	return rig.serveSocket(server)
}

// lastSourceOf is the source of the newest event the mcp client caused.
func (rig *mcpRig) lastSourceOf(actor domain.ID) string {
	rig.t.Helper()
	var page wire.Page[wire.Event]
	rig.send(mcpRigHTTPS, http.MethodGet, wire.PathEvents+"?limit=200", "").data(rig.t, &page)
	source := ""
	var newest int64
	for _, e := range page.Items {
		if e.Actor.ID == actor && e.Seq >= newest {
			newest, source = e.Seq, e.Source
		}
	}
	return source
}

func TestTheAuditEventsOfAClientNameThePathItUsed(t *testing.T) {
	rig := newMCPRig(t, true)
	socket := rig.mcpSocketClient()
	plan := `{"action":"service.restart","targets":[{"type":"service","id":"` + rig.fixtures["service"] + `"}]}`

	rig.send(mcpRigHTTPS, http.MethodPost, wire.PathPlans, plan, rig.keyed()...)
	if got := rig.lastSourceOf(rig.mcp.ID); got != "mcp_https" {
		t.Errorf("event of a request over HTTPS has source %q, want mcp_https", got)
	}

	rig.mcpSocket(socket, http.MethodPost, wire.PathPlans, plan, rig.keyed()...)
	if got := rig.lastSourceOf(rig.mcp.ID); got != "mcp_socket" {
		t.Errorf("event of a request over the socket has source %q, want mcp_socket", got)
	}
}

func bodyReader(body string) io.Reader {
	if body == "" {
		return http.NoBody
	}
	return strings.NewReader(body)
}

// mcpSocket sends one request with the client's marked token over a socket.
func (rig *mcpRig) mcpSocket(client *http.Client, method, path, body string, headers ...string) {
	rig.t.Helper()
	rig.clock.Advance(time.Minute)
	req, err := http.NewRequestWithContext(context.Background(), method, "http://sm"+path, bodyReader(body))
	mcpRigMust(rig.t, err)
	req.Header.Set(wire.HeaderAuthorization, "Bearer "+rig.httpsToken)
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := client.Do(req)
	mcpRigMust(rig.t, err)
	_ = resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		rig.t.Fatalf("socket %s %s: status %d", method, path, resp.StatusCode)
	}
}

func TestARemovedTokenIsRefusedOnTheNextRequestOverHTTPS(t *testing.T) {
	rig := newMCPRig(t, false)
	if r := rig.send(mcpRigHTTPS, http.MethodGet, wire.PathMe, ""); r.status != http.StatusOK {
		t.Fatalf("before removal: status %d: %s", r.status, r.body)
	}

	rig.fixture(http.MethodDelete, wire.PathMCPClients+"/"+rig.mcp.Credential.ID, "")

	r := rig.send(mcpRigHTTPS, http.MethodGet, wire.PathMe, "")
	if r.status != http.StatusUnauthorized {
		t.Errorf("after removal: status %d, want 401: %s", r.status, r.body)
	}
}

func TestAnExpiredTokenIsRefusedOnTheNextRequestOverHTTPS(t *testing.T) {
	rig := newMCPRig(t, false)
	if r := rig.send(mcpRigHTTPS, http.MethodGet, wire.PathMe, ""); r.status != http.StatusOK {
		t.Fatalf("before expiry: status %d: %s", r.status, r.body)
	}

	rig.clock.Advance(91 * 24 * time.Hour)

	r := rig.send(mcpRigHTTPS, http.MethodGet, wire.PathMe, "")
	if r.status != http.StatusUnauthorized {
		t.Errorf("after expiry: status %d, want 401: %s", r.status, r.body)
	}
}

func TestAnUnmarkedClientsTokenIsAnsweredAsAnUnknownTokenOverHTTPS(t *testing.T) {
	rig := newMCPRig(t, false)
	token, hash, err := auth.Mint(auth.KindMCP)
	mcpRigMust(t, err)
	rig.inTx(func(ctx context.Context, tx *database.Tx) error {
		now, identity, client := rig.clock.Now(), rig.ids.NewID(), rig.ids.NewID()
		if err := database.CreateIdentity(ctx, tx, database.Identity{
			ID: identity, ActorType: domain.ActorMCP, Issuer: "supermgmt:mcp-local", Subject: client.String(), CreatedAt: now,
		}); err != nil {
			return err
		}
		err := database.CreateMCPClient(ctx, tx, database.MCPClient{
			ID: client, IdentityID: identity, Name: "unmarked", Origin: database.MCPOriginLocal,
			State: database.MCPClientPendingToken, RequestedBy: rig.admin.ID, ApprovedAt: now, CreatedAt: now, UpdatedAt: now,
		})
		if err != nil {
			return err
		}
		_, err = database.IssueMCPToken(ctx, tx, client, hash, now, now.Add(24*time.Hour))
		return err
	})

	unmarked := rig.bearerOverHTTPS(string(token))
	unknown := rig.bearerOverHTTPS(rig.unknownToken(auth.KindMCP))

	if unmarked.status != http.StatusUnauthorized || unmarked.status != unknown.status || withoutCorrelation(t, unmarked.body) != withoutCorrelation(t, unknown.body) {
		t.Errorf("unmarked token: %d %s\nunknown token:  %d %s", unmarked.status, unmarked.body, unknown.status, unknown.body)
	}
}

// bearerOverHTTPS is GET /me over HTTPS with the given bearer.
func (rig *mcpRig) bearerOverHTTPS(bearer string) mcpRigReply {
	rig.t.Helper()
	saved := rig.httpsToken
	rig.httpsToken = bearer
	defer func() { rig.httpsToken = saved }()
	return rig.send(mcpRigHTTPS, http.MethodGet, wire.PathMe, "")
}

// withoutCorrelation is an error body minus the per-request correlation id.
func withoutCorrelation(t *testing.T, body []byte) string {
	t.Helper()
	var envelope map[string]map[string]any
	mcpRigMust(t, json.Unmarshal(body, &envelope))
	delete(envelope["error"], "correlation_id")
	out, err := json.Marshal(envelope)
	mcpRigMust(t, err)
	return string(out)
}
