package client_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/domain"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func newJSONResponse[T any](status int, data T) *http.Response {
	var body bytes.Buffer
	_ = json.NewEncoder(&body).Encode(wire.Envelope[T]{Data: data})
	return &http.Response{
		StatusCode: status, Header: http.Header{"Content-Type": {wire.ContentType}},
		Body: io.NopCloser(&body),
	}
}

func TestListMCPClientsReadsThePage(t *testing.T) {
	d := startFakeDaemon(t, func(w http.ResponseWriter, _ *http.Request) {
		respond(w, 200, wire.Page[wire.MCPClient]{Items: []wire.MCPClient{{Name: "claude-desktop", State: wire.MCPClientActive}}})
	})

	page, err := d.client(client.Options{}).ListMCPClients(context.Background())

	got := d.Requests()[0]
	if err != nil || len(page.Items) != 1 || page.Items[0].Name != "claude-desktop" {
		t.Fatalf("page = %+v, %v", page, err)
	}
	if got.Method != "GET" || got.Path != "/api/v1/mcp/clients" || got.Header.Get(wire.HeaderIdempotencyKey) != "" {
		t.Errorf("request = %s %s", got.Method, got.Path)
	}
}

func TestRegisterMCPClientIsKeyedAndReturnsThePendingJob(t *testing.T) {
	d := startFakeDaemon(t, func(w http.ResponseWriter, _ *http.Request) {
		respond(w, 202, wire.Direct[wire.MCPClient]{Pending: &wire.Submission{}})
	})

	res, err := d.client(client.Options{}).RegisterMCPClient(context.Background(),
		wire.RegisterMCPClientRequest{Name: "claude-desktop", Origin: wire.MCPOriginLocal})

	got := d.Requests()[0]
	if err != nil || res.Pending == nil || res.Applied != nil {
		t.Fatalf("result = %+v, %v", res, err)
	}
	if got.Method != "POST" || got.Path != "/api/v1/mcp/clients" || got.Header.Get(wire.HeaderIdempotencyKey) == "" {
		t.Errorf("request = %s %s key=%q", got.Method, got.Path, got.Header.Get(wire.HeaderIdempotencyKey))
	}
	var body wire.RegisterMCPClientRequest
	if err := json.Unmarshal(got.Body, &body); err != nil || body.Name != "claude-desktop" || body.Origin != wire.MCPOriginLocal {
		t.Errorf("body = %s", got.Body)
	}
}

func TestIssueMCPTokenIsUnkeyedAndReturnsTheTokenOnce(t *testing.T) {
	d := startFakeDaemon(t, func(w http.ResponseWriter, _ *http.Request) {
		respond(w, 200, wire.MCPTokenIssued{Client: wire.MCPClient{Name: "claude-desktop"}, Token: mcpSocketToken})
	})
	id := domain.UUIDv7Generator{}.NewID()
	expires := time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)

	issued, err := d.client(client.Options{}).IssueMCPToken(context.Background(), id, wire.IssueMCPTokenRequest{ExpiresAt: expires})

	got := d.Requests()[0]
	if err != nil || issued.Token != mcpSocketToken {
		t.Fatalf("issued = %+v, %v", issued, err)
	}
	if got.Method != "POST" || got.Path != "/api/v1/mcp/clients/"+string(id)+"/token" {
		t.Errorf("request = %s %s", got.Method, got.Path)
	}
	if key := got.Header.Get(wire.HeaderIdempotencyKey); key != "" {
		t.Errorf("a credential route sent Idempotency-Key %q", key)
	}
	var body wire.IssueMCPTokenRequest
	if err := json.Unmarshal(got.Body, &body); err != nil || !body.ExpiresAt.Equal(expires) {
		t.Errorf("body = %s", got.Body)
	}
}

func TestDeleteMCPClientIsKeyedAndAddressedByID(t *testing.T) {
	d := startFakeDaemon(t, func(w http.ResponseWriter, _ *http.Request) {
		respond(w, 200, wire.Direct[wire.MCPClient]{Applied: &wire.MCPClient{State: wire.MCPClientDeleted}})
	})
	id := domain.UUIDv7Generator{}.NewID()

	res, err := d.client(client.Options{}).DeleteMCPClient(context.Background(), id)

	got := d.Requests()[0]
	if err != nil || res.Applied == nil || res.Applied.State != wire.MCPClientDeleted {
		t.Fatalf("result = %+v, %v", res, err)
	}
	if got.Method != "DELETE" || got.Path != "/api/v1/mcp/clients/"+string(id) || got.Header.Get(wire.HeaderIdempotencyKey) == "" {
		t.Errorf("request = %s %s key=%q", got.Method, got.Path, got.Header.Get(wire.HeaderIdempotencyKey))
	}
}
