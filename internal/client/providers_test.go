package client_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/domain"
)

func TestRefreshProviderPostsToTheProviderWithoutAKeyAndDecodesTheProvider(t *testing.T) {
	d := startFakeDaemon(t, func(w http.ResponseWriter, _ *http.Request) {
		respond(w, 200, wire.Provider{Name: "pve", Status: "error", LastError: "cluster is on fire"})
	})
	id := domain.UUIDv7Generator{}.NewID()

	got, err := d.client(client.Options{}).RefreshProvider(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "pve" || got.LastError != "cluster is on fire" {
		t.Errorf("provider = %+v", got)
	}
	req := d.Requests()[0]
	if req.Method != "POST" || req.Path != "/api/v1/providers/"+string(id)+"/refresh" {
		t.Errorf("request = %s %s", req.Method, req.Path)
	}
	if key := req.Header.Get(wire.HeaderIdempotencyKey); key != "" {
		t.Errorf("a refresh sent Idempotency-Key %q", key)
	}
}
