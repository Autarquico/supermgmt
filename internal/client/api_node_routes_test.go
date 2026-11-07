package client_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/client"
)

func TestExposeNodeRouteIsKeyedAndPostsTheRequest(t *testing.T) {
	d := startFakeDaemon(t, func(w http.ResponseWriter, _ *http.Request) {
		respond(w, 202, wire.NodeRouteSubmission{})
	})

	res, err := d.client(client.Options{}).ExposeNodeRoute(context.Background(), "01a19231-7dca-73e4-8215-99d21fbaac60",
		wire.ExposeNodeRouteRequest{Hostname: "shop.example.com", Port: 8080, Access: "owners"})

	got := d.Requests()[0]
	if err != nil || res.Route != nil {
		t.Fatalf("result = %+v, %v", res, err)
	}
	if got.Method != "POST" || got.Path != "/api/v1/nodes/01a19231-7dca-73e4-8215-99d21fbaac60/routes" || got.Header.Get(wire.HeaderIdempotencyKey) == "" {
		t.Errorf("request = %s %s key=%q", got.Method, got.Path, got.Header.Get(wire.HeaderIdempotencyKey))
	}
	var body wire.ExposeNodeRouteRequest
	if err := json.Unmarshal(got.Body, &body); err != nil || body.Hostname != "shop.example.com" || body.Port != 8080 || body.Access != "owners" {
		t.Errorf("body = %s", got.Body)
	}
}

func TestUnexposeNodeRouteDeletesTheHostname(t *testing.T) {
	d := startFakeDaemon(t, func(w http.ResponseWriter, _ *http.Request) {
		respond(w, 202, wire.NodeRouteSubmission{Route: &wire.NodeRoute{Hostname: "shop.example.com", Phase: "active"}})
	})

	res, err := d.client(client.Options{}).UnexposeNodeRoute(context.Background(), "01a19231-7dca-73e4-8215-99d21fbaac60", "shop.example.com")

	got := d.Requests()[0]
	if err != nil || res.Route == nil || res.Route.Phase != "active" {
		t.Fatalf("result = %+v, %v", res, err)
	}
	if got.Method != "DELETE" || got.Path != "/api/v1/nodes/01a19231-7dca-73e4-8215-99d21fbaac60/routes/shop.example.com" || got.Header.Get(wire.HeaderIdempotencyKey) == "" {
		t.Errorf("request = %s %s key=%q", got.Method, got.Path, got.Header.Get(wire.HeaderIdempotencyKey))
	}
}

func TestNodeRouteReadsAddressTheNodeOrEverything(t *testing.T) {
	d := startFakeDaemon(t, func(w http.ResponseWriter, _ *http.Request) {
		respond(w, 200, wire.Page[wire.NodeRoute]{Items: []wire.NodeRoute{{Hostname: "shop.example.com"}}})
	})
	api := d.client(client.Options{})

	one, err := api.ListNodeRoutes(context.Background(), "01a19231-7dca-73e4-8215-99d21fbaac60", false)
	if err != nil || len(one.Items) != 1 {
		t.Fatalf("node routes = %+v, %v", one, err)
	}
	all, err := api.ListAllNodeRoutes(context.Background(), true)
	if err != nil || len(all.Items) != 1 {
		t.Fatalf("routes = %+v, %v", all, err)
	}
	reqs := d.Requests()
	if reqs[0].Path != "/api/v1/nodes/01a19231-7dca-73e4-8215-99d21fbaac60/routes" || reqs[1].Path != "/api/v1/node-routes" {
		t.Errorf("paths = %s, %s", reqs[0].Path, reqs[1].Path)
	}
	if reqs[0].Query != "" || reqs[1].Query != "include_removed=true" {
		t.Errorf("queries = %q, %q", reqs[0].Query, reqs[1].Query)
	}
}
