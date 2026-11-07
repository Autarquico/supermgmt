package client_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/client"
)

func TestExposeAppRouteIsKeyedAndPostsTheRequest(t *testing.T) {
	d := startFakeDaemon(t, func(w http.ResponseWriter, _ *http.Request) {
		respond(w, 202, wire.AppRouteSubmission{})
	})

	res, err := d.client(client.Options{}).ExposeAppRoute(context.Background(), "01a19231-7dca-73e4-8215-99d21fbaac60",
		wire.ExposeAppRouteRequest{Hostname: "shop.example.com", Service: "web", Port: 8080, Access: "owners"})

	got := d.Requests()[0]
	if err != nil || res.Route != nil {
		t.Fatalf("result = %+v, %v", res, err)
	}
	if got.Method != "POST" || got.Path != "/api/v1/app-targets/01a19231-7dca-73e4-8215-99d21fbaac60/routes" || got.Header.Get(wire.HeaderIdempotencyKey) == "" {
		t.Errorf("request = %s %s key=%q", got.Method, got.Path, got.Header.Get(wire.HeaderIdempotencyKey))
	}
	var body wire.ExposeAppRouteRequest
	if err := json.Unmarshal(got.Body, &body); err != nil || body.Hostname != "shop.example.com" || body.Port != 8080 || body.Access != "owners" {
		t.Errorf("body = %s", got.Body)
	}
}

func TestUnexposeAppRouteDeletesTheHostname(t *testing.T) {
	d := startFakeDaemon(t, func(w http.ResponseWriter, _ *http.Request) {
		respond(w, 202, wire.AppRouteSubmission{Route: &wire.AppRoute{Hostname: "shop.example.com", Phase: "active"}})
	})

	res, err := d.client(client.Options{}).UnexposeAppRoute(context.Background(), "01a19231-7dca-73e4-8215-99d21fbaac60", "shop.example.com")

	got := d.Requests()[0]
	if err != nil || res.Route == nil || res.Route.Phase != "active" {
		t.Fatalf("result = %+v, %v", res, err)
	}
	if got.Method != "DELETE" || got.Path != "/api/v1/app-targets/01a19231-7dca-73e4-8215-99d21fbaac60/routes/shop.example.com" || got.Header.Get(wire.HeaderIdempotencyKey) == "" {
		t.Errorf("request = %s %s key=%q", got.Method, got.Path, got.Header.Get(wire.HeaderIdempotencyKey))
	}
}

func TestAppRouteReadsAddressTheTargetOrEverything(t *testing.T) {
	d := startFakeDaemon(t, func(w http.ResponseWriter, _ *http.Request) {
		respond(w, 200, wire.Page[wire.AppRoute]{Items: []wire.AppRoute{{Hostname: "shop.example.com"}}})
	})
	api := d.client(client.Options{})

	one, err := api.ListAppTargetRoutes(context.Background(), "01a19231-7dca-73e4-8215-99d21fbaac60")
	if err != nil || len(one.Items) != 1 {
		t.Fatalf("target routes = %+v, %v", one, err)
	}
	all, err := api.ListAppRoutes(context.Background())
	if err != nil || len(all.Items) != 1 {
		t.Fatalf("routes = %+v, %v", all, err)
	}
	reqs := d.Requests()
	if reqs[0].Path != "/api/v1/app-targets/01a19231-7dca-73e4-8215-99d21fbaac60/routes" || reqs[1].Path != "/api/v1/app-routes" {
		t.Errorf("paths = %s, %s", reqs[0].Path, reqs[1].Path)
	}
}
