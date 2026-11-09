package client_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/client"
)

const appsNode = "01a19231-7dca-73e4-8215-99d21fbaac60"

func TestAppReadsAddressTheNodeAndTheProjectAndCarryTheirQuery(t *testing.T) {
	d := startFakeDaemon(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case wire.PathApps:
			respond(w, 200, wire.Page[wire.NodeApps]{})
		case "/api/v1/nodes/" + appsNode + "/apps":
			respond(w, 200, wire.NodeApps{})
		case "/api/v1/nodes/" + appsNode + "/apps/shop":
			respond(w, 200, wire.App{Project: "shop"})
		case "/api/v1/nodes/" + appsNode + "/apps/shop/stats":
			respond(w, 200, wire.AppStats{Project: "shop"})
		default:
			respond(w, 200, wire.AppLogs{Project: "shop", Cursor: "next"})
		}
	})
	api, ctx := d.client(client.Options{}), context.Background()

	_, err1 := api.ListApps(ctx, wire.AppsQuery{Stats: true})
	_, err2 := api.ListNodeApps(ctx, appsNode, wire.AppsQuery{Errors: true})
	app, err3 := api.GetNodeApp(ctx, appsNode, "shop", wire.AppsQuery{})
	_, err4 := api.NodeAppStats(ctx, appsNode, "shop")
	logs, err5 := api.NodeAppLogs(ctx, appsNode, "shop", wire.AppLogQuery{Component: "web", Search: "a b"})

	for _, err := range []error{err1, err2, err3, err4, err5} {
		if err != nil {
			t.Fatal(err)
		}
	}
	if app.Project != "shop" || logs.Cursor != "next" {
		t.Errorf("app %+v logs %+v", app, logs)
	}
	var seen []string
	for _, req := range d.Requests() {
		seen = append(seen, req.Method+" "+req.Path+"?"+req.Query)
		if req.Header.Get(wire.HeaderIdempotencyKey) != "" {
			t.Errorf("a read carried an idempotency key: %s", req.Path)
		}
	}
	want := []string{
		"GET /api/v1/apps?stats=true",
		"GET /api/v1/nodes/" + appsNode + "/apps?errors=true",
		"GET /api/v1/nodes/" + appsNode + "/apps/shop?",
		"GET /api/v1/nodes/" + appsNode + "/apps/shop/stats?",
		"GET /api/v1/nodes/" + appsNode + "/apps/shop/logs?component=web&search=a+b",
	}
	if len(seen) != len(want) {
		t.Fatalf("requests = %v", seen)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Errorf("request %d = %s, want %s", i, seen[i], want[i])
		}
	}
}
