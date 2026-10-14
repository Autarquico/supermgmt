package client_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func deploymentsID() domain.ID { return domain.UUIDv7Generator{}.NewID() }

func TestAppsRoutesUseTheDocumentedPathsAndMethods(t *testing.T) {
	app, target := deploymentsID(), deploymentsID()
	tests := []struct {
		name       string
		call       func(*client.Client) error
		wantMethod string
		wantPath   string
	}{
		{"list", func(c *client.Client) error { _, err := c.ListApps(context.Background(), wire.PageQuery{}); return err }, "GET", "/api/v1/apps"},
		{"get", func(c *client.Client) error { _, err := c.GetApp(context.Background(), app); return err }, "GET", "/api/v1/apps/" + string(app)},
		{"create", func(c *client.Client) error {
			_, err := c.CreateApp(context.Background(), wire.CreateAppRequest{Name: "web"})
			return err
		}, "POST", "/api/v1/apps"},
		{"list targets", func(c *client.Client) error { _, err := c.ListAppTargets(context.Background(), app); return err }, "GET", "/api/v1/apps/" + string(app) + "/targets"},
		{"create target", func(c *client.Client) error {
			_, err := c.CreateAppTarget(context.Background(), app, wire.CreateAppTargetRequest{Environment: "prod", NodeID: target})
			return err
		}, "POST", "/api/v1/apps/" + string(app) + "/targets"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := startFakeDaemon(t, func(w http.ResponseWriter, _ *http.Request) { respond(w, 200, map[string]any{"items": []any{}}) })

			if err := tt.call(d.client(client.Options{})); err != nil {
				t.Fatal(err)
			}
			req := d.Requests()[0]
			if req.Method != tt.wantMethod || req.Path != tt.wantPath {
				t.Errorf("request = %s %s, want %s %s", req.Method, req.Path, tt.wantMethod, tt.wantPath)
			}
			if tt.wantMethod == "POST" && req.Header.Get(wire.HeaderIdempotencyKey) == "" {
				t.Error("a mutation was sent without an Idempotency-Key")
			}
		})
	}
}

func TestCreateAppReturnsTheAppliedApp(t *testing.T) {
	d := startFakeDaemon(t, func(w http.ResponseWriter, _ *http.Request) {
		respond(w, 201, wire.Direct[wire.App]{Applied: &wire.App{Name: "web", SpecRevision: 1}})
	})

	got, err := d.client(client.Options{}).CreateApp(context.Background(), wire.CreateAppRequest{Name: "web", ComposeContent: "services: {}"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Applied == nil || got.Applied.Name != "web" {
		t.Fatalf("direct = %+v", got)
	}
	var sent wire.CreateAppRequest
	if err := json.Unmarshal(d.Requests()[0].Body, &sent); err != nil || sent.ComposeContent != "services: {}" {
		t.Errorf("body = %s (%v)", d.Requests()[0].Body, err)
	}
}

func TestListDeploymentsSendsOnlyTheFiltersThatAreSet(t *testing.T) {
	app := deploymentsID()
	d := startFakeDaemon(t, func(w http.ResponseWriter, _ *http.Request) {
		respond(w, 200, wire.Page[wire.Deployment]{Items: []wire.Deployment{{State: "healthy"}}})
	})

	got, err := d.client(client.Options{}).ListDeployments(context.Background(), wire.DeploymentQuery{AppID: app, State: "failed"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Items) != 1 {
		t.Fatalf("items = %+v", got.Items)
	}
	query, _ := url.ParseQuery(d.Requests()[0].Query)
	if query.Get("app_id") != string(app) || query.Get(wire.QueryState) != "failed" {
		t.Errorf("query = %v", query)
	}
	if query.Has("app_target_id") || query.Has("environment_id") {
		t.Errorf("unset filters were sent: %v", query)
	}
}

func TestDeploymentActionsUseTheirRoutes(t *testing.T) {
	dep := deploymentsID()
	d := startFakeDaemon(t, func(w http.ResponseWriter, _ *http.Request) { respond(w, 202, wire.Deployment{State: "created"}) })
	api := d.client(client.Options{})
	ctx := context.Background()

	if _, err := api.CreateDeployment(ctx, wire.CreateDeploymentRequest{Kind: "deploy", CommitSHA: "abc"}); err != nil {
		t.Fatal(err)
	}
	if _, err := api.RollbackDeployment(ctx, dep, wire.RollbackRequest{}); err != nil {
		t.Fatal(err)
	}
	if _, err := api.CancelDeployment(ctx, dep); err != nil {
		t.Fatal(err)
	}
	if _, err := api.GetDeployment(ctx, dep); err != nil {
		t.Fatal(err)
	}

	want := []string{
		"POST /api/v1/deployments",
		"POST /api/v1/deployments/" + string(dep) + "/rollback",
		"POST /api/v1/deployments/" + string(dep) + "/cancel",
		"GET /api/v1/deployments/" + string(dep),
	}
	for i, req := range d.Requests() {
		if got := req.Method + " " + req.Path; got != want[i] {
			t.Errorf("request %d = %s, want %s", i, got, want[i])
		}
	}
}

func TestDeploymentErrorsCarryTheirCodeAndReason(t *testing.T) {
	d := startFakeDaemon(t, func(w http.ResponseWriter, _ *http.Request) {
		respondError(w, 422, smerr.CodeInvalidArgument, smerr.ReasonComposeRejected, "privileged is not allowed")
	})

	_, err := d.client(client.Options{}).CreateApp(context.Background(), wire.CreateAppRequest{Name: "web"})

	var typed *smerr.Error
	if !errors.As(err, &typed) {
		t.Fatalf("err = %v, want a typed error", err)
	}
	if typed.Code != smerr.CodeInvalidArgument || typed.Reason != smerr.ReasonComposeRejected {
		t.Errorf("code/reason = %s/%s", typed.Code, typed.Reason)
	}
}
