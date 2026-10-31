package cli

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

func routesFixture() (wire.App, wire.AppRoute) {
	web, _, _ := appsFixture()
	route := wire.AppRoute{
		ID: newTestID(), AppTargetID: web.Targets[0].ID, Hostname: "shop.example.com", Service: "web", Port: 8080,
		Access: "public", Phase: "active",
	}
	return web, route
}

func routesAPI(t *testing.T, web wire.App, routes ...wire.AppRoute) *fakeAPI {
	t.Helper()
	target := web.Targets[0].ID
	pending := wire.AppRouteSubmission{Submission: wire.Submission{
		Job:    wire.Job{ID: newTestID(), Type: "control_plane.apply", State: domain.JobAwaitingApproval},
		Policy: wire.Policy{ApprovalRequired: true, Quorum: 1},
	}}
	return newFakeAPI(t, router(map[string]http.HandlerFunc{
		"GET " + wire.PathApps: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Page[wire.App]{Items: []wire.App{web}})
		},
		"GET " + wire.Path(wire.PathApp, string(web.ID)): func(w http.ResponseWriter, _ *http.Request) { reply(w, 200, web) },
		"GET " + wire.PathAppRoutes:                      func(w http.ResponseWriter, _ *http.Request) { reply(w, 200, wire.Page[wire.AppRoute]{Items: routes}) },
		"GET " + wire.Path(wire.PathAppTargetRoutes, string(target)): func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Page[wire.AppRoute]{Items: routes})
		},
		"POST " + wire.Path(wire.PathAppTargetRoutes, string(target)): func(w http.ResponseWriter, _ *http.Request) { reply(w, 202, pending) },
		"DELETE " + wire.Path(wire.PathAppTargetRoute, string(target), "shop.example.com"): func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 202, wire.AppRouteSubmission{Route: &routes[0], Submission: pending.Submission})
		},
	}))
}

func TestAppsExposeSendsTheRequestAndWarnsThatAPublicRouteHasNoAuthentication(t *testing.T) {
	web, route := routesFixture()
	f := routesAPI(t, web, route)

	r := f.run("apps", "expose", "web", "prod", "--hostname", "shop.example.com", "--service", "web", "--port", "8080")

	if r.code != 0 || !strings.Contains(r.stdout, "approval required") {
		t.Fatalf("code=%d out=%q err=%q", r.code, r.stdout, r.stderr)
	}
	if !strings.Contains(r.stderr, "no authentication") {
		t.Errorf("stderr lacks the unauthenticated warning: %q", r.stderr)
	}
	muts := f.Mutations()
	var req wire.ExposeAppRouteRequest
	if len(muts) != 1 || json.Unmarshal([]byte(muts[0].Body), &req) != nil {
		t.Fatalf("mutations = %+v", muts)
	}
	if req.Hostname != "shop.example.com" || req.Service != "web" || req.Port != 8080 || req.Access != "public" {
		t.Errorf("request = %+v", req)
	}
}

func TestAppsExposeOwnersDoesNotWarn(t *testing.T) {
	web, route := routesFixture()
	f := routesAPI(t, web, route)

	r := f.run("apps", "expose", "web", "prod", "--hostname", "shop.example.com", "--service", "web", "--port", "8080", "--access", "owners")

	if r.code != 0 || strings.Contains(r.stderr, "authentication") {
		t.Errorf("code=%d err=%q", r.code, r.stderr)
	}
	var req wire.ExposeAppRouteRequest
	if err := json.Unmarshal([]byte(f.Mutations()[0].Body), &req); err != nil || req.Access != "owners" {
		t.Errorf("request = %+v, %v", req, err)
	}
}

func TestAppsExposeNeedsItsFlagsAndAKnownAccessBeforeAnyRequest(t *testing.T) {
	web, route := routesFixture()
	for name, args := range map[string][]string{
		"no hostname":    {"apps", "expose", "web", "prod", "--service", "web", "--port", "8080"},
		"no service":     {"apps", "expose", "web", "prod", "--hostname", "a.example.com", "--port", "8080"},
		"no port":        {"apps", "expose", "web", "prod", "--hostname", "a.example.com", "--service", "web"},
		"unknown access": {"apps", "expose", "web", "prod", "--hostname", "a.example.com", "--service", "web", "--port", "1", "--access", "all"},
	} {
		f := routesAPI(t, web, route)
		if r := f.run(args...); r.code != exitUsage || len(f.Requests()) != 0 {
			t.Errorf("%s: exit %d, requests %d, stderr %q", name, r.code, len(f.Requests()), r.stderr)
		}
	}
}

func TestAppsUnexposeDeletesTheHostnameOfTheTarget(t *testing.T) {
	web, route := routesFixture()
	f := routesAPI(t, web, route)

	r := f.run("apps", "unexpose", "web", "prod", "--hostname", "shop.example.com")

	if r.code != 0 || !strings.Contains(r.stdout, "shop.example.com") {
		t.Fatalf("code=%d out=%q err=%q", r.code, r.stdout, r.stderr)
	}
	if muts := f.Mutations(); len(muts) != 1 || muts[0].Method != "DELETE" {
		t.Errorf("mutations = %+v", muts)
	}
	if bare := routesAPI(t, web, route).run("apps", "unexpose", "web", "prod"); bare.code != exitUsage {
		t.Errorf("without --hostname: exit %d", bare.code)
	}
}

func TestAppsRoutesListsEverythingOneAppOrOneEnvironment(t *testing.T) {
	web, route := routesFixture()
	f := routesAPI(t, web, route)

	for _, args := range [][]string{{"apps", "routes"}, {"apps", "routes", "web"}, {"apps", "routes", "web", "prod"}} {
		r := f.run(args...)
		if r.code != 0 {
			t.Fatalf("%v: code=%d err=%q", args, r.code, r.stderr)
		}
		for _, want := range []string{"HOSTNAME", "shop.example.com", "web/prod", "web:8080", "public", "active"} {
			if !strings.Contains(r.stdout, want) {
				t.Errorf("%v: output lacks %q:\n%s", args, want, r.stdout)
			}
		}
	}
}

func TestAppsGetShowsTheRoutesOfItsTargets(t *testing.T) {
	web, route := routesFixture()
	route.Phase, route.LastError = "failed", "foreign DNS record"
	other := route
	other.AppTargetID, other.Hostname = newTestID(), "elsewhere.example.com"
	f := routesAPI(t, web, route, other)

	r := f.run("apps", "get", "web")

	if r.code != 0 || !strings.Contains(r.stdout, "shop.example.com") || !strings.Contains(r.stdout, "failed: foreign DNS record") {
		t.Fatalf("code=%d out=%q err=%q", r.code, r.stdout, r.stderr)
	}
	if strings.Contains(r.stdout, "elsewhere.example.com") {
		t.Errorf("another app's route is shown:\n%s", r.stdout)
	}
}
