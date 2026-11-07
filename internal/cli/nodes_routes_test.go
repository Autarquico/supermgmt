package cli

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

func routesFixture() (wire.Node, wire.NodeRoute) {
	node := wire.Node{ID: newTestID(), Name: "edge-1"}
	route := wire.NodeRoute{
		ID: newTestID(), NodeID: node.ID, Hostname: "shop.example.com", Port: 8080,
		Access: "public", Phase: "active",
	}
	return node, route
}

func routesAPI(t *testing.T, node wire.Node, routes ...wire.NodeRoute) *fakeAPI {
	t.Helper()
	pending := wire.NodeRouteSubmission{Submission: wire.Submission{
		Job:    wire.Job{ID: newTestID(), Type: "node_route.expose", State: domain.JobAwaitingApproval, PlanHash: "sha256:abc"},
		Policy: wire.Policy{ApprovalRequired: true, Quorum: 1},
	}}
	return newFakeAPI(t, router(map[string]http.HandlerFunc{
		"GET " + wire.PathNodes: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Page[wire.Node]{Items: []wire.Node{node}})
		},
		"GET " + wire.PathNodeRoutesAll: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Page[wire.NodeRoute]{Items: routes})
		},
		"GET " + wire.Path(wire.PathNodeRoutes, string(node.ID)): func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Page[wire.NodeRoute]{Items: routes})
		},
		"POST " + wire.Path(wire.PathNodeRoutes, string(node.ID)): func(w http.ResponseWriter, _ *http.Request) { reply(w, 202, pending) },
		"DELETE " + wire.Path(wire.PathNodeRoute, string(node.ID), "shop.example.com"): func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 202, wire.NodeRouteSubmission{Route: &routes[0], Submission: pending.Submission})
		},
	}))
}

func TestNodesExposeSendsTheRequestAndWarnsThatAPublicRouteHasNoAuthentication(t *testing.T) {
	node, route := routesFixture()
	f := routesAPI(t, node, route)

	r := f.run("nodes", "expose", "edge-1", "--hostname", "shop.example.com", "--port", "8080")

	if r.code != 0 || !strings.Contains(r.stdout, "approval required") {
		t.Fatalf("code=%d out=%q err=%q", r.code, r.stdout, r.stderr)
	}
	if !strings.Contains(r.stderr, "no authentication") || !strings.Contains(r.stderr, "to approve: sm jobs approve") || !strings.Contains(r.stderr, "--plan-hash sha256:abc") {
		t.Errorf("stderr lacks the warning or the approval line: %q", r.stderr)
	}
	muts := f.Mutations()
	var req wire.ExposeNodeRouteRequest
	if len(muts) != 1 || json.Unmarshal([]byte(muts[0].Body), &req) != nil {
		t.Fatalf("mutations = %+v", muts)
	}
	if req.Hostname != "shop.example.com" || req.Port != 8080 || req.Access != "public" {
		t.Errorf("request = %+v", req)
	}
}

func TestNodesExposeOwnersDoesNotWarn(t *testing.T) {
	node, route := routesFixture()
	f := routesAPI(t, node, route)

	r := f.run("nodes", "expose", "edge-1", "--hostname", "shop.example.com", "--port", "8080", "--access", "owners")

	if r.code != 0 || strings.Contains(r.stderr, "authentication") {
		t.Errorf("code=%d err=%q", r.code, r.stderr)
	}
	var req wire.ExposeNodeRouteRequest
	if err := json.Unmarshal([]byte(f.Mutations()[0].Body), &req); err != nil || req.Access != "owners" {
		t.Errorf("request = %+v, %v", req, err)
	}
}

func TestNodesExposeNeedsItsFlagsAndAKnownAccessBeforeAnyRequest(t *testing.T) {
	node, route := routesFixture()
	for name, args := range map[string][]string{
		"no hostname":    {"nodes", "expose", "edge-1", "--port", "8080"},
		"no port":        {"nodes", "expose", "edge-1", "--hostname", "a.example.com"},
		"unknown access": {"nodes", "expose", "edge-1", "--hostname", "a.example.com", "--port", "1", "--access", "all"},
	} {
		f := routesAPI(t, node, route)
		if r := f.run(args...); r.code != exitUsage || len(f.Requests()) != 0 {
			t.Errorf("%s: exit %d, requests %d, stderr %q", name, r.code, len(f.Requests()), r.stderr)
		}
	}
}

func TestNodesUnexposeDeletesTheHostnameOfTheNode(t *testing.T) {
	node, route := routesFixture()
	f := routesAPI(t, node, route)

	r := f.run("nodes", "unexpose", "edge-1", "--hostname", "shop.example.com")

	if r.code != 0 || !strings.Contains(r.stdout, "shop.example.com") {
		t.Fatalf("code=%d out=%q err=%q", r.code, r.stdout, r.stderr)
	}
	if muts := f.Mutations(); len(muts) != 1 || muts[0].Method != "DELETE" {
		t.Errorf("mutations = %+v", muts)
	}
	if bare := routesAPI(t, node, route).run("nodes", "unexpose", "edge-1"); bare.code != exitUsage {
		t.Errorf("without --hostname: exit %d", bare.code)
	}
}

func TestNodesRoutesListsEverythingOrOneNode(t *testing.T) {
	node, route := routesFixture()
	route.Phase, route.LastError = "failed", "foreign DNS record"
	f := routesAPI(t, node, route)

	for _, args := range [][]string{{"nodes", "routes"}, {"nodes", "routes", "edge-1"}} {
		r := f.run(args...)
		if r.code != 0 {
			t.Fatalf("%v: code=%d err=%q", args, r.code, r.stderr)
		}
		for _, want := range []string{"NODE", "HOSTNAME", "PORT", "ACCESS", "PHASE", "edge-1", "shop.example.com", "8080", "public", "failed: foreign DNS record"} {
			if !strings.Contains(r.stdout, want) {
				t.Errorf("%v: output lacks %q:\n%s", args, want, r.stdout)
			}
		}
	}
}

func TestNodesRoutesAllAsksForRemovedRoutesToo(t *testing.T) {
	node, route := routesFixture()
	route.Phase, route.LastError = "removed", "waited for a deployment; routes no longer wait for one"
	f := routesAPI(t, node, route)

	plain, all := f.run("nodes", "routes"), f.run("nodes", "routes", "--all")

	if plain.code != 0 || all.code != 0 {
		t.Fatalf("codes %d, %d: %q %q", plain.code, all.code, plain.stderr, all.stderr)
	}
	var queries []string
	for _, req := range f.Requests() {
		if strings.HasPrefix(req.Path, wire.PathNodeRoutesAll) {
			queries = append(queries, req.Query)
		}
	}
	if len(queries) != 2 || queries[0] != "" || queries[1] != "include_removed=true" {
		t.Errorf("queries = %q, want none, then include_removed=true", queries)
	}
	if !strings.Contains(all.stdout, "removed: waited for a deployment") {
		t.Errorf("--all output lacks the note:\n%s", all.stdout)
	}
}

func TestTheDeploymentCommandsAreGone(t *testing.T) {
	for _, args := range [][]string{{"apps", "list"}, {"apps", "expose"}, {"deploy"}, {"rollback"}, {"deployments", "list"}} {
		if r := run(args...); r.code != 2 {
			t.Errorf("sm %s still exists", strings.Join(args, " "))
		}
	}
}
