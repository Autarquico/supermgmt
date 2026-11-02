package cli

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

func movesAPI(t *testing.T, web wire.App, nodes []wire.Node, stateful bool, moves ...wire.AppMove) *fakeAPI {
	t.Helper()
	return routedMovesAPI(t, web, nodes, stateful, nil, moves...)
}

// routedMovesAPI answers a move request with a move that has frozen the given routes.
func routedMovesAPI(t *testing.T, web wire.App, nodes []wire.Node, stateful bool, routes []wire.AppMoveRoute, moves ...wire.AppMove) *fakeAPI {
	t.Helper()
	target := web.Targets[0].ID
	submission := wire.Submission{
		Job:    wire.Job{ID: newTestID(), Type: "control_plane.apply", State: domain.JobAwaitingApproval},
		Policy: wire.Policy{ApprovalRequired: true, Quorum: 1},
	}
	started := wire.AppMove{ID: newTestID(), AppTargetID: target, Phase: "preflight", Stateful: stateful, Routes: routes}
	if stateful {
		started.Volumes = []wire.AppMoveVolume{{Name: "sm-web-prod_data", Service: "db", Mount: "/var/lib/db", State: "pending", Attempt: 1}}
	}
	return newFakeAPI(t, router(map[string]http.HandlerFunc{
		"GET " + wire.PathApps: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Page[wire.App]{Items: []wire.App{web}})
		},
		"GET " + wire.Path(wire.PathApp, string(web.ID)): func(w http.ResponseWriter, _ *http.Request) { reply(w, 200, web) },
		"GET " + wire.PathNodes: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Page[wire.Node]{Items: nodes})
		},
		"GET " + wire.Path(wire.PathAppTargetMoves, string(target)): func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Page[wire.AppMove]{Items: moves})
		},
		"POST " + wire.Path(wire.PathAppTargetMoves, string(target)): func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 202, wire.AppMoveSubmission{Move: started, Submission: submission})
		},
		"POST " + wire.Path(wire.PathAppTargetMoveCleanup, string(target)): func(w http.ResponseWriter, _ *http.Request) { reply(w, 202, submission) },
		"POST " + wire.Path(wire.PathAppTargetMoveAbandon, string(target)): func(w http.ResponseWriter, _ *http.Request) { reply(w, 202, submission) },
	}))
}

func TestAppsMoveWarnsThatAStatefulMoveStopsTheAppAndListsItsVolumes(t *testing.T) {
	web, _, node := appsFixture()
	f := movesAPI(t, web, []wire.Node{node}, true)

	r := f.run("apps", "move", "web", "prod", "--to", "edge-1")

	if r.code != 0 || !strings.Contains(r.stdout, "approval required") || !strings.Contains(r.stdout, "preflight") {
		t.Fatalf("code=%d out=%q err=%q", r.code, r.stdout, r.stderr)
	}
	for _, want := range []string{"stops it", "sm-web-prod_data", "/var/lib/db"} {
		if !strings.Contains(r.stderr, want) {
			t.Errorf("stderr lacks %q: %q", want, r.stderr)
		}
	}
	var req wire.MoveAppRequest
	muts := f.Mutations()
	if len(muts) != 1 || json.Unmarshal([]byte(muts[0].Body), &req) != nil || req.ToNode != node.ID {
		t.Fatalf("mutations = %+v", muts)
	}
}

func TestAppsMoveOfAStatelessAppSaysItDoesNotStopIt(t *testing.T) {
	web, _, node := appsFixture()
	f := movesAPI(t, web, []wire.Node{node}, false)

	r := f.run("apps", "move", "web", "prod", "--to", node.ID.String())

	if r.code != 0 || !strings.Contains(r.stderr, "does not stop it") || strings.Contains(r.stderr, "warning") {
		t.Errorf("code=%d err=%q", r.code, r.stderr)
	}
}

func TestAppsMoveCleanupAndAbandonPostTheirOwnRoutes(t *testing.T) {
	web, _, node := appsFixture()
	for flag, suffix := range map[string]string{"--cleanup-source": "/moves/cleanup-source", "--abandon": "/moves/abandon"} {
		f := movesAPI(t, web, []wire.Node{node}, false)

		r := f.run("apps", "move", "web", "prod", flag)

		muts := f.Mutations()
		if r.code != 0 || !strings.Contains(r.stdout, "approval required") || len(muts) != 1 || !strings.HasSuffix(muts[0].Path, suffix) {
			t.Errorf("%s: code=%d out=%q mutations=%+v", flag, r.code, r.stdout, muts)
		}
	}
}

func TestAppsMoveNeedsExactlyOneModeBeforeAnyRequest(t *testing.T) {
	web, _, node := appsFixture()
	for name, args := range map[string][]string{
		"none":              {"apps", "move", "web", "prod"},
		"to and abandon":    {"apps", "move", "web", "prod", "--to", "edge-1", "--abandon"},
		"to and cleanup":    {"apps", "move", "web", "prod", "--to", "edge-1", "--cleanup-source"},
		"cleanup + abandon": {"apps", "move", "web", "prod", "--cleanup-source", "--abandon"},
	} {
		f := movesAPI(t, web, []wire.Node{node}, false)
		if r := f.run(args...); r.code != exitUsage || len(f.Requests()) != 0 {
			t.Errorf("%s: exit %d, requests %d, stderr %q", name, r.code, len(f.Requests()), r.stderr)
		}
	}
}

func TestAppsMovesShowsPhaseNodesAndVolumes(t *testing.T) {
	web, _, node := appsFixture()
	move := wire.AppMove{
		ID: newTestID(), AppTargetID: web.Targets[0].ID, SourceNodeID: web.Targets[0].NodeID, DestNodeID: node.ID,
		Phase: "failed", HaltedPhase: "compensating_source_started", LastError: "source did not become healthy", Stateful: true,
		Volumes:   []wire.AppMoveVolume{{Name: "sm-web-prod_data", State: "verified"}},
		Routes:    []wire.AppMoveRoute{{RouteID: newTestID(), Hostname: "web.example.com", Access: "public", FrozenPhase: "active", State: "dns_switched"}},
		UpdatedAt: time.Date(2026, 11, 1, 10, 30, 0, 0, time.UTC),
	}
	f := movesAPI(t, web, []wire.Node{node}, true, move)

	r := f.run("apps", "moves", "web", "prod")

	if r.code != 0 {
		t.Fatalf("code=%d err=%q", r.code, r.stderr)
	}
	for _, want := range []string{"PHASE", "failed in compensating_source_started: source did not become healthy", "edge-1", "sm-web-prod_data:verified", "ROUTES", "web.example.com:dns_switched"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("output lacks %q:\n%s", want, r.stdout)
		}
	}
}

func TestAppsMoveListsTheHostnamesItRepointsAndWarnsAboutTheRollbackWindowOnlyWhenStateful(t *testing.T) {
	web, _, node := appsFixture()
	for _, stateful := range []bool{false, true} {
		f := routedMovesAPI(t, web, []wire.Node{node}, stateful, []wire.AppMoveRoute{
			{RouteID: newTestID(), Hostname: "web.example.com", FrozenPhase: "active", State: "pending"},
			{RouteID: newTestID(), Hostname: "beta.example.com", FrozenPhase: "waiting", State: "pending"},
		})

		r := f.run("apps", "move", "web", "prod", "--to", "edge-1")

		if r.code != 0 || !strings.Contains(r.stderr, "web.example.com, beta.example.com (waiting") {
			t.Fatalf("stateful=%v code=%d err=%q", stateful, r.code, r.stderr)
		}
		if got := strings.Contains(r.stderr, "serve errors"); got != stateful {
			t.Errorf("stateful=%v: rollback window warning = %v in %q", stateful, got, r.stderr)
		}
	}
}
