package cli

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
)

func appsFixture() (wire.Node, wire.NodeApps) {
	node := wire.Node{ID: newTestID(), Name: "web-1"}
	one, errs := 3, 2
	use := wire.ResourceUse{CPUPercent: 12.5, MemUsedBytes: 3 << 20, MemLimitBytes: 1 << 30}
	read := time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)
	app := wire.App{
		Project: "shop", NodeID: node.ID, Node: "web-1", State: wire.AppDegraded, RestartCount: &one, RecentErrors: &errs,
		Stats: &use, ReadAt: read,
		Components: []wire.AppComponent{{
			Name: "web", Image: "shop/web:1", Status: "running", Health: "unhealthy", RestartCount: &one, Stats: &use,
			Ports:  []string{"0.0.0.0:8080->80/tcp"},
			Mounts: []wire.AppMount{{Type: "volume", Name: "data", Source: "/var/lib/docker/volumes/data/_data", Destination: "/data"}},
			Config: &wire.AppConfig{
				RestartPolicy: "always", Env: []string{"MODE=prod", "API_TOKEN=[REDACTED]"}, Command: []string{"serve"},
				Labels: map[string]string{"owner": "shop"},
			},
		}},
	}
	return node, wire.NodeApps{
		NodeID: node.ID, Node: "web-1", Apps: []wire.App{app},
		OtherServices: []wire.OtherService{{ServiceID: newTestID(), Name: "nginx", Kind: "systemd_unit", Status: "running"}},
	}
}

func appsAPI(t *testing.T, node wire.Node, apps wire.NodeApps, logs func(http.ResponseWriter, *http.Request)) *fakeAPI {
	t.Helper()
	return newFakeAPI(t, router(map[string]http.HandlerFunc{
		"GET " + wire.PathNodes: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Page[wire.Node]{Items: []wire.Node{node}})
		},
		"GET " + wire.PathApps: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Page[wire.NodeApps]{Items: []wire.NodeApps{apps}})
		},
		"GET " + wire.Path(wire.PathNodeApps, string(node.ID)): func(w http.ResponseWriter, _ *http.Request) { reply(w, 200, apps) },
		"GET " + wire.Path(wire.PathNodeApp, string(node.ID), "shop"): func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, apps.Apps[0])
		},
		"GET " + wire.Path(wire.PathNodeAppLogs, string(node.ID), "shop"): logs,
	}))
}

func TestAppsListShowsEachAppWithItsStateRestartsUseAndErrors(t *testing.T) {
	node, apps := appsFixture()
	f := appsAPI(t, node, apps, nil)

	for _, args := range [][]string{{"apps", "list"}, {"apps", "list", "web-1"}} {
		r := f.run(args...)

		if r.code != 0 {
			t.Fatalf("%v: code=%d err=%q", args, r.code, r.stderr)
		}
		for _, want := range []string{"NODE", "web-1", "shop", "degraded", "12.5% / 3.0MiB", "other services outside an app"} {
			if !strings.Contains(r.stdout, want) {
				t.Errorf("%v: output lacks %q:\n%s", args, want, r.stdout)
			}
		}
	}
	for _, req := range f.Requests() {
		if strings.HasPrefix(req.Path, wire.PathApps) && req.Query != "errors=true&stats=true" {
			t.Errorf("query = %q, want stats and errors asked for", req.Query)
		}
	}
}

func TestAppsListMarksStaleAppsAndNamesTheDockerCommand(t *testing.T) {
	node, apps := appsFixture()
	apps.Apps[0].Stale, apps.Apps[0].RestartCount, apps.Apps[0].Stats = true, nil, nil
	apps.Problem, apps.Hint = wire.AppsProblemDocker, "sm nodes setup web-1 --docker-access"
	f := appsAPI(t, node, apps, nil)

	r := f.run("apps", "list")

	if r.code != 0 || !strings.Contains(r.stdout, "degraded (stale)") || !strings.Contains(r.stdout, "a person can allow it with: sm nodes setup web-1 --docker-access") {
		t.Errorf("code=%d out=%q err=%q", r.code, r.stdout, r.stderr)
	}
}

func TestAppsShowPrintsComponentsVolumesPortsAndRedactedConfiguration(t *testing.T) {
	node, apps := appsFixture()
	f := appsAPI(t, node, apps, nil)

	r := f.run("apps", "show", "web-1", "shop")

	if r.code != 0 {
		t.Fatalf("code=%d err=%q", r.code, r.stderr)
	}
	for _, want := range []string{"app:", "shop", "COMPONENT", "unhealthy", "port    0.0.0.0:8080->80/tcp", "volume  data -> /data (volume)", "env     API_TOKEN=[REDACTED]", "label   owner=shop"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("output lacks %q:\n%s", want, r.stdout)
		}
	}
}

func TestAppsLogsPrintsLinesAndSearchSaysWhatItCovered(t *testing.T) {
	node, apps := appsFixture()
	from, to := time.Date(2026, 11, 9, 9, 0, 0, 0, time.UTC), time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)
	f := appsAPI(t, node, apps, func(w http.ResponseWriter, r *http.Request) {
		logs := wire.AppLogs{Project: "shop", Component: "web", Lines: []string{"10:00 timeout"}}
		if r.URL.Query().Get("search") != "" {
			logs.Window = &wire.LogWindow{Lines: 2000, From: &from, To: &to}
		}
		reply(w, 200, logs)
	})

	plain := f.run("apps", "logs", "web-1", "shop", "web", "--lines", "50")
	search := f.run("apps", "logs", "web-1", "shop", "web", "--search", "timeout")

	if plain.code != 0 || plain.stdout != "10:00 timeout\n" || plain.stderr != "" {
		t.Errorf("plain: code=%d out=%q err=%q", plain.code, plain.stdout, plain.stderr)
	}
	if search.code != 0 || !strings.Contains(search.stderr, "searched the last 2000 lines (2026-11-09T09:00:00Z to 2026-11-09T10:00:00Z)") {
		t.Errorf("search: code=%d err=%q", search.code, search.stderr)
	}
	var queries []string
	for _, req := range f.Requests() {
		if strings.HasSuffix(req.Path, "/logs") {
			queries = append(queries, req.Query)
		}
	}
	if len(queries) != 2 || queries[0] != "component=web&lines=50" || queries[1] != "component=web&search=timeout" {
		t.Errorf("queries = %q", queries)
	}
}

func TestAppsLogsFollowPassesTheCursorBackAndSaysWhenLinesWereLost(t *testing.T) {
	appLogsPoll = time.Millisecond
	t.Cleanup(func() { appLogsPoll = 2 * time.Second })
	node, apps := appsFixture()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	polls := 0
	f := appsAPI(t, node, apps, func(w http.ResponseWriter, r *http.Request) {
		polls++
		switch polls {
		case 1:
			reply(w, 200, wire.AppLogs{Lines: []string{"one"}, Cursor: "c1"})
		case 2:
			reply(w, 200, wire.AppLogs{Lines: []string{"two"}, Cursor: "c2", Gap: true})
		default:
			cancel() // the user interrupts while the third poll is out
			reply(w, 200, wire.AppLogs{})
		}
	})

	r := f.runCtx(ctx, "", "apps", "logs", "web-1", "shop", "web", "--follow")

	if r.code != 0 || r.stdout != "one\ntwo\n" || !strings.Contains(r.stderr, "gap: some lines were not delivered") {
		t.Errorf("code=%d out=%q err=%q", r.code, r.stdout, r.stderr)
	}
	var queries []string
	for _, req := range f.Requests() {
		if strings.HasSuffix(req.Path, "/logs") {
			queries = append(queries, req.Query)
		}
	}
	if len(queries) < 2 || queries[0] != "component=web" || queries[1] != "component=web&cursor=c1" {
		t.Errorf("queries = %q", queries)
	}
}

func TestAppsLogsFollowAndSearchDoNotCombineAndTheGroupTakesNoOtherSubcommand(t *testing.T) {
	node, apps := appsFixture()
	f := appsAPI(t, node, apps, nil)

	if r := f.run("apps", "logs", "web-1", "shop", "web", "--follow", "--search", "x"); r.code != exitUsage || len(f.Requests()) != 0 {
		t.Errorf("exit %d, requests %d", r.code, len(f.Requests()))
	}
	for _, args := range [][]string{{"apps", "expose"}, {"apps", "move"}} {
		if r := f.run(args...); r.code != exitUsage {
			t.Errorf("sm %s: exit %d", strings.Join(args, " "), r.code)
		}
	}
}
