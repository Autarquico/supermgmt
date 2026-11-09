package app

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

var web2ID = strings.Repeat("d", 64)

// scaled makes the web service of the project shop two containers, shop-web-1 and shop-web-2.
func (f *appsFixture) scaled() {
	inspect := inspectOf(defaultWebEnv)
	replica := strings.NewReplacer(webID, web2ID, "shop-web-1", "shop-web-2").Replace(inspect[strings.Index(inspect, " {"):strings.Index(inspect, ",\n {\"Id\":\""+dbID)])
	f.node.reply("docker.inspect_all", strings.Replace(inspect, ",\n {\"Id\":\""+dbID, ",\n"+replica+",\n {\"Id\":\""+dbID, 1))
	f.node.reply("docker.stats", statsReply+`{"ID":"dddddddddddd","Name":"shop-web-2","CPUPerc":"1.00%","MemUsage":"1MiB / 1GiB"}`+"\n")
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		rows, err := database.ListServices(ctx, tx, f.nodeID())
		if err != nil {
			return err
		}
		seen := epoch
		_, err = database.CreateService(ctx, tx, domain.Service{
			ID: f.ids.NewID(), RuntimeID: rows[0].RuntimeID, NodeID: f.nodeID(), NativeID: web2ID, Name: "shop-web-2",
			Kind: string(domain.ServiceDockerContainer), Status: "running", LastSeenAt: &seen,
			Metadata: map[string]any{"compose_project": "shop", "labels": map[string]any{"com.docker.compose.service": "web"}, "image": "shop/web:1", "ports": []any{}},
		})
		return err
	})
}

func TestTheReplicasOfAScaledServiceAreSeparateComponentsInDetailsLogsStatsAndErrors(t *testing.T) {
	f := newAppsFixture(t)
	f.scaled()
	one := []string{stamped(1, "ERROR from one"), stamped(2, "fine")}
	two := []string{stamped(1, "from two"), stamped(2, "ERROR two"), stamped(3, "panic two")}
	f.writeLog(webID, &one)
	f.writeLog(web2ID, &two)
	f.writeLog(dbID, new([]string))
	ctx, by := context.Background(), f.caller(f.alice)

	app, err := f.inv.GetApp(ctx, by, f.nodeID(), "shop", wire.AppsQuery{Stats: true, Errors: true})
	mustf(t, err, "GetApp")

	var names []string
	counts := map[string]int{}
	for _, c := range app.Components {
		names = append(names, c.Name)
		if c.RecentErrors != nil {
			counts[c.Name] = *c.RecentErrors
		}
	}
	if strings.Join(names, ",") != "db,shop-web-1,shop-web-2" {
		t.Fatalf("components = %v, want a unique name per container of the scaled service", names)
	}
	if counts["shop-web-1"] != 1 || counts["shop-web-2"] != 2 || app.RecentErrors == nil || *app.RecentErrors != 3 {
		t.Errorf("errors = %v total %v, want each replica's own", counts, app.RecentErrors)
	}
	for name, want := range map[string]string{"shop-web-1": "from one", "shop-web-2": "from two"} {
		logs, err := f.inv.AppLogs(ctx, by, f.nodeID(), "shop", wire.AppLogQuery{Component: name})
		if mustf(t, err, "AppLogs %s", name); !strings.Contains(strings.Join(logs.Lines, "\n"), want) {
			t.Errorf("%s logs = %q, want %q", name, logs.Lines, want)
		}
	}
	stats, err := f.inv.AppStats(ctx, by, f.nodeID(), "shop")
	mustf(t, err, "AppStats")
	var statNames []string
	for _, c := range stats.Components {
		statNames = append(statNames, c.Name)
	}
	slices.Sort(statNames)
	if strings.Join(statNames, ",") != "db,shop-web-1,shop-web-2" {
		t.Errorf("stats components = %v", statNames)
	}
	f.node.down("docker.inspect_all", errors.New("connection refused"))
	stale, err := f.inv.NodeApps(ctx, by, f.nodeID(), wire.AppsQuery{})
	mustf(t, err, "stale")
	if got := stale.Apps[0].Components; len(got) != 3 || got[1].Name != "shop-web-1" || got[2].Name != "shop-web-2" {
		t.Errorf("the last discovery names the replicas differently: %+v", got)
	}
}

func TestANodeWithNoComposeProjectAnswersAnEmptyListNotNull(t *testing.T) {
	f := newAppsFixture(t)
	f.node.reply("docker.inspect_all", "[]")

	got, err := f.inv.NodeApps(context.Background(), f.caller(f.alice), f.nodeID(), wire.AppsQuery{})

	if mustf(t, err, "NodeApps"); got.Apps == nil || len(got.Apps) != 0 || got.Problem != "" {
		t.Errorf("apps = %#v problem %q, want a non-nil empty list", got.Apps, got.Problem)
	}
}

func TestTheAnswerForOneAppCarriesWhyItCouldNotBeReadLive(t *testing.T) {
	f := newAppsFixture(t)
	ctx, by := context.Background(), f.caller(f.alice)
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		return database.SetNodeCapability(ctx, tx, f.nodeID(), database.NodeCapability{Capability: "docker.read", Available: false, CheckedAt: f.clock.Now()})
	})

	app, err := f.inv.GetApp(ctx, by, f.nodeID(), "shop", wire.AppsQuery{})
	overview, overviewErr := f.inv.NodeApps(ctx, by, f.nodeID(), wire.AppsQuery{})

	mustf(t, err, "GetApp")
	mustf(t, overviewErr, "NodeApps")
	if !app.Stale || app.Problem != wire.AppsProblemDocker || app.Hint != overview.Hint || app.Hint != "sm nodes setup web-1 --docker-access" {
		t.Errorf("problem %q hint %q, want the overview's", app.Problem, app.Hint)
	}
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		return database.SetNodeCapability(ctx, tx, f.nodeID(), database.NodeCapability{Capability: "docker.read", Available: true, CheckedAt: f.clock.Now()})
	})
	f.node.down("docker.inspect_all", errors.New("connection refused"))
	down, err := f.inv.GetApp(ctx, by, f.nodeID(), "shop", wire.AppsQuery{})
	if mustf(t, err, "GetApp unreachable"); down.Problem != wire.AppsProblemUnreachable || down.Hint != "" {
		t.Errorf("problem %q hint %q", down.Problem, down.Hint)
	}
	live := newAppsFixture(t)
	fresh, err := live.inv.GetApp(ctx, live.caller(live.alice), live.nodeID(), "shop", wire.AppsQuery{})
	if mustf(t, err, "GetApp live"); fresh.Problem != "" || fresh.Hint != "" || fresh.Stale {
		t.Errorf("a live read carries problem %q hint %q", fresh.Problem, fresh.Hint)
	}
}

func TestANodeThatGoesSilentIsShownStaleWithinTheBudgetWhileTheCallerWaits(t *testing.T) {
	f := newAppsFixture(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	f.node.on("docker.inspect_all", func(templates.Command) (transport.Result, error) {
		<-release
		return transport.Result{}, nil
	})
	previous := appsBudget
	appsBudget = 200 * time.Millisecond
	t.Cleanup(func() { appsBudget = previous })
	type answer struct {
		page wire.Page[wire.NodeApps]
		err  error
	}
	done := make(chan answer, 1)

	go func() {
		page, err := f.inv.Apps(context.Background(), f.caller(f.alice), wire.AppsQuery{})
		done <- answer{page, err}
	}()

	select {
	case got := <-done:
		mustf(t, got.err, "Apps")
		if len(got.page.Items) != 1 || got.page.Items[0].Problem != wire.AppsProblemUnreachable || len(got.page.Items[0].Apps) != 1 || !got.page.Items[0].Apps[0].Stale {
			t.Errorf("items = %+v, want the silent node stale", got.page.Items)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the overview waited for the silent node")
	}
}

func TestEachNodeGetsTheBudgetOfItsRoundSoManyNodesFitTheCallersTimeout(t *testing.T) {
	if got := nodeBudget(1); got != appsBudget {
		t.Errorf("one node: %v", got)
	}
	if got, want := nodeBudget(9), appsBudget/3; got != want {
		t.Errorf("nine nodes read in three rounds: %v, want %v", got, want)
	}
	if got := nodeBudget(400); got != minNodeBudget {
		t.Errorf("400 nodes: %v, want the floor %v", got, minNodeBudget)
	}
}

// panelNamesAnswer reads the panel of shop and checks that logs, stats and error counts answer for each name it
// offers; it returns the names.
func (f *appsFixture) panelNamesAnswer(t *testing.T) []string {
	t.Helper()
	ctx, by := context.Background(), f.caller(f.alice)
	app, err := f.inv.GetApp(ctx, by, f.nodeID(), "shop", wire.AppsQuery{Stats: true, Errors: true})
	mustf(t, err, "GetApp")
	stats, err := f.inv.AppStats(ctx, by, f.nodeID(), "shop")
	mustf(t, err, "AppStats")
	statNames := map[string]bool{}
	for _, c := range stats.Components {
		statNames[c.Name] = true
	}
	var names []string
	for _, c := range app.Components {
		names = append(names, c.Name)
		if _, err := f.inv.AppLogs(ctx, by, f.nodeID(), "shop", wire.AppLogQuery{Component: c.Name}); err != nil {
			t.Errorf("logs of %q: %v", c.Name, err)
		}
		if !statNames[c.Name] && c.Stats != nil {
			t.Errorf("stats do not answer for %q, they name %v", c.Name, statNames)
		}
		if c.RecentErrors == nil {
			t.Errorf("no error count for %q", c.Name)
		}
	}
	return names
}

func TestAGoneRowOfAnOldContainerDoesNotRenameTheLiveOne(t *testing.T) {
	f := newAppsFixture(t)
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		rows, err := database.ListServices(ctx, tx, f.nodeID())
		if err != nil {
			return err
		}
		seen := epoch
		_, err = database.CreateService(ctx, tx, domain.Service{
			ID: f.ids.NewID(), RuntimeID: rows[0].RuntimeID, NodeID: f.nodeID(), NativeID: web2ID, Name: "shop-web-0",
			Kind: string(domain.ServiceDockerContainer), Status: database.StatusGone, LastSeenAt: &seen,
			Metadata: map[string]any{"compose_project": "shop", "labels": map[string]any{"com.docker.compose.service": "web"}, "image": "shop/web:0", "ports": []any{}},
		})
		return err
	})
	for _, name := range []string{webID, dbID} {
		held := []string{stamped(1, "line")}
		f.writeLog(name, &held)
	}

	names := f.panelNamesAnswer(t)

	if strings.Join(names, ",") != "db,web" {
		t.Errorf("components = %v", names)
	}
	f.node.down("docker.inspect_all", errors.New("connection refused"))
	stale, err := f.inv.NodeApps(context.Background(), f.caller(f.alice), f.nodeID(), wire.AppsQuery{})
	mustf(t, err, "stale")
	for _, c := range stale.Apps[0].Components {
		if c.Name == "web" && c.Status != "running" {
			t.Errorf("the gone container took the name of the live one: %+v", c)
		}
	}
	if _, err := f.inv.AppLogs(context.Background(), f.caller(f.alice), f.nodeID(), "shop", wire.AppLogQuery{Component: "web"}); err != nil {
		t.Errorf("logs of web while the node cannot be read live: %v", err)
	}
}

func TestAScaleDownBeforeTheNextDiscoveryStillAnswersForTheNameThePanelOffers(t *testing.T) {
	f := newAppsFixture(t)
	f.scaled()
	f.node.reply("docker.inspect_all", inspectOf(defaultWebEnv)) // web-2 is gone from the node; both rows still run
	for _, name := range []string{webID, dbID} {
		held := []string{stamped(1, "line")}
		f.writeLog(name, &held)
	}

	names := f.panelNamesAnswer(t)

	if strings.Join(names, ",") != "db,web" {
		t.Errorf("components = %v", names)
	}
}
