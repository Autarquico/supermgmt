package app

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/policy"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

var (
	webID = strings.Repeat("a", 64)
	dbID  = strings.Repeat("b", 64)
	apiID = strings.Repeat("c", 64)
)

// appsPolicy separates what the apps need: operators read services and logs, viewers read services only, and
// admins here may only read the node.
const appsPolicy = `version: 1
rules:
  - name: operators
    subjects: ["role:operator"]
    allow: ["node.read", "service.read", "service.logs"]
  - name: viewers
    subjects: ["role:viewer"]
    allow: ["node.read", "service.read"]
  - name: node-only
    subjects: ["role:admin"]
    allow: ["node.read"]
`

// inspectOf is the `docker inspect` of three containers: web and db of the Compose project shop, web restarted
// three times and unhealthy, and a plain container with no project.
func inspectOf(webEnv string) string {
	return fmt.Sprintf(`[
 {"Id":%q,"Name":"/shop-web-1","Image":"sha256:1","RestartCount":3,
  "Config":{"Image":"shop/web:1","Labels":{"com.docker.compose.project":"shop","com.docker.compose.service":"web","traefik.http.middlewares.a.basicauth.users":"admin:$apr1$x$abc","owner":"shop"},
            "Env":[%s],"Cmd":["serve","--password","s3cret","--port","80"],"Entrypoint":["/entry.sh"]},
  "HostConfig":{"RestartPolicy":{"Name":"always"}},
  "Mounts":[{"Type":"volume","Name":"data","Source":"/var/lib/docker/volumes/data/_data","Destination":"/data","RW":true}],
  "State":{"Status":"running","StartedAt":"2026-11-09T10:00:00Z","Health":{"Status":"unhealthy"}},
  "NetworkSettings":{"Ports":{"80/tcp":[{"HostIp":"0.0.0.0","HostPort":"8080"}]}}},
 {"Id":%q,"Name":"/shop-db-1","Image":"sha256:2","RestartCount":0,
  "Config":{"Image":"postgres:16","Labels":{"com.docker.compose.project":"shop","com.docker.compose.service":"db"},"Env":["POSTGRES_PASSWORD=hunter2"]},
  "HostConfig":{"RestartPolicy":{"Name":"no"}},
  "State":{"Status":"running","StartedAt":"2026-11-09T10:00:00Z"},"NetworkSettings":{"Ports":{}}},
 {"Id":%q,"Name":"/redis","Image":"sha256:3","RestartCount":0,"Config":{"Image":"redis","Labels":{}},
  "State":{"Status":"running","StartedAt":"2026-11-09T10:00:00Z"},"NetworkSettings":{"Ports":{}}}
]`, webID, webEnv, dbID, apiID)
}

const defaultWebEnv = `"MODE=prod","DATABASE_URL=postgres://app:pw0rd@db/shop","API_TOKEN=abc123"`

const statsReply = `{"ID":"aaaaaaaaaaaa","Name":"shop-web-1","CPUPerc":"10.00%","MemUsage":"1MiB / 1GiB"}
{"ID":"bbbbbbbbbbbb","Name":"shop-db-1","CPUPerc":"2.50%","MemUsage":"3MiB / 1GiB"}
`

// stamped is a log line as `docker logs --timestamps` prints it, written i seconds past 10:00.
func stamped(i int, text string) string {
	return stampAt(i) + " " + text
}

func stampAt(i int) string {
	return time.Date(2026, 11, 9, 10, 0, i, 0, time.UTC).Format(time.RFC3339Nano)
}

type appsFixture struct {
	*nodeFixture
	node    *fakeNode            // what the node answers to its automation user
	viewer  domain.ID            // reads services, not logs
	nodeOne domain.ID            // reads the node only
	held    map[string]*[]string // the log lines the node holds, by container
}

func newAppsFixture(t *testing.T) *appsFixture {
	t.Helper()
	f := &appsFixture{nodeFixture: newNodeFixture(t, func(c *Config) {
		p, err := policy.Parse([]byte(appsPolicy))
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		c.Policy = p
	})}
	f.grantSetup()
	f.node = f.dialer.as("supermgmt")
	f.node.reply("docker.inspect_all", inspectOf(defaultWebEnv)).reply("docker.stats", statsReply)
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		if err := database.SetNodeCapability(ctx, tx, f.fixture.node.ID, database.NodeCapability{Capability: "docker.read", Available: true, CheckedAt: f.clock.Now()}); err != nil {
			return err
		}
		runtime := domain.Runtime{ID: f.ids.NewID(), NodeID: f.fixture.node.ID, Type: "docker", NativeID: "docker"}
		if err := database.CreateRuntime(ctx, tx, runtime); err != nil {
			return err
		}
		seen := epoch
		for _, c := range []struct{ id, name, project, component, image string }{
			{webID, "shop-web-1", "shop", "web", "shop/web:1"}, {dbID, "shop-db-1", "shop", "db", "postgres:16"}, {apiID, "redis", "", "", "redis"},
		} {
			labels := map[string]any{}
			if c.component != "" {
				labels["com.docker.compose.service"] = c.component
			}
			_, err := database.CreateService(ctx, tx, domain.Service{
				ID: f.ids.NewID(), RuntimeID: runtime.ID, NodeID: f.fixture.node.ID, NativeID: c.id, Name: c.name,
				Kind: string(domain.ServiceDockerContainer), Status: "running", LastSeenAt: &seen,
				Metadata: map[string]any{"compose_project": c.project, "labels": labels, "image": c.image, "ports": []any{}},
			})
			if err != nil {
				return err
			}
		}
		f.viewer = f.identity(ctx, tx, "vic", domain.ActorHuman, f.role(ctx, tx, "viewer"))
		f.nodeOne = f.admin
		return nil
	})
	return f
}

func (f *appsFixture) nodeID() domain.ID { return f.fixture.node.ID }

func TestAProjectIsAnAppAndWhatIsOutsideOneIsAnotherService(t *testing.T) {
	f := newAppsFixture(t)

	got, err := f.inv.NodeApps(context.Background(), f.caller(f.alice), f.nodeID(), wire.AppsQuery{})

	mustf(t, err, "NodeApps")
	if len(got.Apps) != 1 || got.Apps[0].Project != "shop" || len(got.Apps[0].Components) != 2 || got.Problem != "" {
		t.Fatalf("apps = %+v problem %q", got.Apps, got.Problem)
	}
	names := []string{got.Apps[0].Components[0].Name, got.Apps[0].Components[1].Name}
	if names[0] != "db" || names[1] != "web" || got.Apps[0].Components[0].ServiceID == "" {
		t.Errorf("components = %v", names)
	}
	var others []string
	for _, o := range got.OtherServices {
		others = append(others, o.Name)
	}
	if strings.Join(others, ",") != "nginx,redis" {
		t.Errorf("other services = %v, want the unit and the plain container", others)
	}
}

func TestListingAppsOfAllNodesReadsEachNodeTheCallerMayRead(t *testing.T) {
	f := newAppsFixture(t)

	got, err := f.inv.Apps(context.Background(), f.caller(f.alice), wire.AppsQuery{})

	mustf(t, err, "Apps")
	if len(got.Items) != 1 || got.Items[0].Node != "web-1" || len(got.Items[0].Apps) != 1 || got.Items[0].Apps[0].Project != "shop" {
		t.Errorf("items = %+v", got.Items)
	}
}

func TestAnAppIsDegradedByAnUnhealthyComponentAndShowsRestartsUseAndTime(t *testing.T) {
	f := newAppsFixture(t)

	got, err := f.inv.NodeApps(context.Background(), f.caller(f.alice), f.nodeID(), wire.AppsQuery{Stats: true})

	mustf(t, err, "NodeApps")
	app := got.Apps[0]
	if app.State != wire.AppDegraded || app.RestartCount == nil || *app.RestartCount != 3 {
		t.Errorf("state %s restarts %v, want degraded with 3", app.State, app.RestartCount)
	}
	if app.Stats == nil || app.Stats.CPUPercent != 12.5 || app.Stats.MemUsedBytes != 4<<20 || app.StatsAt == nil || !app.StatsAt.Equal(f.clock.Now()) {
		t.Errorf("stats = %+v at %v", app.Stats, app.StatsAt)
	}
	if app.Stale || !app.ReadAt.Equal(f.clock.Now()) {
		t.Errorf("stale %v read at %v", app.Stale, app.ReadAt)
	}
}

func TestAnAppWhoseComponentsAllRunIsRunning(t *testing.T) {
	f := newAppsFixture(t)
	f.node.reply("docker.inspect_all", strings.Replace(inspectOf(defaultWebEnv), `"Health":{"Status":"unhealthy"}`, `"Health":{"Status":"healthy"}`, 1))

	got, err := f.inv.NodeApps(context.Background(), f.caller(f.alice), f.nodeID(), wire.AppsQuery{})

	if mustf(t, err, "NodeApps"); got.Apps[0].State != wire.AppRunning {
		t.Errorf("state = %s", got.Apps[0].State)
	}
}

func TestTheConfigurationOfAnAppIsRedactedForEveryReader(t *testing.T) {
	f := newAppsFixture(t)
	for _, raw := range []bool{false, true} {
		f.inv.redactLogs = !raw // the switch of command output does not reach configuration

		app, err := f.inv.GetApp(context.Background(), f.caller(f.alice), f.nodeID(), "shop", wire.AppsQuery{})

		mustf(t, err, "GetApp")
		var web, db wire.AppComponent
		for _, c := range app.Components {
			if c.Name == "web" {
				web = c
			} else {
				db = c
			}
		}
		everything := strings.Join(append(append(append(web.Config.Env, web.Config.Command...), web.Config.Entrypoint...), db.Config.Env...), "\n")
		for _, label := range web.Config.Labels {
			everything += "\n" + label
		}
		for _, secret := range []string{"hunter2", "s3cret", "pw0rd", "abc123", "$apr1$"} {
			if strings.Contains(everything, secret) {
				t.Errorf("raw=%v: %q leaked in:\n%s", raw, secret, everything)
			}
		}
		for _, kept := range []string{"MODE=prod", "--port", "/entry.sh", "shop"} {
			if !strings.Contains(everything, kept) {
				t.Errorf("raw=%v: %q was masked away in:\n%s", raw, kept, everything)
			}
		}
		if len(web.Mounts) != 1 || web.Mounts[0].Source != "/var/lib/docker/volumes/data/_data" || len(web.Ports) != 1 || web.Config.RestartPolicy != "always" {
			t.Errorf("mounts %+v ports %v policy %q", web.Mounts, web.Ports, web.Config.RestartPolicy)
		}
	}
}

func TestAnUnreachableNodeShowsTheLastDiscoveryStaleWithItsTime(t *testing.T) {
	f := newAppsFixture(t)
	f.node.down("docker.inspect_all", errors.New("connection refused")).down("docker.logs", errors.New("connection refused"))

	got, err := f.inv.NodeApps(context.Background(), f.caller(f.alice), f.nodeID(), wire.AppsQuery{Stats: true})

	mustf(t, err, "NodeApps")
	if got.Problem != wire.AppsProblemUnreachable || got.Hint != "" || len(got.Apps) != 1 {
		t.Fatalf("problem %q hint %q apps %d", got.Problem, got.Hint, len(got.Apps))
	}
	if app := got.Apps[0]; !app.Stale || !app.ReadAt.Equal(epoch) || app.RestartCount != nil || app.Stats != nil || len(app.Components) != 2 {
		t.Errorf("app = %+v", app)
	}
	if _, err := f.inv.AppLogs(context.Background(), f.caller(f.alice), f.nodeID(), "shop", wire.AppLogQuery{Component: "web"}); err == nil {
		t.Error("a live log read of an unreachable node must fail, not answer from discovery")
	}
}

func TestWhenDockerIsNotAccessibleTheNodeNamesTheCommandAndNothingIsDialed(t *testing.T) {
	f := newAppsFixture(t)
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		return database.SetNodeCapability(ctx, tx, f.nodeID(), database.NodeCapability{Capability: "docker.read", Available: false, CheckedAt: f.clock.Now()})
	})

	got, err := f.inv.NodeApps(context.Background(), f.caller(f.alice), f.nodeID(), wire.AppsQuery{Stats: true, Errors: true})

	mustf(t, err, "NodeApps")
	if got.Problem != wire.AppsProblemDocker || got.Hint != "sm nodes setup web-1 --docker-access" {
		t.Errorf("problem %q hint %q", got.Problem, got.Hint)
	}
	_, logsErr := f.inv.AppLogs(context.Background(), f.caller(f.alice), f.nodeID(), "shop", wire.AppLogQuery{Component: "web"})
	if smerr.CodeOf(logsErr) != smerr.CodeCapabilityUnavailable || !strings.Contains(logsErr.Error(), "sm nodes setup web-1 --docker-access") {
		t.Errorf("logs error = %v", logsErr)
	}
	if ran := f.node.ran(); len(ran) != 0 || len(f.dialer.targets()) != 0 {
		t.Errorf("the node was reached: %v %v", ran, f.dialer.targets())
	}
}

func TestReadingAppsNeedsServiceReadOnTheNodeNotNodeRead(t *testing.T) {
	f := newAppsFixture(t)
	ctx, by := context.Background(), f.caller(f.nodeOne)

	_, listErr := f.inv.NodeApps(ctx, by, f.nodeID(), wire.AppsQuery{})
	_, getErr := f.inv.GetApp(ctx, by, f.nodeID(), "shop", wire.AppsQuery{})
	_, statsErr := f.inv.AppStats(ctx, by, f.nodeID(), "shop")
	all, err := f.inv.Apps(ctx, by, wire.AppsQuery{})

	for name, got := range map[string]error{"list": listErr, "get": getErr, "stats": statsErr} {
		if smerr.CodeOf(got) != smerr.CodePolicyDenied {
			t.Errorf("%s: %v, want POLICY_DENIED for an identity that holds node.read only", name, got)
		}
	}
	if mustf(t, err, "Apps"); len(all.Items) != 0 {
		t.Errorf("GET /apps listed %d nodes the caller may not read services of", len(all.Items))
	}
	if len(f.node.ran()) != 0 {
		t.Errorf("a denied caller made the node run %v", f.node.ran())
	}
	if n := len(f.events("policy.deny")); n != 3 {
		t.Errorf("%d refusals audited, want the three direct reads (the listing only leaves nodes out)", n)
	}
}

func TestErrorCountsAndLogsNeedServiceLogsAndAreAbsentNotZeroWithout(t *testing.T) {
	f := newAppsFixture(t)
	f.node.reply("docker.logs", stamped(1, "ok")+"\n"+stamped(2, "ERROR boom")+"\n"+stamped(3, "panic: x")+"\n"+stamped(4, "terrorism is not what it seems")+"\n")
	ctx := context.Background()

	viewer, err := f.inv.NodeApps(ctx, f.caller(f.viewer), f.nodeID(), wire.AppsQuery{Errors: true})
	mustf(t, err, "viewer NodeApps")
	operator, err := f.inv.NodeApps(ctx, f.caller(f.alice), f.nodeID(), wire.AppsQuery{Errors: true})
	mustf(t, err, "operator NodeApps")

	if app := viewer.Apps[0]; app.RecentErrors != nil || app.Components[0].RecentErrors != nil || app.Components[1].RecentErrors != nil {
		t.Errorf("without service.logs the counts must be absent, got %v", app)
	}
	if app := operator.Apps[0]; app.RecentErrors == nil || *app.RecentErrors != 4 || *app.Components[0].RecentErrors != 2 {
		t.Errorf("operator counts = %v, want 2 per component and 4 in all", app.RecentErrors)
	}
	if f.node.count("docker.logs") != 2 {
		t.Errorf("%d log reads, want one per component and none for the viewer", f.node.count("docker.logs"))
	}
	_, err = f.inv.AppLogs(ctx, f.caller(f.viewer), f.nodeID(), "shop", wire.AppLogQuery{Component: "web"})
	if smerr.CodeOf(err) != smerr.CodePolicyDenied {
		t.Errorf("logs without service.logs: %v", err)
	}
}

func TestTheProjectIsValidatedBeforeAnythingUsesIt(t *testing.T) {
	f := newAppsFixture(t)
	for _, project := range []string{"", "Shop", "../etc", "shop;id", "-shop", "sh op", strings.Repeat("a", 129), "shop\n"} {
		by, id := f.caller(f.alice), f.nodeID()
		_, getErr := f.inv.GetApp(context.Background(), by, id, project, wire.AppsQuery{})
		_, statsErr := f.inv.AppStats(context.Background(), by, id, project)
		_, logsErr := f.inv.AppLogs(context.Background(), by, id, project, wire.AppLogQuery{Component: "web"})
		for name, err := range map[string]error{"get": getErr, "stats": statsErr, "logs": logsErr} {
			if smerr.CodeOf(err) != smerr.CodeInvalidArgument {
				t.Errorf("%s of %q: %v, want INVALID_ARGUMENT", name, project, err)
			}
		}
	}
	if len(f.node.ran()) != 0 {
		t.Errorf("an invalid project reached the node: %v", f.node.ran())
	}
}

func TestAnUnknownAppOrComponentIsNotFound(t *testing.T) {
	f := newAppsFixture(t)
	ctx, by, id := context.Background(), f.caller(f.alice), f.nodeID()

	_, getErr := f.inv.GetApp(ctx, by, id, "blog", wire.AppsQuery{})
	_, logsErr := f.inv.AppLogs(ctx, by, id, "shop", wire.AppLogQuery{Component: "cache"})
	_, noComponent := f.inv.AppLogs(ctx, by, id, "shop", wire.AppLogQuery{})

	if smerr.CodeOf(getErr) != smerr.CodeNotFound || smerr.CodeOf(logsErr) != smerr.CodeNotFound || smerr.CodeOf(noComponent) != smerr.CodeInvalidArgument {
		t.Errorf("get %v, logs %v, no component %v", getErr, logsErr, noComponent)
	}
}

func TestAppStatsAreSampledPerComponentAndStoredNowhere(t *testing.T) {
	f := newAppsFixture(t)
	observations := func() int {
		var n int
		mustf(t, f.db.Reader().QueryRowContext(context.Background(), `SELECT COUNT(*) FROM observations`).Scan(&n), "count")
		return n
	}
	before, events := observations(), len(f.events())

	var stats wire.AppStats
	for range 3 {
		var err error
		stats, err = f.inv.AppStats(context.Background(), f.caller(f.alice), f.nodeID(), "shop")
		mustf(t, err, "AppStats")
	}

	if len(stats.Components) != 2 || stats.Total.CPUPercent != 12.5 || stats.Total.MemUsedBytes != 4<<20 || !stats.SampledAt.Equal(f.clock.Now()) {
		t.Errorf("stats = %+v", stats)
	}
	if observations() != before || len(f.events()) != events {
		t.Errorf("a statistic was written: observations %d -> %d, events %d -> %d", before, observations(), events, len(f.events()))
	}
	if f.node.count("docker.stats") != 3 {
		t.Errorf("%d samples for 3 sequential reads: a sample was kept", f.node.count("docker.stats"))
	}
}

func TestCallersWhoAskTogetherShareOneSampleOfTheNode(t *testing.T) {
	f := newAppsFixture(t)
	release, started := make(chan struct{}), make(chan struct{}, 4)
	f.node.on("docker.stats", func(templates.Command) (transport.Result, error) {
		started <- struct{}{}
		<-release
		return transport.Result{Stdout: []byte(statsReply)}, nil
	})
	var wg sync.WaitGroup
	results := make([]wire.AppStats, 2)
	read := func(k int) {
		defer wg.Done()
		var err error
		results[k], err = f.inv.AppStats(context.Background(), f.caller(f.alice), f.nodeID(), "shop")
		mustf(t, err, "AppStats")
	}
	wg.Add(2)

	go read(0)
	<-started
	go read(1)
	eventually(t, "the second caller to join the sample", func() bool { return f.inv.statsFlights.callers(f.nodeID()) == 2 })
	close(release)
	wg.Wait()

	if f.node.count("docker.stats") != 1 {
		t.Errorf("%d samples, want the one both callers share", f.node.count("docker.stats"))
	}
	if results[0].Total != results[1].Total || results[0].Total.CPUPercent != 12.5 {
		t.Errorf("results differ: %+v %+v", results[0], results[1])
	}
}

func TestRecentLogsAreScrubbedWhateverTheInstanceKeepsRaw(t *testing.T) {
	f := newAppsFixture(t)
	f.inv.redactLogs = false
	f.node.reply("docker.logs", stamped(1, "login password=hunter2 ok")+"\n"+stamped(2, "Authorization: Bearer abc.def.ghi")+"\n")

	logs, err := f.inv.AppLogs(context.Background(), f.caller(f.alice), f.nodeID(), "shop", wire.AppLogQuery{Component: "web"})

	mustf(t, err, "AppLogs")
	text := strings.Join(logs.Lines, "\n")
	if strings.Contains(text, "hunter2") || strings.Contains(text, "abc.def.ghi") || !strings.Contains(text, "login") || len(logs.Lines) != 2 {
		t.Errorf("lines = %q", logs.Lines)
	}
	if logs.Cursor == "" || logs.Project != "shop" || logs.Component != "web" {
		t.Errorf("logs = %+v", logs)
	}
}

func (f *appsFixture) logsSince(chunk ...string) *[]string {
	var asked []string
	f.node.on("docker.logs_since", func(c templates.Command) (transport.Result, error) {
		asked = append(asked, c.Line)
		return transport.Result{Stdout: []byte(strings.Join(chunk, "\n") + "\n")}, nil
	})
	return &asked
}

func (f *appsFixture) follow(cursor string) (wire.AppLogs, error) {
	return f.inv.AppLogs(context.Background(), f.caller(f.alice), f.nodeID(), "shop", wire.AppLogQuery{Component: "web", Cursor: cursor})
}

func TestFollowDeliversOnlyWhatIsNewAndReadsTheOverlapAgain(t *testing.T) {
	f := newAppsFixture(t)
	f.node.reply("docker.logs", stamped(1, "one")+"\n"+stamped(2, "two")+"\n")
	first, err := f.inv.AppLogs(context.Background(), f.caller(f.alice), f.nodeID(), "shop", wire.AppLogQuery{Component: "web"})
	mustf(t, err, "first")
	asked := f.logsSince(stamped(1, "one"), stamped(2, "two"), stamped(3, "three"), stamped(4, "four"))

	next, err := f.follow(first.Cursor)

	mustf(t, err, "follow")
	if strings.Join(next.Lines, "|") != stamped(3, "three")+"|"+stamped(4, "four") || next.Gap {
		t.Errorf("lines = %q gap %v", next.Lines, next.Gap)
	}
	if len(*asked) != 1 || !strings.Contains((*asked)[0], "--since '"+stampAt(1)+"'") {
		t.Errorf("asked = %v, want a read from the start of the overlap", *asked)
	}
	again, err := f.follow(next.Cursor)
	mustf(t, err, "follow again")
	if len(again.Lines) != 0 {
		t.Errorf("nothing was written, but %q arrived", again.Lines)
	}
}

func TestAPEMBlockSplitAcrossTwoPollsIsRedactedWhole(t *testing.T) {
	f := newAppsFixture(t)
	f.node.reply("docker.logs", stamped(0, "starting")+"\n"+stamped(1, "-----BEGIN OPENSSH PRIVATE KEY-----")+"\n"+stamped(2, "b3BlbnNzaC1rZXktdjEAAAAA")+"\n")
	first, err := f.inv.AppLogs(context.Background(), f.caller(f.alice), f.nodeID(), "shop", wire.AppLogQuery{Component: "web"})
	mustf(t, err, "first")
	f.logsSince(
		stamped(0, "starting"), stamped(1, "-----BEGIN OPENSSH PRIVATE KEY-----"), stamped(2, "b3BlbnNzaC1rZXktdjEAAAAA"),
		stamped(3, "QUFBQUJtOWlibVVBQUFBQUJHNXZibVU"), stamped(4, "-----END OPENSSH PRIVATE KEY-----"), stamped(5, "after the key"),
	)

	next, err := f.follow(first.Cursor)

	mustf(t, err, "follow")
	all := strings.Join(first.Lines, "\n") + "\n" + strings.Join(next.Lines, "\n")
	if strings.Contains(all, "b3Blbn") || strings.Contains(all, "QUFBQUJt") {
		t.Errorf("the key leaked across the poll boundary:\n%s", all)
	}
	if len(next.Lines) != 1 || !strings.HasSuffix(next.Lines[0], "after the key") {
		t.Errorf("second poll = %q, want only the line after the key", next.Lines)
	}
}

func TestFollowReportsAGapWhenTheLinesTheCursorStoodOnAreGone(t *testing.T) {
	f := newAppsFixture(t)
	f.node.reply("docker.logs", stamped(1, "one")+"\n"+stamped(2, "two")+"\n")
	first, err := f.inv.AppLogs(context.Background(), f.caller(f.alice), f.nodeID(), "shop", wire.AppLogQuery{Component: "web"})
	mustf(t, err, "first")
	f.logsSince(stamped(30, "thirty"), stamped(31, "thirty-one"))

	next, err := f.follow(first.Cursor)

	mustf(t, err, "follow")
	if !next.Gap || len(next.Lines) != 2 {
		t.Errorf("gap %v lines %q: lost lines must be reported and what is there delivered", next.Gap, next.Lines)
	}
}

func TestFollowReportsAGapWhenTheNodeCutsTheOutput(t *testing.T) {
	f := newAppsFixture(t)
	f.node.reply("docker.logs", stamped(1, "one")+"\n")
	first, err := f.inv.AppLogs(context.Background(), f.caller(f.alice), f.nodeID(), "shop", wire.AppLogQuery{Component: "web"})
	mustf(t, err, "first")
	f.node.on("docker.logs_since", func(templates.Command) (transport.Result, error) {
		return transport.Result{Stdout: []byte(stamped(1, "one") + "\n" + stamped(2, "two") + "\n"), Truncated: true}, nil
	})

	next, err := f.follow(first.Cursor)

	if mustf(t, err, "follow"); !next.Gap || !next.Truncated {
		t.Errorf("gap %v truncated %v", next.Gap, next.Truncated)
	}
}

func TestACursorTheDaemonDidNotIssueIsNoCursorAndReportsAGap(t *testing.T) {
	f := newAppsFixture(t)
	held := []string{stamped(1, "one"), stamped(2, "two")}
	f.writeLog(webID, &held)
	valid := f.logs(wire.AppLogQuery{}).Cursor
	forged := base64.RawURLEncoding.EncodeToString([]byte(`{"s":"2026-11-09T10:00:00Z","k":0}`))
	for name, cursor := range map[string]string{
		"garbage": "x", "no tag": forged, "wrong tag": forged + ".AAAA", "payload swapped": forged + "." + strings.SplitN(valid, ".", 2)[1],
	} {
		got, err := f.follow(cursor)
		mustf(t, err, "%s", name)
		if !got.Gap || len(got.Lines) != 2 {
			t.Errorf("%s: gap %v lines %q, want the tail and a gap", name, got.Gap, got.Lines)
		}
		if n := f.node.count("docker.logs_since"); n != 0 {
			t.Errorf("%s: a chosen Since reached the node", name)
		}
	}
}

func TestACursorOfAnEarlierDaemonRunIsStale(t *testing.T) {
	f := newAppsFixture(t)
	held := []string{stamped(1, "one")}
	f.writeLog(webID, &held)
	old := f.logs(wire.AppLogQuery{}).Cursor
	was := cursorKey
	t.Cleanup(func() { cursorKey = was })
	cursorKey = newCursorKey()

	got, err := f.follow(old)

	if mustf(t, err, "follow"); !got.Gap || len(got.Lines) != 1 {
		t.Errorf("gap %v lines %q", got.Gap, got.Lines)
	}
	again, err := f.follow(got.Cursor)
	if mustf(t, err, "again"); again.Gap {
		t.Errorf("the cursor issued after the restart reports a gap")
	}
}

func TestSearchRunsAfterScrubbingOnABoundedWindowAndNeverSendsTheTerm(t *testing.T) {
	f := newAppsFixture(t)
	f.node.reply("docker.logs", stamped(1, "connect timeout to db")+"\n"+stamped(2, "password=hunter2 retry")+"\n"+stamped(3, "Timeout again")+"\n"+stamped(4, "fine")+"\n")
	ctx, by, id := context.Background(), f.caller(f.alice), f.nodeID()

	found, err := f.inv.AppLogs(ctx, by, id, "shop", wire.AppLogQuery{Component: "web", Search: "timeout"})
	probe, probeErr := f.inv.AppLogs(ctx, by, id, "shop", wire.AppLogQuery{Component: "web", Search: "hunter2"})

	mustf(t, err, "search")
	mustf(t, probeErr, "probe")
	if len(found.Lines) != 2 || !strings.Contains(found.Lines[1], "Timeout again") || found.Cursor != "" {
		t.Errorf("matches = %q cursor %q", found.Lines, found.Cursor)
	}
	if found.Window == nil || found.Window.Lines != 4 || found.Window.From == nil || !found.Window.From.Equal(time.Date(2026, 11, 9, 10, 0, 1, 0, time.UTC)) {
		t.Errorf("window = %+v", found.Window)
	}
	if len(probe.Lines) != 0 {
		t.Errorf("a search for a secret matched %q: what is left after scrubbing is all there is to find", probe.Lines)
	}
	for _, call := range f.node.calls {
		if strings.Contains(call.Line, "timeout") || strings.Contains(call.Line, "hunter2") {
			t.Errorf("the term reached the node: %s", call.Line)
		}
	}
	read := slices.IndexFunc(f.node.calls, func(c templates.Command) bool { return c.Template == "docker.logs" })
	if read < 0 || !strings.Contains(f.node.calls[read].Line, fmt.Sprintf("--tail '%d'", searchWindow+followOverlap)) {
		t.Errorf("window not bounded: %v", f.node.calls)
	}
}

func TestSearchTermsMustBeSingleLines(t *testing.T) {
	f := newAppsFixture(t)
	for _, term := range []string{"a\nb", "a\x1b[31m"} {
		_, err := f.inv.AppLogs(context.Background(), f.caller(f.alice), f.nodeID(), "shop", wire.AppLogQuery{Component: "web", Search: term})
		if smerr.CodeOf(err) != smerr.CodeInvalidArgument {
			t.Errorf("term %q: %v", term, err)
		}
	}
}

func TestScrubLinesKeepsLinesApartAndSaysWhereEachStarted(t *testing.T) {
	got := scrubLines([]string{"a", "b password=x", "c"})

	if len(got) != 3 || got[1].raw != 1 || got[1].text != "b password=[REDACTED]" || got[2].text != "c" {
		t.Errorf("lines = %+v", got)
	}
	collapsed := scrubLines([]string{"x -----BEGIN RSA PRIVATE KEY-----", "body", "-----END RSA PRIVATE KEY----- tail", "next"})
	if len(collapsed) != 2 || collapsed[0].raw != 0 || collapsed[1].raw != 3 || strings.Contains(collapsed[0].text, "body") {
		t.Errorf("collapsed = %+v", collapsed)
	}
}
