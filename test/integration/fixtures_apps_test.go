//go:build fixtures

package integration

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/discovery"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/runtimes/docker"
	"github.com/autarquico/supermgmt/internal/runtimes/systemd"
	"github.com/autarquico/supermgmt/test/fixtures/fixture"
)

const (
	shopProject   = "shop"
	shopWeb       = "shop-web-1"
	shopSecret    = "sm-fixture-s3cret-value"
	plainFixture  = "sm-plain"
	shopWebStdout = "/proc/1/fd/1"
)

// startShop brings the fixture's Compose project up (image imported from the rootfs baked into the node, no
// pull) and a plain container beside it.
func startShop(t *testing.T, n *fixtureNode) {
	t.Helper()
	n.shell(t, "systemctl start sm-shop-compose.service")
	n.shell(t, "docker run -d --name "+plainFixture+" sm-shop-base:local sleep infinity")
}

// crash kills the web component's process from outside, as a crash would: the restart policy, unlike for a
// `docker kill`, then restarts it and counts it.
func crash(t *testing.T, n *fixtureNode) {
	t.Helper()
	n.shell(t, "kill -9 $(docker inspect -f '{{.State.Pid}}' "+shopWeb+")")
}

// emit writes lines to the standard output of the web component, the way its process would.
func emit(t *testing.T, n *fixtureNode, lines ...string) {
	t.Helper()
	quoted := make([]string, len(lines))
	for i, l := range lines {
		quoted[i] = "'" + l + "'"
	}
	n.shell(t, fmt.Sprintf("docker exec %s sh -c \"printf '%%s\\n' %s > %s\"", shopWeb, strings.ReplaceAll(strings.Join(quoted, " "), `"`, `\"`), shopWebStdout))
}

func waitForStatus(t *testing.T, n *fixtureNode, container, format, want string) {
	t.Helper()
	waitUntil(t, func() bool {
		out, err := n.tryShell(t, "docker inspect -f '"+format+"' "+container)
		return err == nil && out == want
	})
}

func TestFixturesApps_TheDockerReadsParseAgainstARealComposeProject(t *testing.T) {
	p := provision(t, fixture.Options{}, func(p *systemd.SetupParams) { p.DockerAccess = true })
	startShop(t, p.fixtureNode)
	dk := docker.New()

	t.Run("discovery groups the containers under the Compose project label", func(t *testing.T) {
		d, err := dk.Discover(t.Context(), p.super, runtimes.Filter{})
		if err != nil {
			t.Fatalf("discover: %v", err)
		}
		projects := map[string]string{}
		for _, s := range d.Services {
			project, _ := s.Metadata["compose_project"].(string)
			projects[s.Name] = project
		}
		if projects[shopWeb] != shopProject || projects["shop-db-1"] != shopProject || projects[plainFixture] != "" {
			t.Errorf("compose_project by container = %v; want shop-web-1 and shop-db-1 in %s and %s in none", projects, shopProject, plainFixture)
		}
	})

	t.Run("inspect reports the volume, the port, the healthcheck, the restart policy and the raw environment", func(t *testing.T) {
		details := detailsOf(t, dk, p)
		web, db := details[shopWeb], details["shop-db-1"]
		if web.Project != shopProject || web.Health != "healthy" || web.RestartPolicy != "unless-stopped" || web.RestartCount != 0 {
			t.Errorf("web = %+v; want project %s, healthy, unless-stopped, no restart", web, shopProject)
		}
		if !slices.Contains(web.Ports, "127.0.0.1:18080->8080/tcp") && !slices.ContainsFunc(web.Ports, func(s string) bool { return strings.Contains(s, "18080") }) {
			t.Errorf("web ports = %v; want 18080 published", web.Ports)
		}
		if !slices.Contains(web.Env, "DB_PASSWORD="+shopSecret) {
			t.Errorf("web env = %v; the adapter returns the environment raw and the app layer redacts it", web.Env)
		}
		if !slices.ContainsFunc(db.Mounts, func(m runtimes.ContainerMount) bool {
			return m.Type == "volume" && m.Name == "shop_shop-data" && m.Destination == "/data" && m.ReadWrite
		}) {
			t.Errorf("db mounts = %+v; want the named volume shop_shop-data at /data", db.Mounts)
		}
		if db.Health != "" {
			t.Errorf("db health = %q; it has no healthcheck", db.Health)
		}
	})

	t.Run("docker stats --no-stream --format json parses into one sample per running container", func(t *testing.T) {
		stats, err := dk.Stats(t.Context(), p.super)
		if err != nil {
			t.Fatalf("stats: %v", err)
		}
		seen := map[string]runtimes.ContainerStats{}
		for _, s := range stats {
			seen[s.Name] = s
		}
		for _, name := range []string{shopWeb, "shop-db-1", plainFixture} {
			s, ok := seen[name]
			if !ok {
				t.Fatalf("stats lack %s: %+v", name, stats)
			}
			if s.ID == "" || s.MemUsedBytes == 0 || s.MemLimitBytes < s.MemUsedBytes || s.CPUPercent < 0 {
				t.Errorf("%s stats = %+v; want an id, memory in use below a limit and a non-negative cpu", name, s)
			}
		}
	})

	t.Run("the restart count is the number of restarts the policy performed", func(t *testing.T) {
		crash(t, p.fixtureNode)
		waitForStatus(t, p.fixtureNode, shopWeb, "{{.RestartCount}} {{.State.Status}}", "1 running")
		if got := detailsOf(t, dk, p)[shopWeb].RestartCount; got != 1 {
			t.Errorf("restart count = %d; want 1", got)
		}
	})
}

func detailsOf(t *testing.T, dk docker.Adapter, p *provisioned) map[string]runtimes.ContainerDetail {
	t.Helper()
	all, err := dk.Details(t.Context(), p.super)
	if err != nil {
		t.Fatalf("details: %v", err)
	}
	byName := map[string]runtimes.ContainerDetail{}
	for _, d := range all {
		byName[d.Name] = d
	}
	return byName
}

func TestFixturesApps_LogsSinceTheCursorFormatWorksAndItsBoundaryIsInclusive(t *testing.T) {
	p := provision(t, fixture.Options{}, func(p *systemd.SetupParams) { p.DockerAccess = true })
	startShop(t, p.fixtureNode)
	dk := docker.New()
	ref := containerRef(p, shopWeb)
	var burst []string
	for i := range 60 {
		burst = append(burst, fmt.Sprintf("burst-%02d", i))
	}
	emit(t, p.fixtureNode, burst...)
	chunk, err := dk.Logs(t.Context(), p.super, ref, runtimes.LogQuery{Lines: 100})
	if err != nil || len(chunk.Lines) < len(burst) {
		t.Fatalf("logs: %d lines, err %v", len(chunk.Lines), err)
	}

	t.Run("the epoch is a valid since and returns everything", func(t *testing.T) {
		got, err := dk.LogsSince(t.Context(), p.super, ref, time.Unix(0, 0).UTC(), 1000)
		if err != nil || len(got.Lines) != len(chunk.Lines) {
			t.Errorf("since the epoch: %d lines (err %v); want the %d of the whole log", len(got.Lines), err, len(chunk.Lines))
		}
	})

	t.Run("a nanosecond timestamp returns the line stamped exactly then and every later one", func(t *testing.T) {
		for _, k := range []int{0, 7, len(chunk.Lines) - 1} {
			at := stampOfLine(t, chunk.Lines[k])
			got, err := dk.LogsSince(t.Context(), p.super, ref, at, 1000)
			if err != nil {
				t.Fatalf("since %s: %v", at.Format(time.RFC3339Nano), err)
			}
			if len(got.Lines) == 0 || got.Lines[0] != chunk.Lines[k] {
				t.Fatalf("since the stamp of line %d: first line %q; want %q (the boundary is inclusive)", k, firstOrEmpty(got.Lines), chunk.Lines[k])
			}
			if want := chunk.Lines[k:]; !slices.Equal(got.Lines, want) {
				t.Errorf("since line %d: %d lines; want the %d from it to the end", k, len(got.Lines), len(want))
			}
		}
	})
}

func firstOrEmpty(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	return lines[0]
}

func stampOfLine(t *testing.T, line string) time.Time {
	t.Helper()
	token, _, _ := strings.Cut(line, " ")
	at, err := time.Parse(time.RFC3339Nano, token)
	if err != nil {
		t.Fatalf("log line %q has no timestamp prefix: %v", line, err)
	}
	return at.UTC()
}

// appsRig is a real node served through the real app services: the MCP rig's database, API server and MCP
// session, with its SSH boundary replaced by the fixture's connection pool and the node's capabilities and
// discovery recorded from what the node really reports.
type appsRig struct {
	*provisioned
	rig    *mcpRig
	nodeID domain.ID
	name   string
	inv    *app.Inventory
}

func newAppsRig(t *testing.T, dockerAccess bool) *appsRig {
	t.Helper()
	p := provision(t, fixture.Options{}, func(p *systemd.SetupParams) { p.DockerAccess = dockerAccess })
	if dockerAccess {
		startShop(t, p.fixtureNode)
		p.shell(t, "docker exec sm-plain true")
	}
	rig := newMCPRigGranting(t, false, "")
	rig.runtime.dialer = p.h.pool
	snap, err := discovery.Probe(t.Context(), p.super)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	snap.TakenAt, snap.Setup = rig.clock.Now(), &p.meta
	r := &appsRig{provisioned: p, rig: rig, name: "fixture-node"}
	rig.inTx(func(ctx context.Context, tx *database.Tx) error { return r.seed(ctx, tx, snap) })
	r.inv = rig.services.Inventory
	return r
}

// seed records the node, its capabilities and what discovery finds on it, the way a refresh does.
func (r *appsRig) seed(ctx context.Context, tx *database.Tx, snap discovery.Snapshot) error {
	rig, now := r.rig, r.rig.clock.Now()
	env := domain.ID(rig.fixtures["environment"])
	node, err := database.CreateNode(ctx, tx, domain.Node{
		ID: rig.ids.NewID(), ProviderID: domain.ID(rig.fixtures["provider"]), NativeID: r.name, Name: r.name, Kind: "ssh",
		EnvironmentID: &env, ManagementState: domain.ManagementManaged, Reachability: domain.ReachabilityUnknown,
		Endpoint:  domain.NodeEndpoint{Host: r.Host, Port: r.Port, User: dedicatedUser, AdminUser: fixture.AdminUser, HostPublicKey: r.hostKeyPin},
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		return err
	}
	r.nodeID = node.ID
	for _, c := range discovery.Capabilities(snap, false) {
		if err := database.SetNodeCapability(ctx, tx, node.ID, c); err != nil {
			return err
		}
	}
	if err := database.SetNodeCapability(ctx, tx, node.ID, database.NodeCapability{
		Capability: "node.setup", Available: true, CheckedAt: now, Metadata: setupMetadata(r.meta),
	}); err != nil {
		return err
	}
	return r.recordDiscovery(ctx, tx, node.ID)
}

func setupMetadata(m runtimes.SetupMeta) map[string]any {
	return map[string]any{
		"setup_version": m.SetupVersion, "systemctl_path": m.SystemctlPath, "units": []any{}, "logs_mode": string(m.LogsMode),
		"docker_access": m.DockerAccess, "key_ref": "secret://ssh/default", "key_version": 1, "key_fingerprint": "SHA256:fixture",
	}
}

func (r *appsRig) recordDiscovery(ctx context.Context, tx *database.Tx, node domain.ID) error {
	now := r.rig.clock.Now()
	adapters := []runtimes.Adapter{systemd.New()}
	if r.params.DockerAccess {
		adapters = append(adapters, docker.New())
	}
	for _, adapter := range adapters {
		d, err := adapter.Discover(ctx, r.super, runtimes.Filter{})
		if err != nil {
			return err
		}
		rt := domain.Runtime{ID: r.rig.ids.NewID(), NodeID: node, Type: string(d.Runtime.Type), NativeID: d.Runtime.NativeID, Version: d.Runtime.Version, Status: d.Runtime.Status, LastSeenAt: &now}
		if err := database.CreateRuntime(ctx, tx, rt); err != nil {
			return err
		}
		for _, s := range d.Services {
			if _, err := database.CreateService(ctx, tx, domain.Service{
				ID: r.rig.ids.NewID(), RuntimeID: rt.ID, NodeID: node, NativeID: s.NativeID, Name: s.Name, Kind: string(s.Kind),
				Status: s.Status, Health: s.Health, Metadata: s.Metadata, LastSeenAt: &now,
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *appsRig) admin() app.Caller { return r.rig.admin }

func (r *appsRig) mcpAPI() *client.Client {
	return client.New(client.Options{Transport: r.rig.server.InProcess(r.rig.mcp)})
}

func (r *appsRig) logs(t *testing.T, q wire.AppLogQuery) wire.AppLogs {
	t.Helper()
	out, err := r.inv.AppLogs(t.Context(), r.admin(), r.nodeID, shopProject, q)
	if err != nil {
		t.Fatalf("app logs %+v: %v", q, err)
	}
	return out
}

func (r *appsRig) component(t *testing.T, a wire.App, name string) wire.AppComponent {
	t.Helper()
	for _, c := range a.Components {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("app %s has no component %s: %+v", a.Project, name, a.Components)
	return wire.AppComponent{}
}

func TestFixturesApps_TheOverviewAndThePanelAreWhatTheNodeRuns(t *testing.T) {
	r := newAppsRig(t, true)

	t.Run("the node lists the app with two components and the rest as other services", func(t *testing.T) {
		got, err := r.inv.NodeApps(t.Context(), r.admin(), r.nodeID, wire.AppsQuery{Stats: true, Errors: true})
		if err != nil {
			t.Fatalf("node apps: %v", err)
		}
		if got.Problem != "" || len(got.Apps) != 1 || got.Apps[0].Project != shopProject || len(got.Apps[0].Components) != 2 {
			t.Fatalf("apps = %+v (problem %q); want the single app %s with two components", got.Apps, got.Problem, shopProject)
		}
		names := []string{r.component(t, got.Apps[0], "web").Name, r.component(t, got.Apps[0], "db").Name}
		if !slices.Equal(names, []string{"web", "db"}) {
			t.Errorf("components = %v; want the Compose service names", names)
		}
		var others []string
		for _, o := range got.OtherServices {
			others = append(others, o.Name)
		}
		if !slices.Contains(others, plainFixture) || !slices.Contains(others, demoUnit) || slices.Contains(others, shopWeb) {
			t.Errorf("other services = %v; want the plain container and the unit, not the app's containers", others)
		}
		if got.Apps[0].Stale || got.Apps[0].ReadAt.IsZero() {
			t.Errorf("app = stale %v at %v; want a live read with its time", got.Apps[0].Stale, got.Apps[0].ReadAt)
		}
	})

	t.Run("an app with a restarted component and an unhealthy one is degraded, with restarts and resource use", func(t *testing.T) {
		crash(t, r.fixtureNode)
		waitForStatus(t, r.fixtureNode, shopWeb, "{{.RestartCount}} {{.State.Status}} {{.State.Health.Status}}", "1 running healthy")
		r.shell(t, "docker exec "+shopWeb+" rm /tmp/ready")
		waitForStatus(t, r.fixtureNode, shopWeb, "{{.State.Health.Status}}", "unhealthy")

		got, err := r.inv.GetApp(t.Context(), r.admin(), r.nodeID, shopProject, wire.AppsQuery{Stats: true, Errors: true})
		if err != nil {
			t.Fatalf("get app: %v", err)
		}
		if got.State != wire.AppDegraded {
			t.Errorf("state = %q; want %q", got.State, wire.AppDegraded)
		}
		if got.RestartCount == nil || *got.RestartCount != 1 {
			t.Errorf("app restart count = %v; want 1", got.RestartCount)
		}
		if web := r.component(t, got, "web"); web.Health != "unhealthy" || web.RestartCount == nil || *web.RestartCount != 1 {
			t.Errorf("web = health %q restarts %v; want unhealthy and 1", web.Health, web.RestartCount)
		}
		if got.Stats == nil || got.Stats.MemUsedBytes == 0 || got.StatsAt == nil {
			t.Errorf("stats = %+v at %v; want current memory and the time of the sample", got.Stats, got.StatsAt)
		}
	})

	t.Run("the panel shows image, volumes, published ports and the configuration with the secret masked", func(t *testing.T) {
		got, err := r.inv.GetApp(t.Context(), r.admin(), r.nodeID, shopProject, wire.AppsQuery{})
		if err != nil {
			t.Fatalf("get app: %v", err)
		}
		web, db := r.component(t, got, "web"), r.component(t, got, "db")
		if web.Image != "sm-shop-base:local" || !slices.ContainsFunc(web.Ports, func(s string) bool { return strings.Contains(s, "18080") }) {
			t.Errorf("web = image %q ports %v; want the local image and port 18080", web.Image, web.Ports)
		}
		if !slices.ContainsFunc(db.Mounts, func(m wire.AppMount) bool { return m.Name == "shop_shop-data" && m.Destination == "/data" }) {
			t.Errorf("db mounts = %+v; want the named volume", db.Mounts)
		}
		if web.Config == nil {
			t.Fatal("web has no configuration")
		}
		env := strings.Join(web.Config.Env, "\n")
		if strings.Contains(env, shopSecret) || !strings.Contains(env, "DB_PASSWORD=") || !strings.Contains(env, "APP_MODE=production") {
			t.Errorf("web env = %q; want DB_PASSWORD present with its value masked and APP_MODE kept", env)
		}
	})

	t.Run("the API and MCP serve the secret masked too", func(t *testing.T) {
		viaAPI, err := r.mcpAPI().GetNodeApp(t.Context(), r.nodeID, shopProject, wire.AppsQuery{})
		if err != nil {
			t.Fatalf("api get app: %v", err)
		}
		if strings.Contains(fmt.Sprintf("%+v", viaAPI), shopSecret) {
			t.Errorf("the API served the environment secret: %+v", viaAPI)
		}
		out, fail := mcpSecCall(t, mcpSecRigSession(t, r.rig, false), "infra_get_app", map[string]any{"node": r.name, "project": shopProject})
		if fail != nil {
			t.Fatalf("infra_get_app: %+v", fail)
		}
		if raw := fmt.Sprint(out); strings.Contains(raw, shopSecret) || !strings.Contains(raw, "untrusted_remote_output") || !strings.Contains(raw, "web") {
			t.Errorf("infra_get_app = %s; want the app, untrusted marking and no secret", raw)
		}
	})
}

func TestFixturesApps_FollowKeepsEveryLineOnceAndNoSecretAcrossPolls(t *testing.T) {
	r := newAppsRig(t, true)
	const (
		keyBody1 = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC"
		keyBody2 = "KcwggSjAgEAAoIBAQDfixturefixturefix"
		password = "hunter2-fixture"
	)
	wait := func(lines int) {
		waitUntil(t, func() bool {
			c, err := docker.New().Logs(t.Context(), r.super, containerRef(r.provisioned, shopWeb), runtimes.LogQuery{Lines: 400})
			return err == nil && len(c.Lines) >= lines
		})
	}
	first := r.logs(t, wire.AppLogQuery{Component: "web", Lines: 50})
	seen := slices.Clone(first.Lines)
	cursor := first.Cursor
	poll := func() wire.AppLogs {
		got := r.logs(t, wire.AppLogQuery{Component: "web", Cursor: cursor, Lines: 500})
		seen, cursor = append(seen, got.Lines...), got.Cursor
		if got.Gap {
			t.Errorf("a follow poll reported a gap although nothing was lost: %+v", got)
		}
		return got
	}

	var burst []string
	for i := range 120 {
		burst = append(burst, fmt.Sprintf("burst-%03d", i))
	}
	emit(t, r.fixtureNode, burst[:40]...)
	wait(len(first.Lines) + 40)
	poll()
	emit(t, r.fixtureNode, append(append([]string{"login ok password=" + password}, burst[40:80]...), "-----BEGIN RSA PRIVATE KEY-----", keyBody1)...)
	wait(len(first.Lines) + 83)
	poll()
	emit(t, r.fixtureNode, append([]string{keyBody2, "-----END RSA PRIVATE KEY-----", "after the key"}, burst[80:]...)...)
	wait(len(first.Lines) + 126)
	poll()
	if again := poll(); len(again.Lines) != 0 {
		t.Errorf("a poll with nothing new returned %q; want no lines", again.Lines)
	}

	t.Run("no line is lost and none is delivered twice across polls", func(t *testing.T) {
		var got []string
		for _, l := range seen {
			if _, text, _ := strings.Cut(l, " "); strings.HasPrefix(text, "burst-") {
				got = append(got, text)
			}
		}
		if !slices.Equal(got, burst) {
			t.Errorf("followed burst lines = %d, want %d in order; got %q", len(got), len(burst), got)
		}
	})

	t.Run("the key=value secret and the PEM block split across polls never reach the reader", func(t *testing.T) {
		all := strings.Join(seen, "\n")
		for _, secret := range []string{password, keyBody1, keyBody2} {
			if strings.Contains(all, secret) {
				t.Errorf("follow delivered %q:\n%s", secret, all)
			}
		}
		if strings.Count(all, "after the key") != 1 {
			t.Errorf("the line after the key appears %d times; want once", strings.Count(all, "after the key"))
		}
	})

	t.Run("search redacts the same values and states its window", func(t *testing.T) {
		for _, term := range []string{"login", "hunter2", "MIIEvQ"} {
			got := r.logs(t, wire.AppLogQuery{Component: "web", Search: term})
			if strings.Contains(strings.Join(got.Lines, "\n"), password) || strings.Contains(strings.Join(got.Lines, "\n"), keyBody1) {
				t.Errorf("search %q returned a secret: %q", term, got.Lines)
			}
			if got.Window == nil || got.Window.Lines == 0 {
				t.Errorf("search %q window = %+v; want the lines it covered", term, got.Window)
			}
			if term != "login" && len(got.Lines) != 0 {
				t.Errorf("search %q found %q; a secret cannot be probed for through what matches", term, got.Lines)
			}
		}
		if got := r.logs(t, wire.AppLogQuery{Component: "web", Search: "login"}); len(got.Lines) != 1 || !strings.Contains(got.Lines[0], "password=") {
			t.Errorf("search login = %q; want the one line with its value redacted", got.Lines)
		}
	})

	t.Run("the MCP search tool redacts them and marks the lines untrusted", func(t *testing.T) {
		session := mcpSecRigSession(t, r.rig, false)
		for _, term := range []string{"login", "BEGIN RSA"} {
			out, fail := mcpSecCall(t, session, "infra_search_app_logs", map[string]any{"node": r.name, "project": shopProject, "component": "web", "term": term})
			if fail != nil {
				t.Fatalf("infra_search_app_logs %q: %+v", term, fail)
			}
			raw := fmt.Sprint(out)
			for _, secret := range []string{password, keyBody1, keyBody2} {
				if strings.Contains(raw, secret) {
					t.Errorf("MCP search %q returned %q: %s", term, secret, raw)
				}
			}
			if !strings.Contains(raw, "untrusted_remote_output") {
				t.Errorf("MCP search %q lacks the untrusted marking: %s", term, raw)
			}
		}
	})
}

func TestFixturesApps_NothingIsStoredByReadingStats(t *testing.T) {
	r := newAppsRig(t, true)
	before := tableRowCounts(t, r.rig)
	session := mcpSecRigSession(t, r.rig, false)

	for range 3 {
		if _, err := r.inv.AppStats(t.Context(), r.admin(), r.nodeID, shopProject); err != nil {
			t.Fatalf("app stats: %v", err)
		}
		if _, err := r.inv.NodeApps(t.Context(), r.admin(), r.nodeID, wire.AppsQuery{Stats: true, Errors: true}); err != nil {
			t.Fatalf("node apps: %v", err)
		}
		if _, fail := mcpSecCall(t, session, "infra_get_app_stats", map[string]any{"node": r.name, "project": shopProject}); fail != nil {
			t.Fatalf("infra_get_app_stats: %+v", fail)
		}
	}

	after := tableRowCounts(t, r.rig)
	for table, n := range before {
		if after[table] != n {
			t.Errorf("table %s went from %d to %d rows by reading stats; want nothing written", table, n, after[table])
		}
	}
}

func TestFixturesApps_ANodeWithoutDockerAccessSaysSoAndNamesTheCommand(t *testing.T) {
	r := newAppsRig(t, false)
	before := tableRowCounts(t, r.rig)
	containers := r.shell(t, "docker ps -aq")

	got, err := r.inv.NodeApps(t.Context(), r.admin(), r.nodeID, wire.AppsQuery{Stats: true})
	if err != nil {
		t.Fatalf("node apps: %v", err)
	}

	if got.Problem != wire.AppsProblemDocker || got.Hint != "sm nodes setup "+r.name+" --docker-access" {
		t.Errorf("problem %q hint %q; want %s and the exact command", got.Problem, got.Hint, wire.AppsProblemDocker)
	}
	if after := tableRowCounts(t, r.rig); !maps.Equal(after, before) || r.shell(t, "docker ps -aq") != containers {
		t.Errorf("reading the apps changed the database (%v -> %v) or the node's containers", before, after)
	}
	if out, err := r.tryShell(t, "id -nG "+dedicatedUser); err != nil || strings.Contains(out, "docker") {
		t.Errorf("the dedicated user groups = %q (err %v); reading must not grant docker access", out, err)
	}
}

func TestFixturesApps_ANodeThatStopsAnsweringIsShownFromTheLastDiscoveryAsStale(t *testing.T) {
	r := newAppsRig(t, true)
	if err := r.Pause(t.Context()); err != nil {
		t.Fatalf("pause node: %v", err)
	}
	t.Cleanup(func() { _ = r.Unpause(context.WithoutCancel(t.Context())) })
	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Second)
	defer cancel()

	got, err := r.inv.NodeApps(ctx, r.admin(), r.nodeID, wire.AppsQuery{Stats: true})
	if err != nil {
		t.Fatalf("node apps: %v", err)
	}
	if got.Problem != wire.AppsProblemUnreachable || len(got.Apps) != 1 || !got.Apps[0].Stale || got.Apps[0].ReadAt.IsZero() {
		t.Errorf("answer = problem %q apps %+v; want %s with the last discovery marked stale and its time", got.Problem, got.Apps, wire.AppsProblemUnreachable)
	}
	if _, err := r.inv.AppLogs(ctx, r.admin(), r.nodeID, shopProject, wire.AppLogQuery{Component: "web"}); err == nil {
		t.Error("a live log read of an unreachable node succeeded")
	}
}

// tableRowCounts is the number of rows of every table: a write of any statistic or sample shows as a difference.
func tableRowCounts(t *testing.T, rig *mcpRig) map[string]int {
	t.Helper()
	rows, err := rig.db.Reader().QueryContext(t.Context(), `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`)
	mcpRigMust(t, err)
	var tables []string
	for rows.Next() {
		var name string
		mcpRigMust(t, rows.Scan(&name))
		tables = append(tables, name)
	}
	mcpRigMust(t, rows.Err())
	mcpRigMust(t, rows.Close())
	counts := map[string]int{}
	for _, table := range tables {
		var n int
		mcpRigMust(t, rig.db.Reader().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM "`+table+`"`).Scan(&n))
		counts[table] = n
	}
	return counts
}
