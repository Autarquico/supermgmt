package tui

import (
	"context"
	"slices"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

const (
	idShopWeb domain.ID = "0192a000-0000-7000-8000-00000000f001"
	idShopDB  domain.ID = "0192a000-0000-7000-8000-00000000f002"
	idPlain   domain.ID = "0192a000-0000-7000-8000-00000000f003"

	cursorOne = "cursor-1"
	cursorTwo = "cursor-2"
)

func intp(n int) *int { return &n }

// appsFake is the API with the live app reads, over fixture data a test may change.
type appsFake struct {
	*fakeAPI
	nodes  []wire.NodeApps
	app    wire.App
	stats  wire.AppStats
	recent wire.AppLogs
	polls  []wire.AppLogs // answers to the next cursor reads, in order
	search wire.AppLogs

	logQueries []wire.AppLogQuery
	listed     []wire.AppsQuery
}

func newAppsFake() *appsFake {
	base := newFake()
	base.services[idWeb] = append(base.services[idWeb],
		wire.Service{
			ID: idShopWeb, NodeID: idWeb, Node: "web-1", RuntimeType: domain.RuntimeDocker, Kind: domain.ServiceDockerContainer, NativeID: "shop-web-1", Name: "shop-web-1",
			Status: "running", Health: "healthy", Actions: []domain.ServiceVerb{domain.VerbRestart, domain.VerbStart, domain.VerbStop},
		},
		wire.Service{
			ID: idShopDB, NodeID: idWeb, Node: "web-1", RuntimeType: domain.RuntimeDocker, Kind: domain.ServiceDockerContainer, NativeID: "shop-db-1", Name: "shop-db-1",
			Status: "running", Health: "unhealthy",
		})
	read := epoch.Add(3 * time.Second)
	web := wire.AppComponent{
		Name: "web", ServiceID: idShopWeb, Image: "nginx:1.27", Status: "running", Health: "healthy", StartedAt: "2026-10-10T08:00:00Z",
		RestartCount: intp(3), RecentErrors: intp(5), Stats: &wire.ResourceUse{CPUPercent: 4, MemUsedBytes: 100 << 20, MemLimitBytes: 512 << 20},
		Ports:  []string{"0.0.0.0:8080->80/tcp"},
		Mounts: []wire.AppMount{{Type: "volume", Name: "shop_assets", Source: "/var/lib/docker/volumes/shop_assets/_data", Destination: "/srv/assets", ReadWrite: true}},
		Config: &wire.AppConfig{RestartPolicy: "unless-stopped", Env: []string{"MODE=prod", "API_TOKEN=[REDACTED]"}, Command: []string{"nginx", "-g", "daemon off;"}, Labels: map[string]string{"com.docker.compose.project": "shop"}},
	}
	db := wire.AppComponent{
		Name: "db", ServiceID: idShopDB, Image: "postgres:16", Status: "running", Health: "unhealthy", RestartCount: intp(0), RecentErrors: intp(0),
		Stats:  &wire.ResourceUse{CPUPercent: 8, MemUsedBytes: 310 << 20, MemLimitBytes: 1536 << 20},
		Mounts: []wire.AppMount{{Type: "volume", Name: "shop_pgdata", Destination: "/var/lib/postgresql/data", ReadWrite: true}},
		Config: &wire.AppConfig{RestartPolicy: "always", Env: []string{"POSTGRES_PASSWORD=[REDACTED]"}},
	}
	shop := wire.App{
		Project: "shop", NodeID: idWeb, Node: "web-1", State: wire.AppDegraded, RestartCount: intp(3), RecentErrors: intp(5),
		Stats: &wire.ResourceUse{CPUPercent: 12, MemUsedBytes: 410 << 20, MemLimitBytes: 2 << 30}, StatsAt: &read, ReadAt: read,
		Components: []wire.AppComponent{web, db},
	}
	blog := wire.App{
		Project: "blog", NodeID: idWeb, Node: "web-1", State: wire.AppRunning, RestartCount: intp(0), RecentErrors: intp(0),
		Stats: &wire.ResourceUse{CPUPercent: 1, MemUsedBytes: 64 << 20, MemLimitBytes: 1 << 30}, StatsAt: &read, ReadAt: read,
		Components: []wire.AppComponent{{Name: "ghost", Image: "ghost:5", Status: "running", Health: "healthy"}},
	}
	f := &appsFake{fakeAPI: base, app: shop}
	f.nodes = []wire.NodeApps{{
		NodeID: idWeb, Node: "web-1", Apps: []wire.App{shop, blog},
		OtherServices: []wire.OtherService{
			{ServiceID: idPlain, Name: "redis", Kind: "docker_container", Status: "running", Health: "healthy"},
			{ServiceID: idAPI, Name: "sm-demo.service", Kind: "systemd_unit", Status: "active", Health: "healthy"},
		},
	}}
	f.stats = wire.AppStats{
		Project: "shop", NodeID: idWeb, SampledAt: read, Total: wire.ResourceUse{CPUPercent: 12, MemUsedBytes: 410 << 20, MemLimitBytes: 2 << 30},
		Components: []wire.ComponentUse{{Name: "web", Use: *web.Stats}, {Name: "db", Use: *db.Stats}},
	}
	f.recent = wire.AppLogs{
		Project: "shop", Component: "web", Cursor: cursorOne, CollectedAt: read,
		Lines: []string{"2026-10-10T12:00:01Z listening on :80", "2026-10-10T12:00:02Z upstream timeout talking to db", "2026-10-10T12:00:03Z served /"},
	}
	f.search = wire.AppLogs{
		Project: "shop", Component: "web", CollectedAt: read,
		Lines:  []string{"2026-10-10T12:00:02Z upstream timeout talking to db"},
		Window: &wire.LogWindow{Lines: 2000, From: ptr(epoch.Add(-time.Hour)), To: ptr(read)},
	}
	return f
}

func ptr[T any](v T) *T { return &v }

func (f *appsFake) ListApps(ctx context.Context, q wire.AppsQuery) (wire.Page[wire.NodeApps], error) {
	err := f.enter(ctx, "ListApps")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listed = append(f.listed, q)
	return wire.Page[wire.NodeApps]{Items: slices.Clone(f.nodes)}, err
}

func (f *appsFake) GetNodeApp(ctx context.Context, _ domain.ID, project string, _ wire.AppsQuery) (wire.App, error) {
	err := f.enter(ctx, "GetNodeApp")
	f.mu.Lock()
	defer f.mu.Unlock()
	app := f.app
	app.Project = project
	return app, err
}

func (f *appsFake) NodeAppStats(ctx context.Context, _ domain.ID, _ string) (wire.AppStats, error) {
	err := f.enter(ctx, "NodeAppStats")
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stats, err
}

func (f *appsFake) NodeAppLogs(ctx context.Context, _ domain.ID, _ string, q wire.AppLogQuery) (wire.AppLogs, error) {
	err := f.enter(ctx, "NodeAppLogs")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logQueries = append(f.logQueries, q)
	switch {
	case q.Search != "":
		return f.search, err
	case q.Cursor == "":
		return f.recent, err
	case len(f.polls) > 0:
		next := f.polls[0]
		f.polls = f.polls[1:]
		return next, err
	}
	return wire.AppLogs{Cursor: q.Cursor, CollectedAt: epoch}, err
}

func (f *appsFake) lastLogQuery() wire.AppLogQuery {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.logQueries[len(f.logQueries)-1]
}
