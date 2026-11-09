package app

import (
	"context"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/policy"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/runtimes/docker"
	"github.com/autarquico/supermgmt/internal/transport"
)

// Apps are the Compose projects of a node (spec app-panels, ADR-0043): a projection of the services rows,
// grouped by project, read live from the node when it answers and shown from the last discovery, stale,
// when it does not. They have no table and keep no statistic.

const (
	actionServiceRead = "service.read"
	actionServiceLogs = "service.logs"

	capabilityDockerRead = "docker.read"
	composeServiceLabel  = "com.docker.compose.service"
	composeProjectKey    = "compose_project"

	// appsParallel bounds the nodes, and the containers of a node, read at once.
	appsParallel = 4
)

// projectName is the Compose project name rule; anything else never reaches a query or a node.
var projectName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,127}$`)

func validProject(project string) error {
	if !projectName.MatchString(project) {
		return smerr.New(smerr.CodeInvalidArgument, "", "project must be a Compose project name: lowercase letters, digits, - and _")
	}
	return nil
}

// dockerAccessHint is the command a person runs to let SuperMgmt reach Docker on the node.
func dockerAccessHint(node domain.Node) string {
	return "sm nodes setup " + node.Name + " --docker-access"
}

func dockerUnavailable(node domain.Node) error {
	return smerr.New(smerr.CodeCapabilityUnavailable, "",
		"apps cannot be read: Docker is not accessible to the node's SuperMgmt user; a person can allow it with: "+dockerAccessHint(node))
}

// appRead is what one read of a node returns, besides the services rows.
type appRead struct {
	stats   bool
	errors  bool
	config  bool
	project string // only this app, when set
}

// NodeApps returns the apps of a node and its other services. Errors counts need service.logs on the node and
// are absent without it.
func (i *Inventory) NodeApps(ctx context.Context, by Caller, id domain.ID, q wire.AppsQuery) (wire.NodeApps, error) {
	actor, node, err := i.appNode(ctx, by, actionServiceRead, id)
	if err != nil {
		return wire.NodeApps{}, err
	}
	return i.readNodeApps(ctx, node, appRead{stats: q.Stats, errors: q.Errors && i.mayOnNode(ctx, actor, actionServiceLogs, id)})
}

// Apps returns the apps of every node the caller may read service on; the others are left out.
func (i *Inventory) Apps(ctx context.Context, by Caller, q wire.AppsQuery) (wire.Page[wire.NodeApps], error) {
	db := i.cfg.DB.Reader()
	actor, err := i.beginRequest(ctx, db, by)
	if err != nil {
		return wire.Page[wire.NodeApps]{}, err
	}
	all, err := database.ListNodes(ctx, db)
	if err != nil {
		return wire.Page[wire.NodeApps]{}, err
	}
	nodes := slices.DeleteFunc(all, func(n domain.Node) bool {
		return n.ManagementState == domain.ManagementRetired || !i.mayOnNode(ctx, actor, actionServiceRead, n.ID)
	})
	items := make([]wire.NodeApps, len(nodes))
	failures := make([]error, len(nodes))
	parallel(len(nodes), func(k int) {
		read := appRead{stats: q.Stats, errors: q.Errors && i.mayOnNode(ctx, actor, actionServiceLogs, nodes[k].ID)}
		items[k], failures[k] = i.readNodeApps(ctx, nodes[k], read)
	})
	for _, err := range failures {
		if err != nil {
			return wire.Page[wire.NodeApps]{}, err
		}
	}
	return wire.Page[wire.NodeApps]{Items: items}, nil
}

// GetApp returns one app with the configuration its containers report, redacted.
func (i *Inventory) GetApp(ctx context.Context, by Caller, id domain.ID, project string, q wire.AppsQuery) (wire.App, error) {
	if err := validProject(project); err != nil {
		return wire.App{}, err
	}
	actor, node, err := i.appNode(ctx, by, actionServiceRead, id)
	if err != nil {
		return wire.App{}, err
	}
	read := appRead{stats: q.Stats, errors: q.Errors && i.mayOnNode(ctx, actor, actionServiceLogs, id), config: true, project: project}
	apps, err := i.readNodeApps(ctx, node, read)
	if err != nil {
		return wire.App{}, err
	}
	for _, app := range apps.Apps {
		if app.Project == project {
			return app, nil
		}
	}
	return wire.App{}, smerr.New(smerr.CodeNotFound, "", fmt.Sprintf("app %s not found on node %s", project, node.Name))
}

// AppStats takes one sample of the app's containers. Samples of a node are shared between callers that ask
// together; none is kept.
func (i *Inventory) AppStats(ctx context.Context, by Caller, id domain.ID, project string) (wire.AppStats, error) {
	if err := validProject(project); err != nil {
		return wire.AppStats{}, err
	}
	_, node, err := i.appNode(ctx, by, actionServiceRead, id)
	if err != nil {
		return wire.AppStats{}, err
	}
	rows, err := i.projectRows(ctx, node.ID, project)
	if err != nil {
		return wire.AppStats{}, err
	}
	ex, err := i.dockerExecutor(ctx, node)
	if err != nil {
		return wire.AppStats{}, err
	}
	stats, at, err := i.sampleStats(ctx, node.ID, ex)
	if err != nil {
		return wire.AppStats{}, err
	}
	out := wire.AppStats{Project: project, NodeID: node.ID, SampledAt: at, Components: []wire.ComponentUse{}}
	var total wire.ResourceUse
	for _, row := range rows {
		if use, ok := useOf(stats, row.NativeID); ok {
			out.Components = append(out.Components, wire.ComponentUse{Name: componentOf(row), Use: use})
			total = addUse(total, use)
		}
	}
	out.Total = total
	return out, nil
}

// AppLogs reads the logs of one component of an app, credentials removed whatever the instance is
// configured to do with command output. With a cursor it returns what came after it; with a search it looks
// in a bounded window of recent lines.
func (i *Inventory) AppLogs(ctx context.Context, by Caller, id domain.ID, project string, q wire.AppLogQuery) (wire.AppLogs, error) {
	if err := validProject(project); err != nil {
		return wire.AppLogs{}, err
	}
	lines := q.Lines
	if lines == 0 {
		lines = wire.DefaultLogLines
	}
	if lines < 1 || lines > wire.MaxAppLogLines {
		return wire.AppLogs{}, smerr.New(smerr.CodeInvalidArgument, "", fmt.Sprintf("lines must be in 1..%d", wire.MaxAppLogLines))
	}
	if q.Component == "" {
		return wire.AppLogs{}, smerr.New(smerr.CodeInvalidArgument, "", "component is required")
	}
	_, node, err := i.appNode(ctx, by, actionServiceLogs, id)
	if err != nil {
		return wire.AppLogs{}, err
	}
	rows, err := i.projectRows(ctx, node.ID, project)
	if err != nil {
		return wire.AppLogs{}, err
	}
	row, ok := findComponent(rows, q.Component)
	if !ok {
		return wire.AppLogs{}, smerr.New(smerr.CodeNotFound, "", fmt.Sprintf("app %s has no component %q", project, q.Component))
	}
	ex, err := i.dockerExecutor(ctx, node)
	if err != nil {
		return wire.AppLogs{}, err
	}
	reader := appLogReader{ctx: ctx, ex: ex, ref: serviceRef(row), project: project, component: q.Component, collected: i.cfg.Clock.Now()}
	switch {
	case q.Search != "":
		return reader.search(q.Search)
	case q.Cursor != "":
		return reader.follow(q.Cursor, lines)
	}
	return reader.recent(lines)
}

// appLogReader reads one container's logs; the methods of apps_logs.go decide what to return of them.
type appLogReader struct {
	ctx       context.Context
	ex        transport.Executor
	ref       runtimes.ServiceRef
	project   string
	component string
	collected time.Time
}

func (a appLogReader) tail(lines int) (runtimes.LogChunk, error) {
	return docker.New().Logs(a.ctx, a.ex, a.ref, runtimes.LogQuery{Lines: lines})
}

func (a appLogReader) since(t time.Time, lines int) (runtimes.LogChunk, error) {
	return docker.New().LogsSince(a.ctx, a.ex, a.ref, t, lines)
}

func (a appLogReader) result(lines []string) wire.AppLogs {
	return wire.AppLogs{Project: a.project, Component: a.component, Lines: nonNil(lines), CollectedAt: a.collected}
}

// ---- authorization ----------------------------------------------------------------

// appNode authorizes action on the node, auditing a refusal, and loads it.
func (i *Inventory) appNode(ctx context.Context, by Caller, action string, id domain.ID) (domain.Actor, domain.Node, error) {
	actor, err := i.authorizeOn(ctx, by, action, domain.ResourceRef{Type: domain.ResourceNode, ID: id})
	if err != nil {
		return domain.Actor{}, domain.Node{}, err
	}
	node, err := database.GetNode(ctx, i.cfg.DB.Reader(), id)
	return actor, node, err
}

// mayOnNode evaluates action on the node without auditing a refusal: it decides what to leave out, not
// whether to answer.
func (i *Inventory) mayOnNode(ctx context.Context, actor domain.Actor, action string, id domain.ID) bool {
	target, err := resolveNode(ctx, i.cfg.DB.Reader(), id)
	if err != nil {
		return false
	}
	return i.authorize(policy.Request{Actor: actor, Action: action, Targets: []policy.Target{target.target}}).Decision == policy.DecisionAllow
}

// ---- reading a node ---------------------------------------------------------------

func (i *Inventory) readNodeApps(ctx context.Context, node domain.Node, read appRead) (wire.NodeApps, error) {
	db := i.cfg.DB.Reader()
	rows, err := database.ListServices(ctx, db, node.ID)
	if err != nil {
		return wire.NodeApps{}, err
	}
	projects, others := groupServices(rows)
	out := wire.NodeApps{NodeID: node.ID, Node: node.Name, OtherServices: others}
	live, problem, err := i.liveApps(ctx, node, rows, read)
	if err != nil {
		return wire.NodeApps{}, err
	}
	if problem == "" {
		out.Apps = live
		return out, nil
	}
	out.Problem = problem
	if problem == wire.AppsProblemDocker {
		out.Hint = dockerAccessHint(node)
	}
	out.Apps = discoveredApps(node, projects, read.project)
	return out, nil
}

// liveApps reads the node's containers. A problem names why it could not and the caller falls back to the
// last discovery; an error is a failure of the control plane itself.
func (i *Inventory) liveApps(ctx context.Context, node domain.Node, rows []domain.Service, read appRead) (apps []wire.App, problem string, err error) {
	if !i.dockerReadable(ctx, node.ID) {
		return nil, wire.AppsProblemDocker, nil
	}
	ex, err := i.dockerExecutor(ctx, node)
	if err != nil {
		return nil, wire.AppsProblemUnreachable, nil //nolint:nilerr // an executor that cannot be built is a node that cannot be reached
	}
	details, err := docker.New().Details(ctx, ex)
	if err != nil {
		if smerr.CodeOf(err) == smerr.CodeCapabilityUnavailable {
			return nil, wire.AppsProblemDocker, nil
		}
		return nil, wire.AppsProblemUnreachable, nil //nolint:nilerr // the live read failing is the stale fallback, not a failure
	}
	readAt := i.cfg.Clock.Now()
	byProject := map[string][]runtimes.ContainerDetail{}
	for _, d := range details {
		if projectName.MatchString(d.Project) && (read.project == "" || read.project == d.Project) {
			byProject[d.Project] = append(byProject[d.Project], d)
		}
	}
	var stats []runtimes.ContainerStats
	var sampledAt time.Time
	if read.stats && len(byProject) > 0 {
		// Stats unavailable (an old Docker) leaves the figures out; it does not fail the listing.
		if s, at, err := i.sampleStats(ctx, node.ID, ex); err == nil {
			stats, sampledAt = s, at
		}
	}
	for _, project := range slices.Sorted(maps.Keys(byProject)) {
		apps = append(apps, liveApp(node, project, byProject[project], rows, appSample{stats, sampledAt}, readAt, read.config))
	}
	if read.errors {
		i.countErrors(ctx, ex, node, apps, byProject)
	}
	return apps, "", nil
}

func (i *Inventory) dockerReadable(ctx context.Context, node domain.ID) bool {
	c, err := database.GetNodeCapability(ctx, i.cfg.DB.Reader(), node, capabilityDockerRead)
	return err == nil && c.Available
}

// dockerExecutor is the executor of the node, or the reason a read of its Docker cannot start.
func (i *Inventory) dockerExecutor(ctx context.Context, node domain.Node) (transport.Executor, error) {
	if !i.dockerReadable(ctx, node.ID) {
		return nil, dockerUnavailable(node)
	}
	setup, err := loadSetup(ctx, i.cfg.DB.Reader(), node.ID)
	if err != nil {
		return nil, err
	}
	return i.conn.Automated(node, setup)
}

func (i *Inventory) sampleStats(ctx context.Context, node domain.ID, ex transport.Executor) ([]runtimes.ContainerStats, time.Time, error) {
	return i.statsFlights.sample(ctx, node, i.cfg.Clock, func(ctx context.Context) ([]runtimes.ContainerStats, error) {
		return docker.New().Stats(ctx, ex)
	})
}

// countErrors fills the recent error count of each component of apps, one log read per container, a few at a
// time. A container whose log cannot be read keeps no count.
func (i *Inventory) countErrors(ctx context.Context, ex transport.Executor, node domain.Node, apps []wire.App, byProject map[string][]runtimes.ContainerDetail) {
	type target struct {
		app, component int
		ref            runtimes.ServiceRef
	}
	var targets []target
	for a, app := range apps {
		for c, comp := range app.Components {
			if ref, ok := containerRef(node.ID, byProject[app.Project], comp.Name); ok {
				targets = append(targets, target{a, c, ref})
			}
		}
	}
	counts := make([]*int, len(targets))
	parallel(len(targets), func(k int) {
		chunk, err := docker.New().Logs(ctx, ex, targets[k].ref, runtimes.LogQuery{Lines: errorWindow})
		if err == nil {
			n := recentErrors(chunk.Lines)
			counts[k] = &n
		}
	})
	for k, t := range targets {
		if counts[k] == nil {
			continue
		}
		apps[t.app].Components[t.component].RecentErrors = counts[k]
		sum := *counts[k]
		if apps[t.app].RecentErrors != nil {
			sum += *apps[t.app].RecentErrors
		}
		apps[t.app].RecentErrors = &sum
	}
}

func containerRef(node domain.ID, details []runtimes.ContainerDetail, component string) (runtimes.ServiceRef, bool) {
	for _, d := range details {
		if detailComponent(d) == component {
			return runtimes.ServiceRef{NodeID: node, Kind: domain.ServiceDockerContainer, NativeID: d.ID, Name: d.Name}, true
		}
	}
	return runtimes.ServiceRef{}, false
}

// parallel runs fn for 0..n-1, at most appsParallel at a time, and waits for all.
func parallel(n int, fn func(int)) {
	var wg sync.WaitGroup
	slots := make(chan struct{}, appsParallel)
	for k := range n {
		wg.Add(1)
		slots <- struct{}{}
		go func() {
			defer func() { <-slots; wg.Done() }()
			fn(k)
		}()
	}
	wg.Wait()
}

// ---- building apps ----------------------------------------------------------------

// projectRows are the discovered containers of one project; NOT_FOUND when there are none.
func (i *Inventory) projectRows(ctx context.Context, node domain.ID, project string) ([]domain.Service, error) {
	rows, err := database.ListServices(ctx, i.cfg.DB.Reader(), node)
	if err != nil {
		return nil, err
	}
	projects, _ := groupServices(rows)
	if len(projects[project]) == 0 {
		return nil, smerr.New(smerr.CodeNotFound, "", "app "+project+" not found")
	}
	return projects[project], nil
}

// groupServices splits the services of a node into the containers of each Compose project and the rest.
func groupServices(rows []domain.Service) (map[string][]domain.Service, []wire.OtherService) {
	projects := map[string][]domain.Service{}
	others := []wire.OtherService{}
	for _, s := range rows {
		project, _ := s.Metadata[composeProjectKey].(string)
		if s.Kind == string(domain.ServiceDockerContainer) && projectName.MatchString(project) {
			projects[project] = append(projects[project], s)
			continue
		}
		others = append(others, wire.OtherService{ServiceID: s.ID, Name: s.Name, Kind: s.Kind, Status: s.Status, Health: s.Health})
	}
	return projects, others
}

func componentOf(s domain.Service) string {
	if labels, ok := s.Metadata["labels"].(map[string]any); ok {
		if name, ok := labels[composeServiceLabel].(string); ok && name != "" {
			return name
		}
	}
	return s.Name
}

func detailComponent(d runtimes.ContainerDetail) string {
	if name := d.Labels[composeServiceLabel]; name != "" {
		return name
	}
	return d.Name
}

func findComponent(rows []domain.Service, name string) (domain.Service, bool) {
	k := slices.IndexFunc(rows, func(s domain.Service) bool { return componentOf(s) == name })
	if k < 0 {
		return domain.Service{}, false
	}
	return rows[k], true
}

func isHealthy(status, health string) bool { return status == "running" && health != "unhealthy" }

func appState(components []wire.AppComponent) string {
	for _, c := range components {
		if !isHealthy(c.Status, c.Health) {
			return wire.AppDegraded
		}
	}
	return wire.AppRunning
}

// appSample is the stats sample an app is read with; none when stats were not asked for or not available.
type appSample struct {
	stats []runtimes.ContainerStats
	at    time.Time
}

func liveApp(node domain.Node, project string, details []runtimes.ContainerDetail, rows []domain.Service, sample appSample, readAt time.Time, config bool) wire.App {
	components := make([]wire.AppComponent, 0, len(details))
	restarts := 0
	var total wire.ResourceUse
	sampled := false
	for _, d := range details {
		restart := d.RestartCount
		restarts += restart
		c := wire.AppComponent{
			Name: detailComponent(d), Image: d.Image, Status: d.Status, Health: d.Health, StartedAt: d.StartedAt,
			RestartCount: &restart, Ports: d.Ports,
		}
		if k := slices.IndexFunc(rows, func(s domain.Service) bool { return s.NativeID == d.ID }); k >= 0 {
			c.ServiceID = rows[k].ID
		}
		if use, ok := useOf(sample.stats, d.ID); ok {
			c.Stats, sampled = &use, true
			total = addUse(total, use)
		}
		if config {
			c.Mounts = mountsOf(d.Mounts)
			c.Config = appConfigOf(d)
		}
		components = append(components, c)
	}
	slices.SortFunc(components, func(a, b wire.AppComponent) int { return strings.Compare(a.Name, b.Name) })
	app := wire.App{
		Project: project, NodeID: node.ID, Node: node.Name, State: appState(components),
		RestartCount: &restarts, ReadAt: readAt, Components: components,
	}
	if sampled {
		app.Stats, app.StatsAt = &total, &sample.at
	}
	return app
}

func mountsOf(in []runtimes.ContainerMount) []wire.AppMount {
	out := make([]wire.AppMount, len(in))
	for k, m := range in {
		out[k] = wire.AppMount{Type: m.Type, Name: m.Name, Source: m.Source, Destination: m.Destination, ReadWrite: m.ReadWrite}
	}
	return out
}

// discoveredApps are the apps as the last discovery saw them, stale, read at the time they were last seen.
func discoveredApps(node domain.Node, projects map[string][]domain.Service, only string) []wire.App {
	apps := []wire.App{}
	for _, project := range slices.Sorted(maps.Keys(projects)) {
		if only != "" && only != project {
			continue
		}
		components := make([]wire.AppComponent, 0, len(projects[project]))
		var seen time.Time
		for _, s := range projects[project] {
			image, _ := s.Metadata["image"].(string)
			started, _ := s.Metadata["started_at"].(string)
			ports, _ := s.Metadata["ports"].([]any)
			c := wire.AppComponent{Name: componentOf(s), ServiceID: s.ID, Image: image, Status: s.Status, Health: s.Health, StartedAt: started}
			for _, p := range ports {
				if text, ok := p.(string); ok {
					c.Ports = append(c.Ports, text)
				}
			}
			components = append(components, c)
			if s.LastSeenAt != nil && s.LastSeenAt.After(seen) {
				seen = *s.LastSeenAt
			}
		}
		slices.SortFunc(components, func(a, b wire.AppComponent) int { return strings.Compare(a.Name, b.Name) })
		apps = append(apps, wire.App{
			Project: project, NodeID: node.ID, Node: node.Name, State: appState(components),
			ReadAt: seen, Stale: true, Components: components,
		})
	}
	return apps
}

// ---- resource use ------------------------------------------------------------------

func useOf(stats []runtimes.ContainerStats, containerID string) (wire.ResourceUse, bool) {
	for _, s := range stats {
		if s.ID != "" && strings.HasPrefix(containerID, s.ID) {
			return wire.ResourceUse{CPUPercent: s.CPUPercent, MemUsedBytes: s.MemUsedBytes, MemLimitBytes: s.MemLimitBytes}, true
		}
	}
	return wire.ResourceUse{}, false
}

// addUse adds CPU and memory; the limit of the sum is the largest limit, since a container's default limit is
// the memory of the node.
func addUse(a, b wire.ResourceUse) wire.ResourceUse {
	return wire.ResourceUse{CPUPercent: a.CPUPercent + b.CPUPercent, MemUsedBytes: a.MemUsedBytes + b.MemUsedBytes, MemLimitBytes: max(a.MemLimitBytes, b.MemLimitBytes)}
}
