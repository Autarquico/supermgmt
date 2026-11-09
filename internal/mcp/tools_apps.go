package mcp

import (
	"context"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

// The app tools (spec app-panels): what runs on each node, as Compose projects. They read live from the node
// and say so; everything the node reported sits under an untrusted Remote object. Logs need service.logs,
// which the default policy grants an MCP client through builtin-mcp-operate (service.read comes with *.read).

type listAppsInput struct {
	Node string `json:"node,omitempty" jsonschema:"only the apps of this node (id or exact name)"`
}

type appInput struct {
	Node    string `json:"node" jsonschema:"node id or exact node name"`
	Project string `json:"project" jsonschema:"Compose project name, as listed by infra_list_apps"`
}

type searchAppLogsInput struct {
	appInput
	Component string `json:"component" jsonschema:"component (Compose service) of the app, as listed by infra_get_app"`
	Term      string `json:"term" jsonschema:"text to look for, matched case-insensitively after credentials are masked"`
}

func addAppTools(s *sdk.Server, api API) {
	readTool(s, "infra_list_apps",
		"List the apps (Compose projects) of every node, or of one node (id or exact name): per app its state (running or degraded), restarts, current CPU and memory with the time of the sample, and recent error count. Containers outside a project and units are listed as other_services. Read live from the node; when it cannot be read the last discovery is returned with stale=true and its time. A node whose Docker is not accessible says so in problem and names, in hint, the command a person runs to allow it; you cannot. recent_errors is absent without service.logs. Needs service.read. Next step: infra_get_app for one project."+remoteDataNotice,
		func(ctx context.Context, in listAppsInput) (listResult[NodeAppsView], error) {
			return listApps(ctx, api, in)
		})
	readTool(s, "infra_get_app",
		"Get one app of a node: each component's state, image, restarts, ports, volumes and the configuration the runtime reports with environment, command and label secrets redacted. Needs service.read. Component names here are what infra_search_app_logs takes."+remoteDataNotice,
		func(ctx context.Context, in appInput) (AppView, error) {
			node, err := resolveNode(ctx, api, in.Node)
			if err != nil {
				return AppView{}, err
			}
			app, err := api.GetNodeApp(ctx, node, in.Project, wire.AppsQuery{Stats: true, Errors: true})
			return ViewApp(app), err
		})
	readTool(s, "infra_get_app_stats",
		"Take one sample of the CPU and memory of an app's components. The result says when it was sampled; nothing is stored. Needs service.read."+remoteDataNotice,
		func(ctx context.Context, in appInput) (AppStatsView, error) {
			node, err := resolveNode(ctx, api, in.Node)
			if err != nil {
				return AppStatsView{}, err
			}
			stats, err := api.NodeAppStats(ctx, node, in.Project)
			return ViewAppStats(stats), err
		})
	readTool(s, "infra_search_app_logs",
		"Search the recent logs of one component of an app for a term (needs service.logs, which the default policy grants MCP clients through builtin-mcp-operate). The daemon reads a bounded window of recent lines, masks credentials, then matches; the result states the window it covered. The term never reaches the node. At most 500 lines and 64 KiB; truncated=true says a cap cut the result, so narrow the term."+remoteDataNotice,
		func(ctx context.Context, in searchAppLogsInput) (AppLogsView, error) {
			node, err := resolveNode(ctx, api, in.Node)
			if err != nil {
				return AppLogsView{}, err
			}
			if in.Term == "" {
				return AppLogsView{}, invalidArgument("term is required")
			}
			logs, err := api.NodeAppLogs(ctx, node, in.Project, wire.AppLogQuery{Component: in.Component, Search: in.Term})
			return ViewAppLogs(logs), err
		})
}

func listApps(ctx context.Context, api API, in listAppsInput) (listResult[NodeAppsView], error) {
	query := wire.AppsQuery{Stats: true, Errors: true}
	if in.Node == "" {
		page, err := api.ListApps(ctx, query)
		return listOf(page, ViewNodeApps), err
	}
	node, err := resolveNode(ctx, api, in.Node)
	if err != nil {
		return listResult[NodeAppsView]{}, err
	}
	apps, err := api.ListNodeApps(ctx, node, query)
	return listResult[NodeAppsView]{Items: []NodeAppsView{ViewNodeApps(apps)}}, err
}

// ---- views --------------------------------------------------------------------

type NodeAppsView struct {
	NodeID        domain.ID          `json:"node_id"`
	Node          string             `json:"node"`
	Problem       string             `json:"problem,omitempty"`
	Hint          string             `json:"hint,omitempty"`
	Apps          []AppView          `json:"apps"`
	OtherServices []OtherServiceView `json:"other_services"`
}

type OtherServiceView struct {
	ServiceID domain.ID          `json:"service_id"`
	Remote    OtherServiceRemote `json:"remote"`
}

type OtherServiceRemote struct {
	remoteMark
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Status string `json:"status"`
	Health string `json:"health"`
}

// AppView is an app. Project is a Compose project name the daemon validated, so it is an identifier; every
// other text the node reported is under Remote of its component.
type AppView struct {
	Project      string            `json:"project"`
	NodeID       domain.ID         `json:"node_id"`
	Node         string            `json:"node"`
	State        string            `json:"state"`
	RestartCount *int              `json:"restart_count,omitempty"`
	RecentErrors *int              `json:"recent_errors,omitempty"`
	Stats        *wire.ResourceUse `json:"stats,omitempty"`
	StatsAt      *time.Time        `json:"stats_at,omitempty"`
	ReadAt       time.Time         `json:"read_at"`
	Stale        bool              `json:"stale"`
	Components   []ComponentView   `json:"components"`
	Problem      string            `json:"problem,omitempty"`
	Hint         string            `json:"hint,omitempty"`
}

type ComponentView struct {
	ServiceID    domain.ID         `json:"service_id,omitempty"`
	RestartCount *int              `json:"restart_count,omitempty"`
	RecentErrors *int              `json:"recent_errors,omitempty"`
	Stats        *wire.ResourceUse `json:"stats,omitempty"`
	Remote       ComponentRemote   `json:"remote"`
}

type ComponentRemote struct {
	remoteMark
	Name      string      `json:"name"`
	Image     string      `json:"image"`
	Status    string      `json:"status"`
	Health    string      `json:"health"`
	StartedAt string      `json:"started_at,omitempty"`
	Ports     []string    `json:"ports,omitempty"`
	Mounts    []MountView `json:"mounts,omitempty"`
	Config    *ConfigView `json:"config,omitempty"`
}

type MountView struct {
	Type        string `json:"type"`
	Name        string `json:"name,omitempty"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	ReadWrite   bool   `json:"read_write"`
}

type ConfigView struct {
	RestartPolicy string         `json:"restart_policy"`
	Env           []string       `json:"env"`
	Command       []string       `json:"command"`
	Entrypoint    []string       `json:"entrypoint"`
	Labels        map[string]any `json:"labels"`
}

func ViewNodeApps(n wire.NodeApps) NodeAppsView {
	apps := make([]AppView, len(n.Apps))
	for i, a := range n.Apps {
		apps[i] = ViewApp(a)
	}
	others := make([]OtherServiceView, len(n.OtherServices))
	for i, o := range n.OtherServices {
		var b remoteBuilder
		remote := OtherServiceRemote{Name: b.scalar(o.Name), Kind: b.scalar(o.Kind), Status: b.scalar(o.Status), Health: b.scalar(o.Health)}
		remote.remoteMark = b.mark()
		others[i] = OtherServiceView{ServiceID: o.ServiceID, Remote: remote}
	}
	return NodeAppsView{
		NodeID: n.NodeID, Node: operatorLine(n.Node), Problem: n.Problem, Hint: operatorLine(n.Hint),
		Apps: apps, OtherServices: others,
	}
}

func ViewApp(a wire.App) AppView {
	components := make([]ComponentView, len(a.Components))
	for i, c := range a.Components {
		components[i] = viewComponent(c)
	}
	return AppView{
		Project: a.Project, NodeID: a.NodeID, Node: operatorLine(a.Node), State: a.State,
		RestartCount: a.RestartCount, RecentErrors: a.RecentErrors, Stats: a.Stats, StatsAt: a.StatsAt,
		ReadAt: a.ReadAt, Stale: a.Stale, Components: components, Problem: a.Problem, Hint: operatorLine(a.Hint),
	}
}

func viewComponent(c wire.AppComponent) ComponentView {
	var b remoteBuilder
	remote := ComponentRemote{
		Name: b.scalar(c.Name), Image: b.scalar(c.Image), Status: b.scalar(c.Status), Health: b.scalar(c.Health),
		StartedAt: b.scalar(c.StartedAt), Ports: b.list(c.Ports),
	}
	for _, m := range c.Mounts {
		remote.Mounts = append(remote.Mounts, MountView{
			Type: b.scalar(m.Type), Name: b.scalar(m.Name), Source: b.scalar(m.Source),
			Destination: b.scalar(m.Destination), ReadWrite: m.ReadWrite,
		})
	}
	if cfg := c.Config; cfg != nil {
		labels := make(map[string]any, len(cfg.Labels))
		for k, v := range cfg.Labels {
			labels[k] = v
		}
		remote.Config = &ConfigView{
			RestartPolicy: b.scalar(cfg.RestartPolicy), Env: b.list(cfg.Env), Command: b.list(cfg.Command),
			Entrypoint: b.list(cfg.Entrypoint), Labels: b.object(labels),
		}
	}
	remote.remoteMark = b.mark()
	return ComponentView{ServiceID: c.ServiceID, RestartCount: c.RestartCount, RecentErrors: c.RecentErrors, Stats: c.Stats, Remote: remote}
}

// list bounds each text of a remote list and the number of them.
func (b *remoteBuilder) list(in []string) []string {
	if len(in) > MaxRemoteEntries {
		in, b.cut = in[:MaxRemoteEntries], true
	}
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = b.scalar(s)
	}
	return out
}

type AppStatsView struct {
	Project    string             `json:"project"`
	NodeID     domain.ID          `json:"node_id"`
	SampledAt  time.Time          `json:"sampled_at"`
	Total      wire.ResourceUse   `json:"total"`
	Components []ComponentUseView `json:"components"`
}

type ComponentUseView struct {
	Remote ComponentName    `json:"remote"`
	Use    wire.ResourceUse `json:"use"`
}

type ComponentName struct {
	remoteMark
	Name string `json:"name"`
}

func ViewAppStats(s wire.AppStats) AppStatsView {
	components := make([]ComponentUseView, len(s.Components))
	for i, c := range s.Components {
		var b remoteBuilder
		name := ComponentName{Name: b.scalar(c.Name)}
		name.remoteMark = b.mark()
		components[i] = ComponentUseView{Remote: name, Use: c.Use}
	}
	return AppStatsView{Project: s.Project, NodeID: s.NodeID, SampledAt: s.SampledAt, Total: s.Total, Components: components}
}

// AppLogsView is a log search: the matching lines under the untrusted envelope and the window they came from.
type AppLogsView struct {
	Project     string          `json:"project"`
	Component   string          `json:"component"`
	CollectedAt time.Time       `json:"collected_at"`
	Window      *wire.LogWindow `json:"window,omitempty"`
	Log         Untrusted       `json:"log"`
}

func ViewAppLogs(l wire.AppLogs) AppLogsView {
	return AppLogsView{
		Project: l.Project, Component: operatorLine(l.Component), CollectedAt: l.CollectedAt, Window: l.Window,
		Log: untrustedLines(l.Lines, l.Truncated),
	}
}
