package discovery

import (
	"context"
	"fmt"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// Probe runs the node probe in ONE session (spec §12) and parses it. The
// caller stamps Snapshot.TakenAt and Snapshot.Setup.
func Probe(ctx context.Context, ex transport.Executor) (Snapshot, error) {
	c, err := templates.Render("probe", map[string]string{})
	if err != nil {
		return Snapshot{}, err
	}
	res, err := ex.Run(ctx, c)
	if err != nil {
		return Snapshot{}, fmt.Errorf("probe: %w", err)
	}
	return Parse(res.Stdout)
}

// Capabilities derives the node's capabilities (spec §7). Read capabilities
// follow the probe on every node. Mutating ones (service.start|stop|restart)
// are available only when !local and s.Setup is set, i.e. node.setup
// completed (ADR-0009 g); they are always reported, as unavailable otherwise,
// so a stale "available" row is overwritten. node.setup itself is written by
// the setup job, not derived here.
func Capabilities(s Snapshot, local bool) []database.NodeCapability {
	at := s.TakenAt
	capability := func(name string, available bool, meta map[string]any) database.NodeCapability {
		return database.NodeCapability{Capability: name, Available: available, Metadata: meta, CheckedAt: at}
	}
	hasSystemd := s.Systemd.Active
	hasDocker := s.Docker.Reachable()
	caps := []database.NodeCapability{
		capability("node.read", true, nil),
		capability("node.metrics", s.CPU.UsageKnown || s.Memory.TotalKB > 0 || s.Disk.TotalKB > 0, nil),
		capability("node.ssh", !local, nil),
		capability("node.exec.template", !local, nil),
		capability("node.packages.read", len(s.PackageManagers) > 0, map[string]any{"managers": s.PackageManagers}),
		capability("service.read", hasSystemd || hasDocker, nil),
		capability("service.logs", hasSystemd || hasDocker, map[string]any{"mode": logsMode(s)}),
		capability("docker.read", hasDocker, map[string]any{"server": s.Docker.ServerVersion, "compose": s.Docker.ComposeVersion}),
		capability("docker.logs", hasDocker, nil),
		capability("tool.lazydocker", s.Tools.Lazydocker, nil),
		capability("tool.btop", s.Tools.Btop, nil),
		capability("tool.tmux", s.Tools.Tmux, nil),
	}
	return append(caps, mutatingCapabilities(s, local, at)...)
}

func logsMode(s Snapshot) runtimes.LogsMode {
	if s.Setup != nil && s.Setup.LogsMode != "" {
		return s.Setup.LogsMode
	}
	return runtimes.LogsJournalGroup
}

// mutatingCapabilities reports service.start|stop|restart. They need an SSH
// node with node.setup; the granted units (systemd) and docker_access
// (containers) say what they apply to.
func mutatingCapabilities(s Snapshot, local bool, at time.Time) []database.NodeCapability {
	var caps []database.NodeCapability
	for _, verb := range domain.AllServiceVerbs() {
		units, containers := []string{}, false
		if !local && s.Setup != nil {
			if s.Systemd.Active {
				units = grantedUnits(*s.Setup, verb)
			}
			containers = s.Setup.DockerAccess && s.Docker.Reachable()
		}
		caps = append(caps, database.NodeCapability{
			Capability: verb.Action(), Available: len(units) > 0 || containers, CheckedAt: at,
			Metadata: map[string]any{"units": units, "containers": containers},
		})
	}
	return caps
}

func grantedUnits(setup runtimes.SetupMeta, verb domain.ServiceVerb) []string {
	units := []string{}
	for _, g := range setup.Units {
		if setup.Granted(g.Unit, verb) {
			units = append(units, g.Unit)
		}
	}
	return units
}
