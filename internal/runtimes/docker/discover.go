package docker

import (
	"context"
	"path"
	"slices"
	"strings"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/transport"
)

const composeProjectLabel = "com.docker.compose.project"

// Discover lists the Docker engine and its containers (running or not). Include
// and Exclude are shell globs on the container name; Exclude wins and an empty
// Include admits every container.
func (Adapter) Discover(ctx context.Context, ex transport.Executor, f runtimes.Filter) (runtimes.Discovered, error) {
	for _, p := range slices.Concat(f.Include, f.Exclude) {
		if _, err := path.Match(p, ""); err != nil {
			return runtimes.Discovered{}, smerr.New(smerr.CodeInvalidArgument, "", "invalid filter pattern "+p)
		}
	}
	version, err := engineVersion(ctx, ex)
	if err != nil {
		return runtimes.Discovered{}, err
	}
	containers, err := listContainers(ctx, ex)
	if err != nil {
		return runtimes.Discovered{}, err
	}
	var services []runtimes.DiscoveredService
	for _, c := range containers {
		if name := containerName(c); admits(f, name) {
			services = append(services, service(c, name))
		}
	}
	return runtimes.Discovered{
		Runtime: runtimes.DiscoveredRuntime{
			Type: domain.RuntimeDocker, NativeID: "docker", Version: version, Status: "running",
			Metadata: map[string]any{"compose_version": composeVersion(ctx, ex)},
		},
		Services: services,
	}, nil
}

// engineVersion parses the Version line of the Server section of `docker
// version`. No server section means the daemon is unreachable or the session
// user has no access to it.
func engineVersion(ctx context.Context, ex transport.Executor) (string, error) {
	res, err := read(ctx, ex, "docker.version", nil)
	if err != nil {
		return "", err
	}
	inServer := false
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Server"):
			inServer = true
		case inServer && strings.HasPrefix(trimmed, "Version:"):
			return sanitize(strings.TrimSpace(strings.TrimPrefix(trimmed, "Version:"))), nil
		}
	}
	return "", smerr.New(smerr.CodeCapabilityUnavailable, "", "the docker engine is not reachable")
}

// composeVersion is "" when the Compose plugin is absent.
func composeVersion(ctx context.Context, ex transport.Executor) string {
	res, err := read(ctx, ex, "docker.compose_version", nil)
	if err != nil || res.ExitStatus != 0 {
		return ""
	}
	return sanitize(strings.TrimSpace(string(res.Stdout)))
}

func listContainers(ctx context.Context, ex transport.Executor) ([]inspected, error) {
	res, err := read(ctx, ex, "docker.inspect_all", nil)
	if err != nil {
		return nil, err
	}
	if res.ExitStatus != 0 {
		return nil, smerr.New(smerr.CodeCapabilityUnavailable, "", "docker containers cannot be listed")
	}
	if res.Truncated {
		return nil, smerr.New(smerr.CodeInternal, "", "docker inspect output exceeds the template limit")
	}
	return decodeInspect(res.Stdout)
}

func containerName(c inspected) string { return sanitize(strings.TrimPrefix(c.Name, "/")) }

func admits(f runtimes.Filter, name string) bool {
	matches := func(patterns []string) bool {
		return slices.ContainsFunc(patterns, func(p string) bool { ok, _ := path.Match(p, name); return ok })
	}
	return !matches(f.Exclude) && (len(f.Include) == 0 || matches(f.Include))
}

func service(c inspected, name string) runtimes.DiscoveredService {
	health := ""
	if c.State.Health != nil {
		health = sanitize(c.State.Health.Status)
	}
	labels := make(map[string]any, len(c.Config.Labels))
	for k, v := range c.Config.Labels {
		labels[sanitize(k)] = sanitize(v)
	}
	return runtimes.DiscoveredService{
		Kind: domain.ServiceDockerContainer, NativeID: sanitize(c.ID), Name: name,
		Status: sanitize(c.State.Status), Health: health,
		Metadata: map[string]any{
			"image":           sanitize(c.Config.Image),
			"image_id":        sanitize(c.Image),
			"labels":          labels,
			"ports":           ports(c),
			"compose_project": sanitize(c.Config.Labels[composeProjectLabel]),
			"started_at":      sanitize(c.State.StartedAt),
		},
	}
}

// ports lists published ports as "host_ip:host_port->container_port", sorted.
func ports(c inspected) []string {
	var out []string
	for container, bindings := range c.NetworkSettings.Ports {
		for _, b := range bindings {
			out = append(out, sanitize(b.HostIP+":"+b.HostPort+"->"+container))
		}
	}
	slices.Sort(out)
	return out
}
