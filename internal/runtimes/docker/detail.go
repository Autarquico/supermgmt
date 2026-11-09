package docker

import (
	"context"

	"github.com/autarquico/supermgmt/internal/textsafe"

	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/transport"
)

// Details reads every container of the node as `docker inspect` reports it.
// The values are raw (environment, commands, labels): they must be redacted
// before leaving the daemon and must not be logged.
func (Adapter) Details(ctx context.Context, ex transport.Executor) ([]runtimes.ContainerDetail, error) {
	all, err := listContainers(ctx, ex)
	if err != nil {
		return nil, err
	}
	details := make([]runtimes.ContainerDetail, len(all))
	for i, c := range all {
		details[i] = detail(c)
	}
	return details, nil
}

func detail(c inspected) runtimes.ContainerDetail {
	health := ""
	if c.State.Health != nil {
		health = textsafe.Line(c.State.Health.Status)
	}
	labels := make(map[string]string, len(c.Config.Labels))
	for k, v := range c.Config.Labels {
		labels[textsafe.Line(k)] = textsafe.Line(v)
	}
	mounts := make([]runtimes.ContainerMount, len(c.Mounts))
	for i, m := range c.Mounts {
		mounts[i] = runtimes.ContainerMount{
			Type: textsafe.Line(m.Type), Name: textsafe.Line(m.Name),
			Source: textsafe.Line(m.Source), Destination: textsafe.Line(m.Destination), ReadWrite: m.RW,
		}
	}
	return runtimes.ContainerDetail{
		ID: textsafe.Line(c.ID), Name: containerName(c), Image: textsafe.Line(c.Config.Image),
		Project: textsafe.Line(c.Config.Labels[composeProjectLabel]),
		Status:  textsafe.Line(c.State.Status), Health: health, StartedAt: textsafe.Line(c.State.StartedAt),
		RestartCount:      c.RestartCount,
		RestartPolicy:     textsafe.Line(c.HostConfig.RestartPolicy.Name),
		RestartMaxRetries: c.HostConfig.RestartPolicy.MaximumRetryCount,
		Ports:             ports(c), Mounts: mounts,
		Env: lines(c.Config.Env), Cmd: lines(c.Config.Cmd), Entrypoint: lines(c.Config.Entrypoint),
		Labels: labels,
	}
}

func lines(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = textsafe.Line(s)
	}
	return out
}
