// Package docker is the Docker runtime adapter (spec §17): container
// discovery, bounded logs and start/stop/restart with completion evidence.
// Docker access is effectively root on the node; actions need the plan
// parameter docker_access at node.setup (ADR-0009).
package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/autarquico/supermgmt/internal/textsafe"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// Adapter implements runtimes.Adapter for Docker containers. It holds no state.
type Adapter struct{}

var _ runtimes.Adapter = Adapter{}

// New returns the Docker adapter.
func New() Adapter { return Adapter{} }

func (Adapter) Type() domain.RuntimeType { return domain.RuntimeDocker }

// Logs reads the last q.Lines lines of the container's output (timestamped,
// stdout and stderr merged). q.Mode does not apply to Docker.
func (Adapter) Logs(ctx context.Context, ex transport.Executor, s runtimes.ServiceRef, q runtimes.LogQuery) (runtimes.LogChunk, error) {
	if err := checkContainer(s); err != nil {
		return runtimes.LogChunk{}, err
	}
	if q.Lines < 1 || q.Lines > runtimes.MaxLogLines {
		return runtimes.LogChunk{}, smerr.New(smerr.CodeInvalidArgument, "", fmt.Sprintf("lines must be in 1..%d", runtimes.MaxLogLines))
	}
	res, err := read(ctx, ex, "docker.logs", map[string]string{"container": s.NativeID, "lines": strconv.Itoa(q.Lines)})
	if err != nil {
		return runtimes.LogChunk{}, err
	}
	if res.ExitStatus != 0 {
		return runtimes.LogChunk{}, smerr.New(smerr.CodeCapabilityUnavailable, "", fmt.Sprintf("logs of %s are unavailable (exit %d)", s.Name, res.ExitStatus))
	}
	return runtimes.LogChunk{Lines: splitLines(res.Stdout), Truncated: res.Truncated}, nil
}

// Preflight checks that the container exists. Docker has no unit trust
// profile: its privilege boundary is the docker group (spec §17).
func (Adapter) Preflight(ctx context.Context, ex transport.Executor, s runtimes.ServiceRef) error {
	if err := checkContainer(s); err != nil {
		return err
	}
	_, err := inspect(ctx, ex, s.NativeID)
	return err
}

// PreState captures State.StartedAt and Running before dispatch (spec §20.4).
func (Adapter) PreState(ctx context.Context, ex transport.Executor, s runtimes.ServiceRef) (json.RawMessage, error) {
	if err := checkContainer(s); err != nil {
		return nil, err
	}
	state, err := inspect(ctx, ex, s.NativeID)
	if err != nil {
		return nil, err
	}
	return state.marshal()
}

// Mutate renders the marker-wrapped `docker <verb> -- <container>`. It
// requires node.setup with docker_access: without it the session user is not
// in the docker group.
func (Adapter) Mutate(s runtimes.ServiceRef, v domain.ServiceVerb, marker string, setup runtimes.SetupMeta) (templates.Command, error) {
	if err := checkContainer(s); err != nil {
		return templates.Command{}, err
	}
	if !v.Valid() {
		return templates.Command{}, smerr.New(smerr.CodeInvalidArgument, "", "unknown service verb")
	}
	if !setup.DockerAccess {
		return templates.Command{}, smerr.New(smerr.CodeCapabilityUnavailable, "", "node.setup did not grant docker_access")
	}
	return templates.RenderMutating("docker."+string(v), marker, map[string]string{"container": s.NativeID})
}

// Observe reports completion evidence for a dispatched verb. Only the
// marker's .done file with exit status 0 is proof (ADR-0015); without it the
// result is an error and the job waits for a human.
func (Adapter) Observe(ctx context.Context, ex transport.Executor, s runtimes.ServiceRef, v domain.ServiceVerb, marker string,
	pre json.RawMessage, _ time.Time,
) (jobs.Evidence, error) {
	o, err := observe(ctx, ex, s, v, marker, pre)
	if err != nil {
		return jobs.Evidence{}, err
	}
	return o.evidence(), nil
}

func checkContainer(s runtimes.ServiceRef) error {
	if s.Kind != domain.ServiceDockerContainer {
		return smerr.New(smerr.CodeInvalidArgument, "", "not a docker container")
	}
	if err := templates.ValidateContainer(s.NativeID); err != nil {
		return smerr.New(smerr.CodeInvalidArgument, "", "container id: "+err.Error())
	}
	return nil
}

func read(ctx context.Context, ex transport.Executor, name string, args map[string]string) (transport.Result, error) {
	c, err := templates.Render(name, args)
	if err != nil {
		return transport.Result{}, err
	}
	res, err := ex.Run(ctx, c)
	if err != nil {
		return transport.Result{}, fmt.Errorf("%s: %w", name, err)
	}
	return res, nil
}

func splitLines(out []byte) []string {
	text := strings.TrimRight(string(out), "\n")
	if text == "" {
		return nil
	}
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		lines[i] = textsafe.Line(strings.TrimSuffix(line, "\r"))
	}
	return lines
}
