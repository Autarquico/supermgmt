package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/deployments/compose"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/health"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// healthRun is everything one health verification reads, taken from the
// plan's frozen snapshots (spec §20.2: workers never read live configuration).
// Container is the container docker-health checks inspect.
type healthRun struct {
	Checks      []health.Check
	Ports       []compose.HostPort
	AllowedBind []netip.Addr
	Container   string
}

// healthVerdict is the outcome of a verification. Failure names the first
// failing check and why; it never carries a response body or node output.
type healthVerdict struct {
	Healthy bool
	Failure string
}

// healthVerifier runs the checks of a deployment (spec §21): node-scope checks
// through SSH templates, control_plane-scope checks through HTTP, a netguard
// client in production. Checks are read-only, so they need no intent.
type healthVerifier struct {
	Node  transport.Executor
	HTTP  *http.Client
	Sleep func(ctx context.Context, d time.Duration) // default: a real timer
}

// healthProbe is one attempt of a validated check.
type healthProbe func(ctx context.Context) (healthy bool, detail string)

// verify passes only when every check passes within its attempts. No check at
// all is unhealthy: nothing would prove the new version works, and a
// known-good mark drives later rollbacks. An invalid check is unhealthy too,
// without reaching the node. An error is returned only when ctx ends.
func (v healthVerifier) verify(ctx context.Context, run healthRun) (healthVerdict, error) {
	if len(run.Checks) == 0 {
		return healthVerdict{Failure: "no health check is configured"}, nil
	}
	probes := make([]healthProbe, len(run.Checks))
	for i, c := range run.Checks {
		probe, err := v.probe(run, c)
		if err != nil {
			return healthVerdict{Failure: healthFailure(i, c, err.Error())}, nil
		}
		probes[i] = probe
	}
	for i, c := range run.Checks {
		detail, err := v.attempt(ctx, c, probes[i])
		if err != nil {
			return healthVerdict{}, err
		}
		if detail != "" {
			return healthVerdict{Failure: healthFailure(i, c, detail)}, nil
		}
	}
	return healthVerdict{Healthy: true}, nil
}

func healthFailure(index int, c health.Check, detail string) string {
	return fmt.Sprintf("check %d (%s): %s", index+1, c.Type, detail)
}

// attempt retries probe every c.Interval, at most c.Attempts times. It returns
// "" once the probe is healthy, else why the last attempt was not.
func (v healthVerifier) attempt(ctx context.Context, c health.Check, probe healthProbe) (string, error) {
	attempts := max(c.Attempts, 1)
	for n := 1; ; n++ {
		healthy, detail := probe(ctx)
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if healthy {
			return "", nil
		}
		if n == attempts {
			return fmt.Sprintf("%s after %d attempts", detail, attempts), nil
		}
		v.sleep(ctx, c.Interval)
		if err := ctx.Err(); err != nil {
			return "", err
		}
	}
}

func (v healthVerifier) sleep(ctx context.Context, d time.Duration) {
	if v.Sleep != nil {
		v.Sleep(ctx, d)
		return
	}
	sleepFor(ctx, d)
}

func (v healthVerifier) probe(run healthRun, c health.Check) (healthProbe, error) {
	destination, err := run.destination(c)
	if err != nil {
		return nil, err
	}
	if c.Scope == health.ScopeControlPlane {
		return v.controlPlaneProbe(c), nil
	}
	template, args, err := health.NodeInvocation(c, destination)
	if err != nil {
		return nil, err
	}
	if c.Type == health.TypeDockerHealth {
		if run.Container == "" {
			return nil, errors.New("docker-health needs the container of the deployed service")
		}
		args["container"] = run.Container
	}
	cmd, err := templates.Render(template, args)
	if err != nil {
		return nil, errors.New("the check cannot be rendered for the node")
	}
	return func(ctx context.Context) (bool, string) { return v.nodeAttempt(ctx, c, cmd) }, nil
}

// destination validates c under the rules of its origin; the address comes
// from the frozen model's published ports, never from the check.
func (r healthRun) destination(c health.Check) (health.Destination, error) {
	switch c.Origin {
	case health.OriginManifest:
		return health.ValidateManifest(c, r.Ports)
	case health.OriginControlPlane:
		return health.ValidateControlPlane(c, r.Ports, r.AllowedBind)
	}
	return health.Destination{}, fmt.Errorf("health: unknown origin %q", c.Origin)
}

func (v healthVerifier) controlPlaneProbe(c health.Check) healthProbe {
	return func(ctx context.Context) (bool, string) {
		res, err := health.ControlPlane(ctx, v.HTTP, c)
		if err != nil {
			return false, "the check is malformed"
		}
		return res.Healthy, res.Detail
	}
}

func (v healthVerifier) nodeAttempt(ctx context.Context, c health.Check, cmd templates.Command) (bool, string) {
	res, err := v.Node.Run(ctx, cmd)
	if err != nil {
		return false, "the node could not be reached"
	}
	return healthNodeVerdict(c, res)
}

// healthNodeVerdict reads a node-scope result by check type. Remote output is
// untrusted: only a parsed status code or a known word is ever repeated.
func healthNodeVerdict(c health.Check, res transport.Result) (bool, string) {
	if res.ExitStatus != 0 {
		return false, fmt.Sprintf("the check command exited with status %d", res.ExitStatus)
	}
	out := strings.TrimSpace(string(res.Stdout))
	switch c.Type {
	case health.TypeHTTP:
		code, err := strconv.Atoi(out)
		if err != nil {
			return false, "the HTTP status was not recognized"
		}
		return code >= 200 && code <= 299, fmt.Sprintf("HTTP status %d", code)
	case health.TypeDockerHealth:
		return out == "healthy", "container health is " + healthDockerWord(out)
	}
	return true, ""
}

func healthDockerWord(out string) string {
	switch out {
	case "starting", "unhealthy", "none":
		return out
	}
	return "not recognized"
}

// settleVerification applies the verdict to a deployment in verifying (spec
// §20.1): healthy succeeds and marks it known-good, in the caller's
// transaction; unhealthy continues as rollBackOrFail. It returns the state the
// deployment moved to.
func settleVerification(ctx context.Context, q database.Querier, id domain.ID, v healthVerdict,
	rollback deployments.RollbackInputs, now time.Time,
) (deployments.State, error) {
	if !v.Healthy {
		return rollBackOrFail(ctx, q, id, rollback, now)
	}
	if err := database.TransitionDeployment(ctx, q, id, deployments.StateSucceeded, database.StateFailure{}, now); err != nil {
		return "", err
	}
	if err := database.MarkDeploymentKnownGood(ctx, q, id, now); err != nil {
		return "", err
	}
	return deployments.StateSucceeded, nil
}
