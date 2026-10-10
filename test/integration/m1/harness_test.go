//go:build fixtures

package m1

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/test/fixtures/fixture"
)

const (
	demoUnit      = "sm-demo.service"
	slowUnit      = "sm-slow.service"
	demoContainer = "sm-demo-web"
)

var (
	buildFixtureOnce sync.Once
	buildFixtureErr  error
)

// ---- nodes ---------------------------------------------------------------------

// node is a running fixture container.
type node struct {
	*fixture.Node
	hostKey string // authorized_keys form of the host key the run injected
}

// startNodes starts n fixtures in parallel; they are removed with the test.
func startNodes(t *testing.T, opts ...fixture.Options) []*node {
	t.Helper()
	buildFixtureOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 10*time.Minute)
		defer cancel()
		buildFixtureErr = fixture.Build(ctx)
	})
	if buildFixtureErr != nil {
		t.Fatalf("build fixture image: %v", buildFixtureErr)
	}
	nodes := make([]*node, len(opts))
	errs := make([]error, len(opts))
	var wg sync.WaitGroup
	for i, o := range opts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 5*time.Minute)
			defer cancel()
			n, err := fixture.Start(ctx, o)
			if err != nil {
				errs[i] = err
				return
			}
			nodes[i] = &node{Node: n, hostKey: strings.TrimSpace(string(cryptossh.MarshalAuthorizedKey(n.HostKey)))}
		}()
	}
	wg.Wait()
	for i, n := range nodes {
		if n != nil {
			t.Cleanup(func() {
				bg := context.WithoutCancel(t.Context())
				if t.Failed() {
					t.Logf("fixture %s console:\n%s", n.Name, n.Logs(bg))
				}
				if err := n.Stop(bg); err != nil {
					t.Errorf("stop fixture: %v", err)
				}
			})
		}
		if errs[i] != nil {
			t.Fatalf("start fixture %d: %v", i, errs[i])
		}
	}
	return nodes
}

// sh runs a script as root inside the node and fails the test on error.
func (n *node) sh(t *testing.T, script string) string {
	t.Helper()
	out, err := n.Exec(t.Context(), "sh", "-c", script)
	if err != nil {
		t.Fatalf("on %s: %q: %v\n%s", n.Name, script, err, out)
	}
	return strings.TrimSpace(out)
}

// trySh is sh without the fatal.
func (n *node) trySh(t *testing.T, script string) (string, error) {
	t.Helper()
	out, err := n.Exec(t.Context(), "sh", "-c", script)
	return strings.TrimSpace(out), err
}

// invocationID is the systemd InvocationID of a unit on the node.
func (n *node) invocationID(t *testing.T, unit string) string {
	t.Helper()
	return n.sh(t, "systemctl show -p InvocationID --value "+unit)
}

// ---- driving the API --------------------------------------------------------------

// addNode scans, confirms (against the key the fixture injected) and adds a node.
func addNode(t *testing.T, api *client.Client, in *instance, n *node, name, environment string) wire.Node {
	t.Helper()
	in.agent.hold(n.ClientSigner)
	scanned, err := api.ScanHostKey(t.Context(), wire.ScanHostKeyRequest{Host: n.Host, Port: n.Port})
	if err != nil {
		t.Fatalf("scan host key of %s: %v", name, err)
	}
	if scanned.AuthorizedKey != n.hostKey {
		t.Fatalf("scanned key %s differs from the injected key %s", scanned.AuthorizedKey, n.hostKey)
	}
	added, err := api.AddSSHNode(t.Context(), wire.AddSSHNodeRequest{
		Name: name, Host: n.Host, Port: n.Port, AdminUser: fixture.AdminUser,
		HostPublicKey: scanned.AuthorizedKey, Environment: environment,
	})
	if err != nil {
		t.Fatalf("add node %s: %v", name, err)
	}
	if added.Applied != nil {
		return *added.Applied
	}
	// A production environment gates even node.add: approve the control_plane.apply job.
	approve(t, api, *added.Pending)
	waitJob(t, api, added.Pending.Job.ID, domain.JobSucceeded, time.Minute)
	page, err := api.ListNodes(t.Context(), wire.NodeQuery{})
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	for _, n := range page.Items {
		if n.Name == name {
			return n
		}
	}
	t.Fatalf("node %s missing after its add was approved", name)
	return wire.Node{}
}

// waitJob polls a job until it reaches want, failing on any other final state.
func probe(t *testing.T, api *client.Client, id domain.ID) {
	t.Helper()
	sub, err := api.ProbeNode(t.Context(), id)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	waitJob(t, api, sub.Job.ID, domain.JobSucceeded, time.Minute)
}

// setup plans node.setup, submits it, approves it as the same human (local mode
// allows self-approval) and waits for it to finish.
func setup(t *testing.T, api *client.Client, n wire.Node, dockerAccess bool, grants ...string) wire.Job {
	t.Helper()
	sub := submitSetup(t, api, n, dockerAccess, grants...)
	approve(t, api, sub)
	return waitJob(t, api, sub.Job.ID, domain.JobSucceeded, 3*time.Minute)
}

func submitSetup(t *testing.T, api *client.Client, n wire.Node, dockerAccess bool, grants ...string) wire.Submission {
	t.Helper()
	plan, err := api.CreatePlan(t.Context(), wire.CreatePlanRequest{
		Action:  "node.setup",
		Targets: []wire.ResourceRef{{Type: domain.ResourceNode, ID: n.ID}},
		Parameters: map[string]any{
			"docker_access": fmt.Sprint(dockerAccess), "logs_mode": "journal-group", "grants": grants,
		},
	})
	if err != nil {
		t.Fatalf("plan node.setup: %v", err)
	}
	if !plan.Policy.ApprovalRequired {
		t.Fatalf("node.setup is high risk and must need approval: %+v", plan.Policy)
	}
	sub, err := api.SubmitPlan(t.Context(), plan.PlanID, plan.PlanHash)
	if err != nil {
		t.Fatalf("submit node.setup: %v", err)
	}
	return sub
}

func approve(t *testing.T, api *client.Client, sub wire.Submission) {
	t.Helper()
	if _, err := api.Approve(t.Context(), sub.Job.ID, wire.DecisionRequest{PlanHash: sub.Job.PlanHash, Reason: "e2e"}); err != nil {
		t.Fatalf("approve job %s: %v", sub.Job.ID, err)
	}
}

func allVerbs(units ...string) []string {
	var grants []string
	for _, u := range units {
		for _, v := range domain.AllServiceVerbs() {
			grants = append(grants, string(v)+" "+u)
		}
	}
	return grants
}

func serviceNamed(t *testing.T, api *client.Client, node domain.ID, name string) wire.Service {
	t.Helper()
	page, err := api.ListServices(t.Context(), node, wire.PageQuery{Limit: wire.MaxLimit})
	if err != nil {
		t.Fatalf("list services: %v", err)
	}
	for _, s := range page.Items {
		if s.Name == name {
			return s
		}
	}
	names := make([]string, len(page.Items))
	for i, s := range page.Items {
		names[i] = s.Name
	}
	t.Fatalf("service %q not discovered on %s; have %v", name, node, names)
	return wire.Service{}
}
