//go:build e2e && fixtures

package e2e_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/test/e2e/harness"
)

// Commits of the acceptance scenarios; every scenario that shares a world uses its own.
const (
	deployCommitCI      = "1111111111111111111111111111111111111111" // CI passed here
	deployCommitMovedOn = "2222222222222222222222222222222222222222" // main moved here after; its CI failed
)

// deployAppRequest is a CI-gated acme/shop application, as createShop builds it, under another name.
func deployAppRequest(provider wire.Provider, name string) wire.CreateAppRequest {
	providerID, repositoryID := provider.ID, int64(m4RepoID)
	return wire.CreateAppRequest{
		Name: name, ProviderID: &providerID, RepositoryID: &repositoryID, ManifestPath: ".supermgmt.yaml",
		DeployedService: m4Service, ImagePolicy: wire.ImagePolicy{Deployed: m4RegistryHost + "/" + m4ImageRepo},
		ComposeSource: "control-plane", ComposeContent: m4Compose,
		CIPolicy: &wire.CIPolicy{
			RepositoryID: m4RepoID, OwnerID: m4OwnerID, Branch: m4Branch, AllowedEvents: []string{"push"},
			RequiredChecks: []wire.RequiredCheck{{Name: "build", AppID: m4ActionsAppID, WorkflowPath: m4CIWorkflow}},
			DeployWorkflow: m4DeployWorkflow,
		},
	}
}

// deployCreateApp creates the application described by req and one target of it on the node.
func (w *m4World) deployCreateApp(req wire.CreateAppRequest, node wire.Node, policy wire.DeploymentPolicy) wire.AppTarget {
	w.t.Helper()
	created, err := w.api.CreateApp(w.ctx(), req)
	if err != nil {
		w.t.Fatalf("create app %s: %v", req.Name, err)
	}
	if created.Pending != nil {
		w.settleJob(created.Pending.Job.ID, m4SetupJobTimeout)
	}
	app := w.findApp(req.Name)
	target, err := w.api.CreateAppTarget(w.ctx(), app.ID, wire.CreateAppTargetRequest{Environment: m4EnvName, NodeID: node.ID, DeploymentPolicy: policy})
	if err != nil {
		w.t.Fatalf("create the target of %s: %v", req.Name, err)
	}
	if target.Pending != nil {
		w.settleJob(target.Pending.Job.ID, m4SetupJobTimeout)
	}
	return w.findApp(req.Name).Targets[0]
}

// deployReportCI makes the required check of commit complete with the conclusion, as workflow run
// number run of the CI workflow.
func (s *m4Sim) deployReportCI(commit string, run int64, conclusion string) {
	s.t.Helper()
	suite := 9000 + run
	s.post("/sim/workflow-runs", map[string]any{
		"repo_id": m4RepoID, "suite_id": suite, "id": 5000 + run, "run_attempt": 1, "path": m4CIWorkflow,
		"head_branch": m4Branch, "head_sha": commit, "event": "push", "status": "completed", "conclusion": conclusion,
	})
	s.post("/sim/check-runs", map[string]any{
		"repo_id": m4RepoID, "commit": commit, "id": 7000 + run, "name": "build", "app_id": m4ActionsAppID,
		"status": "completed", "conclusion": conclusion, "suite_id": suite,
	})
}

// deployAddFile puts a file in the repository at commit.
func (s *m4Sim) deployAddFile(commit, path, content string) {
	s.t.Helper()
	s.post("/sim/files", map[string]any{"repo_id": m4RepoID, "commit": commit, "path": path, "content": content})
}

// deployTellCIPassed has the world learn that CI is green for commit: by webhook when the world has
// an endpoint for it, otherwise the daemon finds out by polling.
func (w *m4World) deployTellCIPassed(commit string, run int64) {
	w.t.Helper()
	w.sim.deployReportCI(commit, run, "success")
	if w.webhookURL == "" {
		return
	}
	if got := w.sim.deliverWebhook(w.webhookURL, commit, fmt.Sprintf("delivery-%d", run), false); got != http.StatusOK {
		w.t.Fatalf("a signed webhook was answered %d, want 200", got)
	}
}

// deploySucceeded waits for the deployment to finish and fails with the diagnosis unless it succeeded.
func (w *m4World) deploySucceeded(d wire.Deployment) wire.Deployment {
	w.t.Helper()
	done := w.waitDeployment(d.ID, m4DeployTimeout, string(deployments.StateSucceeded), string(deployments.StateFailed),
		string(deployments.StateRolledBack), string(deployments.StateRollbackFailed))
	if done.State != string(deployments.StateSucceeded) {
		w.t.Fatalf("deployment ended %s (%s/%s)\nsteps:\n%s%s", done.State, done.StateCode, done.StateReason, m4Timeline(done), w.diagnosis(done))
	}
	return done
}

// deployServerContainer is the container `sm server` runs in: the one that holds the database.
func (w *m4World) deployServerContainer() *harness.Container {
	w.t.Helper()
	names, err := harness.Docker(w.ctx(), "", "ps", "--format", "{{.Names}}")
	if err != nil {
		w.t.Fatal(err)
	}
	for _, name := range strings.Fields(names.Stdout) {
		c := harness.Adopt(w.t, name)
		if c.Exec(w.ctx(), "", "test", "-f", harness.ServerData+"/supermgmt.db").Code == 0 {
			return c
		}
	}
	w.t.Fatal("no running container holds the server database")
	return nil
}

// deployAllowAutomaticRollback declares automatic rollback safe for the staging environment: the
// environment, not the app, decides (PLAN §9 row 3). The harness configures the server without it,
// so the server's configuration is amended and the service restarted.
func (w *m4World) deployAllowAutomaticRollback() {
	w.t.Helper()
	server := w.deployServerContainer()
	const key = "    risk_level: " + m4EnvName
	server.MustExec(w.ctx(), "sed", "-i", "s/^"+key+"$/"+key+"\\n    allow_automatic_rollback: true/", harness.ServerConfig)
	server.MustExec(w.ctx(), "systemctl", "restart", "supermgmt")
	deadline := harness.Now().Add(time.Minute)
	for harness.Now().Before(deadline) {
		if _, err := w.api.ListApps(w.ctx(), wire.PageQuery{Limit: 1}); err == nil {
			return
		}
		time.Sleep(time.Second)
	}
	w.t.Fatal("the server did not come back after the configuration change")
}

// TestM4_DeployExactAttestedDigest
//
// Spec scenario "despliegue del commit/digest exacto que pasó CI" (PLAN §9 row 1), server mode: CI is
// green for one commit and the image of that commit is attested; main then moves to a commit whose
// CI failed and whose image is attested too. Creating the deployment runs the image the registry
// holds under the requested digest on the selected node, never the newer one.
func TestM4_DeployExactAttestedDigest(t *testing.T) {
	w := newM4ServerWorld(t)
	provider, node := w.waitForStaticConfig()
	w.sim.addShopRepository()
	w.prepareNode(node)
	target := w.createShop(provider, node)

	passed := w.sim.pushImage(m4Image{Version: "passed-ci"})
	movedOn := w.sim.pushImage(m4Image{Version: "main-moved-on"})
	w.sim.attest(passed, deployCommitCI)
	w.sim.attest(movedOn, deployCommitMovedOn)
	w.sim.deployReportCI(deployCommitMovedOn, 2, "failure")

	d := w.deployShop(target, deployCommitCI, passed)
	w.deployTellCIPassed(deployCommitCI, 1)
	done := w.deploySucceeded(d)

	t.Run("the deployment records the requested commit and digest on the selected node", func(t *testing.T) {
		if done.CommitSHA != deployCommitCI || len(done.Images) != 1 || done.Images[0].Digest != passed || done.NodeID != node.ID {
			t.Fatalf("deployment = commit %s images %+v node %s, want commit %s digest %s node %s",
				done.CommitSHA, done.Images, done.NodeID, deployCommitCI, passed, node.ID)
		}
	})
	t.Run("the node runs exactly the digest that passed CI", func(t *testing.T) {
		running := w.runningImage(target)
		if running != m4ImageRef(passed) {
			t.Fatalf("running image = %q, want %q", running, m4ImageRef(passed))
		}
		if strings.Contains(running, movedOn) {
			t.Fatalf("the node runs the image of the commit main moved to: %q", running)
		}
	})
}

// TestM4_LocalModePollsCIThenDeploys
//
// The same scenario without a server (PLAN §9 row 1): the local daemon has no webhook endpoint, so
// the deployment stays in waiting_ci until its poll sees the check pass, then runs the exact digest.
func TestM4_LocalModePollsCIThenDeploys(t *testing.T) {
	w := newM4LocalWorld(t)
	provider, node := w.waitForStaticConfig()
	w.sim.addShopRepository()
	w.prepareNode(node)
	target := w.createShop(provider, node)

	digest := w.sim.pushImage(m4Image{Version: "polled"})
	w.sim.attest(digest, deployCommitCI)
	d := w.deployShop(target, deployCommitCI, digest)

	t.Run("the deployment waits for CI without a job", func(t *testing.T) {
		waiting := w.waitDeployment(d.ID, m4DeployTimeout, string(deployments.StateWaitingCI))
		if waiting.JobID != nil {
			t.Fatalf("a deployment waiting for CI already has job %s", *waiting.JobID)
		}
	})

	w.deployTellCIPassed(deployCommitCI, 1)
	w.deploySucceeded(d)

	t.Run("the node runs exactly the attested digest", func(t *testing.T) {
		if got, want := w.runningImage(target), m4ImageRef(digest); got != want {
			t.Fatalf("running image = %q, want %q", got, want)
		}
	})
}
