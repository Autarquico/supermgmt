//go:build e2e && fixtures

package e2e_test

import (
	"net/http"
	"testing"

	"github.com/autarquico/supermgmt/internal/deployments"
)

// TestM4_Smoke
//
// The M4 world works end to end (PLAN T18a): an application bound to a repository whose CI the
// product checks is created, a deployment of an attested image digest waits for CI, and once CI is
// green the image the registry holds under that digest is what runs on the managed node. Once with
// `sm server` (CI is re-evaluated when GitHub's webhook arrives) and once with the local daemon
// (it polls GitHub).
func TestM4_Smoke(t *testing.T) {
	t.Run("server", func(t *testing.T) { m4Smoke(t, newM4ServerWorld(t)) })
	t.Run("local", func(t *testing.T) { m4Smoke(t, newM4LocalWorld(t)) })
}

func m4Smoke(t *testing.T, w *m4World) {
	provider, node := w.waitForStaticConfig()
	w.sim.addShopRepository()
	w.prepareNode(node)
	t.Run("node.setup leaves deploy_root where the deploy account can stage a project", func(t *testing.T) {
		// A deployment's first staging step makes <deploy_root>/<project> as the supermgmt account.
		res := w.node.c.Exec(w.ctx(), "", "runuser", "-u", "supermgmt", "--", "mkdir", "-m", "0750", "/srv/supermgmt/m4-probe")
		if res.Code != 0 {
			t.Errorf("supermgmt cannot create a project directory in /srv/supermgmt: %s", res.Output())
			// Carry on with the root handed to the account, so the rest of the pipeline is still exercised.
			w.node.c.MustExec(w.ctx(), "chown", "supermgmt:supermgmt", "/srv/supermgmt")
			return
		}
		w.node.c.MustExec(w.ctx(), "rmdir", "/srv/supermgmt/m4-probe")
	})
	target := w.createShop(provider, node)

	const commit = "aabbccddeeff00112233445566778899aabbccdd"
	digest := w.sim.pushImage(m4Image{Version: "v1"})
	w.sim.attest(digest, commit)

	d := w.deployShop(target, commit, digest)

	t.Run("the deployment waits while CI has not reported", func(t *testing.T) {
		waiting := w.waitDeployment(d.ID, m4DeployTimeout, string(deployments.StateWaitingCI))
		if waiting.JobID != nil {
			t.Fatalf("a deployment waiting for CI already has job %s", *waiting.JobID)
		}
	})

	t.Run("a webhook with a wrong signature acts on nothing", func(t *testing.T) {
		if w.webhookURL == "" {
			t.Skip("local mode has no webhook endpoint")
		}
		if got := w.sim.deliverWebhook(w.webhookURL, commit, "forged-1", true); got != http.StatusUnauthorized {
			t.Fatalf("a forged webhook was answered %d, want 401", got)
		}
	})

	w.sim.reportCI(commit, "completed", "success")
	if w.webhookURL != "" {
		if got := w.sim.deliverWebhook(w.webhookURL, commit, "delivery-1", false); got != http.StatusOK {
			t.Fatalf("a signed webhook was answered %d, want 200", got)
		}
	}

	t.Run("the deployment succeeds once CI is green", func(t *testing.T) {
		done := w.waitDeployment(d.ID, m4DeployTimeout, string(deployments.StateSucceeded), string(deployments.StateFailed), string(deployments.StateRolledBack))
		if done.State != string(deployments.StateSucceeded) {
			t.Fatalf("deployment ended %s (%s/%s)\nsteps:\n%s%s", done.State, done.StateCode, done.StateReason, m4Timeline(done), w.diagnosis(done))
		}
		if !done.KnownGood {
			t.Error("a succeeded deployment is not known good")
		}
	})

	t.Run("the node runs exactly the attested digest", func(t *testing.T) {
		if got, want := w.runningImage(target), m4ImageRef(digest); got != want {
			t.Fatalf("running image = %q, want %q", got, want)
		}
	})
}
