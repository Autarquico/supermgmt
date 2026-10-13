//go:build e2e && fixtures

package e2e_test

import (
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/deployments"
)

const (
	rollbackGoodCommit = "3333333333333333333333333333333333333333"
	rollbackBadCommit  = "4444444444444444444444444444444444444444"
)

// rollbackPolicy declares rollback safe (automatic, stateless, no backup) and checks the app over HTTP.
func rollbackPolicy() wire.DeploymentPolicy {
	return wire.DeploymentPolicy{
		Rollback: "automatic",
		Health:   &wire.HealthCheck{Type: "http", Scope: "node", Port: m4AppPort, Path: "/health", Timeout: "3s", Interval: "2s", Attempts: 4},
	}
}

// TestM4_HealthFailureRollsBackToKnownGood
//
// Spec scenario "rollback por health check fallido" (PLAN §9 row 3): a first deployment is healthy
// and known good; the next one answers 503 on its health path, so the node returns to the first
// image and the failed one is never known good.
func TestM4_HealthFailureRollsBackToKnownGood(t *testing.T) {
	w := newM4ServerWorld(t)
	provider, node := w.waitForStaticConfig()
	w.sim.addShopRepository()
	w.deployAllowAutomaticRollback()
	w.prepareNode(node)
	target := w.deployCreateApp(deployAppRequest(provider, m4AppName), node, rollbackPolicy())

	good := w.sim.pushImage(m4Image{Version: "good"})
	bad := w.sim.pushImage(m4Image{Version: "bad", Unhealthy: true})
	w.sim.attest(good, rollbackGoodCommit)
	w.sim.attest(bad, rollbackBadCommit)

	first := w.deployShop(target, rollbackGoodCommit, good)
	w.deployTellCIPassed(rollbackGoodCommit, 1)
	first = w.deploySucceeded(first)
	if !first.KnownGood {
		t.Fatal("the healthy first deployment is not known good")
	}

	second := w.deployShop(target, rollbackBadCommit, bad)
	w.deployTellCIPassed(rollbackBadCommit, 2)
	finished := w.waitDeployment(second.ID, m4DeployTimeout, string(deployments.StateSucceeded), string(deployments.StateFailed),
		string(deployments.StateRolledBack), string(deployments.StateRollbackFailed))

	t.Run("the deployment whose health check fails ends rolled back", func(t *testing.T) {
		if finished.State != string(deployments.StateRolledBack) {
			t.Fatalf("deployment ended %s (%s/%s), want rolled_back\nsteps:\n%s%s",
				finished.State, finished.StateCode, finished.StateReason, m4Timeline(finished), w.diagnosis(finished))
		}
	})
	t.Run("the node runs the previous good version again", func(t *testing.T) {
		if got, want := w.runningImage(target), m4ImageRef(good); got != want {
			t.Fatalf("running image = %q, want %q", got, want)
		}
	})
	t.Run("only the previous version stays known good", func(t *testing.T) {
		if finished.KnownGood {
			t.Error("a rolled-back deployment is known good")
		}
		again, err := w.api.GetDeployment(w.ctx(), first.ID)
		if err != nil {
			t.Fatal(err)
		}
		if !again.KnownGood {
			t.Error("the previous deployment lost its known-good mark")
		}
	})
}
