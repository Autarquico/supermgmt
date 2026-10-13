package deployments_test

import (
	"testing"

	"github.com/autarquico/supermgmt/internal/deployments"
)

func TestRollbackAvailable_Table(t *testing.T) {
	good := deployments.RollbackInputs{
		Mode: deployments.RollbackAutomatic, EnvAllows: true,
		HasKnownGood: true, Kind: deployments.KindDeploy,
	}
	with := func(f func(*deployments.RollbackInputs)) deployments.RollbackInputs {
		in := good
		f(&in)
		return in
	}
	tests := []struct {
		name  string
		in    deployments.RollbackInputs
		ok    bool
		cause string
	}{
		{"all conditions hold", good, true, ""},
		{"manifest automatic keeps automatic", with(func(i *deployments.RollbackInputs) { i.ManifestMode = deployments.RollbackAutomatic }), true, ""},
		{"control plane manual", with(func(i *deployments.RollbackInputs) { i.Mode = deployments.RollbackManual }), false, deployments.CauseManualMode},
		{"manifest manual downgrades", with(func(i *deployments.RollbackInputs) { i.ManifestMode = deployments.RollbackManual }), false, deployments.CauseManualMode},
		{"manifest automatic never upgrades manual", with(func(i *deployments.RollbackInputs) {
			i.Mode, i.ManifestMode = deployments.RollbackManual, deployments.RollbackAutomatic
		}), false, deployments.CauseManualMode},
		{"unknown mode is manual", with(func(i *deployments.RollbackInputs) { i.Mode = "" }), false, deployments.CauseManualMode},
		{"stateful", with(func(i *deployments.RollbackInputs) { i.Stateful = true }), false, deployments.CauseStateful},
		{"environment forbids", with(func(i *deployments.RollbackInputs) { i.EnvAllows = false }), false, deployments.CauseEnvironmentForbids},
		{"first deployment", with(func(i *deployments.RollbackInputs) { i.HasKnownGood = false }), false, deployments.CauseNoKnownGood},
		{"rollback kind", with(func(i *deployments.RollbackInputs) { i.Kind = deployments.KindRollback }), false, deployments.CauseRollbackKind},
		{"empty kind", with(func(i *deployments.RollbackInputs) { i.Kind = "" }), false, deployments.CauseRollbackKind},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, cause := deployments.RollbackAvailable(tt.in)
			if ok != tt.ok || cause != tt.cause {
				t.Errorf("got (%v, %q), want (%v, %q)", ok, cause, tt.ok, tt.cause)
			}
		})
	}
}
