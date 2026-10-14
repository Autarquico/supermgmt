package app

import (
	"context"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// mcpDeployer is an mcp identity whose role (deployer) permits every
// deployment action, so only the MCP gate can refuse it.
func (f *finFixture) mcpDeployer() Caller {
	f.t.Helper()
	var id domain.ID
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		id = f.identity(ctx, tx, "assistant", domain.ActorMCP, f.role(ctx, tx, "deployer"))
		return nil
	})
	return f.caller(id)
}

// sideEffects counts what an admitted request would have left behind.
type sideEffects struct{ deployments, jobs, plans, githubReads int }

func (f *finFixture) sideEffects() sideEffects {
	return sideEffects{f.rowCount("deployments"), f.rowCount("jobs"), f.rowCount("plans"), len(f.gh.reads)}
}

func TestDeploymentAdmission_MCPWithWritesOffLeavesNothingBehind(t *testing.T) {
	f := newFinFixture(t, finOptions{pinned: true, gated: true})
	good := f.goodDeployment(depCommit)
	mcp := f.mcpDeployer()
	waiting := f.create()
	before := f.sideEffects()

	_, createErr := f.deployments.Create(context.Background(), mcp, f.request(func(r *CreateDeployment) { r.CommitSHA = depOtherCommit }))
	_, rollbackErr := f.final.Rollback(context.Background(), mcp, good.ID, wire.RollbackRequest{})
	_, cancelErr := f.deployments.Cancel(context.Background(), mcp, waiting.ID)

	for name, err := range map[string]error{"create": createErr, "rollback": rollbackErr, "cancel": cancelErr} {
		t.Run(name, func(t *testing.T) { wantError(t, err, smerr.CodePolicyDenied, smerr.ReasonMCPWritesDisabled) })
	}
	if after := f.sideEffects(); after != before {
		t.Errorf("side effects = %+v, want unchanged %+v", after, before)
	}
	if got := f.row(waiting.ID).State; got != deployments.StateWaitingCI {
		t.Errorf("a refused cancel moved the deployment to %s", got)
	}
	if denied := f.events("policy.deny"); len(denied) != 3 {
		t.Errorf("policy.deny events = %d, want the three refusals audited", len(denied))
	}
}

func TestDeploymentAdmission_MCPWithWritesOnIsJudgedByPolicy(t *testing.T) {
	f := newFinFixture(t, finOptions{pinned: true, gated: true})
	f.deployments.cfg.MCPWritesEnabled = true
	mcp := f.mcpDeployer()

	created, err := f.deployments.Create(context.Background(), mcp, f.request())
	mustf(t, err, "Create")
	_, err = f.deployments.Cancel(context.Background(), mcp, created.ID)

	mustf(t, err, "Cancel")
}

func TestDeploymentAdmission_AHumanDeniedByPolicyLeavesNothingBehind(t *testing.T) {
	f := newFinFixture(t, finOptions{pinned: true, gated: true})
	good := f.goodDeployment(depCommit)
	before := f.sideEffects()

	_, err := f.final.Rollback(context.Background(), f.caller(f.dave), good.ID, wire.RollbackRequest{})

	wantAppsCode(t, err, smerr.CodePolicyDenied)
	if after := f.sideEffects(); after != before {
		t.Errorf("side effects = %+v, want unchanged %+v", after, before)
	}
}
