package app

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/plan"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
)

// Revalidation of deployment plans (ADR-0007). A deployment plan binds content
// that lives in immutable snapshot rows, so a claim compares only what can
// change under it: the configured inputs and the authorization of the requester.
//
//	forward   deployment.create: inputs rebuilt from the database, every snapshot
//	          row and bound secret version still present.
//	rollback  deployment.rollback: the same authorization inputs, but the content
//	          is the known-good deployment's frozen rows; the app's current
//	          Compose source, health and secrets are not compared.
//	recovery  safety recovery by the system: only checks that the frozen
//	          restoration target can still be restored (RevalidateRecovery).

// causeNodePinChanged is recorded next to ROLLBACK_UNAVAILABLE when the node's
// endpoint or host key is no longer the one the plan pinned.
const causeNodePinChanged = "NODE_PIN_CHANGED"

// rebuildForwardDeployment recomputes a deployment.create plan from the
// database; any configured input that moved makes it stale (PLAN_STALE).
func rebuildForwardDeployment(ctx context.Context, q database.Querier, rec database.PlanRecord) (built, error) {
	stored, scope, err := loadStoredDeployment(ctx, q, rec)
	if err != nil {
		return built{}, err
	}
	if err := requireSnapshotRows(ctx, q, stored.Content); err != nil {
		return built{}, err
	}
	if err := requireBoundSecretVersions(ctx, q, stored.Content.SecretBindings); err != nil {
		return built{}, err
	}
	current, err := buildDeploymentPlan(ctx, q, deploymentPlanSpec{
		action: rec.Action, requester: rec.ActorID, scope: scope, content: stored.Content,
		secrets: secretInputsOf(stored.Content.SecretBindings), includeApp: true, backup: planHasBackup(stored),
	})
	if err != nil {
		return built{}, err
	}
	return current, requireSamePlan(current, rec)
}

// rebuildRollbackDeployment recomputes a deployment.rollback plan from the
// known-good deployment's frozen rows. The target's own spec revision is taken
// from the plan: editing the target's policy (health, bind addresses) changes
// what the next deploy does, never what a rollback redeploys.
func rebuildRollbackDeployment(ctx context.Context, q database.Querier, rec database.PlanRecord, job jobs.Job) (built, error) {
	stored, scope, err := loadStoredDeployment(ctx, q, rec)
	if err != nil {
		return built{}, err
	}
	dep, err := database.GetDeploymentByJob(ctx, q, job.ID)
	if err != nil {
		return built{}, err
	}
	if dep.PreviousDeploymentID == nil {
		return built{}, smerr.New(smerr.CodeInternal, "", "rollback deployment names no deployment to return to")
	}
	good, err := database.GetDeployment(ctx, q, *dep.PreviousDeploymentID)
	if err != nil {
		return built{}, err
	}
	kg, err := loadKnownGood(ctx, q, good)
	if err != nil {
		return built{}, err
	}
	scope.target.SpecRevision = *stored.Targets[0].SpecRevision
	current, err := buildDeploymentPlan(ctx, q, deploymentPlanSpec{
		action: rec.Action, requester: rec.ActorID, scope: scope, content: rollbackContent(kg),
		secrets: secretInputsOf(kg.plan.Content.SecretBindings), backup: kg.policy.PreDeployBackup != nil,
	})
	if err != nil {
		return built{}, err
	}
	return current, requireSamePlan(current, rec)
}

// loadStoredDeployment parses the stored plan and loads the scope of its one
// target. A target or app that no longer exists makes the plan stale.
func loadStoredDeployment(ctx context.Context, q database.Querier, rec database.PlanRecord) (plan.Plan, deploymentScope, error) {
	stored, err := plan.Parse(rec.PlanJSON)
	if err != nil {
		return plan.Plan{}, deploymentScope{}, err
	}
	if len(stored.Targets) != 1 || stored.Targets[0].SpecRevision == nil {
		return plan.Plan{}, deploymentScope{}, smerr.New(smerr.CodeInternal, "", "stored deployment plan must have exactly one revisioned target")
	}
	scope, err := loadDeploymentScope(ctx, q, domain.ID(stored.Targets[0].ID))
	if smerr.CodeOf(err) == smerr.CodeNotFound {
		return plan.Plan{}, deploymentScope{}, planStale()
	}
	return *stored, scope, err
}

func planHasBackup(p plan.Plan) bool {
	return slices.ContainsFunc(p.SubActions, func(s plan.SubAction) bool {
		return s.Action == policy.ActionNodeBackupTemplateRun
	})
}

func requireSamePlan(current built, rec database.PlanRecord) error {
	hash, err := plan.Hash(&current.plan)
	if err != nil {
		return err
	}
	if hash != rec.PlanHash {
		return planStale()
	}
	return nil
}

// requireSnapshotRows re-reads every snapshot the plan binds; a worker executes
// these rows, so a missing or altered one stops the claim (STAGING_FAILED).
func requireSnapshotRows(ctx context.Context, q database.Querier, c plan.Content) error {
	for _, hash := range []*string{c.ComposeHash, c.ExceptionsHash, c.HealthHash, c.DeploymentPolicyHash} {
		if hash == nil {
			return revalidationStagingFailed(deployments.CauseSnapshotGone, "the plan names no snapshot")
		}
		_, err := database.GetExecutionSnapshot(ctx, q, *hash)
		switch {
		case smerr.CodeOf(err) == smerr.CodeNotFound:
			return revalidationStagingFailed(deployments.CauseSnapshotGone, "snapshot %s no longer exists", *hash)
		case errors.Is(err, smerr.FromReason(smerr.ReasonStagingFailed, "")):
			return revalidationStagingFailed(deployments.CauseSnapshotMismatch, "snapshot %s no longer matches its hash", *hash)
		case err != nil:
			return err
		}
	}
	return nil
}

// requireBoundSecretVersions fails when a bound version is gone: a deployment
// never runs with a newer value than the one it was approved with (ADR-0008).
func requireBoundSecretVersions(ctx context.Context, q database.Querier, bindings []plan.SecretBinding) error {
	for _, b := range bindings {
		_, err := database.GetSecret(ctx, q, b.SecretID, int(b.Version))
		if smerr.CodeOf(err) == smerr.CodeNotFound {
			return revalidationStagingFailed(deployments.CauseSecretVersionGone, "version %d of secret %s no longer exists", b.Version, b.SecretID)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func revalidationStagingFailed(cause, format string, args ...any) *smerr.Error {
	e := smerr.FromReason(smerr.ReasonStagingFailed, fmt.Sprintf(format, args...))
	e.Details = map[string]any{"cause": cause}
	return e
}

// RevalidateRecovery is the claim check of a safety recovery (ADR-0029): the
// system restores the plan's frozen rollback target, so neither the requester's
// credential, nor policy, nor the approval quorum are consulted. It fails only
// when the restoration target is no longer restorable: its snapshot rows or
// secret versions are gone, or the node is no longer the one the plan pinned.
func (*Revalidator) RevalidateRecovery(ctx context.Context, q database.Querier, job jobs.Job) error {
	if job.PlanID == nil {
		return smerr.New(smerr.CodeInternal, "", "job has no plan to recover")
	}
	rec, err := database.GetPlan(ctx, q, *job.PlanID)
	if err != nil {
		return err
	}
	stored, err := plan.Parse(rec.PlanJSON)
	if err != nil {
		return err
	}
	dep, err := database.GetDeploymentByJob(ctx, q, job.ID)
	if err != nil {
		return err
	}
	target, err := frozenRecoveryTarget(*stored, dep)
	if err != nil {
		return err
	}
	good, err := database.GetDeployment(ctx, q, target)
	if err != nil {
		return err
	}
	if good.ComposeHash != stored.Content.RollbackTarget.ComposeHash {
		return rollbackUnavailable(deployments.CauseSnapshotMismatch, "deployment %s no longer has the model the plan froze", good.ID)
	}
	if _, err := loadKnownGood(ctx, q, good); err != nil {
		return err
	}
	return requirePinnedNode(ctx, q, *stored, dep.NodeID)
}

// frozenRecoveryTarget is the deployment the recovery record names, which must
// be the one the plan froze at finalization, never a newer known-good.
func frozenRecoveryTarget(p plan.Plan, dep database.Deployment) (domain.ID, error) {
	frozen := p.Content.RollbackTarget
	switch {
	case dep.Recovery == nil || dep.Recovery.Mode != deployments.RecoverySafetyRecovery || dep.Recovery.Target == nil:
		return "", smerr.New(smerr.CodeInternal, "", "deployment has no safety recovery record")
	case frozen == nil || frozen.DeploymentID != dep.Recovery.Target.String():
		return "", smerr.New(smerr.CodeInternal, "", "recovery target is not the plan's frozen rollback target")
	}
	return *dep.Recovery.Target, nil
}

// requirePinnedNode compares the node's endpoint and host key with the plan's
// pin. The node's spec revision is left out: tags and labels may change.
func requirePinnedNode(ctx context.Context, q database.Querier, p plan.Plan, nodeID domain.ID) error {
	node, err := database.GetNode(ctx, q, nodeID)
	if err != nil {
		return err
	}
	current, err := nodeInput(node)
	if err != nil {
		return rollbackUnavailable(causeNodePinChanged, "the node's host key is unreadable: %v", err)
	}
	for _, in := range p.Inputs {
		if in.Type != string(domain.ResourceNode) || in.ID != nodeID.String() {
			continue
		}
		if in.Endpoint != nil && current.Endpoint != nil && *in.Endpoint == *current.Endpoint &&
			in.HostPublicKeySHA256 != nil && *in.HostPublicKeySHA256 == *current.HostPublicKeySHA256 {
			return nil
		}
		break
	}
	return rollbackUnavailable(causeNodePinChanged, "node %s no longer has the endpoint and host key the plan pinned", nodeID)
}
