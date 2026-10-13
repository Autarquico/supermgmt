package app

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/plan"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const deploymentRollbackAction = "deployment.rollback"

// Rollback requests a manual rollback of the deployment id (action
// deployment.rollback, ADR-0011): a new kind: rollback deployment on the same
// app target that redeploys a known-good deployment, the newest one older than
// id unless req names one. Its plan freezes that deployment's snapshots, digests
// and exact secret versions (ADR-0007 rollback mode); there is no CI gate, so it
// is finalized at once. A snapshot or secret version that no longer exists makes
// the rollback unavailable before anything is enqueued.
func (f *DeploymentFinalizer) Rollback(ctx context.Context, by Caller, id domain.ID, req wire.RollbackRequest) (DeploymentView, error) {
	return commit(ctx, f.core, by, func(ctx context.Context, tx *database.Tx) (DeploymentView, error) {
		actor, err := f.beginRequest(ctx, tx, by)
		if err != nil {
			return DeploymentView{}, err
		}
		source, err := database.GetDeployment(ctx, tx, id)
		if err != nil {
			return DeploymentView{}, err
		}
		scope, err := loadDeploymentScope(ctx, tx, source.AppTargetID)
		if err != nil {
			return DeploymentView{}, err
		}
		if err := f.authorizeAdmission(ctx, tx, actor, deploymentRollbackAction, scope); err != nil {
			return DeploymentView{}, err
		}
		good, err := rollbackSource(ctx, tx, source, req.ToDeploymentID)
		if err != nil {
			return DeploymentView{}, err
		}
		kg, err := loadKnownGood(ctx, tx, good)
		if err != nil {
			return DeploymentView{}, err
		}
		b, err := buildDeploymentPlan(ctx, tx, deploymentPlanSpec{
			action: deploymentRollbackAction, requester: by.ID, scope: scope, content: rollbackContent(kg),
			secrets: secretInputsOf(kg.plan.Content.SecretBindings), backup: kg.policy.PreDeployBackup != nil,
		})
		if err != nil {
			return DeploymentView{}, err
		}
		res, err := f.decide(ctx, tx, actor, b)
		if err != nil {
			return DeploymentView{}, err
		}
		if err := decisionError(res); err != nil {
			return DeploymentView{}, reject(err)
		}
		row, err := f.insertRollback(ctx, tx, by, actor, source, good, scope)
		if err != nil {
			return DeploymentView{}, err
		}
		if err := f.enqueue(ctx, tx, row, b, res, good.ComposeHash); err != nil {
			return DeploymentView{}, err
		}
		queued, err := database.GetDeployment(ctx, tx, row.ID)
		if err != nil {
			return DeploymentView{}, err
		}
		return f.viewOf(ctx, tx, queued)
	})
}

// rollbackSource picks the known-good deployment to return to.
func rollbackSource(ctx context.Context, q database.Querier, source database.Deployment, to *domain.ID) (database.Deployment, error) {
	if to == nil {
		good, err := database.NewestKnownGood(ctx, q, source.AppTargetID, &source.ID)
		if smerr.CodeOf(err) == smerr.CodeNotFound {
			return database.Deployment{}, rollbackUnavailable(deployments.CauseNoKnownGood, "no known-good deployment precedes %s on this target", source.ID)
		}
		return good, err
	}
	good, err := database.GetDeployment(ctx, q, *to)
	if err != nil {
		return database.Deployment{}, err
	}
	if good.AppTargetID != source.AppTargetID || !good.KnownGood {
		return database.Deployment{}, invalidArgument("to_deployment_id is not a known-good deployment of this target")
	}
	return good, nil
}

// rollbackContent is the content of the known-good plan, to the last hash and
// secret version. It has no rollback target of its own: a rollback never rolls
// back automatically (spec §20.1).
func rollbackContent(kg knownGood) plan.Content {
	c := kg.plan.Content
	c.Images = slices.Clone(c.Images)
	c.HostPorts = slices.Clone(c.HostPorts)
	c.SecretBindings = slices.Clone(c.SecretBindings)
	c.RollbackTarget = nil
	return c
}

func secretInputsOf(bindings []plan.SecretBinding) []plan.Input {
	versions := make(map[string]int64, len(bindings))
	for _, b := range bindings {
		versions[b.SecretID] = b.Version
	}
	return secretInputs(versions)
}

// insertRollback records the rollback deployment: it returns to good, and
// reverts source.
func (f *DeploymentFinalizer) insertRollback(ctx context.Context, tx *database.Tx, by Caller, actor domain.Actor, source, good database.Deployment, scope deploymentScope) (database.Deployment, error) {
	requested, err := requestedFromRefs(good)
	if err != nil {
		return database.Deployment{}, err
	}
	now := f.cfg.Clock.Now()
	row := database.Deployment{
		ID: f.cfg.IDs.NewID(), Kind: deployments.KindRollback, AppID: scope.app.ID, AppTargetID: scope.target.ID,
		EnvironmentID: scope.env.ID, NodeID: scope.target.NodeID, ArtifactID: good.ArtifactID,
		State: deployments.StateCreated, RequestedBy: by.ID, PreviousDeploymentID: &good.ID,
		RollbackOfDeploymentID: &source.ID, CommitSha: good.CommitSha, RequestedRaw: requested,
		Credential: by.Credential, CreatedAt: now, UpdatedAt: now,
	}
	ctx = audit.WithCorrelationID(ctx, row.ID)
	if err := database.InsertDeployment(ctx, tx, row); err != nil {
		return database.Deployment{}, err
	}
	data := map[string]any{
		"app_target_id": scope.target.ID.String(), "commit_sha": row.CommitSha, "kind": row.Kind,
		"rollback_of": source.ID.String(), "known_good": good.ID.String(), "credential_kind": string(by.Credential.Kind),
	}
	return row, f.emit(ctx, tx, actor, eventDeploymentCreated, deploymentResource(row.ID), domain.ResultSucceeded, data)
}

// requestedFromRefs restates the images of a known-good deployment as the
// request a deployment of them would have made.
func requestedFromRefs(good database.Deployment) (json.RawMessage, error) {
	if len(good.RequestedRaw) == 0 {
		return nil, fmt.Errorf("known-good deployment %s has no recorded images", good.ID)
	}
	var images []wire.RequestedImage
	if err := json.Unmarshal(good.RequestedRaw, &images); err != nil {
		return nil, fmt.Errorf("stored requested images are unreadable: %w", err)
	}
	slices.SortFunc(images, func(a, b wire.RequestedImage) int { return strings.Compare(a.Service, b.Service) })
	return json.Marshal(images)
}
