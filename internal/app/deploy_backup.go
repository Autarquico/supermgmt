package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/plan"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

const (
	backupTemplate   = "postgres-dump" // the only backup template in M4 (ADR-0029)
	backupTimeoutCap = time.Hour       // the node-side cap of the template
	backupIntentKind = "deployment"
)

// backupSubActionGate re-evaluates the plan's backup sub-action under the
// policy in force (spec §11.3). A denial stops the step before the node is
// reached.
type backupSubActionGate func(ctx context.Context, sub plan.SubAction) error

// backupRequest is the pre-deploy backup of one deployment, read from the
// persisted plan and the policy snapshot.
type backupRequest struct {
	Deployment domain.ID
	Plan       plan.Plan
	Template   string
	Args       map[string]string
	Timeout    time.Duration // pre_deploy_backup.timeout
}

// backupStep runs the pre-deploy backup (spec §19.1, ADR-0029).
type backupStep struct {
	store *jobs.Store
	clock domain.Clock
	ids   domain.IDGenerator
	gate  backupSubActionGate
}

// run records a fenced intent, dispatches postgres-dump under the policy
// timeout and returns the artifact path it printed on its last line (the
// step's output_ref). Any failure returns an error and no path, so the
// handler never proceeds to pull or compose up:
//
//   - denied or missing sub-action, bad request: nothing is dispatched;
//   - non-zero exit, timeout, missing or out-of-pattern path: the intent is
//     closed as failed;
//   - a lost connection or an interrupted run: the intent stays recorded and
//     the error wraps jobs.ErrOutcomeUnknown, so the reconciler decides.
func (b backupStep) run(ctx context.Context, ex transport.Executor, lease jobs.Lease, req backupRequest) (string, error) {
	if err := b.authorize(ctx, req); err != nil {
		return "", err
	}
	marker := b.ids.NewID().String()
	cmd, err := templates.RenderMutating(backupTemplate, marker, req.Args)
	if err != nil {
		return "", backupFailed("the backup arguments were refused: %v", err)
	}
	intent, err := b.store.RecordIntent(ctx, lease, jobs.NewIntent{
		Step: deployments.StepPreDeployBackup, Operation: policy.ActionNodeBackupTemplateRun,
		TargetType: backupIntentKind, TargetID: req.Deployment.String(),
		Marker: marker, DeadlineAt: b.clock.Now().Add(cmd.Deadline),
	})
	if err != nil {
		return "", err
	}
	if err := b.store.MarkDispatched(ctx, lease, intent.ID); err != nil {
		return "", err
	}
	runCtx, cancel := context.WithTimeout(ctx, req.Timeout)
	defer cancel()
	res, runErr := ex.Run(runCtx, cmd)
	switch {
	case runErr != nil && runCtx.Err() != nil && ctx.Err() == nil:
		return "", b.fail(ctx, lease, intent.ID, "the backup exceeded its timeout of %s", req.Timeout)
	case runErr != nil:
		return "", backupOutcomeUnknown(runErr)
	case res.ExitStatus != 0:
		return "", b.fail(ctx, lease, intent.ID, "the backup exited with status %d", res.ExitStatus)
	case res.Truncated:
		return "", b.fail(ctx, lease, intent.ID, "the backup output was cut before its last line")
	}
	artifact, err := templates.ParseBackupPath(res.Stdout)
	if err != nil {
		return "", b.fail(ctx, lease, intent.ID, "the backup did not print a valid artifact path")
	}
	if err := b.complete(ctx, lease, intent.ID, jobs.OutcomeSucceeded, map[string]string{"artifact": artifact}); err != nil {
		return "", err
	}
	return artifact, nil
}

// authorize refuses what must never reach the node: another template, a
// timeout outside (0, 1h], a plan without the backup sub-action, or a policy
// that no longer allows it.
func (b backupStep) authorize(ctx context.Context, req backupRequest) error {
	if req.Template != backupTemplate {
		return backupFailed("backup template %q is not supported", req.Template)
	}
	if req.Timeout <= 0 || req.Timeout > backupTimeoutCap {
		return backupFailed("the backup timeout must be between 0 and %s", backupTimeoutCap)
	}
	for _, sub := range req.Plan.SubActions {
		if sub.Action == policy.ActionNodeBackupTemplateRun {
			if err := b.gate(ctx, sub); err != nil {
				return fmt.Errorf("backup sub-action: %w", err)
			}
			return nil
		}
	}
	return backupFailed("the plan carries no %s sub-action", policy.ActionNodeBackupTemplateRun)
}

// fail closes the intent as failed and returns the typed deployment error.
// The node's output is never part of the message: it is untrusted (spec §30).
func (b backupStep) fail(ctx context.Context, lease jobs.Lease, intent domain.ID, format string, args ...any) error {
	reason := fmt.Sprintf(format, args...)
	if err := b.complete(ctx, lease, intent, jobs.OutcomeFailed, map[string]string{"reason": reason}); err != nil {
		return err
	}
	return backupFailed("%s", reason)
}

func (b backupStep) complete(ctx context.Context, lease jobs.Lease, intent domain.ID, outcome string, evidence any) error {
	raw, err := json.Marshal(evidence)
	if err != nil {
		return fmt.Errorf("encode backup evidence: %w", err)
	}
	return b.store.CompleteIntent(ctx, lease, intent, outcome, raw)
}

func backupFailed(format string, args ...any) error {
	e := smerr.FromReason(smerr.ReasonStagingFailed, fmt.Sprintf(format, args...))
	e.Details = map[string]any{"cause": deployments.CauseBackupFailed}
	return e
}

func backupOutcomeUnknown(cause error) error {
	return smerr.Wrap(errors.Join(jobs.ErrOutcomeUnknown, cause), smerr.CodeNodeUnreachable, "",
		"the pre-deploy backup was dispatched but its outcome could not be established")
}
