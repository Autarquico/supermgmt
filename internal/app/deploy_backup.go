package app

import (
	"context"
	"encoding/json"
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
	ledger intentLedger
	clock  domain.Clock
	ids    domain.IDGenerator
	gate   backupSubActionGate
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
func (b backupStep) run(ctx context.Context, ex transport.Executor, req backupRequest) (string, error) {
	if err := b.authorize(ctx, req); err != nil {
		return "", err
	}
	marker := b.ids.NewID().String()
	cmd, err := templates.RenderMutating(backupTemplate, marker, req.Args)
	if err != nil {
		return "", backupFailed("the backup arguments were refused: %v", err)
	}
	dispatcher := commandDispatcher{Node: ex, Ledger: b.ledger, Clock: b.clock}
	sent, err := dispatcher.send(ctx, nodeCommand{
		Step: deployments.StepPreDeployBackup, Operation: policy.ActionNodeBackupTemplateRun, Deployment: req.Deployment,
		Marker: marker, Command: cmd, RunTimeout: req.Timeout,
	})
	if err != nil {
		return "", err
	}
	res := sent.Result
	switch {
	case sent.TimedOut:
		return "", b.fail(ctx, dispatcher, sent, "the backup exceeded its timeout of %s", req.Timeout)
	case res.ExitStatus != 0:
		return "", b.fail(ctx, dispatcher, sent, "the backup exited with status %d", res.ExitStatus)
	case res.Truncated:
		return "", b.fail(ctx, dispatcher, sent, "the backup output was cut before its last line")
	}
	artifact, err := templates.ParseBackupPath(res.Stdout)
	if err != nil {
		return "", b.fail(ctx, dispatcher, sent, "the backup did not print a valid artifact path")
	}
	if err := b.ledger.CompleteIntent(ctx, sent.Intent, jobs.OutcomeSucceeded, backupDoneEvidence(artifact)); err != nil {
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
func (b backupStep) fail(ctx context.Context, d commandDispatcher, sent sentCommand, format string, args ...any) error {
	if err := d.closeFailed(ctx, sent.Intent, sent.Result.ExitStatus); err != nil {
		return err
	}
	return backupFailed(format, args...)
}

// backupDoneEvidence is the proven exit evidence of a finished backup plus the
// artifact it printed.
func backupDoneEvidence(artifact string) json.RawMessage {
	var proven map[string]any
	_ = json.Unmarshal(commandExitEvidence(jobs.OutcomeSucceeded, 0), &proven)
	proven["artifact"] = artifact
	raw, _ := json.Marshal(proven)
	return raw
}

func backupFailed(format string, args ...any) error {
	e := smerr.FromReason(smerr.ReasonStagingFailed, fmt.Sprintf(format, args...))
	e.Details = map[string]any{"cause": deployments.CauseBackupFailed}
	return e
}
