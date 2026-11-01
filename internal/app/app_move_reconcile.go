package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// Reconciliation of an interrupted move, cleanup or abandon (ADR-0041, spec §15). The run reads the node before it
// repeats anything, so the job resumes whatever the evidence says about its last command; the policy only has to
// admit the evidence and requeue.

// Operation names of the move intents (app_move_job_forward.go, app_move_copy.go, app_move_job_compensate.go).
const (
	operationComposeCreate = "compose.create"
	operationComposeStart  = "compose.start"
	operationComposeStop   = "compose.stop"
	operationComposeDown   = "compose.down"
	operationVolumeRm      = "docker.volume_rm"
	operationVolumeImport  = "docker.volume_import"
	operationUpdateRestart = "docker.update_restart"

	// proofImportDeadline names the proof of an import, which has no marker: its deadline plus the kill margin has
	// passed, so the node-side timeout has ended it.
	proofImportDeadline = "import_deadline"
)

var moveOperations = []string{
	operationComposeCreate, operationComposeStart, operationComposeStop, operationComposeDown, operationVolumeRm,
	operationVolumeImport, operationUpdateRestart,
}

// MovePolicy is the jobs.TypePolicy of the three move job types. It never weakens the fixed rule that every
// dispatched intent needs proof; it admits the classifications a move produces and requeues the job while it has
// attempts, because the next run reads each node before it acts.
type MovePolicy struct{}

var _ jobs.TypePolicy = MovePolicy{}

// TypePolicies is Config.TypePolicies for the move job types.
func (p MovePolicy) TypePolicies() map[string]jobs.TypePolicy {
	return map[string]jobs.TypePolicy{appMoveAction: p, appMoveCleanupAction: p, appMoveAbandonAction: p}
}

// Admit lets complete, not started and partial_stable evidence form a pair: a project whose containers moved on
// since the command ran is still proof that the command finished.
func (MovePolicy) Admit(ev jobs.Evidence) bool {
	switch ev.Classification {
	case jobs.ClassComplete, jobs.ClassNotStarted, jobs.ClassPartialStable:
		return true
	case jobs.ClassUnknown:
	}
	return false
}

func (MovePolicy) ClaimMode(context.Context, database.Querier, jobs.Job) (jobs.ClaimMode, error) {
	return jobs.ClaimForward, nil
}

func (MovePolicy) RevalidateRecovery(context.Context, database.Querier, jobs.Job) error {
	return smerr.New(smerr.CodeInternal, "", "a move has no safety recovery")
}

func (MovePolicy) EscalateToRecovery(context.Context, *database.Tx, jobs.Job, error) (bool, error) {
	return false, nil
}

func (MovePolicy) Mirror(context.Context, database.Querier, jobs.Job, domain.JobState, domain.JobState, jobs.ClaimMode, *jobs.Failure) error {
	return nil
}

// Reconcile requeues the job while it has attempts. Without one, a resumable move waits for an operator, who
// resumes it by requesting the move again, and an idempotent job fails.
func (MovePolicy) Reconcile(_ context.Context, _ *database.Tx, job jobs.Job, _ []jobs.Intent, _ map[domain.ID]jobs.Evidence) (jobs.Verdict, error) {
	switch {
	case job.Attempts < job.MaxAttempts:
		return jobs.Verdict{Action: jobs.VerdictRequeued, Reason: "every dispatched command is proven; the next run reads the nodes and continues"}, nil
	case job.RetryClass == domain.RetryIdempotent:
		const reason = "the job was interrupted and its attempts are exhausted"
		return jobs.Verdict{Action: jobs.VerdictFailed, Reason: reason, Failure: &jobs.Failure{Code: smerr.CodeInternal, Message: reason}}, nil
	}
	return jobs.Verdict{Action: jobs.VerdictHeld, Reason: "the move has no attempt left: request it again to resume"}, nil
}

// ---- evidence ------------------------------------------------------------------------------------------------------

// MoveEvidence implements jobs.EvidenceSource for the commands of a move and passes every other intent on. A command
// with a marker is proven by the marker (.done holding exit 0); what it left on the node is the classification:
//
//	compose.create  the project has containers
//	compose.start   every container runs
//	compose.stop    no container runs
//	compose.down    no container is left
//	docker.volume_rm  the volume is gone (when the step names it)
//	docker.update_restart  nothing (its marker alone proves it)
//	docker.volume_import  no marker: its deadline plus the kill margin has passed, so the node's timeout ended it
//
// Anything the node cannot answer is an error, which the reconciler reads as no evidence yet.
type MoveEvidence struct {
	core
	dial func(domain.Node, *runtimes.SetupMeta) (transport.Executor, error)
	next jobs.EvidenceSource
}

var _ jobs.EvidenceSource = (*MoveEvidence)(nil)

// NewMoveEvidence validates cfg. next answers for every intent that is not a move command.
func NewMoveEvidence(cfg Config, conn Connector, next jobs.EvidenceSource) (*MoveEvidence, error) {
	c, err := newCore(cfg)
	if err != nil {
		return nil, err
	}
	if next == nil {
		return nil, errors.New("app: move evidence needs the evidence source of the other intents")
	}
	return &MoveEvidence{core: c, dial: conn.Automated, next: next}, nil
}

// Collect gathers evidence for one dispatched intent.
func (e *MoveEvidence) Collect(ctx context.Context, intent jobs.Intent) (jobs.Evidence, error) {
	if !slices.Contains(moveOperations, intent.Operation) {
		return e.next.Collect(ctx, intent)
	}
	if intent.DispatchedAt == nil {
		return jobs.Evidence{}, fmt.Errorf("intent %s was never dispatched", intent.ID)
	}
	if intent.Operation == operationVolumeImport {
		return e.importEvidence(intent)
	}
	q := e.cfg.DB.Reader()
	dep, err := database.GetDeployment(ctx, q, domain.ID(intent.TargetID))
	if err != nil {
		return jobs.Evidence{}, err
	}
	target, err := database.GetAppTarget(ctx, q, dep.AppTargetID)
	if err != nil {
		return jobs.Evidence{}, err
	}
	node, err := database.GetNode(ctx, q, dep.NodeID)
	if err != nil {
		return jobs.Evidence{}, err
	}
	setup, err := loadSetup(ctx, q, node.ID)
	if err != nil {
		return jobs.Evidence{}, err
	}
	ex, err := e.dial(node, setup)
	if err != nil {
		return jobs.Evidence{}, err
	}
	state, err := markerState(ctx, ex, intent.Marker)
	if err != nil {
		return jobs.Evidence{}, err
	}
	switch state.Kind {
	case templates.MarkerAbsent:
		return markerAbsent(intent), nil
	case templates.MarkerStarted, templates.MarkerDone:
		return e.observed(ctx, ex, target.ComposeProject, intent, state)
	case templates.MarkerUnavailable:
	}
	return jobs.Evidence{}, smerr.New(smerr.CodeCapabilityUnavailable, "", "the node's markers directory cannot be read")
}

// importEvidence is the proof of an import: there is no marker, so only the deadline, which includes the kill
// margin, proves that nothing of it still runs. What it wrote is unknown, so the evidence is partial_stable.
func (e *MoveEvidence) importEvidence(intent jobs.Intent) (jobs.Evidence, error) {
	if e.cfg.Clock.Now().Before(intent.DeadlineAt) {
		return jobs.Evidence{}, fmt.Errorf("the import %s may still run until %s", intent.ID, intent.DeadlineAt.UTC().Format("2006-01-02T15:04:05Z"))
	}
	return withFingerprint(jobs.Evidence{
		Done: true, Proof: proofImportDeadline, Classification: jobs.ClassPartialStable,
		Fingerprint: json.RawMessage(`{"import":"deadline_elapsed"}`),
	}, intent)
}

// moveFingerprint is what two samples must agree on to form a pair.
type moveFingerprint struct {
	Marker   string `json:"marker"`
	Exit     int    `json:"exit"`
	Observed string `json:"observed,omitempty"`
}

func (e *MoveEvidence) observed(ctx context.Context, ex transport.Executor, project string, intent jobs.Intent, state templates.MarkerState) (jobs.Evidence, error) {
	ev := jobs.Evidence{Done: state.Kind == templates.MarkerDone, ExitStatus: state.ExitStatus, Classification: jobs.ClassUnknown}
	fingerprint := moveFingerprint{Marker: string(state.Kind), Exit: state.ExitStatus}
	if ev.Done {
		ev.Proof = jobs.ProofDoneFile
	}
	if state.CompletionProof() {
		var err error
		if ev.Classification, fingerprint.Observed, err = effectOf(ctx, ex, project, intent); err != nil {
			return jobs.Evidence{}, err
		}
	}
	raw, err := json.Marshal(fingerprint)
	if err != nil {
		return jobs.Evidence{}, fmt.Errorf("encode move fingerprint: %w", err)
	}
	ev.Fingerprint = raw
	return withFingerprint(ev, intent)
}

// effectOf judges what the finished command left on the node, and describes it for the fingerprint.
func effectOf(ctx context.Context, ex transport.Executor, project string, intent jobs.Intent) (jobs.Classification, string, error) {
	switch intent.Operation {
	case operationVolumeRm:
		return volumeRmEffect(ctx, ex, intent)
	case operationUpdateRestart:
		return jobs.ClassComplete, "", nil
	}
	out, err := preflightRead(ctx, ex, "compose.ps_state", map[string]string{"project": project})
	if err != nil {
		return "", "", err
	}
	containers, err := templates.ParsePsState(out, project)
	if err != nil {
		return "", "", err
	}
	described := make([]string, len(containers))
	for i, c := range containers {
		described[i] = c.Name + "=" + c.State
	}
	slices.Sort(described)
	observed := strings.Join(described, ",")
	holds := false
	switch intent.Operation {
	case operationComposeCreate:
		holds = len(containers) > 0
	case operationComposeStart:
		holds = len(containers) > 0 && !slices.ContainsFunc(containers, func(c templates.ContainerState) bool { return c.State != "running" })
	case operationComposeStop:
		holds = !slices.ContainsFunc(containers, running)
	case operationComposeDown:
		holds = len(containers) == 0
	}
	if holds {
		return jobs.ClassComplete, observed, nil
	}
	return jobs.ClassPartialStable, observed, nil
}

// volumeRmEffect looks for the volume the step names. A removal whose step names none (the replacement of a failed
// copy recreates the volume at once) is judged by its marker alone.
func volumeRmEffect(ctx context.Context, ex transport.Executor, intent jobs.Intent) (jobs.Classification, string, error) {
	volume, named := strings.CutPrefix(intent.Step, stepCompensateRmPrefix)
	if !named {
		return jobs.ClassComplete, "", nil
	}
	out, err := preflightRead(ctx, ex, "docker.volume_inspect_many", map[string]string{"volumes": volume})
	if err != nil {
		return "", "", err
	}
	found, err := templates.ParseVolumeInspectMany(out)
	if err != nil {
		return "", "", err
	}
	if slices.ContainsFunc(found, func(v templates.Volume) bool { return v.Name == volume }) {
		return jobs.ClassPartialStable, volume + "=present", nil
	}
	return jobs.ClassComplete, volume + "=absent", nil
}
