package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/textsafe"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

const (
	eventAppMoveStarted   = "app_move.started"
	eventAppMoveCommitted = "app_move.committed"
	eventAppMoveHalted    = "app_move.halted"
)

// appMoveHandler runs app_target.move, app_target.cleanup_source and app_target.abandon_move (ADR-0041). The forward
// path of a move (preflight to done) is app_move_job_forward.go; cleanup and abandon are not implemented yet.
//
// A move job walks the phases of its app_moves row, resuming from the one recorded, and sends every node mutation
// through the intent dispatcher of deployments. It works on the nodes the move froze, never on the target's live
// node, which the commit changes.
type appMoveHandler struct {
	core
	// dep supplies what a deployment shares with a move: dialing, frozen content, secrets, the dispatcher's ledger,
	// the health verifier and the sleeper.
	dep  *deployHandler
	conn Connector
	// checkpoint, when set, runs after every durable write of a move run; a test returns an error from it to stop
	// the run at that checkpoint, as a crash would.
	checkpoint func() error
}

func (h appMoveHandler) Run(ctx context.Context, lease jobs.Lease) error {
	job, err := h.dep.store.Get(ctx, h.cfg.DB.Reader(), lease.JobID)
	if err != nil {
		return err
	}
	if job.Type != appMoveAction {
		return smerr.New(smerr.CodeInternal, "", job.Type+" is not implemented yet")
	}
	r, err := h.load(ctx, lease, job)
	if err != nil {
		return err
	}
	return r.run(ctx)
}

// moveNode is one end of the move: the node and what a run needs to work on it.
type moveNode struct {
	node  domain.Node
	setup *runtimes.SetupMeta
	ex    transport.Executor
	root  string
	caps  map[string]bool
}

// moveRun is one attempt of a move job.
type moveRun struct {
	h      appMoveHandler
	lease  jobs.Lease
	job    jobs.Job
	move   database.AppMove
	target database.AppTarget
	app    database.App
	env    domain.Environment
	good   knownGood
	a, b   moveNode
	bDep   database.Deployment // B's deployment; zero until staged
	frozen *frozenDeployment
}

func (h appMoveHandler) load(ctx context.Context, lease jobs.Lease, job jobs.Job) (*moveRun, error) {
	q := h.cfg.DB.Reader()
	if job.PlanID == nil {
		return nil, smerr.New(smerr.CodeInternal, "", "move job has no plan")
	}
	move, err := moveOfPlan(ctx, q, job.Resource.ID, *job.PlanID)
	if err != nil {
		return nil, err
	}
	r := &moveRun{h: h, lease: lease, job: job, move: move}
	if r.target, err = database.GetAppTarget(ctx, q, move.AppTargetID); err != nil {
		return nil, err
	}
	if r.app, err = database.GetApp(ctx, q, r.target.AppID); err != nil {
		return nil, err
	}
	if r.env, err = database.GetEnvironment(ctx, q, r.target.EnvironmentID); err != nil {
		return nil, err
	}
	good, err := database.GetDeployment(ctx, q, move.KnownGoodDeploymentID)
	if err != nil {
		return nil, err
	}
	if r.good, err = loadKnownGood(ctx, q, good); err != nil {
		return nil, err
	}
	if r.a, err = h.dial(ctx, q, move.SourceNodeID); err != nil {
		return nil, err
	}
	if r.b, err = h.dial(ctx, q, move.DestNodeID); err != nil {
		return nil, err
	}
	if move.DestDeploymentID != nil {
		r.bDep, err = database.GetDeployment(ctx, q, *move.DestDeploymentID)
	}
	return r, err
}

// dial reads the node, its recorded setup and capabilities, and reaches it as an unattended job does.
func (h appMoveHandler) dial(ctx context.Context, q database.Querier, id domain.ID) (moveNode, error) {
	node, err := database.GetNode(ctx, q, id)
	if err != nil {
		return moveNode{}, err
	}
	setup, err := loadSetup(ctx, q, id)
	if err != nil {
		return moveNode{}, err
	}
	if setup == nil {
		return moveNode{}, smerr.New(smerr.CodeCapabilityUnavailable, "", "node.setup has not completed on node "+node.Name)
	}
	n := moveNode{node: node, setup: setup, root: templates.DefaultDeployRoot}
	if setup.DeployRoot != "" {
		n.root = setup.DeployRoot
	}
	capabilities, err := database.ListNodeCapabilities(ctx, q, id)
	if err != nil {
		return moveNode{}, err
	}
	n.caps = make(map[string]bool, len(capabilities))
	for _, c := range capabilities {
		n.caps[c.Capability] = c.Available
	}
	n.ex, err = h.dep.dial(node, setup)
	return n, err
}

var errCompensationResumed = errors.New("the move was interrupted while compensating")

func (r *moveRun) run(ctx context.Context) error {
	switch phase := r.move.Phase; {
	case phase == database.AppMoveRolledBack:
		return smerr.New(smerr.CodeConflict, "", "the move was rolled back: request it again")
	case phase.Halted():
		if err := r.unhalt(ctx); err != nil {
			return err
		}
	}
	if strings.HasPrefix(string(r.move.Phase), "compensating_") {
		return r.h.compensate(ctx, r, errCompensationResumed)
	}
	return r.settle(ctx, r.forward(ctx))
}

// unhalt returns a halted move to the phase it held, but only for the first attempt of a job: an automatic retry
// must not undo a halt.
func (r *moveRun) unhalt(ctx context.Context) error {
	if r.job.Attempts > 1 {
		return smerr.New(smerr.CodeConflict, "", fmt.Sprintf("the move is halted (%s); resolve it and run the command again", r.move.LastError))
	}
	return r.change(ctx, func(ctx context.Context, tx *database.Tx) (database.AppMove, error) {
		return database.ResumeHaltedAppMove(ctx, tx, r.move.ID, r.move.Phase, r.h.cfg.Clock.Now())
	})
}

// compensate undoes a move that failed before its commit (spec §7, phases compensating_*). It is filled in with
// the compensation; until then the failure ends the job and leaves the move where it stopped.
func (h appMoveHandler) compensate(_ context.Context, _ *moveRun, cause error) error {
	return cause
}

// settle decides what a failure of the forward path means. A failure that ends the move for good compensates it
// before the commit and halts it after, when nothing can be undone; any other failure is left to the job's retry.
func (r *moveRun) settle(ctx context.Context, err error) error {
	if err == nil || !r.ends(ctx, err) {
		return err
	}
	if !pastCommit(r.move) {
		return r.h.compensate(ctx, r, err)
	}
	if herr := r.halt(ctx, err); herr != nil {
		return errors.Join(err, herr)
	}
	return err
}

// ends reports whether err settles the move: a definite, typed refusal, or the failure of the job's last attempt.
// A shutdown, a lost lease, an unknown outcome and a node that does not answer leave the move as it is for the retry.
func (r *moveRun) ends(ctx context.Context, err error) bool {
	if ctx.Err() != nil || errors.Is(err, jobs.ErrOutcomeUnknown) || errors.Is(err, jobs.ErrLeaseLost) {
		return false
	}
	if code := smerr.CodeOf(err); isTyped(err) && code != smerr.CodeNodeUnreachable && code != smerr.CodeTimeout {
		return true
	}
	return r.job.RetryClass != domain.RetryIdempotent || r.job.Attempts >= r.job.MaxAttempts
}

// ---- the move record -------------------------------------------------------------------------------------------

// fenced runs fn in a write transaction whose first statement is the lease fence.
func (r *moveRun) fenced(ctx context.Context, fn func(ctx context.Context, tx *database.Tx) error) error {
	if err := r.h.dep.fenced(ctx, r.lease, fn); err != nil {
		return err
	}
	if r.h.checkpoint != nil {
		return r.h.checkpoint()
	}
	return nil
}

// change applies a fenced change of the move row and keeps the result.
func (r *moveRun) change(ctx context.Context, step func(ctx context.Context, tx *database.Tx) (database.AppMove, error)) error {
	var changed database.AppMove
	err := r.fenced(ctx, func(ctx context.Context, tx *database.Tx) error {
		var err error
		changed, err = step(ctx, tx)
		return err
	})
	if err == nil {
		r.move = changed
	}
	return err
}

// advance moves the move to phase to, with an audit event in the same fenced transaction when event is not empty.
func (r *moveRun) advance(ctx context.Context, to database.AppMovePhase, event string) error {
	return r.change(ctx, func(ctx context.Context, tx *database.Tx) (database.AppMove, error) {
		next, err := database.AdvanceAppMovePhase(ctx, tx, r.move.ID, r.move.Phase, to, r.h.cfg.Clock.Now())
		if err != nil || event == "" {
			return next, err
		}
		return next, r.emitMove(ctx, tx, event, domain.ResultSucceeded, map[string]any{"phase": string(to)})
	})
}

// halt records that the move stopped after its commit, with a sanitized message and the audit event.
func (r *moveRun) halt(ctx context.Context, cause error) error {
	message := textsafe.Line(audit.ScrubString(cause.Error()))
	if utf8.RuneCountInString(message) > maxRecordedErrorLength {
		message = string([]rune(message)[:maxRecordedErrorLength])
	}
	phase := r.move.Phase
	return r.change(context.WithoutCancel(ctx), func(ctx context.Context, tx *database.Tx) (database.AppMove, error) {
		halted, err := database.HaltAppMove(ctx, tx, r.move.ID, phase, database.AppMoveFailed, message, r.h.cfg.Clock.Now())
		if err != nil {
			return halted, err
		}
		return halted, r.emitMove(ctx, tx, eventAppMoveHalted, domain.ResultFailed, map[string]any{"phase": string(phase)})
	})
}

func (r *moveRun) emitMove(ctx context.Context, tx *database.Tx, action string, result domain.Result, data map[string]any) error {
	actor, err := loadActor(ctx, tx, r.job.ActorID, credentialOf(r.job))
	if err != nil {
		return err
	}
	data["move_id"], data["job_id"] = r.move.ID.String(), r.job.ID.String()
	data["source_node_id"], data["dest_node_id"] = r.move.SourceNodeID.String(), r.move.DestNodeID.String()
	return r.h.emit(ctx, tx, actor, action, appTargetRef(r.target.ID), result, data)
}

// ---- B's deployment --------------------------------------------------------------------------------------------

// destJob is B's deployment as the deployment handler's step executors take it.
func (r *moveRun) destJob() *deployJob {
	return &deployJob{
		lease: r.lease, job: r.job, dep: r.bDep, target: r.target, app: r.app, env: r.env, node: r.b.node, ex: r.b.ex,
		root: r.b.root, caps: r.b.caps, mode: deployments.RecoveryForward,
	}
}

// freeze reads the known-good content the move carries and resolves its secret versions, once per run.
func (r *moveRun) freeze(ctx context.Context) (frozenDeployment, error) {
	if r.frozen == nil {
		fz, err := r.h.dep.freeze(ctx, r.good.plan.Content)
		if err != nil {
			return frozenDeployment{}, err
		}
		r.frozen = &fz
	}
	return *r.frozen, nil
}
