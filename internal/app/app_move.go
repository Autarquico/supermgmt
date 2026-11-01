package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/policy"
)

// The actions of a move (ADR-0041). A move is requested through AppMoves, never through POST /plans: its record is
// written together with its plan and job.
const (
	appMoveAction        = policy.ActionAppTargetMove
	appMoveCleanupAction = policy.ActionAppTargetCleanup
	appMoveAbandonAction = policy.ActionAppTargetAbandon
)

// AppMoves requests moves of an app target to another node, the removal of a parked source and the abandonment of
// a move that halted in compensation.
type AppMoves struct {
	core
	plans *Plans
	// tunnel reads the Access applications of the routes a move carries; nil until UseTunnel.
	tunnel *tunnelEngine
}

// NewAppMoves validates cfg. plans must have been built with the job store the moves run on.
func NewAppMoves(cfg Config, plans *Plans) (*AppMoves, error) {
	c, err := newCore(cfg)
	if err != nil {
		return nil, err
	}
	if plans == nil {
		return nil, errors.New("app: moves need the plans service")
	}
	return &AppMoves{core: c, plans: plans}, nil
}

// UseTunnel gives the service the Cloudflare options with which admission reads the Access applications of the
// routes of a target (ADR-0042). Without them a target with an owners route is refused: an unchecked Access
// application is never assumed to be there.
func (s *AppMoves) UseTunnel(opts *TunnelOptions) error {
	engine, err := newTunnelEngine(s.core, opts)
	s.tunnel = engine
	return err
}

// AppMoveView is a move with its volume map.
type AppMoveView struct {
	Move    database.AppMove
	Volumes []database.AppMoveVolume
}

// AppMoveResult is the outcome of a move request. Resumed says that the request continued an open move whose job
// had ended, instead of starting one.
type AppMoveResult struct {
	AppMoveView
	Submission Submission
	Resumed    bool
}

// Move requests the move of the target to node to (action app_target.move). It refuses everything spec item 1 lists
// before any node is touched. A target with an open move whose job has ended resumes it: the move keeps its record
// and gets the new plan and job.
func (s *AppMoves) Move(ctx context.Context, by Caller, targetID, to domain.ID) (AppMoveResult, error) {
	return commit(ctx, s.core, by, func(ctx context.Context, tx *database.Tx) (AppMoveResult, error) {
		actor, scope, err := s.begin(ctx, tx, by, targetID, appMoveAction, map[string]any{policy.ParamToNode: to.String()})
		if err != nil {
			return AppMoveResult{}, err
		}
		open, err := database.GetOpenAppMoveByTarget(ctx, tx, targetID)
		switch {
		case err == nil:
			_, lerr := database.GetLiveAppMoveByTarget(ctx, tx, targetID)
			if lerr == nil {
				return s.resume(ctx, tx, by, actor, scope, open, to)
			}
			if smerr.CodeOf(lerr) != smerr.CodeNotFound {
				return AppMoveResult{}, lerr
			}
			if err := s.settleNeverRan(ctx, tx, actor, scope.target, open); err != nil {
				return AppMoveResult{}, err
			}
		case smerr.CodeOf(err) != smerr.CodeNotFound:
			return AppMoveResult{}, err
		}
		basis, err := s.admit(ctx, tx, scope, to)
		if err != nil {
			return AppMoveResult{}, err
		}
		b, err := buildMovePlan(ctx, tx, basis, by.ID)
		if err != nil {
			return AppMoveResult{}, err
		}
		submission, err := s.submit(ctx, tx, by, actor, b)
		if err != nil {
			return AppMoveResult{}, err
		}
		now := s.cfg.Clock.Now()
		created, err := database.InsertAppMove(ctx, tx, database.AppMove{
			ID: s.cfg.IDs.NewID(), AppTargetID: scope.target.ID, SourceNodeID: basis.source.ID, DestNodeID: basis.dest.ID,
			PlanID: *submission.Job.PlanID, JobID: submission.Job.ID, KnownGoodDeploymentID: basis.kg.deployment.ID,
			Stateful: basis.facts.stateful, CreatedBy: actor.ID, CreatedAt: now,
		}, basis.facts.volumes)
		if err != nil {
			return AppMoveResult{}, err
		}
		if _, err := database.InsertAppMoveRoutes(ctx, tx, created.ID, basis.routes, now); err != nil {
			return AppMoveResult{}, err
		}
		return s.viewOf(ctx, tx, created, submission, false)
	})
}

// settleNeverRan ends a move whose plan or job ended before a worker claimed it (rejected or expired plan, cancelled
// job) as rolled_back. It touched no node, so no command is needed, and the target is free again.
func (s *AppMoves) settleNeverRan(ctx context.Context, tx *database.Tx, actor domain.Actor, target database.AppTarget, m database.AppMove) error {
	rolled, err := database.AdvanceAppMovePhase(ctx, tx, m.ID, m.Phase, database.AppMoveRolledBack, s.cfg.Clock.Now())
	if err != nil {
		return err
	}
	return s.emit(ctx, tx, actor, eventAppMoveRolledBack, appTargetRef(target.ID), domain.ResultFailed, map[string]any{
		"move_id": m.ID.String(), "job_id": m.JobID.String(), "phase": string(rolled.Phase),
		"source_node_id": m.SourceNodeID.String(), "dest_node_id": m.DestNodeID.String(),
		"cause": "the plan or job of the move ended before it ran",
	})
}

// begin identifies the caller, loads the target and authorizes the action at the door, before anything about the
// target is revealed. params only has to satisfy the action's schema here: policy rules do not read them.
func (s *AppMoves) begin(ctx context.Context, tx *database.Tx, by Caller, targetID domain.ID, action string, params map[string]any) (domain.Actor, deploymentScope, error) {
	actor, err := s.beginRequest(ctx, tx, by)
	if err != nil {
		return domain.Actor{}, deploymentScope{}, err
	}
	scope, err := loadDeploymentScope(ctx, tx, targetID)
	if err != nil {
		return domain.Actor{}, deploymentScope{}, err
	}
	target, err := scope.policyTarget(ctx, tx, appTargetRef(targetID))
	if err != nil {
		return domain.Actor{}, deploymentScope{}, err
	}
	res := s.authorize(policy.Request{Actor: actor, Action: action, Params: params, Targets: []policy.Target{target}})
	if err := s.auditDecision(ctx, tx, actor, action, target.Ref, res); err != nil {
		return domain.Actor{}, deploymentScope{}, err
	}
	if err := decisionError(res); err != nil {
		return domain.Actor{}, deploymentScope{}, reject(err)
	}
	return actor, scope, nil
}

// admit loads both nodes and the newest known-good deployment and runs every request-time refusal.
func (s *AppMoves) admit(ctx context.Context, q database.Querier, scope deploymentScope, to domain.ID) (moveBasis, error) {
	source, err := database.GetNode(ctx, q, scope.target.NodeID)
	if err != nil {
		return moveBasis{}, err
	}
	dest, err := database.GetNode(ctx, q, to)
	if err != nil {
		return moveBasis{}, err
	}
	if err := requireMoveNodes(source, dest); err != nil {
		return moveBasis{}, err
	}
	good, err := database.NewestKnownGood(ctx, q, scope.target.ID, nil)
	if smerr.CodeOf(err) == smerr.CodeNotFound {
		return moveBasis{}, invalidArgument("the target has no known-good deployment to move: deploy it first")
	}
	if err != nil {
		return moveBasis{}, err
	}
	if err := requireNoMoveConflicts(ctx, q, scope.target, dest, nil); err != nil {
		return moveBasis{}, err
	}
	basis, err := newMoveBasis(ctx, q, scope, source, dest, good)
	if err != nil {
		return moveBasis{}, err
	}
	if basis.routes, err = admitMoveRoutes(ctx, q, s.core, scope.target, source, dest, nil); err != nil {
		return moveBasis{}, err
	}
	if err := checkMoveAccessApps(ctx, q, s.tunnel, basis.routes); err != nil {
		return moveBasis{}, err
	}
	return basis, nil
}

// resume gives the open move the plan and job of this request. It needs the move's job to have ended, the same
// destination, and, before the commit, a target still on the source node.
func (s *AppMoves) resume(ctx context.Context, tx *database.Tx, by Caller, actor domain.Actor, scope deploymentScope, open database.AppMove, to domain.ID) (AppMoveResult, error) {
	job, err := s.plans.jobs.Get(ctx, tx, open.JobID)
	if err != nil {
		return AppMoveResult{}, err
	}
	switch {
	case !job.State.Terminal():
		return AppMoveResult{}, smerr.New(smerr.CodeConflict, "", fmt.Sprintf(
			"the target has a move in progress (phase %s, job %s %s)", open.Phase, job.ID, job.State))
	case to != open.DestNodeID:
		return AppMoveResult{}, openMoveError(open)
	}
	if pastCommit(open) {
		scope.target.SpecRevision = open.CommittedRevision
	} else if scope.target.NodeID != open.SourceNodeID {
		return AppMoveResult{}, smerr.New(smerr.CodeConflict, "", "the target no longer runs on the move's source node")
	}
	if err := requireFrozenRoutes(ctx, tx, open); err != nil {
		return AppMoveResult{}, err
	}
	b, err := movePlanOfRecord(ctx, tx, scope, open, by.ID)
	if err != nil {
		return AppMoveResult{}, err
	}
	submission, err := s.submit(ctx, tx, by, actor, b)
	if err != nil {
		return AppMoveResult{}, err
	}
	rebound, err := database.RebindAppMoveJob(ctx, tx, open.ID, open.JobID, *submission.Job.PlanID, submission.Job.ID, s.cfg.Clock.Now())
	if err != nil {
		return AppMoveResult{}, err
	}
	return s.viewOf(ctx, tx, rebound, submission, true)
}

func (s *AppMoves) submit(ctx context.Context, tx *database.Tx, by Caller, actor domain.Actor, b built) (Submission, error) {
	res, err := s.evaluate(ctx, tx, actor, b)
	if err != nil {
		return Submission{}, err
	}
	return s.plans.planAndSubmit(ctx, tx, by, actor, b, res)
}

func (s *AppMoves) viewOf(ctx context.Context, q database.Querier, m database.AppMove, submission Submission, resumed bool) (AppMoveResult, error) {
	volumes, err := database.ListAppMoveVolumes(ctx, q, m.ID)
	return AppMoveResult{AppMoveView: AppMoveView{Move: m, Volumes: volumes}, Submission: submission, Resumed: resumed}, err
}

// CleanupSource requests the removal of the containers a done move left parked on its source node (action
// app_target.cleanup_source). Volumes are never removed. It refuses a target that runs on that node again and a
// node on which another target uses the Compose project; the labels of the containers are read by the job.
func (s *AppMoves) CleanupSource(ctx context.Context, by Caller, targetID domain.ID) (Submission, error) {
	return commit(ctx, s.core, by, func(ctx context.Context, tx *database.Tx) (Submission, error) {
		actor, scope, err := s.begin(ctx, tx, by, targetID, appMoveCleanupAction, map[string]any{policy.ParamMoveID: ""})
		if err != nil {
			return Submission{}, err
		}
		m, err := lastDoneMove(ctx, tx, targetID)
		if err != nil {
			return Submission{}, err
		}
		if err := requireCleanable(ctx, tx, scope.target, m); err != nil {
			return Submission{}, err
		}
		b, err := buildCleanupPlan(ctx, tx, scope, m, by.ID)
		if err != nil {
			return Submission{}, err
		}
		return s.submit(ctx, tx, by, actor, b)
	})
}

// lastDoneMove is the newest finished move of the target that reached its destination.
func lastDoneMove(ctx context.Context, q database.Querier, targetID domain.ID) (database.AppMove, error) {
	all, err := database.ListAppMovesByTarget(ctx, q, targetID)
	if err != nil {
		return database.AppMove{}, err
	}
	for _, m := range all {
		if m.Phase == database.AppMoveDone {
			return m, nil
		}
	}
	return database.AppMove{}, smerr.New(smerr.CodeNotFound, "", "the target has no completed move whose source could be cleaned")
}

// requireCleanable refuses to remove containers on the source of m while the target runs there again, a move is
// open, or another target uses the Compose project on that node.
func requireCleanable(ctx context.Context, q database.Querier, target database.AppTarget, m database.AppMove) error {
	if target.NodeID == m.SourceNodeID {
		return smerr.New(smerr.CodeConflict, "", "the target runs on that node again: there is no parked source to clean")
	}
	if err := requireNoOpenMove(ctx, q, target.ID); err != nil {
		return err
	}
	all, err := database.ListAppTargets(ctx, q)
	if err != nil {
		return err
	}
	for _, other := range all {
		if other.ID != target.ID && other.NodeID == m.SourceNodeID && other.ComposeProject == target.ComposeProject {
			return smerr.New(smerr.CodeConflict, "", "another target uses the compose project "+target.ComposeProject+" on the source node")
		}
	}
	return nil
}

// Abandon requests that the target's move, halted in compensation, be recorded as rolled back (action
// app_target.abandon_move). It leaves both nodes exactly as they are.
func (s *AppMoves) Abandon(ctx context.Context, by Caller, targetID domain.ID) (Submission, error) {
	return commit(ctx, s.core, by, func(ctx context.Context, tx *database.Tx) (Submission, error) {
		actor, scope, err := s.begin(ctx, tx, by, targetID, appMoveAbandonAction, map[string]any{policy.ParamMoveID: ""})
		if err != nil {
			return Submission{}, err
		}
		m, err := database.GetOpenAppMoveByTarget(ctx, tx, targetID)
		if smerr.CodeOf(err) == smerr.CodeNotFound {
			return Submission{}, invalidArgument("the target has no open move")
		}
		if err != nil {
			return Submission{}, err
		}
		if !m.Phase.Halted() || !compensating(m) {
			return Submission{}, smerr.New(smerr.CodeConflict, "", fmt.Sprintf(
				"the move is in phase %s: only a move halted in compensation can be abandoned", m.Phase))
		}
		if err := requireAbandonable(ctx, tx, m); err != nil {
			return Submission{}, err
		}
		b, err := buildAbandonPlan(ctx, tx, scope, m, by.ID)
		if err != nil {
			return Submission{}, err
		}
		return s.submit(ctx, tx, by, actor, b)
	})
}

// List returns the target's moves, newest first, with their volumes, if the caller may read the target.
func (s *AppMoves) List(ctx context.Context, by Caller, targetID domain.ID) ([]AppMoveView, error) {
	q := s.cfg.DB.Reader()
	actor, err := s.beginRequest(ctx, q, by)
	if err != nil {
		return nil, err
	}
	resolved, err := resolveAppTarget(ctx, q, targetID)
	if err != nil {
		return nil, err
	}
	if res := s.authorize(policy.Request{Actor: actor, Action: "app_target.read", Targets: []policy.Target{resolved.target}}); res.Decision != policy.DecisionAllow {
		return nil, decisionError(res)
	}
	moves, err := database.ListAppMovesByTarget(ctx, q, targetID)
	if err != nil {
		return nil, err
	}
	out := make([]AppMoveView, len(moves))
	for i, m := range moves {
		volumes, err := database.ListAppMoveVolumes(ctx, q, m.ID)
		if err != nil {
			return nil, err
		}
		out[i] = AppMoveView{Move: m, Volumes: volumes}
	}
	return out, nil
}
