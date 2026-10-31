package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/plan"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
)

// readActionFor is the read permission a plan creator needs on a target (spec §23).
var readActionFor = map[domain.ResourceType]string{
	domain.ResourceNode:      "node.read",
	domain.ResourceService:   "service.read",
	domain.ResourceApp:       "app.read",
	domain.ResourceAppTarget: "app_target.read",
	domain.ResourceInstance:  "config.read",
}

// Plans creates and submits plans (spec §23 "Plans").
type Plans struct {
	core
	jobs *jobs.Store
}

// NewPlans validates cfg. The store must have been built with this package's
// Revalidator and LockPlanner.
func NewPlans(cfg Config, store *jobs.Store) (*Plans, error) {
	c, err := newCore(cfg)
	if err != nil {
		return nil, err
	}
	if store == nil {
		return nil, errors.New("app: job store is required")
	}
	return &Plans{core: c, jobs: store}, nil
}

// PlanRequest asks for a plan. M0 plans have exactly one target.
type PlanRequest struct {
	Action     string
	Target     domain.ResourceRef
	Parameters map[string]any
}

// CreatedPlan is what POST /plans returns: the stored plan and what policy
// says about running it. Policy may be a denial; creating a plan does not
// require permission for the action itself (spec §23).
type CreatedPlan struct {
	Record database.PlanRecord
	Plan   *plan.Plan
	Policy policy.Result
}

// Create evaluates the proposed action for the caller, builds the version 3
// plan with the current spec_revision of every input, and persists it with its
// expiry. The caller needs plan.create and the read permission on the target.
func (p *Plans) Create(ctx context.Context, by Caller, req PlanRequest) (CreatedPlan, error) {
	return commit(ctx, p.core, by, func(ctx context.Context, tx *database.Tx) (CreatedPlan, error) {
		actor, err := loadCaller(ctx, tx, by)
		if err != nil {
			return CreatedPlan{}, err
		}
		if err := p.requireActive(ctx, by.Credential); err != nil {
			return CreatedPlan{}, err
		}
		if err := requireJobAction(req.Action); err != nil {
			return CreatedPlan{}, err
		}
		req.Parameters = p.withDefaults(req.Action, req.Parameters)
		b, err := build(ctx, tx, req.Action, by.ID, req.Target, req.Parameters)
		if err != nil {
			return CreatedPlan{}, err
		}
		if err := p.requireTunnelAvailable(ctx, tx, req); err != nil {
			return CreatedPlan{}, err
		}
		if err := p.requireMayPlan(ctx, tx, actor, b.target); err != nil {
			return CreatedPlan{}, err
		}
		res := p.authorize(b.request(actor))
		if err := p.auditDecision(ctx, tx, actor, req.Action, req.Target, res); err != nil {
			return CreatedPlan{}, err
		}
		rec, err := p.persist(ctx, tx, by, b.plan)
		if err != nil {
			return CreatedPlan{}, err
		}
		parsed, err := plan.Parse(rec.PlanJSON)
		if err != nil {
			return CreatedPlan{}, err
		}
		err = p.emit(ctx, tx, actor, "plan.create", domain.ResourceRef{Type: domain.ResourcePlan, ID: rec.ID},
			domain.ResultSucceeded, map[string]any{"action": req.Action, "plan_hash": rec.PlanHash})
		return CreatedPlan{Record: rec, Plan: parsed, Policy: res}, err
	})
}

// requireTunnelAvailable refuses the tunnel actions when the instance has no
// cloudflare: block or the node is not an ssh node: node.setup with
// tunnel=true, node.tunnel.disable and the service-token rotation. The
// operator is told when asking, not when the job runs.
func (p *Plans) requireTunnelAvailable(ctx context.Context, q database.Querier, req PlanRequest) error {
	switch req.Action {
	case policy.ActionCloudflareRotate:
		if p.cfg.Cloudflare == nil {
			return requireTunnelAllowed(false, domain.Node{})
		}
		return nil
	case policy.ActionNodeTunnelDisable:
	case policy.ActionNodeSetup:
		if tunnel, err := tunnelRequested(req.Parameters[policy.ParamTunnel]); err != nil || !tunnel {
			return err
		}
	default:
		return nil
	}
	node, err := database.GetNode(ctx, q, req.Target.ID)
	if err != nil {
		return err
	}
	if err := requireTunnelAllowed(p.cfg.Cloudflare != nil, node); err != nil {
		return err
	}
	if req.Action == policy.ActionNodeTunnelDisable {
		if err := requireDirectPath(node); err != nil {
			return err
		}
		if node.Endpoint.TunnelHostname != "" {
			return nil // the node already has its hostname
		}
	}
	_, err = tunnelHostnameOf(node.Name, p.cfg.Cloudflare.Zone)
	return err
}

// withDefaults fills what a plan may leave out, so the plan (and its hash)
// states everything that will execute: a node.setup without logs_mode gets
// ssh.logs_mode.
func (p *Plans) withDefaults(action string, params map[string]any) map[string]any {
	if _, given := params[policy.ParamLogsMode]; action != policy.ActionNodeSetup || given {
		return params
	}
	filled := make(map[string]any, len(params)+1)
	maps.Copy(filled, params)
	filled[policy.ParamLogsMode] = string(p.cfg.DefaultLogsMode)
	return filled
}

// requireMayPlan checks plan.create and the target's read permission. A denial
// is audited and rejects the request; nothing else is written.
func (p *Plans) requireMayPlan(ctx context.Context, q database.Querier, actor domain.Actor, target policy.Target) error {
	for _, action := range []string{"plan.create", readActionFor[target.Ref.Type]} {
		res := p.authorize(policy.Request{Actor: actor, Action: action, Targets: []policy.Target{target}})
		if res.Decision == policy.DecisionAllow {
			continue
		}
		if err := p.auditDecision(ctx, q, actor, action, target.Ref, res); err != nil {
			return err
		}
		return reject(decisionError(res))
	}
	return nil
}

func (p *Plans) persist(ctx context.Context, q database.Querier, by Caller, pl plan.Plan) (database.PlanRecord, error) {
	canonical, err := plan.Canonical(&pl)
	if err != nil {
		return database.PlanRecord{}, err
	}
	hash, err := plan.Hash(&pl)
	if err != nil {
		return database.PlanRecord{}, err
	}
	now := p.cfg.Clock.Now()
	rec := database.PlanRecord{
		ID:          p.cfg.IDs.NewID(),
		Action:      pl.Action,
		ActorID:     by.ID,
		Credential:  by.Credential,
		PlanJSON:    canonical,
		PlanHash:    hash,
		FinalizedAt: now,
		CreatedAt:   now,
		ExpiresAt:   now.Add(p.cfg.PlanTTL),
	}
	return rec, database.InsertPlan(ctx, q, rec)
}

// Submission is the job a plan became and the policy decision behind it.
type Submission struct {
	Job    jobs.Job
	Policy policy.Result
}

// Submit turns a plan into a job, once (spec §23). The plan, its submission
// mark, the job and the events commit in a single write transaction. The job
// starts awaiting_approval when policy requires approval, queued otherwise.
// The submitting request's credential context is the one stored on the job.
func (p *Plans) Submit(ctx context.Context, by Caller, planID domain.ID, planHash string) (Submission, error) {
	return commit(ctx, p.core, by, func(ctx context.Context, tx *database.Tx) (Submission, error) {
		rec, err := database.GetPlan(ctx, tx, planID)
		if err != nil {
			return Submission{}, err
		}
		actor, err := loadCaller(ctx, tx, by)
		if err != nil {
			return Submission{}, err
		}
		if rec.ActorID != by.ID {
			return Submission{}, p.refuseForeignSubmit(ctx, tx, actor, rec)
		}
		if err := p.checkSubmittable(rec, planHash); err != nil {
			return Submission{}, err
		}
		if err := p.requireActive(ctx, by.Credential); err != nil {
			return Submission{}, err
		}
		b, err := rebuild(ctx, tx, rec)
		if err != nil {
			return Submission{}, err
		}
		res := p.authorize(b.request(actor))
		if err := p.auditDecision(ctx, tx, actor, rec.Action, b.target.Ref, res); err != nil {
			return Submission{}, err
		}
		if err := decisionError(res); err != nil {
			return Submission{}, reject(err)
		}
		job, err := p.enqueue(ctx, tx, by, rec, b, res)
		if err != nil {
			return Submission{}, err
		}
		if err := database.MarkSubmitted(ctx, tx, rec.ID, job.ID); err != nil {
			return Submission{}, err
		}
		err = p.emit(ctx, tx, actor, "plan.submit", domain.ResourceRef{Type: domain.ResourcePlan, ID: rec.ID},
			domain.ResultSucceeded, map[string]any{"job_id": job.ID.String(), "approval_required": res.ApprovalRequired})
		return Submission{Job: job, Policy: res}, err
	})
}

// refuseForeignSubmit audits and rejects a submit by someone other than the plan's actor.
func (p *Plans) refuseForeignSubmit(ctx context.Context, q database.Querier, actor domain.Actor, rec database.PlanRecord) error {
	res := policy.Result{Decision: policy.DecisionDeny, Reason: smerr.ReasonNotPlanActor}
	planRef := domain.ResourceRef{Type: domain.ResourcePlan, ID: rec.ID}
	if err := p.auditDecision(ctx, q, actor, rec.Action, planRef, res); err != nil {
		return err
	}
	return reject(smerr.FromReason(smerr.ReasonNotPlanActor, "only the plan's actor may submit it"))
}

// checkSubmittable applies the checks that need only the stored plan.
func (p *Plans) checkSubmittable(rec database.PlanRecord, planHash string) error {
	switch {
	case rec.SubmittedJobID != nil:
		return smerr.FromReason(smerr.ReasonAlreadySubmitted, "plan already has a submitted job")
	case rec.PlanHash != planHash:
		return smerr.FromReason(smerr.ReasonPlanStale, "plan hash does not match the stored plan")
	case !p.cfg.Clock.Now().Before(rec.ExpiresAt):
		return smerr.FromReason(smerr.ReasonPlanExpired, "plan expired")
	}
	return nil
}

func (p *Plans) enqueue(ctx context.Context, q database.Querier, by Caller, rec database.PlanRecord, b built, res policy.Result) (jobs.Job, error) {
	payload, err := json.Marshal(b.plan.Parameters)
	if err != nil {
		return jobs.Job{}, fmt.Errorf("encode job payload: %w", err)
	}
	return p.jobs.Enqueue(ctx, q, jobs.NewJob{
		Type:             jobTypeOf(b.spec),
		Resource:         b.target.Ref,
		ActorID:          by.ID,
		Credential:       by.Credential,
		Risk:             b.plan.Risk,
		RetryClass:       b.spec.Retry,
		Payload:          payload,
		PlanID:           &rec.ID,
		PlanHash:         rec.PlanHash,
		MaxAttempts:      b.spec.MaxAttempts,
		AwaitingApproval: res.ApprovalRequired,
	})
}
