package app

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/plan"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
)

// Queries are the read endpoints that need no node: identity, jobs,
// approvals and events. They answer from the database only.
type Queries struct {
	core
	jobs *jobs.Store
	mode config.Mode
}

// NewQueries validates cfg.
func NewQueries(cfg Config, store *jobs.Store, mode config.Mode) (*Queries, error) {
	c, err := newCore(cfg)
	if err != nil {
		return nil, err
	}
	if store == nil {
		return nil, errors.New("app: job store is required")
	}
	return &Queries{core: c, jobs: store, mode: mode}, nil
}

// Me describes the caller as the daemon authenticated it. Every identity may
// read itself; it is not policy-evaluated (spec §11.2).
func (q *Queries) Me(ctx context.Context, by Caller) (wire.Me, error) {
	r := q.cfg.DB.Reader()
	actor, err := q.beginRequest(ctx, r, by)
	if err != nil {
		return wire.Me{}, err
	}
	identity, err := database.GetIdentity(ctx, r, by.ID)
	if err != nil {
		return wire.Me{}, err
	}
	return wire.Me{
		IdentityID: identity.ID, ActorType: identity.ActorType, DisplayName: identity.Subject,
		Credential: by.Credential.Kind, Roles: nonNil(actor.Roles), InstanceMode: string(q.mode),
	}, nil
}

// RequireRead authorizes a query action on ref for the caller and audits a
// refusal (spec §11.3). Nodes and services are evaluated with their own
// attributes; any other ref (the instance, a plan, the job list) with none.
// It returns the caller's actor on success.
func (q *Queries) RequireRead(ctx context.Context, by Caller, action string, ref domain.ResourceRef) (domain.Actor, error) {
	reader := q.cfg.DB.Reader()
	actor, err := q.beginRequest(ctx, reader, by)
	if err != nil {
		return domain.Actor{}, err
	}
	target := policy.Target{Ref: ref}
	if ref.Type == domain.ResourceNode || ref.Type == domain.ResourceService {
		resolved, err := resolve(ctx, reader, ref)
		if err != nil {
			return domain.Actor{}, err
		}
		target = resolved.target
	}
	res := q.authorize(policy.Request{Actor: actor, Action: action, Targets: []policy.Target{target}})
	if res.Decision == policy.DecisionAllow {
		return actor, nil
	}
	err = q.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		if err := q.auditDecision(ctx, tx, actor, action, ref, res); err != nil {
			return err
		}
		return reject(decisionError(res))
	})
	return domain.Actor{}, err
}

func (q *Queries) requireRead(ctx context.Context, by Caller, action string, typ domain.ResourceType) (domain.Actor, error) {
	return q.RequireRead(ctx, by, action, domain.ResourceRef{Type: typ})
}

// Plan returns a stored plan with what policy says about running it now
// (action plan.read, GET /plans/{id}). A plan whose inputs changed since it
// was made is reported with a PLAN_STALE verdict instead of failing the read.
func (q *Queries) Plan(ctx context.Context, by Caller, id domain.ID) (wire.CreatedPlan, error) {
	if _, err := q.RequireRead(ctx, by, "plan.read", domain.ResourceRef{Type: domain.ResourcePlan, ID: id}); err != nil {
		return wire.CreatedPlan{}, err
	}
	reader := q.cfg.DB.Reader()
	rec, err := database.GetPlan(ctx, reader, id)
	if err != nil {
		return wire.CreatedPlan{}, err
	}
	verdict := wire.Policy{Decision: string(policy.DecisionDeny), Reason: smerr.ReasonPlanStale}
	if current, err := rebuild(ctx, reader, rec); err == nil {
		if requester, err := loadActor(ctx, reader, rec.ActorID, domain.CredentialContext{}); err == nil {
			verdict = PolicyView(q.authorize(current.request(requester)))
		}
	}
	return wire.CreatedPlan{
		PlanID: rec.ID, Plan: json.RawMessage(rec.PlanJSON), PlanHash: rec.PlanHash, ExpiresAt: rec.ExpiresAt, Policy: verdict,
	}, nil
}

// Jobs lists jobs, newest first, optionally by state (action job.read).
func (q *Queries) Jobs(ctx context.Context, by Caller, f wire.JobQuery) (wire.Page[wire.Job], error) {
	if _, err := q.requireRead(ctx, by, "job.read", domain.ResourceJob); err != nil {
		return wire.Page[wire.Job]{}, err
	}
	// Ask for one job past the page to learn whether another page follows.
	limit := f.Limit
	if limit <= 0 {
		limit = wire.DefaultLimit
	}
	all, err := q.jobs.List(ctx, q.cfg.DB.Reader(), jobs.ListFilter{States: f.States, Limit: wire.MaxLimit})
	if err != nil {
		return wire.Page[wire.Job]{}, err
	}
	page, err := paginate(all, wire.PageQuery{Cursor: f.Cursor, Limit: limit}, func(j jobs.Job) domain.ID { return j.ID })
	if err != nil {
		return wire.Page[wire.Job]{}, err
	}
	out := wire.Page[wire.Job]{Items: make([]wire.Job, len(page.items)), NextCursor: page.next}
	for k, j := range page.items {
		out.Items[k] = JobView(j)
	}
	return out, nil
}

// Job returns one job with its operation intents (action job.read).
func (q *Queries) Job(ctx context.Context, by Caller, id domain.ID) (wire.JobDetail, error) {
	if _, err := q.requireRead(ctx, by, "job.read", domain.ResourceJob); err != nil {
		return wire.JobDetail{}, err
	}
	detail, err := q.jobs.Detail(ctx, q.cfg.DB.Reader(), id)
	if err != nil {
		return wire.JobDetail{}, err
	}
	out := wire.JobDetail{Job: JobView(detail.Job), Intents: make([]wire.Intent, len(detail.Intents))}
	for k, in := range detail.Intents {
		out.Intents[k] = intentView(in)
	}
	return out, nil
}

func intentView(in jobs.Intent) wire.Intent {
	return wire.Intent{
		ID: in.ID, Step: in.Step, State: domain.IntentState(in.State), Operation: in.Operation,
		Target: in.TargetType + ":" + in.TargetID, PreState: in.PreState, DeadlineAt: in.DeadlineAt,
		DispatchedAt: in.DispatchedAt, CompletedAt: in.CompletedAt, Outcome: in.Outcome, Evidence: in.Evidence,
	}
}

// Approvals lists the jobs waiting for approval with what an approver must
// see (spec §39.5): the plan, the environments and the quorum state.
func (q *Queries) Approvals(ctx context.Context, by Caller, page wire.PageQuery) (wire.Page[wire.Approval], error) {
	if _, err := q.requireRead(ctx, by, "job.read", domain.ResourceJob); err != nil {
		return wire.Page[wire.Approval]{}, err
	}
	reader := q.cfg.DB.Reader()
	waiting, err := q.jobs.List(ctx, reader, jobs.ListFilter{States: []domain.JobState{domain.JobAwaitingApproval}, Limit: wire.MaxLimit})
	if err != nil {
		return wire.Page[wire.Approval]{}, err
	}
	paged, err := paginate(waiting, page, func(j jobs.Job) domain.ID { return j.ID })
	if err != nil {
		return wire.Page[wire.Approval]{}, err
	}
	out := wire.Page[wire.Approval]{Items: make([]wire.Approval, 0, len(paged.items)), NextCursor: paged.next}
	for _, j := range paged.items {
		view, err := q.approvalView(ctx, reader, j)
		if err != nil {
			return wire.Page[wire.Approval]{}, err
		}
		out.Items = append(out.Items, view)
	}
	return out, nil
}

func (q *Queries) approvalView(ctx context.Context, r database.Querier, job jobs.Job) (wire.Approval, error) {
	rec, err := database.GetPlan(ctx, r, *job.PlanID)
	if err != nil {
		return wire.Approval{}, err
	}
	stored, err := plan.Parse(rec.PlanJSON)
	if err != nil {
		return wire.Approval{}, err
	}
	decisions, err := database.ListDecisions(ctx, r, job.ID, job.PlanHash)
	if err != nil {
		return wire.Approval{}, err
	}
	granted := 0
	for _, d := range decisions {
		if d.Decision == domain.DecisionApprove && q.cfg.Clock.Now().Before(d.ExpiresAt) {
			granted++
		}
	}
	return wire.Approval{
		Job: JobView(job), Plan: json.RawMessage(rec.PlanJSON), Environments: q.environmentsOf(ctx, r, stored),
		Quorum: q.quorumOf(ctx, r, job, rec), Approvals: granted, ExpiresAt: rec.ExpiresAt,
	}, nil
}

func (q *Queries) environmentsOf(ctx context.Context, r database.Querier, p *plan.Plan) []string {
	names := []string{}
	for _, in := range p.Inputs {
		if in.Type != string(domain.ResourceEnvironment) {
			continue
		}
		if env, err := database.GetEnvironment(ctx, r, domain.ID(in.ID)); err == nil {
			names = append(names, env.Name)
		}
	}
	return names
}

// quorumOf is the quorum the requester's policy demands now; 1 when it cannot
// be evaluated (the claim-time revalidation is the authority).
func (q *Queries) quorumOf(ctx context.Context, r database.Querier, job jobs.Job, rec database.PlanRecord) int {
	current, err := rebuildCurrent(ctx, r, rec)
	if err != nil {
		return 1
	}
	requester, err := loadActor(ctx, r, job.ActorID, credentialOf(job))
	if err != nil {
		return 1
	}
	if res := q.authorize(current.request(requester)); res.Decision == policy.DecisionAllow && res.Quorum > 0 {
		return res.Quorum
	}
	return 1
}

// Events lists audit events oldest first, after a cursor or sequence number
// (action event.read). The cursor is the last seq returned.
func (q *Queries) Events(ctx context.Context, by Caller, f wire.EventQuery) (wire.Page[wire.Event], error) {
	if _, err := q.requireRead(ctx, by, "event.read", domain.ResourceEvent); err != nil {
		return wire.Page[wire.Event]{}, err
	}
	after := f.AfterSeq
	if f.Cursor != "" {
		seq, err := strconv.ParseInt(f.Cursor, 10, 64)
		if err != nil || seq < 0 {
			return wire.Page[wire.Event]{}, smerr.New(smerr.CodeInvalidArgument, "", "invalid cursor")
		}
		after = max(after, seq)
	}
	limit := f.Limit
	if limit <= 0 {
		limit = wire.DefaultLimit
	}
	return q.eventsAfter(ctx, after, limit, f)
}

// eventsAfter reads batches until the page is full or the log ends, because
// the resource filter is applied here, not in the query.
func (q *Queries) eventsAfter(ctx context.Context, after int64, limit int, f wire.EventQuery) (wire.Page[wire.Event], error) {
	out := wire.Page[wire.Event]{Items: []wire.Event{}}
	cursor := after
	for len(out.Items) < limit {
		batch, err := database.ListEvents(ctx, q.cfg.DB.Reader(), cursor, wire.MaxLimit)
		if err != nil {
			return wire.Page[wire.Event]{}, err
		}
		for _, e := range batch {
			cursor = e.Seq
			if !eventMatches(e, f) {
				continue
			}
			out.Items = append(out.Items, eventView(e))
			if len(out.Items) == limit {
				out.NextCursor = strconv.FormatInt(e.Seq, 10)
				return out, nil
			}
		}
		if len(batch) < wire.MaxLimit {
			return out, nil
		}
	}
	return out, nil
}

func eventMatches(e domain.Event, f wire.EventQuery) bool {
	return (f.ResourceType == "" || e.ResourceType == f.ResourceType) && (f.ResourceID == "" || e.ResourceID == f.ResourceID)
}

func eventView(e domain.Event) wire.Event {
	return wire.Event{
		EventID: e.EventID, Seq: e.Seq, Timestamp: e.Timestamp, Actor: wire.Actor{Type: e.ActorType, ID: e.ActorID},
		Source: e.Source, Action: e.Action, Resource: wire.ResourceRef{Type: e.ResourceType, ID: e.ResourceID},
		CorrelationID: e.CorrelationID, Severity: e.Severity, Result: e.Result, Data: nonNilMap(e.Data),
	}
}
