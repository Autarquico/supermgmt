package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/plan"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// JobControlPlaneApply is the type of the job a `direct` action becomes when
// policy requires approval (spec §11.2): it applies the approved change.
const JobControlPlaneApply = "control_plane.apply"

// Direct actions the control plane applies in M1.
const (
	actionNodeAdd      = "node.add"
	actionNodeUpdate   = "node.update"
	actionNodeRemove   = "node.remove"
	actionProviderWite = "provider.write"
)

// jobTypeOf is the type of the job that runs a plan of spec's action.
func jobTypeOf(spec policy.ActionSpec) string {
	if spec.Mode == policy.ModeDirect {
		return JobControlPlaneApply
	}
	return spec.Name
}

// requireJobAction refuses an action that does not run through a plan:
// direct actions are applied (or wrapped) by their own endpoints (spec §23).
func requireJobAction(action string) error {
	if spec, known := policy.Lookup(action); known && spec.Mode != policy.ModeJob {
		return smerr.New(smerr.CodeInvalidArgument, "", fmt.Sprintf("action %s does not run through a plan", action))
	}
	return nil
}

// ---- request and parameter shapes ------------------------------------------

// nodeAddParams is what a node.add plan and job carry. The ids are generated
// when the request is made, so the approved plan names the node it creates.
type nodeAddParams struct {
	NodeID             domain.ID `json:"node_id"`
	ProviderID         domain.ID `json:"provider_id"`
	Name               string    `json:"name"`
	Host               string    `json:"host"`
	Port               int       `json:"port"`
	User               string    `json:"user"`
	AdminUser          string    `json:"admin_user"`
	HostPublicKey      string    `json:"host_public_key"`
	CredentialRef      string    `json:"credential_ref"`
	AdminCredentialRef string    `json:"admin_credential_ref"`
	Environment        string    `json:"environment"`
	Tags               []string  `json:"tags"`
}

// NodePatch changes the configured fields of a node; nil fields are unchanged.
// An empty Environment clears the node's environment.
type NodePatch = wire.NodePatch

// localParams is what registering the local provider carries.
type localParams struct {
	ProviderID domain.ID `json:"provider_id"`
	NodeID     domain.ID `json:"node_id"`
	Name       string    `json:"name"`
}

// toParams converts a request struct to plan parameters. Numbers stay exact
// (json.Number), because a plan never contains a float.
func toParams(v any) (map[string]any, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("encode parameters: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var params map[string]any
	if err := dec.Decode(&params); err != nil {
		return nil, fmt.Errorf("encode parameters: %w", err)
	}
	return params, nil
}

// fromParams is the strict inverse of toParams: an unknown key is an error, so
// nothing can be smuggled into an approved plan.
func fromParams[T any](params map[string]any) (T, error) {
	var out T
	raw, err := json.Marshal(params)
	if err != nil {
		return out, fmt.Errorf("decode parameters: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return out, smerr.Wrap(err, smerr.CodeInvalidArgument, "", "parameters do not match the action")
	}
	return out, nil
}

// ---- building the plans of direct actions ---------------------------------

// buildDirect builds the plan of a direct action that policy wraps in a
// control_plane.apply job. The plan names the resource the action creates or
// changes, so quorum, staleness and cancel work as for any other job.
func buildDirect(ctx context.Context, q database.Querier, spec policy.ActionSpec, actorID domain.ID, ref domain.ResourceRef, params map[string]any) (built, error) {
	spec.Retry, spec.MaxAttempts = domain.RetryIdempotent, 3
	target, revision, inputs, err := directTarget(ctx, q, spec, ref, params)
	if err != nil {
		return built{}, err
	}
	return built{
		spec:   spec,
		target: target,
		plan: plan.Plan{
			Version:    plan.Version,
			Action:     spec.Name,
			Actor:      "identity/" + actorID.String(),
			Targets:    []plan.Target{{Type: string(ref.Type), ID: ref.ID.String(), SpecRevision: revision}},
			Inputs:     inputs,
			Parameters: params,
			Risk:       spec.Risk,
		},
	}, nil
}

func directTarget(ctx context.Context, q database.Querier, spec policy.ActionSpec, ref domain.ResourceRef, params map[string]any) (policy.Target, *int64, []plan.Input, error) {
	if ref.Type != spec.Resource {
		return policy.Target{}, nil, nil, smerr.New(smerr.CodeInvalidArgument, "",
			fmt.Sprintf("action %s targets a %s, not a %s", spec.Name, spec.Resource, ref.Type))
	}
	switch spec.Name {
	case actionNodeAdd:
		p, err := fromParams[nodeAddParams](params)
		if err != nil {
			return policy.Target{}, nil, nil, err
		}
		return newNodeTarget(ctx, q, ref, p)
	case actionNodeUpdate, actionNodeRemove:
		r, err := resolveNode(ctx, q, ref.ID)
		if err != nil {
			return policy.Target{}, nil, nil, err
		}
		return r.target, &r.revision, r.inputs, nil
	case actionProviderWite:
		p, err := fromParams[localParams](params)
		if err != nil {
			return policy.Target{}, nil, nil, err
		}
		return policy.Target{Ref: ref, Attrs: policy.Attributes{Provider: p.Name}}, nil, nil, nil
	}
	return policy.Target{}, nil, nil, smerr.New(smerr.CodeInvalidArgument, "", "unsupported direct action "+spec.Name)
}

// newNodeTarget is the policy view of a node that does not exist yet, from
// what the request says about it: its tags, environment, name and provider.
func newNodeTarget(ctx context.Context, q database.Querier, ref domain.ResourceRef, p nodeAddParams) (policy.Target, *int64, []plan.Input, error) {
	target := policy.Target{Ref: ref, Attrs: policy.Attributes{Tags: p.Tags, Node: p.Name, Provider: p.Name}}
	var inputs []plan.Input
	if p.Environment != "" {
		env, err := environmentNamed(ctx, q, p.Environment)
		if err != nil {
			return policy.Target{}, nil, nil, err
		}
		target.Attrs.Environment = env.Name
		target.Attrs.EnvironmentRisk = env.RiskLevel
		target.Attrs.ApprovalsRequired = env.ApprovalsRequired
		inputs = append(inputs, revisionInput(domain.ResourceEnvironment, env.ID, env.SpecRevision))
	}
	return target, nil, inputs, nil
}

func environmentNamed(ctx context.Context, q database.Querier, name string) (domain.Environment, error) {
	all, err := database.ListEnvironments(ctx, q)
	if err != nil {
		return domain.Environment{}, err
	}
	for _, env := range all {
		if env.Name == name {
			return env, nil
		}
	}
	return domain.Environment{}, smerr.New(smerr.CodeInvalidArgument, "", fmt.Sprintf("environment %q does not exist", name))
}

// ---- parameters of job-mode actions -----------------------------------------

// validateParameters applies the checks the catalog's closed schema cannot
// express. node.setup grants are "<verb> <unit>" lines of the sudoers drop-in.
func validateParameters(action string, params map[string]any) error {
	if action != policy.ActionNodeSetup {
		return nil
	}
	_, err := parseSetupRequest(params)
	return err
}

// setupRequest is the typed form of a node.setup plan's parameters.
type setupRequest struct {
	DockerAccess bool
	LogsMode     runtimes.LogsMode
	Grants       []runtimes.UnitGrant
}

func parseSetupRequest(params map[string]any) (setupRequest, error) {
	docker, _ := params[policy.ParamDockerAccess].(string)
	mode, _ := params[policy.ParamLogsMode].(string)
	grants, err := parseGrants(params[policy.ParamGrants])
	if err != nil {
		return setupRequest{}, err
	}
	return setupRequest{DockerAccess: docker == "true", LogsMode: runtimes.LogsMode(mode), Grants: grants}, nil
}

// parseGrants reads the grants parameter ("<verb> <unit>" per entry) into one
// UnitGrant per unit, units in first-seen order and verbs in canonical order.
func parseGrants(raw any) ([]runtimes.UnitGrant, error) {
	var entries []string
	switch list := raw.(type) {
	case nil:
	case []string:
		entries = list
	case []any:
		for _, item := range list {
			text, ok := item.(string)
			if !ok {
				return nil, smerr.New(smerr.CodeInvalidArgument, "", "grants must be a list of strings")
			}
			entries = append(entries, text)
		}
	default:
		return nil, smerr.New(smerr.CodeInvalidArgument, "", "grants must be a list of strings")
	}
	var order []string
	verbs := map[string][]domain.ServiceVerb{}
	for _, entry := range entries {
		verbText, unit, ok := strings.Cut(entry, " ")
		verb, err := domain.ParseServiceVerb(verbText)
		if !ok || err != nil || templates.ValidateUnit(unit) != nil {
			return nil, smerr.New(smerr.CodeInvalidArgument, "", `each grant must be "<start|stop|restart> <unit>.service"`)
		}
		if _, seen := verbs[unit]; !seen {
			order = append(order, unit)
		}
		if !slices.Contains(verbs[unit], verb) {
			verbs[unit] = append(verbs[unit], verb)
		}
	}
	grants := make([]runtimes.UnitGrant, len(order))
	for i, unit := range order {
		grants[i] = runtimes.UnitGrant{Unit: unit, Verbs: canonicalVerbs(verbs[unit])}
	}
	return grants, nil
}

func canonicalVerbs(verbs []domain.ServiceVerb) []domain.ServiceVerb {
	var out []domain.ServiceVerb
	for _, v := range domain.AllServiceVerbs() {
		if slices.Contains(verbs, v) {
			out = append(out, v)
		}
	}
	return out
}

// ---- submitting a plan on the caller's behalf --------------------------------

// planAndSubmit persists the plan of b and enqueues its job in the caller's
// transaction (spec §23 convenience endpoints; the wrapped direct actions).
// Policy has already allowed the plan.
func (p *Plans) planAndSubmit(ctx context.Context, q database.Querier, by Caller, actor domain.Actor, b built, res policy.Result) (Submission, error) {
	rec, err := p.persist(ctx, q, by, b.plan)
	if err != nil {
		return Submission{}, err
	}
	planRef := domain.ResourceRef{Type: domain.ResourcePlan, ID: rec.ID}
	if err := p.emit(ctx, q, actor, "plan.create", planRef, domain.ResultSucceeded,
		map[string]any{"action": b.plan.Action, "plan_hash": rec.PlanHash}); err != nil {
		return Submission{}, err
	}
	job, err := p.enqueue(ctx, q, by, rec, b, res)
	if err != nil {
		return Submission{}, err
	}
	if err := database.MarkSubmitted(ctx, q, rec.ID, job.ID); err != nil {
		return Submission{}, err
	}
	err = p.emit(ctx, q, actor, "plan.submit", planRef, domain.ResultSucceeded,
		map[string]any{"job_id": job.ID.String(), "approval_required": res.ApprovalRequired})
	return Submission{Job: job, Policy: res}, err
}

// evaluate authorizes b for actor and audits a refusal. A refusal rejects the
// request with its typed error, keeping the audit event.
func (c core) evaluate(ctx context.Context, q database.Querier, actor domain.Actor, b built) (policy.Result, error) {
	res := c.authorize(b.request(actor))
	if err := c.auditDecision(ctx, q, actor, b.plan.Action, b.target.Ref, res); err != nil {
		return res, err
	}
	if err := decisionError(res); err != nil {
		return res, reject(err)
	}
	return res, nil
}

// ---- control_plane.apply ---------------------------------------------------

// applyHandler runs the approved change of a control_plane.apply job.
type applyHandler struct {
	inv *Inventory
}

func (h applyHandler) Run(ctx context.Context, lease jobs.Lease) error {
	return h.inv.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		if err := lease.Fence(ctx, tx); err != nil {
			return err
		}
		job, err := h.inv.jobs.Get(ctx, tx, lease.JobID)
		if err != nil {
			return err
		}
		actor, err := loadActor(ctx, tx, job.ActorID, credentialOf(job))
		if err != nil {
			return err
		}
		rec, err := database.GetPlan(ctx, tx, *job.PlanID)
		if err != nil {
			return err
		}
		return h.inv.applyApproved(ctx, tx, actor, rec.Action, job)
	})
}
