package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/plan"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
	sshnode "github.com/autarquico/supermgmt/internal/providers/ssh"
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
	// Tunnel starts an enrollment through a Cloudflare Tunnel instead of inserting the node (ADR-0039):
	// the host and credentials are empty, and ExpiresIn is the enrollment's lifetime in seconds.
	Tunnel    bool `json:"tunnel,omitempty"`
	ExpiresIn int  `json:"expires_in_seconds,omitempty"`
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
	spec.Retry, spec.MaxAttempts = retryOfDirect(spec.Name)
	target, revision, inputs, err := directTarget(ctx, q, spec, ref, params)
	if err != nil {
		return built{}, err
	}
	if isNodeRouteAction(spec.Name) {
		if spec.Risk, err = policy.RiskFor(spec.Name, params); err != nil { // public raises the risk of an expose
			return built{}, err
		}
	}
	steps, err := directSteps(spec.Name, params)
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
			Steps:      steps,
			Parameters: params,
			Risk:       spec.Risk,
		},
	}, nil
}

// directSteps are the human lines of a direct action's plan, computed from its parameters alone so that
// building the plan again at approval gives the same hash. Only node.add and a node.remove that takes a tunnel
// down have them: the approver sees whom the control plane will trust and with which credentials, or what
// disappears from Cloudflare.
func directSteps(action string, params map[string]any) ([]string, error) {
	if action == actionNodeRemove && params[policy.ParamTunnel] == "true" {
		return nodeRemoveTunnelSteps, nil
	}
	if action != actionNodeAdd {
		return nil, nil
	}
	p, err := fromParams[nodeAddParams](params)
	if err != nil || p.Tunnel {
		return nil, err
	}
	key, err := sshnode.ParseHostKey(p.HostPublicKey)
	if err != nil {
		return nil, err
	}
	return []string{
		fmt.Sprintf("trust host key (compare with the host): %s %s", key.Type(), cryptossh.FingerprintSHA256(key)),
		"name: " + p.Name,
		fmt.Sprintf("host: %s", net.JoinHostPort(p.Host, strconv.Itoa(p.Port))),
		"admin user: " + p.AdminUser,
		"automation user: " + p.User,
		"admin credential: " + p.AdminCredentialRef,
		"automation credential: " + p.CredentialRef,
	}, nil
}

// retryOfDirect: the change of a key operation is not safe to repeat blindly
// (a second rotation makes a second key), so a failed or interrupted one is
// resolved by an operator instead of retried.
func retryOfDirect(action string) (domain.RetryClass, int) {
	if action == actionSecretWrite {
		return domain.RetryNonRetryable, 1
	}
	return domain.RetryIdempotent, 3
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
	case actionNodeUpdate:
		return nodeTarget(ctx, q, ref)
	case actionNodeRemove:
		if _, err := policy.RiskFor(spec.Name, params); err != nil {
			return policy.Target{}, nil, nil, err
		}
		return nodeTarget(ctx, q, ref)
	case actionProviderWite:
		return providerWriteTarget(ref, params)
	case nodeRouteExposeAction, nodeRouteUnexposeAction:
		return nodeRouteTarget(ctx, q, spec, ref, params)
	case actionMCPClientRegister:
		return mcpRegisterTarget(ref, params)
	case actionMCPClientDelete:
		return mcpDeleteTarget(ctx, q, ref, params)
	case actionSecretWrite:
		p, err := fromParams[secretWriteParams](params)
		if err != nil {
			return policy.Target{}, nil, nil, err
		}
		return policy.Target{Ref: ref}, nil, nil, p.validate()
	}
	return policy.Target{}, nil, nil, smerr.New(smerr.CodeInvalidArgument, "", "unsupported direct action "+spec.Name)
}

func nodeTarget(ctx context.Context, q database.Querier, ref domain.ResourceRef) (policy.Target, *int64, []plan.Input, error) {
	r, err := resolveNode(ctx, q, ref.ID)
	if err != nil {
		return policy.Target{}, nil, nil, err
	}
	return r.target, &r.revision, r.inputs, nil
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

func mismatchedTarget(what string) error {
	return invalidArgument("%s does not match the target of the plan", what)
}

func invalidArgument(format string, args ...any) error {
	return smerr.New(smerr.CodeInvalidArgument, "", fmt.Sprintf(format, args...))
}

// ---- provider writes --------------------------------------------------------

func providerWriteTarget(ref domain.ResourceRef, params map[string]any) (policy.Target, *int64, []plan.Input, error) {
	p, err := fromParams[localParams](params)
	if err != nil {
		return policy.Target{}, nil, nil, err
	}
	return policy.Target{Ref: ref, Attrs: policy.Attributes{Provider: p.Name}}, nil, nil, nil
}

// ---- parameters of job-mode actions -----------------------------------------

// validateParameters applies the checks the catalog's closed schema cannot
// express. node.setup grants are "<verb> <unit>" lines of the sudoers drop-in.
func validateParameters(action string, params map[string]any) error {
	if action != policy.ActionNodeSetup {
		return nil
	}
	if _, err := deployRootOf(params); err != nil {
		return err
	}
	_, err := parseSetupRequest(params)
	return err
}

// setupRequest is the typed form of a node.setup plan's parameters.
type setupRequest struct {
	DockerAccess bool
	LogsMode     runtimes.LogsMode
	Grants       []runtimes.UnitGrant
	Tunnel       bool
	Proxmox      bool
}

func parseSetupRequest(params map[string]any) (setupRequest, error) {
	docker, _ := params[policy.ParamDockerAccess].(string)
	mode, _ := params[policy.ParamLogsMode].(string)
	if mode == "" {
		mode = string(runtimes.LogsJournalGroup)
	}
	grants, err := parseGrants(params[policy.ParamGrants])
	if err != nil {
		return setupRequest{}, err
	}
	tunnel, err := tunnelRequested(params[policy.ParamTunnel])
	if err != nil {
		return setupRequest{}, err
	}
	proxmox, err := optionRequested(policy.ParamProxmox, params[policy.ParamProxmox])
	if err != nil {
		return setupRequest{}, err
	}
	return setupRequest{DockerAccess: docker == "true", LogsMode: runtimes.LogsMode(mode), Grants: grants, Tunnel: tunnel, Proxmox: proxmox}, nil
}

// tunnelRequested reads the tunnel parameter: absent and "false" mean no
// tunnel, "true" asks for one; anything else is refused.
func tunnelRequested(raw any) (bool, error) { return optionRequested(policy.ParamTunnel, raw) }

func optionRequested(param string, raw any) (bool, error) {
	switch raw {
	case nil, "false":
		return false, nil
	case "true":
		return true, nil
	}
	return false, smerr.New(smerr.CodeInvalidArgument, "", param+" must be \"true\" or \"false\"")
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

// applyHandler runs the approved change of a control_plane.apply job. enrollments takes the node.add jobs that
// start or advance a tunnel enrollment (ADR-0039); it is nil without a
// cloudflare: block, and such a job then fails in applyNodeAdd.
type applyHandler struct {
	inv         *Inventory
	enrollments *TunnelEnrollments
	// routes moves the node route of a node_route.expose or node_route.unexpose plan once the apply step
	// admitted it (ADR-0040); nil without a cloudflare: block.
	routes *nodeRouteHandler
	// tunnel takes the Cloudflare objects of a node down before a node.remove retires it; nil without a
	// cloudflare: block.
	tunnel *tunnelEngine
}

func (h applyHandler) Run(ctx context.Context, lease jobs.Lease) error {
	if handled, err := h.enrollments.runJob(ctx, lease); handled || err != nil {
		return err
	}
	job, err := h.inv.jobs.Get(ctx, h.inv.cfg.DB.Reader(), lease.JobID)
	if err != nil {
		return err
	}
	action, err := jobAction(ctx, h.inv.cfg.DB.Reader(), job)
	if err != nil {
		return err
	}
	if action == actionNodeRemove {
		if err := (nodeRemoval{core: h.inv.core, tunnel: h.tunnel}).run(ctx, lease, job); err != nil {
			return err
		}
	}
	if !isNodeRouteAction(action) {
		return h.inv.runApproved(ctx, lease, action)
	}
	if h.routes == nil {
		return requireTunnelAllowed(false, domain.Node{})
	}
	if err := h.inv.runApproved(ctx, lease, action); err != nil {
		return err
	}
	return h.routes.run(ctx, lease, job, action)
}
