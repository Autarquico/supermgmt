package app

import (
	"context"
	"fmt"
	"slices"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/plan"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/policy"
	"github.com/autarquico/supermgmt/internal/runtimes"
)

// resolved is a target as the database sees it now: the policy view (effective
// attributes, capabilities), its spec_revision, and the configured resources
// its attributes derive from (spec §6.4, §11.3).
type resolved struct {
	target   policy.Target
	revision int64
	inputs   []plan.Input
}

// resolve supports nodes, services, apps, app targets and the instance. The
// instance has no spec_revision and no configured inputs (spec §29.1 backups
// act on it).
func resolve(ctx context.Context, q database.Querier, ref domain.ResourceRef) (resolved, error) {
	switch ref.Type { //nolint:exhaustive // every other type is refused below
	case domain.ResourceNode:
		return resolveNode(ctx, q, ref.ID)
	case domain.ResourceService:
		return resolveService(ctx, q, ref.ID)
	case domain.ResourceApp:
		return resolveApp(ctx, q, ref.ID)
	case domain.ResourceAppTarget:
		return resolveAppTarget(ctx, q, ref.ID)
	case domain.ResourceInstance:
		return resolved{target: policy.Target{Ref: ref}}, nil
	}
	return resolved{}, smerr.New(smerr.CodeInvalidArgument, "", fmt.Sprintf("resource type %q is not supported yet", ref.Type))
}

// resolveApp is the policy view of an app. An app has no environment of its
// own, so a change to it is judged by the strictest environment among its
// targets: editing the Compose of a production app needs the production
// approvals (spec §19.2). Every target and environment is a plan input.
func resolveApp(ctx context.Context, q database.Querier, id domain.ID) (resolved, error) {
	app, err := database.GetApp(ctx, q, id)
	if err != nil {
		return resolved{}, err
	}
	targets, err := database.ListAppTargetsByApp(ctx, q, id)
	if err != nil {
		return resolved{}, err
	}
	out := resolved{target: appPolicyTarget(id, app.Name), revision: app.SpecRevision}
	var strictest *domain.Environment
	for _, t := range targets {
		env, err := database.GetEnvironment(ctx, q, t.EnvironmentID)
		if err != nil {
			return resolved{}, err
		}
		out.inputs = append(out.inputs,
			revisionInput(domain.ResourceAppTarget, t.ID, t.SpecRevision),
			revisionInput(domain.ResourceEnvironment, env.ID, env.SpecRevision))
		if strictest == nil || stricterEnvironment(env, *strictest) {
			strictest = &env
		}
	}
	if strictest != nil {
		out.target.Attrs.Environment = strictest.Name
		out.target.Attrs.EnvironmentRisk = strictest.RiskLevel
		out.target.Attrs.ApprovalsRequired = strictest.ApprovalsRequired
	}
	return out, nil
}

// stricterEnvironment orders environments by risk level, then by approvals.
func stricterEnvironment(a, b domain.Environment) bool {
	rank := func(e domain.Environment) int {
		return slices.Index(domain.AllEnvironmentRiskLevels(), e.RiskLevel)
	}
	if rank(a) != rank(b) {
		return rank(a) > rank(b)
	}
	return a.ApprovalsRequired > b.ApprovalsRequired
}

// resolveAppTarget is the policy view of a target: its environment, its app's
// name and its node's name, tags and capabilities (docker.compose.deploy is a
// capability of the node).
func resolveAppTarget(ctx context.Context, q database.Querier, id domain.ID) (resolved, error) {
	row, err := database.GetAppTarget(ctx, q, id)
	if err != nil {
		return resolved{}, err
	}
	app, err := database.GetApp(ctx, q, row.AppID)
	if err != nil {
		return resolved{}, err
	}
	env, err := database.GetEnvironment(ctx, q, row.EnvironmentID)
	if err != nil {
		return resolved{}, err
	}
	node, err := database.GetNode(ctx, q, row.NodeID)
	if err != nil {
		return resolved{}, err
	}
	capabilities, err := capabilitiesOf(ctx, q, node.ID)
	if err != nil {
		return resolved{}, err
	}
	return resolved{
		target: policy.Target{
			Ref: domain.ResourceRef{Type: domain.ResourceAppTarget, ID: id}, Attrs: appTargetAttributes(app, env, node), Capabilities: capabilities,
		},
		revision: row.SpecRevision,
		inputs: []plan.Input{
			revisionInput(domain.ResourceApp, app.ID, app.SpecRevision),
			revisionInput(domain.ResourceEnvironment, env.ID, env.SpecRevision),
			revisionInput(domain.ResourceNode, node.ID, node.SpecRevision),
		},
	}, nil
}

func appTargetAttributes(app database.App, env domain.Environment, node domain.Node) policy.Attributes {
	return policy.Attributes{
		Tags: node.Tags, Environment: env.Name, EnvironmentRisk: env.RiskLevel,
		ApprovalsRequired: env.ApprovalsRequired, Node: node.Name, App: app.Name,
	}
}

func resolveNode(ctx context.Context, q database.Querier, id domain.ID) (resolved, error) {
	node, err := database.GetNode(ctx, q, id)
	if err != nil {
		return resolved{}, err
	}
	out := resolved{
		target:   policy.Target{Ref: domain.ResourceRef{Type: domain.ResourceNode, ID: id}},
		revision: node.SpecRevision,
	}
	out.target.Attrs = policy.Attributes{Tags: node.Tags, Node: node.Name}

	if node.EnvironmentID != nil {
		env, err := database.GetEnvironment(ctx, q, *node.EnvironmentID)
		if err != nil {
			return resolved{}, err
		}
		out.target.Attrs.Environment = env.Name
		out.target.Attrs.EnvironmentRisk = env.RiskLevel
		out.target.Attrs.ApprovalsRequired = env.ApprovalsRequired
		out.inputs = append(out.inputs, revisionInput(domain.ResourceEnvironment, env.ID, env.SpecRevision))
	}
	provider, err := database.GetProvider(ctx, q, node.ProviderID)
	if err != nil {
		return resolved{}, err
	}
	out.target.Attrs.Provider = provider.Name
	out.inputs = append(out.inputs, revisionInput(domain.ResourceProvider, provider.ID, provider.SpecRevision))

	out.target.Capabilities, err = capabilitiesOf(ctx, q, id)
	return out, err
}

// resolveService takes its attributes and capabilities from its node (spec
// §11.3: service-level tags do not exist in V1) and records the node as an input.
func resolveService(ctx context.Context, q database.Querier, id domain.ID) (resolved, error) {
	service, err := database.GetService(ctx, q, id)
	if err != nil {
		return resolved{}, err
	}
	if _, err := serviceLock(service, domain.LockExclusive); err != nil {
		return resolved{}, err
	}
	out, err := resolveNode(ctx, q, service.NodeID)
	if err != nil {
		return resolved{}, err
	}
	nodeInput := revisionInput(domain.ResourceNode, service.NodeID, out.revision)
	out.inputs = append([]plan.Input{nodeInput}, out.inputs...)
	out.target.Ref = domain.ResourceRef{Type: domain.ResourceService, ID: id}
	out.revision = service.SpecRevision
	return out, nil
}

func capabilitiesOf(ctx context.Context, q database.Querier, node domain.ID) (policy.CapabilitySet, error) {
	all, err := database.ListNodeCapabilities(ctx, q, node)
	if err != nil {
		return nil, err
	}
	// node.read is the one capability that is true of every node by
	// definition (discovery reports it available on every probe), so a node
	// that was just added can be probed before its first refresh.
	set := policy.NewCapabilitySet("node.read")
	for _, c := range all {
		if c.Available {
			set[c.Capability] = struct{}{}
		}
	}
	return set, nil
}

func revisionInput(typ domain.ResourceType, id domain.ID, revision int64) plan.Input {
	return plan.Input{Type: string(typ), ID: id.String(), SpecRevision: &revision}
}

// built is a plan together with the policy view of its target it was built from.
type built struct {
	plan   plan.Plan
	target policy.Target
	spec   policy.ActionSpec
	subs   []policy.SubAction
}

// request is the policy request that decides whether actor may run this plan.
// Direct actions carry their request in the plan parameters, but the catalog
// declares no parameters for them, so policy evaluates them without.
func (b built) request(actor domain.Actor) policy.Request {
	params := b.plan.Parameters
	if b.spec.Mode == policy.ModeDirect {
		params = nil
	}
	return policy.Request{
		Actor: actor, Action: b.plan.Action, Params: params,
		Targets: []policy.Target{b.target}, SubActions: b.subs,
	}
}

// build assembles the version 3 plan for action on ref from the current
// database state (Appendix C). Only job-mode actions go through plans, and the
// target must be of the type the catalog declares.
func build(ctx context.Context, q database.Querier, action string, actorID domain.ID, ref domain.ResourceRef, params map[string]any) (built, error) {
	spec, ok := policy.Lookup(action)
	switch {
	case !ok:
		return built{}, smerr.New(smerr.CodeInvalidArgument, smerr.ReasonUnknownAction, "unknown action: "+action)
	case spec.Mode == policy.ModeDirect:
		return buildDirect(ctx, q, spec, actorID, ref, params)
	case spec.Mode != policy.ModeJob:
		return built{}, smerr.New(smerr.CodeInvalidArgument, "", fmt.Sprintf("action %s does not run through a plan", action))
	case spec.Resource != ref.Type:
		return built{}, smerr.New(smerr.CodeInvalidArgument, "",
			fmt.Sprintf("action %s targets a %s, not a %s", action, spec.Resource, ref.Type))
	}
	risk, err := policy.RiskFor(action, params)
	if err != nil {
		return built{}, err
	}
	if err := validateParameters(action, params); err != nil {
		return built{}, err
	}
	target, err := resolve(ctx, q, ref)
	if err != nil {
		return built{}, err
	}
	revision := target.revision
	if action == policy.ActionNodeTunnelDisable {
		// The job moves the node's endpoint itself, partway through; a
		// takeover re-claims it, and the claim must not find its own change
		// a reason to call the plan stale (ADR-0037).
		revision = 0
	}
	subs, planned := compositeOf(action, params, target.target)
	return built{
		spec:   spec,
		target: target.target,
		subs:   subs,
		plan: plan.Plan{
			Version:    plan.Version,
			Action:     action,
			Actor:      "identity/" + actorID.String(),
			Targets:    []plan.Target{{Type: string(ref.Type), ID: ref.ID.String(), SpecRevision: &revision}},
			Inputs:     target.inputs,
			SubActions: planned,
			Parameters: params,
			Risk:       risk,
		},
	}, nil
}

// compositeOf lists the sub-actions a plan evaluates alongside its action
// (spec §11.3): node.setup always writes sudoers, and installs the log broker
// in broker mode (ADR-0009).
func compositeOf(action string, params map[string]any, target policy.Target) ([]policy.SubAction, []plan.SubAction) {
	if action != policy.ActionNodeSetup {
		return nil, nil
	}
	names := []string{policy.ActionSudoersWrite}
	if mode, _ := params[policy.ParamLogsMode].(string); mode == string(runtimes.LogsBroker) {
		names = append(names, policy.ActionLogBrokerInstall)
	}
	subs := make([]policy.SubAction, len(names))
	planned := make([]plan.SubAction, len(names))
	for i, name := range names {
		subs[i] = policy.SubAction{Action: name, Target: target}
		planned[i] = plan.SubAction{Action: name, Target: plan.SubTarget{Type: string(target.Ref.Type), ID: target.Ref.ID.String()}}
	}
	return subs, planned
}

// rebuildCurrent recomputes a stored plan's action on its target from the
// current database state. A target that no longer exists makes the plan stale.
func rebuildCurrent(ctx context.Context, q database.Querier, rec database.PlanRecord) (built, error) {
	stored, err := plan.Parse(rec.PlanJSON)
	if err != nil {
		return built{}, err
	}
	if len(stored.Targets) != 1 {
		return built{}, smerr.New(smerr.CodeInternal, "", "stored plan must have exactly one target")
	}
	t := stored.Targets[0]
	ref := domain.ResourceRef{Type: domain.ResourceType(t.Type), ID: domain.ID(t.ID)}
	current, err := build(ctx, q, rec.Action, rec.ActorID, ref, stored.Parameters)
	if smerr.CodeOf(err) == smerr.CodeNotFound {
		return built{}, planStale()
	}
	return current, err
}

// rebuild is rebuildCurrent plus the staleness check: the plan hash covers
// every input, so a recomputed hash that differs from the stored one means a
// configured input changed. Observations never change it (spec §6.4).
func rebuild(ctx context.Context, q database.Querier, rec database.PlanRecord) (built, error) {
	current, err := rebuildCurrent(ctx, q, rec)
	if err != nil {
		return built{}, err
	}
	hash, err := plan.Hash(&current.plan)
	if err != nil {
		return built{}, err
	}
	if hash != rec.PlanHash {
		return built{}, planStale()
	}
	return current, nil
}

func planStale() error {
	return smerr.FromReason(smerr.ReasonPlanStale, "plan inputs changed since the plan was created")
}
