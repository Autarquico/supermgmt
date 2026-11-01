package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/plan"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/health"
	"github.com/autarquico/supermgmt/internal/policy"
)

// The plans of a move (ADR-0041). A move plan freezes both nodes (id, endpoint, pinned host key), the known-good
// deployment (its id and its Compose hash in content.rollback_target, and its snapshots in the content hashes) and
// the destination in the to_node parameter. Whether the move is stateful and its volume map are functions of those
// snapshots, so the plan hash binds them: volumeMapOf recomputes them wherever they are needed.

// moveBasis is everything a move plan is built from.
type moveBasis struct {
	scope  deploymentScope // the target; scope.target.SpecRevision is the revision the plan binds
	source domain.Node
	dest   domain.Node
	kg     knownGood
	facts  moveFacts
}

// moveFacts are derived from the frozen known-good model and policy.
type moveFacts struct {
	stateful bool
	volumes  []database.AppMoveVolume
}

// ---- admission ----------------------------------------------------------------------------------------------------

// newMoveBasis reads the known-good deployment good and derives what the move does with it. It refuses the models a
// move cannot carry: a host port bound to an address other than 127.0.0.1 or 0.0.0.0 (the allowed addresses are
// the source node's), a named volume no service mounts read-write, and a health check that runs in the control
// plane (it would not prove B healthy).
func newMoveBasis(ctx context.Context, q database.Querier, scope deploymentScope, source, dest domain.Node, good database.Deployment) (moveBasis, error) {
	kg, err := loadKnownGood(ctx, q, good)
	if err != nil {
		return moveBasis{}, err
	}
	if err := requireMovableBinds(ctx, q, kg); err != nil {
		return moveBasis{}, err
	}
	if err := requireNodeScopeHealth(ctx, q, kg); err != nil {
		return moveBasis{}, err
	}
	facts, err := moveFactsOf(ctx, q, scope.target.ComposeProject, kg)
	if err != nil {
		return moveBasis{}, err
	}
	return moveBasis{scope: scope, source: source, dest: dest, kg: kg, facts: facts}, nil
}

// requireMoveNodes refuses a destination that is the source, is not managed, or lives in another environment.
func requireMoveNodes(source, dest domain.Node) error {
	switch {
	case dest.ID == source.ID:
		return invalidArgument("the destination %s is the node the target already runs on", dest.Name)
	case dest.ManagementState != domain.ManagementManaged:
		return invalidArgument("the destination %s is not managed", dest.Name)
	case !sameNodeEnvironment(source.EnvironmentID, dest.EnvironmentID):
		return invalidArgument("the destination %s is in another environment than %s", dest.Name, source.Name)
	}
	return nil
}

func sameNodeEnvironment(a, b *domain.ID) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// requireNoMoveConflicts is the part of admission that depends on what else is going on: open deployments,
// rollbacks and moves of the target, another target that uses the Compose project on the destination (an open
// move counts as using it) and routes. A move runs it at request time and again under its claim locks, so it
// reads the database only and never excludes the target's own open move: that one is the move being checked.
func requireNoMoveConflicts(ctx context.Context, q database.Querier, target database.AppTarget, dest domain.Node, own *domain.ID) error {
	if err := requireNoOpenDeployment(ctx, q, target.ID); err != nil {
		return err
	}
	if err := requireNoOtherOpenMove(ctx, q, target.ID, own); err != nil {
		return err
	}
	if err := requireProjectFreeOn(ctx, q, target, dest); err != nil {
		return err
	}
	return requireNoTargetRoutes(ctx, q, target.ID)
}

// requireNoOpenDeployment refuses a target with a deployment or rollback that has not ended, provisional ones
// included: finalizing them would deploy while the move copies.
func requireNoOpenDeployment(ctx context.Context, q database.Querier, targetID domain.ID) error {
	for _, state := range deployments.AllStates() {
		if state.Terminal() {
			continue
		}
		open, err := database.ListDeployments(ctx, q, database.DeploymentFilter{AppTargetID: targetID, State: state}, 1)
		if err != nil {
			return err
		}
		if len(open) > 0 {
			return smerr.New(smerr.CodeConflict, "", fmt.Sprintf(
				"the target has a %s %s in state %s: let it finish or cancel it before moving", open[0].Kind, open[0].ID, state))
		}
	}
	return nil
}

func requireNoOtherOpenMove(ctx context.Context, q database.Querier, targetID domain.ID, own *domain.ID) error {
	open, err := database.GetLiveAppMoveByTarget(ctx, q, targetID)
	switch {
	case smerr.CodeOf(err) == smerr.CodeNotFound:
		return nil
	case err != nil:
		return err
	case own != nil && open.ID == *own:
		return nil
	}
	return openMoveError(open)
}

// requireNoOpenMove is the refusal of every other path that would change a target while it is being moved.
func requireNoOpenMove(ctx context.Context, q database.Querier, targetID domain.ID) error {
	return requireNoOtherOpenMove(ctx, q, targetID, nil)
}

func openMoveError(m database.AppMove) error {
	return smerr.New(smerr.CodeConflict, "", fmt.Sprintf(
		"the target has a move to node %s in progress (phase %s): wait for it, resume it with `sm apps move`, or abandon it",
		m.DestNodeID, m.Phase))
}

// requireProjectFreeOn refuses the destination when another target uses the target's Compose project there, or
// is being moved there. (node_id, compose_project) is unique, so an insert that raced this check would fail too.
func requireProjectFreeOn(ctx context.Context, q database.Querier, target database.AppTarget, dest domain.Node) error {
	all, err := database.ListAppTargets(ctx, q)
	if err != nil {
		return err
	}
	for _, other := range all {
		if other.ID == target.ID || other.ComposeProject != target.ComposeProject {
			continue
		}
		onDest := other.NodeID == dest.ID
		if !onDest {
			open, err := database.GetLiveAppMoveByTarget(ctx, q, other.ID)
			if err != nil && smerr.CodeOf(err) != smerr.CodeNotFound {
				return err
			}
			onDest = err == nil && open.DestNodeID == dest.ID
		}
		if onDest {
			return smerr.New(smerr.CodeConflict, "", fmt.Sprintf(
				"another target already uses the compose project %s on %s, or is being moved there", target.ComposeProject, dest.Name))
		}
	}
	return nil
}

// requireNoTargetRoutes refuses a target that has a route that is not removed: moving routes comes with
// app-move-routes.
func requireNoTargetRoutes(ctx context.Context, q database.Querier, targetID domain.ID) error {
	routes, err := database.ListAppRoutes(ctx, q, database.AppRouteFilter{TargetID: targetID})
	if err != nil || len(routes) == 0 {
		return err
	}
	return smerr.New(smerr.CodeConflict, "", fmt.Sprintf(
		"the target has a route (%s): unexpose it first, moving routes is not supported yet", routes[0].Hostname))
}

// requireMovableBinds refuses a model that publishes a port on an address other than loopback or every IPv4
// interface: any other address belongs to the source node.
func requireMovableBinds(ctx context.Context, q database.Querier, kg knownGood) error {
	ports, err := frozenHostPorts(ctx, q, kg.plan.Content.ComposeHash)
	if err != nil {
		return err
	}
	for _, p := range ports {
		if addr := p.Addr.Unmap(); addr != loopback && addr != netip.IPv4Unspecified() {
			return invalidArgument("service %s publishes port %d on %s: a move carries only ports bound to 127.0.0.1 or 0.0.0.0",
				p.Service, p.Port, p.Addr)
		}
	}
	return nil
}

// requireNodeScopeHealth refuses a health check that runs in the control plane: it does not run on a node, so it
// cannot prove that B is healthy before the commit.
func requireNodeScopeHealth(ctx context.Context, q database.Querier, kg knownGood) error {
	check, err := readSnapshotJSON[*health.Check](ctx, q, kg.plan.Content.HealthHash)
	if err != nil {
		return err
	}
	if check != nil && check.Scope == health.ScopeControlPlane {
		return invalidArgument("the health check runs in the control plane and cannot prove the destination healthy: give the target a node-scope check")
	}
	return nil
}

// ---- stateful and the volume map ----------------------------------------------------------------------------------

// moveFactsOf derives whether a move stops the source and the volume map from the frozen model. Stateful is the
// policy flag or any named volume; tmpfs mounts are not data.
func moveFactsOf(ctx context.Context, q database.Querier, project string, kg knownGood) (moveFacts, error) {
	model, err := readSnapshotJSON[composeSnapshot](ctx, q, kg.plan.Content.ComposeHash)
	if err != nil {
		return moveFacts{}, err
	}
	volumes, err := volumeMapOf(project, model.Effective)
	if err != nil {
		return moveFacts{}, err
	}
	return moveFacts{stateful: kg.policy.Stateful || len(volumes) > 0, volumes: volumes}, nil
}

// effectiveModel is the part of a frozen Compose model a move reads.
type effectiveModel struct {
	Services map[string]struct {
		Volumes []effectiveMount `json:"volumes"`
	} `json:"services"`
	Volumes map[string]struct {
		Name string `json:"name"`
	} `json:"volumes"`
}

type effectiveMount struct {
	Type     string `json:"type"`
	Source   string `json:"source"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only"`
}

type volumeMount struct {
	service, target string
	writable        bool
}

// volumeMapOf lists one entry per distinct named volume (<project>_<volume>), sorted by name. Its export and import
// service is the first, in name order, that mounts the volume read-write (at its first read-write target); every
// other service that mounts it is listed too. A volume that no service mounts read-write cannot be imported or
// verified, so it is refused.
func volumeMapOf(project string, effective json.RawMessage) ([]database.AppMoveVolume, error) {
	var model effectiveModel
	if err := json.Unmarshal(effective, &model); err != nil {
		return nil, smerr.Wrap(err, smerr.CodeInternal, "", "the known-good model is unreadable")
	}
	mounts := map[string][]volumeMount{}
	for _, service := range sortedKeys(model.Services) {
		for _, m := range model.Services[service].Volumes {
			switch m.Type {
			case "tmpfs":
				continue
			case "volume":
			default:
				return nil, invalidArgument("service %s has a %q mount: a move carries named volumes only", service, m.Type)
			}
			name, err := volumeName(project, m.Source, model)
			if err != nil {
				return nil, err
			}
			mounts[name] = append(mounts[name], volumeMount{service: service, target: m.Target, writable: !m.ReadOnly})
		}
	}
	out := make([]database.AppMoveVolume, 0, len(mounts))
	for _, name := range sortedKeys(mounts) {
		entry, err := volumeEntry(name, mounts[name])
		if err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	return out, nil
}

// volumeName is the Docker name of the volume a mount names: the project-prefixed key the Compose pipeline
// guarantees, or the declared name when the model states it.
func volumeName(project, source string, model effectiveModel) (string, error) {
	if source == "" {
		return "", invalidArgument("a volume mount names no volume")
	}
	if declared, ok := model.Volumes[source]; ok && declared.Name != "" {
		return declared.Name, nil
	}
	return project + "_" + source, nil
}

func volumeEntry(name string, mounts []volumeMount) (database.AppMoveVolume, error) {
	slices.SortStableFunc(mounts, func(a, b volumeMount) int {
		return strings.Compare(a.service+"\x00"+a.target, b.service+"\x00"+b.target)
	})
	if i := slices.IndexFunc(mounts, func(m volumeMount) bool { return m.service == "" || m.target == "" }); i >= 0 {
		return database.AppMoveVolume{}, invalidArgument("the volume %s has a mount with no service name or no target path", name)
	}
	i := slices.IndexFunc(mounts, func(m volumeMount) bool { return m.writable })
	if i < 0 {
		return database.AppMoveVolume{}, invalidArgument("the volume %s is mounted by no service read-write: nothing could export or import it", name)
	}
	exporter := mounts[i]
	others := []string{}
	for _, m := range mounts {
		if m.service != exporter.service && !slices.Contains(others, m.service) {
			others = append(others, m.service)
		}
	}
	return database.AppMoveVolume{VolumeName: name, Service: exporter.service, MountTarget: exporter.target, OtherServices: others}, nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// moveSteps is the plan's step list: the forward phases in order, the stateful ones only for a stateful move.
func moveSteps(stateful bool) []string {
	phases := []database.AppMovePhase{database.AppMovePreflight, database.AppMoveStaged}
	if stateful {
		phases = append(phases, database.AppMoveSourceStop, database.AppMoveDataCopied)
	}
	phases = append(phases, database.AppMoveStarted, database.AppMoveVerified, database.AppMoveCommitted, database.AppMoveSourceParked)
	steps := make([]string, len(phases))
	for i, p := range phases {
		steps[i] = string(p)
	}
	return steps
}

// ---- building the plans -------------------------------------------------------------------------------------------

// policyTargetOn is the policy view of the scope's app target as seen from node: the node's attributes and
// capabilities with the environment and app of the target.
func (s deploymentScope) policyTargetOn(ctx context.Context, q database.Querier, nodeID domain.ID, ref domain.ResourceRef) (policy.Target, error) {
	node, err := resolveNode(ctx, q, nodeID)
	if err != nil {
		return policy.Target{}, err
	}
	target := node.target
	target.Ref = ref
	target.Attrs.Environment, target.Attrs.EnvironmentRisk = s.env.Name, s.env.RiskLevel
	target.Attrs.ApprovalsRequired, target.Attrs.App = s.env.ApprovalsRequired, s.app.Name
	return target, nil
}

// buildMovePlan assembles the app_target.move plan of b. The target is evaluated from the source node, and the
// destination is a sub-action, so policy rules and capabilities apply to both nodes.
func buildMovePlan(ctx context.Context, q database.Querier, b moveBasis, requester domain.ID) (built, error) {
	params := map[string]any{policy.ParamToNode: b.dest.ID.String()}
	action, risk, err := lookupMoveAction(appMoveAction, params)
	if err != nil {
		return built{}, err
	}
	target, err := b.scope.policyTargetOn(ctx, q, b.source.ID, appTargetRef(b.scope.target.ID))
	if err != nil {
		return built{}, err
	}
	destTarget, err := b.scope.policyTargetOn(ctx, q, b.dest.ID, nodeRef(b.dest.ID))
	if err != nil {
		return built{}, err
	}
	sourcePin, err := pinnedNodeInput(b.source)
	if err != nil {
		return built{}, err
	}
	destPin, err := pinnedNodeInput(b.dest)
	if err != nil {
		return built{}, err
	}
	content := rollbackContent(b.kg)
	content.RollbackTarget = &plan.RollbackTarget{DeploymentID: b.kg.deployment.ID.String(), ComposeHash: b.kg.deployment.ComposeHash}
	inputs := append([]plan.Input{revisionInput(domain.ResourceEnvironment, b.scope.env.ID, b.scope.env.SpecRevision), sourcePin, destPin},
		secretInputsOf(b.kg.plan.Content.SecretBindings)...)
	revision := b.scope.target.SpecRevision
	return built{
		spec: action, target: target,
		subs: []policy.SubAction{{Action: appMoveAction, Params: params, Target: destTarget}},
		plan: plan.Plan{
			Version: plan.Version, Action: appMoveAction, Actor: "identity/" + requester.String(),
			Targets:    []plan.Target{{Type: string(domain.ResourceAppTarget), ID: b.scope.target.ID.String(), SpecRevision: &revision}},
			Inputs:     inputs,
			Content:    content,
			SubActions: []plan.SubAction{{Action: appMoveAction, Target: plan.SubTarget{Type: string(domain.ResourceNode), ID: b.dest.ID.String()}}},
			Parameters: params, Steps: moveSteps(b.facts.stateful), Risk: risk,
		},
	}, nil
}

// buildCleanupPlan assembles the app_target.cleanup_source plan for the done move m: it freezes the move, the
// source node and the deployment whose containers the source is left with.
func buildCleanupPlan(ctx context.Context, q database.Querier, scope deploymentScope, m database.AppMove, requester domain.ID) (built, error) {
	params := map[string]any{policy.ParamMoveID: m.ID.String()}
	action, risk, err := lookupMoveAction(appMoveCleanupAction, params)
	if err != nil {
		return built{}, err
	}
	source, err := database.GetNode(ctx, q, m.SourceNodeID)
	if err != nil {
		return built{}, err
	}
	pin, err := pinnedNodeInput(source)
	if err != nil {
		return built{}, err
	}
	parked, err := database.GetDeployment(ctx, q, m.KnownGoodDeploymentID)
	if err != nil {
		return built{}, err
	}
	target, err := scope.policyTargetOn(ctx, q, source.ID, appTargetRef(scope.target.ID))
	if err != nil {
		return built{}, err
	}
	revision := scope.target.SpecRevision
	return built{
		spec: action, target: target,
		plan: plan.Plan{
			Version: plan.Version, Action: appMoveCleanupAction, Actor: "identity/" + requester.String(),
			Targets:    []plan.Target{{Type: string(domain.ResourceAppTarget), ID: scope.target.ID.String(), SpecRevision: &revision}},
			Inputs:     []plan.Input{revisionInput(domain.ResourceEnvironment, scope.env.ID, scope.env.SpecRevision), pin},
			Content:    plan.Content{RollbackTarget: &plan.RollbackTarget{DeploymentID: parked.ID.String(), ComposeHash: parked.ComposeHash}},
			Parameters: params, Steps: []string{"compose-down"}, Risk: risk,
		},
	}, nil
}

// buildAbandonPlan assembles the app_target.abandon_move plan for the halted move m. It touches no node.
func buildAbandonPlan(ctx context.Context, q database.Querier, scope deploymentScope, m database.AppMove, requester domain.ID) (built, error) {
	params := map[string]any{policy.ParamMoveID: m.ID.String()}
	action, risk, err := lookupMoveAction(appMoveAbandonAction, params)
	if err != nil {
		return built{}, err
	}
	target, err := scope.policyTarget(ctx, q, appTargetRef(scope.target.ID))
	if err != nil {
		return built{}, err
	}
	revision := scope.target.SpecRevision
	return built{
		spec: action, target: target,
		plan: plan.Plan{
			Version: plan.Version, Action: appMoveAbandonAction, Actor: "identity/" + requester.String(),
			Targets:    []plan.Target{{Type: string(domain.ResourceAppTarget), ID: scope.target.ID.String(), SpecRevision: &revision}},
			Inputs:     []plan.Input{revisionInput(domain.ResourceEnvironment, scope.env.ID, scope.env.SpecRevision)},
			Parameters: params, Steps: []string{"abandon"}, Risk: risk,
		},
	}, nil
}

func lookupMoveAction(name string, params map[string]any) (policy.ActionSpec, domain.RiskClass, error) {
	action, ok := policy.Lookup(name)
	if !ok {
		return policy.ActionSpec{}, "", smerr.New(smerr.CodeInvalidArgument, smerr.ReasonUnknownAction, "unknown action: "+name)
	}
	risk, err := policy.RiskFor(name, params)
	return action, risk, err
}

func pinnedNodeInput(node domain.Node) (plan.Input, error) {
	pin, err := nodeInput(node)
	if err != nil {
		return plan.Input{}, smerr.Wrap(err, smerr.CodeInvalidArgument, "", "the host key of node "+node.Name+" is unreadable")
	}
	return pin, nil
}

// ---- revalidation -------------------------------------------------------------------------------------------------

// isMoveAction reports whether action is one of the three move actions. They are requested through their own
// service, never through POST /plans: the move record is written together with the plan.
func isMoveAction(action string) bool {
	return action == appMoveAction || action == appMoveCleanupAction || action == appMoveAbandonAction
}

// pastCommit reports whether the move's target node already is the destination: the move is committed, parking
// the source or done. A halted move counts by the phase it held.
func pastCommit(m database.AppMove) bool {
	phase := m.Phase
	if phase.Halted() {
		phase = m.HaltedPhase
	}
	return phase == database.AppMoveCommitted || phase == database.AppMoveSourceParked || phase == database.AppMoveDone
}

// rebuildMoveAction recomputes the plan of a move action at a claim (spec §9).
func rebuildMoveAction(ctx context.Context, q database.Querier, rec database.PlanRecord) (built, error) {
	stored, scope, err := loadStoredDeployment(ctx, q, rec)
	if err != nil {
		return built{}, err
	}
	switch rec.Action {
	case appMoveAction:
		return rebuildMove(ctx, q, rec, stored, scope)
	case appMoveCleanupAction:
		return rebuildCleanup(ctx, q, rec, stored, scope)
	}
	return rebuildAbandon(ctx, q, rec, stored, scope)
}

// moveOfPlan is the move a plan belongs to. A resuming request rebinds the move to its own plan, so the plan of an
// earlier request finds none and is stale.
func moveOfPlan(ctx context.Context, q database.Querier, targetID, planID domain.ID) (database.AppMove, error) {
	all, err := database.ListAppMovesByTarget(ctx, q, targetID)
	if err != nil {
		return database.AppMove{}, err
	}
	for _, m := range all {
		if m.PlanID == planID {
			return m, nil
		}
	}
	return database.AppMove{}, planStale()
}

func storedParameter(p plan.Plan, name string) string {
	value, _ := p.Parameters[name].(string)
	return value
}

// rebuildMove validates a claim of app_target.move. Before the commit the plan is rebuilt against the nodes and
// the known-good deployment the move froze, and must hash as stored. From the commit on the rebuild of a moved
// target always differs from its plan, so the claim is validated against the move record: its plan, job,
// destination, B's deployment and the revision the commit wrote must all match. The returned plan only serves
// the requester's authorization then, and is built from the frozen nodes either way.
func rebuildMove(ctx context.Context, q database.Querier, rec database.PlanRecord, stored plan.Plan, scope deploymentScope) (built, error) {
	m, err := moveOfPlan(ctx, q, scope.target.ID, rec.ID)
	if err != nil {
		return built{}, err
	}
	if rec.SubmittedJobID == nil || *rec.SubmittedJobID != m.JobID || storedParameter(stored, policy.ParamToNode) != m.DestNodeID.String() {
		return built{}, planStale()
	}
	if pastCommit(m) {
		if err := requireCommittedMove(ctx, q, m, scope.target); err != nil {
			return built{}, err
		}
		scope.target.SpecRevision = *stored.Targets[0].SpecRevision
	} else if scope.target.NodeID != m.SourceNodeID {
		return built{}, planStale()
	}
	b, err := movePlanOfRecord(ctx, q, scope, m, rec.ActorID)
	if err != nil {
		return built{}, err
	}
	if pastCommit(m) {
		return b, requireSameNodePins(b.plan, stored)
	}
	return b, requireSamePlan(b, rec)
}

// requireSameNodePins refuses a plan whose nodes are not reached at the endpoints and host keys it was approved with.
// It is what stays of the plan hash once the commit has changed the target the rest of the plan describes.
func requireSameNodePins(current, stored plan.Plan) error {
	nodes := func(p plan.Plan) map[string]plan.Input {
		out := map[string]plan.Input{}
		for _, in := range p.Inputs {
			if in.Type == string(domain.ResourceNode) {
				out[in.ID] = in
			}
		}
		return out
	}
	now, then := nodes(current), nodes(stored)
	if len(now) != len(then) {
		return planStale()
	}
	for id, in := range then {
		if got, ok := now[id]; !ok || !samePin(got, in) {
			return planStale()
		}
	}
	return nil
}

// samePin reports whether two inputs of one node have the same endpoint and host key, as requirePinnedNode compares
// them.
func samePin(a, b plan.Input) bool {
	return a.Endpoint != nil && b.Endpoint != nil && *a.Endpoint == *b.Endpoint &&
		a.HostPublicKeySHA256 != nil && b.HostPublicKeySHA256 != nil && *a.HostPublicKeySHA256 == *b.HostPublicKeySHA256
}

// requireCommittedMove checks a committed move against the world it wrote: the target runs on B at the revision
// the commit recorded, and B's deployment is the move deployment of this target on B.
func requireCommittedMove(ctx context.Context, q database.Querier, m database.AppMove, target database.AppTarget) error {
	if m.DestDeploymentID == nil || m.CommittedRevision == 0 || target.NodeID != m.DestNodeID || target.SpecRevision != m.CommittedRevision {
		return planStale()
	}
	dep, err := database.GetDeployment(ctx, q, *m.DestDeploymentID)
	if err != nil {
		return err
	}
	if dep.Kind != deployments.KindMove || dep.AppTargetID != target.ID || dep.NodeID != m.DestNodeID {
		return planStale()
	}
	return nil
}

// movePlanOfRecord rebuilds the plan of the move m from the nodes and the deployment it froze, whatever the
// target's node is now.
func movePlanOfRecord(ctx context.Context, q database.Querier, scope deploymentScope, m database.AppMove, requester domain.ID) (built, error) {
	source, err := database.GetNode(ctx, q, m.SourceNodeID)
	if err != nil {
		return built{}, err
	}
	dest, err := database.GetNode(ctx, q, m.DestNodeID)
	if err != nil {
		return built{}, err
	}
	good, err := database.GetDeployment(ctx, q, m.KnownGoodDeploymentID)
	if err != nil {
		return built{}, err
	}
	basis, err := newMoveBasis(ctx, q, scope, source, dest, good)
	if err != nil {
		return built{}, err
	}
	return buildMovePlan(ctx, q, basis, requester)
}

func rebuildCleanup(ctx context.Context, q database.Querier, rec database.PlanRecord, stored plan.Plan, scope deploymentScope) (built, error) {
	m, err := movePlanned(ctx, q, scope.target.ID, stored)
	if err != nil {
		return built{}, err
	}
	b, err := buildCleanupPlan(ctx, q, scope, m, rec.ActorID)
	if err != nil {
		return built{}, err
	}
	return b, requireSamePlan(b, rec)
}

func rebuildAbandon(ctx context.Context, q database.Querier, rec database.PlanRecord, stored plan.Plan, scope deploymentScope) (built, error) {
	m, err := movePlanned(ctx, q, scope.target.ID, stored)
	if err != nil {
		return built{}, err
	}
	b, err := buildAbandonPlan(ctx, q, scope, m, rec.ActorID)
	if err != nil {
		return built{}, err
	}
	return b, requireSamePlan(b, rec)
}

// movePlanned is the move a cleanup or abandon plan names, which must belong to the plan's target.
func movePlanned(ctx context.Context, q database.Querier, targetID domain.ID, stored plan.Plan) (database.AppMove, error) {
	m, err := database.GetAppMove(ctx, q, domain.ID(storedParameter(stored, policy.ParamMoveID)))
	if smerr.CodeOf(err) == smerr.CodeNotFound || err == nil && m.AppTargetID != targetID {
		return database.AppMove{}, planStale()
	}
	return m, err
}
