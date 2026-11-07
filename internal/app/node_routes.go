package app

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
)

// maxRoutesPerNode is the 100-rule limit of a tunnel's ingress minus the SSH rule and the catch-all.
const maxRoutesPerNode = 98

// reservedSSHLabelPrefix marks the namespace of node SSH hostnames (ssh-<node>.<zone>).
const reservedSSHLabelPrefix = "ssh-"

// NodeRoutes exposes a local port of a node through the node's Cloudflare Tunnel (ADR-0040, ADR-0043). A request
// is a plan of node_route.expose or node_route.unexpose. The route row is written when the request is admitted:
// in the request transaction when policy needs no approval, else by the apply step of the approved job, always
// in admitted. The Cloudflare work itself runs in that same control_plane.apply job (node_routes_job.go),
// which is the only writer of the route's progress from then on.
type NodeRoutes struct {
	core
	plans *Plans
}

// NewNodeRoutes validates cfg and builds the node routes service. The job store is the one built with this
// package's Revalidator and LockPlanner.
func NewNodeRoutes(cfg Config, jobStore *jobs.Store) (*NodeRoutes, error) {
	plans, err := NewPlans(cfg, jobStore)
	if err != nil {
		return nil, err
	}
	return &NodeRoutes{core: plans.core, plans: plans}, nil
}

// ExposeRouteRequest asks to publish a port of a node under a hostname.
type ExposeRouteRequest struct {
	Hostname string
	Port     int
	// Access is public or owners. Empty means public: the omitted value is normalised before policy evaluates.
	Access string
}

// NodeRouteResult is the outcome of an expose or unexpose request. Submission is the plan's job, which waits for
// approval when policy asks. Route is nil while an expose waits for approval: nothing is written before it.
type NodeRouteResult struct {
	Route      *database.NodeRoute
	Submission Submission
}

func (r NodeRouteResult) createdJob() *domain.ID { return &r.Submission.Job.ID }

// Expose requests a route for the node (action node_route.expose).
func (s *NodeRoutes) Expose(ctx context.Context, by Caller, nodeID domain.ID, r ExposeRouteRequest) (NodeRouteResult, error) {
	p, err := s.exposeParams(r)
	if err != nil {
		return NodeRouteResult{}, err
	}
	return commit(ctx, s.core, by, func(ctx context.Context, tx *database.Tx) (NodeRouteResult, error) {
		actor, err := s.beginRequest(ctx, tx, by)
		if err != nil {
			return NodeRouteResult{}, err
		}
		b, err := s.planOf(ctx, tx, by, nodeRouteExposeAction, nodeID, p)
		if err != nil {
			return NodeRouteResult{}, err
		}
		res, err := s.evaluate(ctx, tx, actor, b)
		if err != nil {
			return NodeRouteResult{}, err
		}
		if res.ApprovalRequired {
			// Nothing is written before the approval, but an expose that cannot be admitted is refused now.
			if _, _, err := s.assess(ctx, tx, nodeID, p, true); err != nil {
				return NodeRouteResult{}, err
			}
		}
		submission, err := s.plans.planAndSubmit(ctx, tx, by, actor, b, res)
		if err != nil || res.ApprovalRequired {
			return NodeRouteResult{Submission: submission}, err
		}
		row, err := s.admit(ctx, tx, actor, nodeID, *submission.Job.PlanID, p, true)
		return NodeRouteResult{Route: &row, Submission: submission}, err
	})
}

// Unexpose requests the removal of the node's route for hostname (action node_route.unexpose).
func (s *NodeRoutes) Unexpose(ctx context.Context, by Caller, nodeID domain.ID, hostname string) (NodeRouteResult, error) {
	p := nodeRouteParams{Hostname: canonicalHostname(hostname)}
	return commit(ctx, s.core, by, func(ctx context.Context, tx *database.Tx) (NodeRouteResult, error) {
		actor, err := s.beginRequest(ctx, tx, by)
		if err != nil {
			return NodeRouteResult{}, err
		}
		route, err := s.routeOf(ctx, tx, nodeID, p.Hostname)
		if err != nil {
			return NodeRouteResult{}, err
		}
		p.RouteID = route.ID.String()
		b, err := s.planOf(ctx, tx, by, nodeRouteUnexposeAction, nodeID, p)
		if err != nil {
			return NodeRouteResult{}, err
		}
		res, err := s.evaluate(ctx, tx, actor, b)
		if err != nil {
			return NodeRouteResult{}, err
		}
		submission, err := s.plans.planAndSubmit(ctx, tx, by, actor, b, res)
		return NodeRouteResult{Route: &route, Submission: submission}, err
	})
}

// List returns the routes of one node or of every node when nodeID is empty, those the caller may read. Removed
// routes are left out unless includeRemoved is set.
func (s *NodeRoutes) List(ctx context.Context, by Caller, nodeID domain.ID, includeRemoved bool) ([]database.NodeRoute, error) {
	q := s.cfg.DB.Reader()
	actor, err := s.beginRequest(ctx, q, by)
	if err != nil {
		return nil, err
	}
	rows, err := database.ListNodeRoutes(ctx, q, database.NodeRouteFilter{NodeID: nodeID, IncludeRemoved: includeRemoved})
	if err != nil {
		return nil, err
	}
	readable := map[domain.ID]bool{}
	out := make([]database.NodeRoute, 0, len(rows))
	for _, row := range rows {
		allowed, known := readable[row.NodeID]
		if !known {
			resolved, err := resolveNode(ctx, q, row.NodeID)
			if err != nil {
				return nil, err
			}
			allowed = s.authorize(policy.Request{Actor: actor, Action: "node_route.read", Targets: []policy.Target{resolved.target}}).Decision == policy.DecisionAllow
			readable[row.NodeID] = allowed
		}
		if allowed {
			out = append(out, row)
		}
	}
	return out, nil
}

func (s *NodeRoutes) planOf(ctx context.Context, q database.Querier, by Caller, action string, nodeID domain.ID, p nodeRouteParams) (built, error) {
	params, err := toParams(p)
	if err != nil {
		return built{}, err
	}
	return build(ctx, q, action, by.ID, nodeRef(nodeID), params)
}

// routeOf is the live route of hostname on the node; NOT_FOUND when the hostname belongs to nobody or to
// another node (the caller cannot tell which).
func (s *NodeRoutes) routeOf(ctx context.Context, q database.Querier, nodeID domain.ID, hostname string) (database.NodeRoute, error) {
	route, err := database.GetLiveNodeRouteByHostname(ctx, q, hostname)
	if err == nil && route.NodeID != nodeID {
		return database.NodeRoute{}, smerr.New(smerr.CodeNotFound, "", "the node has no route for "+hostname)
	}
	if smerr.CodeOf(err) == smerr.CodeNotFound {
		return database.NodeRoute{}, smerr.New(smerr.CodeNotFound, "", "the node has no route for "+hostname)
	}
	return route, err
}

// ---- parameters -------------------------------------------------------------------------------------

// exposeParams validates the shape of a request and writes it in its canonical form, before policy sees it.
func (s *NodeRoutes) exposeParams(r ExposeRouteRequest) (nodeRouteParams, error) {
	if s.cfg.Cloudflare == nil {
		return nodeRouteParams{}, requireTunnelAllowed(false, domain.Node{})
	}
	hostname, err := routeHostname(r.Hostname, s.cfg.Cloudflare.Zone)
	if err != nil {
		return nodeRouteParams{}, err
	}
	access := r.Access
	if access == "" {
		access = "public"
	}
	p := nodeRouteParams{Hostname: hostname, Port: strconv.Itoa(r.Port), Access: access}
	return p, p.validate(true)
}

// canonicalHostname is the stored form of a hostname: lower case, without a trailing dot.
func canonicalHostname(hostname string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(hostname)), ".")
}

// routeHostname canonicalises hostname and holds it to a name under zone on a label boundary, outside the
// namespace of the nodes' SSH hostnames.
func routeHostname(hostname, zone string) (string, error) {
	host, suffix := canonicalHostname(hostname), "."+canonicalHostname(zone)
	if !strings.HasSuffix(host, suffix) || len(host) == len(suffix) {
		return "", invalidArgument("the hostname %q is not under the zone %s", hostname, zone)
	}
	if len(host) > 253 {
		return "", invalidArgument("the hostname %q is too long", hostname)
	}
	for _, label := range strings.Split(host, ".") {
		if !validDNSLabel(label) {
			return "", invalidArgument("the hostname %q is not a valid DNS name: each label is 1-63 letters, digits or hyphens, and neither starts nor ends with a hyphen", hostname)
		}
	}
	if strings.HasPrefix(host, reservedSSHLabelPrefix) {
		return "", invalidArgument("hostnames starting with %q are reserved for the SSH hostnames of nodes", reservedSSHLabelPrefix)
	}
	return host, nil
}

func validDNSLabel(label string) bool {
	if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, c := range label {
		if c != '-' && (c < '0' || c > '9') && (c < 'a' || c > 'z') {
			return false
		}
	}
	return true
}

// ---- admission --------------------------------------------------------------------------------------

// assess runs the refusals of spec item 1 and says what the admitted route would start as: nothing when
// the hostname already belongs to this very route, else its tunnel identity.
func (s *NodeRoutes) assess(ctx context.Context, q database.Querier, nodeID domain.ID, p nodeRouteParams, request bool) (*admission, *database.NodeRoute, error) {
	if s.cfg.Cloudflare == nil {
		return nil, nil, requireTunnelAllowed(false, domain.Node{})
	}
	existing, err := database.GetLiveNodeRouteByHostname(ctx, q, p.Hostname)
	switch {
	case err == nil:
		if routeHas(existing, nodeID, p) && (!request || existing.Phase.Halted()) {
			return nil, &existing, nil
		}
		holder, err := database.GetNode(ctx, q, existing.NodeID)
		if err != nil {
			return nil, nil, err
		}
		return nil, nil, smerr.New(smerr.CodeConflict, "", fmt.Sprintf(
			"the hostname %s is already routed on the node %s (%s); to free it, run `sm nodes unexpose %s --hostname %s`",
			p.Hostname, holder.Name, existing.Phase, holder.Name, p.Hostname))
	case smerr.CodeOf(err) != smerr.CodeNotFound:
		return nil, nil, err
	}
	node, err := database.GetNode(ctx, q, nodeID)
	if err != nil {
		return nil, nil, err
	}
	port, _ := strconv.Atoi(p.Port) // validated by exposeParams and by the plan's target
	if err := requireRoutableNode(node); err != nil {
		return nil, nil, err
	}
	if err := requirePublishablePort(ctx, q, node, port); err != nil {
		return nil, nil, err
	}
	tunnelID, generation, err := nodeTunnelIdentity(ctx, q, node)
	if err != nil {
		return nil, nil, err
	}
	if err := requireRouteCapacity(ctx, q, node, 1); err != nil {
		return nil, nil, err
	}
	instance, err := database.GetInstance(ctx, q)
	if err != nil {
		return nil, nil, err
	}
	return &admission{
		node: node, tunnelID: tunnelID, generation: generation, instanceID: instance.ID.String(),
	}, nil, nil
}

// requireRoutableNode holds a route to a managed node reached through a Cloudflare connector.
func requireRoutableNode(node domain.Node) error {
	if node.ManagementState != domain.ManagementManaged {
		return invalidArgument("node %s is not managed", node.Name)
	}
	if node.Endpoint.Transport.Effective() != domain.TransportCloudflare {
		return errNoConnector(node)
	}
	return nil
}

// tunnelSSHPort is the local port the tunnel's SSH rule serves (cloudflare.ServiceSSH).
const tunnelSSHPort = 22

// requirePublishablePort refuses the node's SSH ports, the one of its direct route and the one the tunnel
// already serves under the SSH hostname, and a port another route of the node publishes, a halted one
// included: it may still own objects.
func requirePublishablePort(ctx context.Context, q database.Querier, node domain.Node, port int) error {
	if port == node.Endpoint.Port || port == tunnelSSHPort {
		return invalidArgument("port %d is the SSH port of the node %s and is not routable", port, node.Name)
	}
	other, err := database.GetLiveNodeRouteByNodePort(ctx, q, node.ID, port)
	if smerr.CodeOf(err) == smerr.CodeNotFound {
		return nil
	}
	if err != nil {
		return err
	}
	return smerr.New(smerr.CodeConflict, "", fmt.Sprintf(
		"port %d of the node %s is already routed as %s (%s); to free it, run `sm nodes unexpose %s --hostname %s`",
		port, node.Name, other.Hostname, other.Phase, node.Name, other.Hostname))
}

// requireRouteCapacity is the one transactional capacity check of a node's tunnel: the node's live routes and the
// routes being added must fit in the tunnel's ingress.
func requireRouteCapacity(ctx context.Context, q database.Querier, node domain.Node, adding int) error {
	live, err := database.CountLiveNodeRoutesByNode(ctx, q, node.ID)
	if err != nil {
		return err
	}
	if live+adding > maxRoutesPerNode {
		return smerr.New(smerr.CodeConflict, "", fmt.Sprintf(
			"the node %s has %d routes: %d more would pass the limit of %d of its tunnel",
			node.Name, live, adding, maxRoutesPerNode))
	}
	return nil
}

// admission is what an accepted route freezes and how it starts.
type admission struct {
	node       domain.Node
	tunnelID   string
	generation int64
	instanceID string
}

// admit writes the route of p for the node, in admitted, and returns it. A plan admits one route: when the
// plan wrote one already, in any phase, that row comes back and nothing is written, so a retried or late job
// never admits again. Else the route that carries the hostname for this same request is returned. The count of
// the node's routes and the insert share the caller's transaction.
func (s *NodeRoutes) admit(ctx context.Context, q database.Querier, actor domain.Actor, nodeID, planID domain.ID, p nodeRouteParams, request bool) (database.NodeRoute, error) {
	admitted, err := database.GetNodeRouteByPlan(ctx, q, planID)
	if err == nil || smerr.CodeOf(err) != smerr.CodeNotFound {
		return admitted, err
	}
	adm, existing, err := s.assess(ctx, q, nodeID, p, request)
	if err != nil || existing != nil {
		if existing != nil {
			return *existing, nil
		}
		return database.NodeRoute{}, err
	}
	port, _ := strconv.Atoi(p.Port)
	now := s.cfg.Clock.Now()
	return database.InsertNodeRoute(ctx, q, database.NodeRoute{
		ID: s.cfg.IDs.NewID(), NodeID: adm.node.ID, Hostname: p.Hostname, Port: port,
		Access: p.Access, AccountID: s.cfg.Cloudflare.AccountID, Zone: s.cfg.Cloudflare.Zone, InstanceID: adm.instanceID,
		TunnelID: adm.tunnelID, TunnelGeneration: adm.generation, PlanID: &planID, CreatedBy: actor.ID, CreatedAt: now,
	})
}

// routeHas reports whether route is the one nodeID's expose with parameters p asks for.
func routeHas(route database.NodeRoute, nodeID domain.ID, p nodeRouteParams) bool {
	port, _ := strconv.Atoi(p.Port) // validated by exposeParams and by the plan's target
	return route.NodeID == nodeID && route.Port == port && route.Access == p.Access
}

// applyApproved is the apply step of the control_plane.apply job of a node route plan. It admits the
// route of an expose that waited for approval, and only that one: with no approval the request admitted the route
// itself, so a retry or a late job of that never admits again. It does nothing for an unexpose either. The
// Cloudflare work follows in the same job (nodeRouteHandler).
func (s *NodeRoutes) applyApproved(ctx context.Context, q database.Querier, actor domain.Actor, action string, job jobs.Job) error {
	if action == nodeRouteUnexposeAction {
		return nil
	}
	if job.PlanID == nil {
		return smerr.New(smerr.CodeInternal, "", "node route job has no plan")
	}
	decisions, err := database.ListDecisions(ctx, q, job.ID, job.PlanHash)
	if err != nil || len(decisions) == 0 {
		return err
	}
	p, err := payloadOf[nodeRouteParams](job)
	if err != nil {
		return err
	}
	_, err = s.admit(ctx, q, actor, job.Resource.ID, *job.PlanID, p, false)
	return err
}
