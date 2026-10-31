package app

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/deployments/compose"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/plan"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
)

// maxRoutesPerNode is the 100-rule limit of a tunnel's ingress minus the SSH rule and the catch-all.
const maxRoutesPerNode = 98

// reservedSSHLabelPrefix marks the namespace of node SSH hostnames (ssh-<node>.<zone>).
const reservedSSHLabelPrefix = "ssh-"

// AppRoutes exposes an app target's published port through its node's Cloudflare Tunnel (ADR-0040). A request
// is a plan of app_route.expose or app_route.unexpose. The route row is written when the request is admitted:
// in the request transaction when policy needs no approval, else by the apply step of the approved job, always
// in waiting. The Cloudflare work itself runs in that same control_plane.apply job (app_routes_job.go), which
// is the only writer of the route's progress from then on.
type AppRoutes struct {
	core
	plans *Plans
}

// Routes returns the app routes service of the catalog.
func (a *Apps) Routes() *AppRoutes { return &AppRoutes{core: a.core, plans: a.plans} }

// ExposeRouteRequest asks to publish a service port of an app target under a hostname.
type ExposeRouteRequest struct {
	Hostname string
	Service  string
	Port     int
	// Access is public or owners. Empty means public: the omitted value is normalised before policy evaluates.
	Access string
}

// AppRouteResult is the outcome of an expose or unexpose request. Submission is the plan's job, which waits for
// approval when policy asks. Route is nil while an expose waits for approval: nothing is written before it.
type AppRouteResult struct {
	Route      *database.AppRoute
	Submission Submission
}

func (r AppRouteResult) createdJob() *domain.ID { return &r.Submission.Job.ID }

// Expose requests a route for the target (action app_route.expose).
func (s *AppRoutes) Expose(ctx context.Context, by Caller, targetID domain.ID, r ExposeRouteRequest) (AppRouteResult, error) {
	p, err := s.exposeParams(r)
	if err != nil {
		return AppRouteResult{}, err
	}
	return commit(ctx, s.core, by, func(ctx context.Context, tx *database.Tx) (AppRouteResult, error) {
		actor, err := s.beginRequest(ctx, tx, by)
		if err != nil {
			return AppRouteResult{}, err
		}
		b, err := s.planOf(ctx, tx, by, appRouteExposeAction, targetID, p)
		if err != nil {
			return AppRouteResult{}, err
		}
		res, err := s.evaluate(ctx, tx, actor, b)
		if err != nil {
			return AppRouteResult{}, err
		}
		if res.ApprovalRequired {
			// Nothing is written before the approval, but an expose that cannot be admitted is refused now.
			if _, _, err := s.assess(ctx, tx, targetID, p, true); err != nil {
				return AppRouteResult{}, err
			}
		}
		submission, err := s.plans.planAndSubmit(ctx, tx, by, actor, b, res)
		if err != nil || res.ApprovalRequired {
			return AppRouteResult{Submission: submission}, err
		}
		row, err := s.admit(ctx, tx, actor, targetID, *submission.Job.PlanID, p, true)
		return AppRouteResult{Route: &row, Submission: submission}, err
	})
}

// Unexpose requests the removal of the target's route for hostname (action app_route.unexpose).
func (s *AppRoutes) Unexpose(ctx context.Context, by Caller, targetID domain.ID, hostname string) (AppRouteResult, error) {
	p := appRouteParams{Hostname: canonicalHostname(hostname)}
	return commit(ctx, s.core, by, func(ctx context.Context, tx *database.Tx) (AppRouteResult, error) {
		actor, err := s.beginRequest(ctx, tx, by)
		if err != nil {
			return AppRouteResult{}, err
		}
		route, err := s.routeOf(ctx, tx, targetID, p.Hostname)
		if err != nil {
			return AppRouteResult{}, err
		}
		b, err := s.planOf(ctx, tx, by, appRouteUnexposeAction, targetID, p)
		if err != nil {
			return AppRouteResult{}, err
		}
		res, err := s.evaluate(ctx, tx, actor, b)
		if err != nil {
			return AppRouteResult{}, err
		}
		submission, err := s.plans.planAndSubmit(ctx, tx, by, actor, b, res)
		return AppRouteResult{Route: &route, Submission: submission}, err
	})
}

// List returns the routes that are not removed, of one target or of every target when targetID is empty,
// those the caller may read.
func (s *AppRoutes) List(ctx context.Context, by Caller, targetID domain.ID) ([]database.AppRoute, error) {
	q := s.cfg.DB.Reader()
	actor, err := s.beginRequest(ctx, q, by)
	if err != nil {
		return nil, err
	}
	rows, err := database.ListAppRoutes(ctx, q, database.AppRouteFilter{TargetID: targetID})
	if err != nil {
		return nil, err
	}
	readable := map[domain.ID]bool{}
	out := make([]database.AppRoute, 0, len(rows))
	for _, row := range rows {
		allowed, known := readable[row.AppTargetID]
		if !known {
			resolved, err := resolveAppTarget(ctx, q, row.AppTargetID)
			if err != nil {
				return nil, err
			}
			allowed = s.authorize(policy.Request{Actor: actor, Action: "app_target.read", Targets: []policy.Target{resolved.target}}).Decision == policy.DecisionAllow
			readable[row.AppTargetID] = allowed
		}
		if allowed {
			out = append(out, row)
		}
	}
	return out, nil
}

func (s *AppRoutes) planOf(ctx context.Context, q database.Querier, by Caller, action string, targetID domain.ID, p appRouteParams) (built, error) {
	params, err := toParams(p)
	if err != nil {
		return built{}, err
	}
	return build(ctx, q, action, by.ID, appTargetRef(targetID), params)
}

// routeOf is the live route of hostname on the target; NOT_FOUND when the hostname belongs to nobody or to
// another target (the caller cannot tell which).
func (s *AppRoutes) routeOf(ctx context.Context, q database.Querier, targetID domain.ID, hostname string) (database.AppRoute, error) {
	route, err := database.GetLiveAppRouteByHostname(ctx, q, hostname)
	if err == nil && route.AppTargetID != targetID {
		return database.AppRoute{}, smerr.New(smerr.CodeNotFound, "", "the target has no route for "+hostname)
	}
	if smerr.CodeOf(err) == smerr.CodeNotFound {
		return database.AppRoute{}, smerr.New(smerr.CodeNotFound, "", "the target has no route for "+hostname)
	}
	return route, err
}

// ---- parameters -------------------------------------------------------------------------------------

// exposeParams validates the shape of a request and writes it in its canonical form, before policy sees it.
func (s *AppRoutes) exposeParams(r ExposeRouteRequest) (appRouteParams, error) {
	if s.cfg.Cloudflare == nil {
		return appRouteParams{}, requireTunnelAllowed(false, domain.Node{})
	}
	hostname, err := routeHostname(r.Hostname, s.cfg.Cloudflare.Zone)
	if err != nil {
		return appRouteParams{}, err
	}
	access := r.Access
	if access == "" {
		access = "public"
	}
	p := appRouteParams{Hostname: hostname, Service: strings.TrimSpace(r.Service), Port: strconv.Itoa(r.Port), Access: access}
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
func (s *AppRoutes) assess(ctx context.Context, q database.Querier, targetID domain.ID, p appRouteParams, request bool) (*admission, *database.AppRoute, error) {
	if s.cfg.Cloudflare == nil {
		return nil, nil, requireTunnelAllowed(false, domain.Node{})
	}
	port, _ := strconv.Atoi(p.Port) // validated by exposeParams and by the plan's target
	existing, err := database.GetLiveAppRouteByHostname(ctx, q, p.Hostname)
	switch {
	case err == nil:
		switch {
		case !routeHas(existing, targetID, p):
			return nil, nil, smerr.New(smerr.CodeConflict, "", fmt.Sprintf("the hostname %s is already routed", p.Hostname))
		case request && !existing.Phase.Halted():
			return nil, nil, smerr.New(smerr.CodeConflict, "", fmt.Sprintf("the hostname %s is already routed (%s)", p.Hostname, existing.Phase))
		}
		return nil, &existing, nil
	case smerr.CodeOf(err) != smerr.CodeNotFound:
		return nil, nil, err
	}
	target, err := database.GetAppTarget(ctx, q, targetID)
	if err != nil {
		return nil, nil, err
	}
	node, err := database.GetNode(ctx, q, target.NodeID)
	if err != nil {
		return nil, nil, err
	}
	if node.Endpoint.Transport.Effective() != domain.TransportCloudflare {
		return nil, nil, smerr.New(smerr.CodeCapabilityUnavailable, "", fmt.Sprintf(
			"the node %s has no Cloudflare connector; run `sm nodes setup %s --tunnel`", node.Name, node.Name))
	}
	tunnelID, generation, err := nodeTunnelIdentity(ctx, q, node.ID)
	if err != nil {
		return nil, nil, err
	}
	live, err := database.CountLiveAppRoutesByNode(ctx, q, node.ID)
	if err != nil {
		return nil, nil, err
	}
	if live >= maxRoutesPerNode {
		return nil, nil, smerr.New(smerr.CodeConflict, "", fmt.Sprintf(
			"the node %s already has %d routes, the limit of its tunnel", node.Name, maxRoutesPerNode))
	}
	if err := requireKnownGoodServes(ctx, q, targetID, p.Service, port); err != nil {
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

// admission is what an accepted route freezes and how it starts.
type admission struct {
	node       domain.Node
	tunnelID   string
	generation int64
	instanceID string
}

// newestKnownGoodServes reports whether the target has a known-good deployment and whether the newest one
// publishes service:port for the tunnel.
func newestKnownGoodServes(ctx context.Context, q database.Querier, targetID domain.ID, service string, port int) (known, serves bool, err error) {
	good, err := database.NewestKnownGood(ctx, q, targetID, nil)
	if smerr.CodeOf(err) == smerr.CodeNotFound {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	ports, err := deploymentHostPorts(ctx, q, good)
	if err != nil {
		return false, false, err
	}
	return true, routeServed(ports, service, port), nil
}

// requireKnownGoodServes refuses a route when the newest known-good deployment of the target does not publish
// its port. A target with none yet is accepted: the route waits for one.
func requireKnownGoodServes(ctx context.Context, q database.Querier, targetID domain.ID, service string, port int) error {
	known, serves, err := newestKnownGoodServes(ctx, q, targetID, service, port)
	if err != nil || !known || serves {
		return err
	}
	return invalidArgument(
		"the newest known-good deployment does not publish service %q on port %d over TCP at 127.0.0.1 or 0.0.0.0, the only addresses the tunnel connector dials", service, port)
}

// admit writes the route of p for the target, in waiting, and returns it. A plan admits one route: when the
// plan wrote one already, in any phase, that row comes back and nothing is written, so a retried or late job
// never admits again. Else the route that carries the hostname for this same request is returned. The count of
// the node's routes and the insert share the caller's transaction.
func (s *AppRoutes) admit(ctx context.Context, q database.Querier, actor domain.Actor, targetID, planID domain.ID, p appRouteParams, request bool) (database.AppRoute, error) {
	admitted, err := database.GetAppRouteByPlan(ctx, q, planID)
	if err == nil || smerr.CodeOf(err) != smerr.CodeNotFound {
		return admitted, err
	}
	adm, existing, err := s.assess(ctx, q, targetID, p, request)
	if err != nil || existing != nil {
		if existing != nil {
			return *existing, nil
		}
		return database.AppRoute{}, err
	}
	port, _ := strconv.Atoi(p.Port)
	now := s.cfg.Clock.Now()
	return database.InsertAppRoute(ctx, q, database.AppRoute{
		ID: s.cfg.IDs.NewID(), AppTargetID: targetID, NodeID: adm.node.ID, Hostname: p.Hostname, Service: p.Service, Port: port,
		Access: p.Access, AccountID: s.cfg.Cloudflare.AccountID, Zone: s.cfg.Cloudflare.Zone, InstanceID: adm.instanceID,
		TunnelID: adm.tunnelID, TunnelGeneration: adm.generation, PlanID: &planID, CreatedBy: actor.ID, CreatedAt: now,
	})
}

// routeHas reports whether route is the one targetID's expose with parameters p asks for.
func routeHas(route database.AppRoute, targetID domain.ID, p appRouteParams) bool {
	port, _ := strconv.Atoi(p.Port) // validated by exposeParams and by the plan's target
	return route.AppTargetID == targetID && route.Service == p.Service && route.Port == port && route.Access == p.Access
}

// applyApprovedAppRoute is the apply step of the control_plane.apply job of an app route plan. It admits the
// route of an expose that waited for approval, and only that one: with no approval the request admitted the route
// itself, and the system's activation is for a route admitted already, so a retry or a late job of those never
// admits again. It does nothing for an unexpose either. The Cloudflare work follows in the same job
// (appRouteHandler).
func (a *Apps) applyApprovedAppRoute(ctx context.Context, q database.Querier, actor domain.Actor, action string, job jobs.Job) error {
	if action == appRouteUnexposeAction || actor.Type == domain.ActorSystem {
		return nil // the system activates a route admitted already; it admits none, even one a human approved
	}
	if job.PlanID == nil {
		return smerr.New(smerr.CodeInternal, "", "app route job has no plan")
	}
	decisions, err := database.ListDecisions(ctx, q, job.ID, job.PlanHash)
	if err != nil || len(decisions) == 0 {
		return err
	}
	p, err := payloadOf[appRouteParams](job)
	if err != nil {
		return err
	}
	_, err = a.Routes().admit(ctx, q, actor, job.Resource.ID, *job.PlanID, p, false)
	return err
}

// ---- what a model publishes -------------------------------------------------------------------------

var loopback = netip.AddrFrom4([4]byte{127, 0, 0, 1})

// routeServed reports whether ports has service:port over TCP on an address the connector dials: it
// connects to 127.0.0.1, so a port bound to 127.0.0.1 or to every IPv4 interface is reachable, and an IPv6 or
// other-interface binding is not.
func routeServed(ports []compose.HostPort, service string, port int) bool {
	for _, p := range ports {
		addr := p.Addr.Unmap()
		if p.Service == service && int(p.Port) == port && p.Proto == "tcp" && (addr == loopback || addr == netip.IPv4Unspecified()) {
			return true
		}
	}
	return false
}

// deploymentHostPorts are the host ports of the model a deployment's plan froze.
func deploymentHostPorts(ctx context.Context, q database.Querier, dep database.Deployment) ([]compose.HostPort, error) {
	if dep.PlanID == nil {
		return nil, smerr.New(smerr.CodeInternal, "", "deployment "+dep.ID.String()+" has no plan")
	}
	rec, err := database.GetPlan(ctx, q, *dep.PlanID)
	if err != nil {
		return nil, err
	}
	stored, err := plan.Parse(rec.PlanJSON)
	if err != nil {
		return nil, err
	}
	return frozenHostPorts(ctx, q, stored.Content.ComposeHash)
}

// frozenHostPorts are the host ports of the compose_model snapshot with the given hash.
func frozenHostPorts(ctx context.Context, q database.Querier, composeHash *string) ([]compose.HostPort, error) {
	model, err := readSnapshotJSON[composeSnapshot](ctx, q, composeHash)
	if err != nil {
		return nil, err
	}
	frozen, err := model.Frozen(*composeHash)
	return frozen.HostPorts, err
}
