package app

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare"
)

// servesIngress reports whether the route's rule belongs to the node's ingress (ADR-0040). A route that
// halted while being exposed never serves: a halt fails closed, and the next writer drops its rule. One that
// halted while being removed keeps the rule until its removal reaches that step.
func servesIngress(r database.AppRoute) bool {
	phase := r.Phase
	if phase.Halted() {
		return r.HaltedPhase == database.AppRouteRemoving || r.HaltedPhase == database.AppRouteDNSRemoved
	}
	switch phase {
	case database.AppRouteProvisioning, database.AppRouteIngressReady, database.AppRouteAccessReady, database.AppRouteActive,
		database.AppRouteRemoving, database.AppRouteDNSRemoved:
		return true
	case database.AppRouteWaiting, database.AppRouteIngressRemoved, database.AppRouteRemoved,
		database.AppRouteFailed, database.AppRouteConflict:
	}
	return false
}

// desiredIngress is the one builder of a node tunnel's ingress: the SSH rule, a rule per route that serves,
// then the catch-all. Every writer calls it after taking the instance Cloudflare lock, so the list it
// writes is the state at that moment. skip leaves one route out: the one being removed.
func desiredIngress(ctx context.Context, q database.Querier, nodeID domain.ID, sshHostname string, skip domain.ID) ([]cloudflare.IngressRule, error) {
	if nodeID == "" {
		return cloudflare.NodeIngress(sshHostname, nil), nil // an enrollment has no node row, so no routes
	}
	routes, err := database.ListAppRoutes(ctx, q, database.AppRouteFilter{NodeID: nodeID})
	if err != nil {
		return nil, err
	}
	var rules []cloudflare.RouteRule
	for _, r := range routes {
		if r.ID != skip && servesIngress(r) {
			rules = append(rules, cloudflare.RouteRule{Hostname: r.Hostname, Port: uint16(r.Port)}) //nolint:gosec // the table checks 1..65535
		}
	}
	return cloudflare.NodeIngress(sshHostname, rules), nil
}

// requireNoLiveRoutes refuses to close the tunnel of a node that still has routes that are not removed. The
// disable job repeats it after taking the ingress lock.
func requireNoLiveRoutes(ctx context.Context, q database.Querier, nodeID domain.ID) error {
	routes, err := database.ListAppRoutes(ctx, q, database.AppRouteFilter{NodeID: nodeID})
	if err != nil || len(routes) == 0 {
		return err
	}
	hostnames := make([]string, len(routes))
	for i, r := range routes {
		hostnames[i] = r.Hostname
	}
	slices.Sort(hostnames)
	return smerr.New(smerr.CodeConflict, "", fmt.Sprintf(
		"the node still has app routes (%s); remove them with `sm apps unexpose` before disabling the tunnel", strings.Join(hostnames, ", ")))
}

// routeTunnelCarries reports whether the node's tunnel is still the one the route froze at admission. ops
// are the node's tunnel operations, newest first. A setup rerun opens a newer generation of the same tunnel
// and keeps the route valid; a disable after the frozen generation, or a tunnel that is not the frozen one,
// does not.
func routeTunnelCarries(ops []database.TunnelOperation, route database.AppRoute) bool {
	tunnelID := ""
	for _, op := range ops {
		if op.Generation < route.TunnelGeneration || op.Kind == database.TunnelDisable {
			return false
		}
		tunnelID = cmp.Or(tunnelID, op.Objects.TunnelID)
		if op.Generation == route.TunnelGeneration {
			return op.Kind == database.TunnelEnable && op.Phase == database.PhaseCommitted && tunnelID == route.TunnelID
		}
	}
	return false
}

// nodeTunnelIdentity is the tunnel of the node and the generation of its newest committed enable, which a
// route freezes when it is admitted. It fails with errNoTunnel when the node has no committed tunnel or a
// disable came after its last enable.
func nodeTunnelIdentity(ctx context.Context, q database.Querier, nodeID domain.ID) (string, int64, error) {
	ops, err := database.ListTunnelOperations(ctx, q, nodeID)
	if err != nil {
		return "", 0, err
	}
	var (
		tunnelID   string
		generation int64
	)
	for _, op := range ops {
		if op.Kind == database.TunnelDisable {
			break
		}
		tunnelID = cmp.Or(tunnelID, op.Objects.TunnelID)
		if generation == 0 && op.Phase == database.PhaseCommitted {
			generation = op.Generation
		}
	}
	if generation == 0 || tunnelID == "" {
		return "", 0, errNoTunnel
	}
	return tunnelID, generation, nil
}

var errNoTunnel = smerr.New(smerr.CodeCapabilityUnavailable, "", "the node has no Cloudflare connector; run `sm nodes setup <node> --tunnel`")
