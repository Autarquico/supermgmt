package app

import (
	"context"
	"errors"
	"slices"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare"
)

// removeRoute takes the route down in the reverse of the order it was built, with the progress persisted
// after each step: the DNS record first, then the ingress rule, and the Access application last. Cached DNS
// can still reach the hostname after its record is gone, so the rule stops serving before the protection goes
// (the order of the tunnel teardown, ADR-0037).
func (r *routeRun) removeRoute(ctx context.Context) error {
	if !removalPhase(r.route.Phase) {
		if err := r.reconcileUnrecorded(ctx); err != nil {
			return r.run("reconciliation of the unrecorded objects", err)
		}
		err := r.change(ctx, func(ctx context.Context, tx *database.Tx) (database.AppRoute, error) {
			return database.MarkAppRouteRemoving(ctx, tx, r.route.ID, r.route.Phase, r.cfg.Clock.Now())
		})
		if err != nil {
			return err
		}
	}
	steps := []struct {
		from database.AppRoutePhase
		name string
		run  func(context.Context) error
	}{
		{database.AppRouteRemoving, "removal of the DNS record", r.removeDNS},
		{database.AppRouteDNSRemoved, "removal of the ingress rule", r.removeIngress},
		{database.AppRouteIngressRemoved, "removal of the Access application", r.removeAccess},
	}
	for _, s := range steps {
		if r.route.Phase != s.from {
			continue
		}
		if err := r.run(s.name, s.run(ctx)); err != nil {
			return err
		}
	}
	return nil
}

func removalPhase(p database.AppRoutePhase) bool {
	return p == database.AppRouteRemoving || p == database.AppRouteDNSRemoved || p == database.AppRouteIngressRemoved
}

// reconcileUnrecorded settles the one create-to-record window an expose was left in, while the route still
// carries the phase and phase start that say which attempt could have created an object. The Access
// application is created in phase ingress_ready; the DNS record needs no record, because its removal
// recognises the route's marker.
func (r *routeRun) reconcileUnrecorded(ctx context.Context) error {
	if r.route.Access != "owners" || r.route.Objects.AccessAppID != "" || r.route.Phase != database.AppRouteIngressReady {
		return nil
	}
	state, err := database.GetCloudflareState(ctx, r.cfg.DB.Reader())
	if err != nil {
		return err
	}
	name := cloudflare.RouteAccessAppName(r.tun.instanceID, r.route.ID.String())
	apps, err := lookUpCreated(ctx, r.tun, true, func() ([]cloudflare.AccessApp, error) { return r.tun.api.FindAccessApps(ctx, name) })
	if err != nil {
		return err
	}
	app, find, err := claim("Access application", name, apps, func(a cloudflare.AccessApp) bool {
		return r.createdSince(a.CreatedAt) && a.Domain == r.route.Hostname && len(a.PolicyIDs) == 1 && a.PolicyIDs[0] == state.OwnersPolicyID
	})
	switch {
	case err != nil || find.left > 0:
		return routeConflict("Access application", name) // present, and not provably this route's
	case len(apps) == 0:
		return nil
	}
	return r.advance(ctx, r.route.Phase, database.AppRouteObjects{AccessAppID: app.ID}, eventAccessAppAdopted,
		map[string]any{"access_app_id": app.ID, "name": name})
}

func (r *routeRun) removeDNS(ctx context.Context) error {
	records, err := r.tun.api.FindDNSRecords(ctx, r.tun.zoneID, r.route.Hostname)
	if err != nil {
		return err
	}
	recorded, found := r.route.Objects.DNSRecordID, false
	for _, rec := range records {
		ours := rec.Comment == r.dnsComment()
		switch {
		case rec.ID == recorded && !ours:
			return routeFailed("the DNS record recorded for this route lost its marker; it was left alone")
		case !ours:
			continue // somebody else's record on the hostname is never touched
		case rec.Type != "CNAME" || rec.Content != cloudflare.TunnelTarget(r.route.TunnelID):
			return routeConflictRecord(rec, "carries this route's marker but is not a CNAME to its tunnel")
		}
		found = true
		if err := r.guard(ctx); err != nil {
			return err
		}
		if err := r.tun.api.DeleteDNSRecord(ctx, r.tun.zoneID, rec.ID); err != nil && !cloudflare.IsNotFound(err) {
			return err
		}
		if err := r.audit(ctx, eventDNSDeleted, map[string]any{"dns_record_id": rec.ID}); err != nil {
			return err
		}
	}
	if !found && recorded != "" {
		if err := r.audit(ctx, eventObjectVanished, map[string]any{"kind": "DNS record", "object_id": recorded}); err != nil {
			return err
		}
	}
	return r.advance(ctx, database.AppRouteDNSRemoved, database.AppRouteObjects{}, "", nil)
}

// removeIngress takes the rule out of the frozen tunnel's ingress. When the frozen tunnel is no longer the
// node's, the node's desired list says nothing about it, so its rule is taken out directly; a tunnel that no
// longer exists has no rule to take out.
func (r *routeRun) removeIngress(ctx context.Context) error {
	err := r.requireTunnel(ctx)
	if err == nil {
		err = r.syncIngress(ctx, r.route.ID)
	}
	if errors.Is(err, errTunnelChanged) {
		err = r.dropFrozenRule(ctx)
	}
	if err != nil {
		return err
	}
	return r.advance(ctx, database.AppRouteIngressRemoved, database.AppRouteObjects{}, "", nil)
}

// dropFrozenRule rewrites the frozen tunnel's ingress without the rule of this route's hostname, keeping every
// other rule in its place.
func (r *routeRun) dropFrozenRule(ctx context.Context) error {
	current, err := r.tun.api.GetTunnelConfig(ctx, r.route.TunnelID)
	if cloudflare.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	kept := slices.DeleteFunc(slices.Clone(current.Ingress), func(rule cloudflare.IngressRule) bool {
		return rule.Hostname == r.route.Hostname
	})
	if len(kept) == len(current.Ingress) {
		return nil
	}
	if err := r.guard(ctx); err != nil {
		return err
	}
	if _, err := r.tun.api.PutTunnelIngress(ctx, r.route.TunnelID, kept); err != nil {
		return err
	}
	return r.audit(ctx, eventIngressSet, map[string]any{"tunnel_id": r.route.TunnelID, "rules": len(kept)})
}

func (r *routeRun) removeAccess(ctx context.Context) error {
	recorded := r.route.Objects.AccessAppID
	if recorded != "" {
		name := cloudflare.RouteAccessAppName(r.tun.instanceID, r.route.ID.String())
		apps, err := r.tun.api.FindAccessApps(ctx, name)
		if err != nil {
			return err
		}
		found := false
		for _, app := range apps {
			if app.ID != recorded {
				continue // an application of this name that was never recorded is not provably ours
			}
			found = true
			if err := r.guard(ctx); err != nil {
				return err
			}
			if err := r.tun.api.DeleteAccessApp(ctx, app.ID); err != nil && !cloudflare.IsNotFound(err) {
				return err
			}
			if err := r.audit(ctx, eventAccessAppGone, map[string]any{"access_app_id": app.ID, "name": name}); err != nil {
				return err
			}
		}
		if !found {
			if err := r.audit(ctx, eventObjectVanished, map[string]any{"kind": "Access application", "object_id": recorded}); err != nil {
				return err
			}
		}
	}
	return r.advance(ctx, database.AppRouteRemoved, database.AppRouteObjects{}, eventAppRouteRemoved, map[string]any{})
}
