package app

import (
	"context"
	"fmt"
	"slices"

	"github.com/autarquico/supermgmt/internal/database"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare"
)

// exposeRoute walks the route from where it stopped to active, in the ADR-0037 order: the ingress rule, the
// Access application (owners only) and the proxied CNAME last, so the hostname is never routable without
// its Access application.
func (r *routeRun) exposeRoute(ctx context.Context) error {
	if r.route.Phase == database.AppRouteWaiting {
		return smerr.New(smerr.CodeInternal, "", "the route waits for a deployment that publishes its port; a succeeded deployment schedules it")
	}
	// Checked on every run, resumes included, and before the first mutation.
	if _, err := r.checkDNS(ctx); err != nil {
		return err
	}
	steps := []struct {
		from database.AppRoutePhase
		name string
		run  func(context.Context) error
	}{
		{database.AppRouteProvisioning, "tunnel ingress", r.exposeIngress},
		{database.AppRouteIngressReady, "Access application", r.exposeAccess},
		{database.AppRouteAccessReady, "DNS record", r.exposeDNS},
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

// run names the step that failed without hiding the cause's type.
func (r *routeRun) run(name string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("exposing %s failed at %s: %w", r.route.Hostname, name, err)
}

func (r *routeRun) dnsComment() string {
	return cloudflare.RouteDNSComment(r.tun.instanceID, r.route.ID.String())
}

// checkDNS proves that every record of the hostname is this route's own: it carries the route's marker, is a
// proxied CNAME and points at the frozen tunnel. A record that is not (a foreign one, a sibling that appeared
// after an earlier check, one that changed) halts the route and is never touched. It returns the route's
// record, nil when there is none. The record may exist only once the Access application is in place.
func (r *routeRun) checkDNS(ctx context.Context) (*cloudflare.DNSRecord, error) {
	records, err := r.tun.api.FindDNSRecords(ctx, r.tun.zoneID, r.route.Hostname)
	if err != nil {
		return nil, err
	}
	var own *cloudflare.DNSRecord
	for _, rec := range records {
		switch {
		case rec.Comment != r.dnsComment():
			return nil, routeConflictRecord(rec, "was not created by this route")
		case rec.Type != "CNAME" || !rec.Proxied || rec.Content != cloudflare.TunnelTarget(r.route.TunnelID):
			return nil, routeConflictRecord(rec, "carries this route's marker but is not a proxied CNAME to its tunnel")
		case own != nil:
			return nil, routeConflictRecord(rec, "is a second record carrying this route's marker")
		}
		own = &rec
	}
	if recorded := r.route.Objects.DNSRecordID; recorded != "" && (own == nil || own.ID != recorded) {
		return nil, routeFailed("the DNS record recorded for this route changed or no longer exists; unexpose the route and expose it again")
	}
	if own != nil && r.route.Phase != database.AppRouteAccessReady && r.route.Phase != database.AppRouteActive {
		return nil, routeConflictRecord(*own, "exists before the Access application of this route")
	}
	return own, nil
}

func routeConflictRecord(rec cloudflare.DNSRecord, why string) error {
	return &routeHalt{halt: database.AppRouteConflict, inner: smerr.New(smerr.CodeConflict, "", fmt.Sprintf(
		"the %s record %s for %s %s; it was left alone. Resolve it in Cloudflare and expose the route again", rec.Type, rec.ID, rec.Name, why))}
}

func (r *routeRun) exposeIngress(ctx context.Context) error {
	if err := r.syncIngress(ctx, ""); err != nil {
		return err
	}
	return r.advance(ctx, database.AppRouteIngressReady, database.AppRouteObjects{}, eventIngressSet,
		map[string]any{"tunnel_id": r.route.TunnelID})
}

func (r *routeRun) exposeAccess(ctx context.Context) error {
	if r.route.Access != "owners" {
		return r.advance(ctx, database.AppRouteAccessReady, database.AppRouteObjects{}, "", nil)
	}
	state, err := database.GetCloudflareState(ctx, r.cfg.DB.Reader())
	if err != nil {
		return err
	}
	if state.OwnersPolicyID == "" {
		return smerr.New(smerr.CodeCapabilityUnavailable, "", "the instance has no owners policy yet: run a tunnel setup first")
	}
	idps, err := r.tun.api.ResolveAllowedIdPs(ctx, r.tun.opts.Config.AccessIdentityProviders)
	if err != nil {
		return err
	}
	name := cloudflare.RouteAccessAppName(r.tun.instanceID, r.route.ID.String())
	spec := cloudflare.AppSpec{Name: name, Domain: r.route.Hostname, PolicyIDs: []string{state.OwnersPolicyID}, AllowedIdPs: idps}
	app, how, err := ensureRouteNamed(ctx, r.fenced(), namedObject[cloudflare.AccessApp]{
		kind: "Access application", name: name, known: r.route.Objects.AccessAppID,
		find:   func(ctx context.Context) ([]cloudflare.AccessApp, error) { return r.tun.api.FindAccessApps(ctx, name) },
		create: func(ctx context.Context) (cloudflare.AccessApp, error) { return r.tun.api.CreateAccessApp(ctx, spec) },
		idOf:   func(a cloudflare.AccessApp) string { return a.ID },
		adoptable: func(a cloudflare.AccessApp) bool {
			return r.createdSince(a.CreatedAt) && a.Domain == r.route.Hostname && slices.Equal(a.PolicyIDs, spec.PolicyIDs)
		},
	}, r.objectGone("Access application"))
	if err != nil {
		return err
	}
	if how != foundCreated && (!slices.Equal(app.PolicyIDs, spec.PolicyIDs) || !sameSet(app.AllowedIdPs, spec.AllowedIdPs)) {
		if err := r.guard(ctx); err != nil {
			return err
		}
		if _, err := r.tun.api.UpdateAccessApp(ctx, app.ID, spec); err != nil {
			return err
		}
		if err := r.audit(ctx, eventAccessAppUpdated, map[string]any{"access_app_id": app.ID, "name": name}); err != nil {
			return err
		}
	}
	return r.advance(ctx, database.AppRouteAccessReady, database.AppRouteObjects{AccessAppID: app.ID},
		tunnelEvent(how, eventAccessAppCreated, eventAccessAppAdopted), map[string]any{"access_app_id": app.ID, "name": name})
}

func (r *routeRun) exposeDNS(ctx context.Context) error {
	if r.route.Access == "owners" && r.route.Objects.AccessAppID == "" {
		return smerr.New(smerr.CodeInternal, "", "the DNS record is created only after the Access application is recorded")
	}
	tunnelID, comment := r.route.TunnelID, r.dnsComment()
	record, how, err := ensureRouteNamed(ctx, r.fenced(), namedObject[cloudflare.DNSRecord]{
		kind: "DNS record", name: r.route.Hostname, known: r.route.Objects.DNSRecordID,
		find: func(ctx context.Context) ([]cloudflare.DNSRecord, error) {
			return r.tun.api.FindDNSRecords(ctx, r.tun.zoneID, r.route.Hostname)
		},
		create: func(ctx context.Context) (cloudflare.DNSRecord, error) {
			return r.tun.api.CreateTunnelCNAME(ctx, r.tun.zoneID, r.route.Hostname, tunnelID, comment)
		},
		idOf: func(d cloudflare.DNSRecord) string { return d.ID },
		adoptable: func(d cloudflare.DNSRecord) bool {
			return r.createdSince(d.CreatedOn) && d.Type == "CNAME" && d.Proxied && d.Comment == comment && d.Content == cloudflare.TunnelTarget(tunnelID)
		},
	}, r.objectGone("DNS record"))
	if err != nil {
		return err
	}
	return r.advance(ctx, database.AppRouteActive, database.AppRouteObjects{DNSRecordID: record.ID}, eventAppRouteExposed,
		map[string]any{"dns_record_id": record.ID, "how": tunnelEvent(how, "created", "adopted")})
}
