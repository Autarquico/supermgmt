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
// its Access application. A waiting route starts only when the newest known-good deployment publishes its port
// and its DNS preflight passed; it then persists provisioning, which puts its rule in the desired ingress, and
// the first PUT follows at once. Until then no other writer publishes the rule.
func (r *routeRun) exposeRoute(ctx context.Context) error {
	waiting := r.route.Phase == database.AppRouteWaiting
	if waiting {
		_, serves, err := newestKnownGoodServes(ctx, r.cfg.DB.Reader(), r.route.AppTargetID, r.route.Service, r.route.Port)
		if err != nil || !serves {
			return err // the route keeps waiting; a succeeded deployment that publishes the port schedules a new job
		}
	}
	// Checked on every run, resumes included, and before the first mutation.
	if _, err := r.checkDNS(ctx); err != nil {
		return err
	}
	if waiting {
		if err := r.guard(ctx); err != nil {
			return err
		}
		if err := r.advance(ctx, database.AppRouteProvisioning, database.AppRouteObjects{}, "", nil); err != nil {
			return err
		}
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

// accessSpec is the Access application the route needs: its hostname, behind the owners policy only.
func (r *routeRun) accessSpec(ctx context.Context) (cloudflare.AppSpec, error) {
	state, err := database.GetCloudflareState(ctx, r.cfg.DB.Reader())
	if err != nil {
		return cloudflare.AppSpec{}, err
	}
	if state.OwnersPolicyID == "" {
		return cloudflare.AppSpec{}, smerr.New(smerr.CodeCapabilityUnavailable, "", "the instance has no owners policy yet: run a tunnel setup first")
	}
	idps, err := r.tun.api.ResolveAllowedIdPs(ctx, r.tun.opts.Config.AccessIdentityProviders)
	if err != nil {
		return cloudflare.AppSpec{}, err
	}
	return cloudflare.AppSpec{
		Name: cloudflare.RouteAccessAppName(r.tun.instanceID, r.route.ID.String()), Domain: r.route.Hostname,
		PolicyIDs: []string{state.OwnersPolicyID}, AllowedIdPs: idps,
	}, nil
}

// repairAccessApp brings an Access application that drifted from spec (domain, policies, identity providers)
// back to it, under the guard.
func (r *routeRun) repairAccessApp(ctx context.Context, app cloudflare.AccessApp, spec cloudflare.AppSpec) error {
	if app.Domain == spec.Domain && slices.Equal(app.PolicyIDs, spec.PolicyIDs) && sameSet(app.AllowedIdPs, spec.AllowedIdPs) {
		return nil
	}
	if err := r.guard(ctx); err != nil {
		return err
	}
	if _, err := r.tun.api.UpdateAccessApp(ctx, app.ID, spec); err != nil {
		return err
	}
	return r.audit(ctx, eventAccessAppUpdated, map[string]any{"access_app_id": app.ID, "name": spec.Name})
}

func (r *routeRun) exposeAccess(ctx context.Context) error {
	if r.route.Access != "owners" {
		return r.advance(ctx, database.AppRouteAccessReady, database.AppRouteObjects{}, "", nil)
	}
	spec, err := r.accessSpec(ctx)
	if err != nil {
		return err
	}
	name := spec.Name
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
	if how != foundCreated {
		if err := r.repairAccessApp(ctx, app, spec); err != nil {
			return err
		}
	}
	return r.advance(ctx, database.AppRouteAccessReady, database.AppRouteObjects{AccessAppID: app.ID},
		tunnelEvent(how, eventAccessAppCreated, eventAccessAppAdopted), map[string]any{"access_app_id": app.ID, "name": name})
}

// requireAccessApp holds the DNS record back until the Access application recorded for an owners route still
// exists and guards the hostname: a resume can come long after the application was recorded. A missing one
// halts the route; one that drifted is repaired first.
func (r *routeRun) requireAccessApp(ctx context.Context) error {
	spec, err := r.accessSpec(ctx)
	if err != nil {
		return err
	}
	apps, err := r.tun.api.FindAccessApps(ctx, spec.Name)
	if err != nil {
		return err
	}
	for _, app := range apps {
		if app.ID == r.route.Objects.AccessAppID {
			return r.repairAccessApp(ctx, app, spec)
		}
	}
	return r.objectGone("Access application")()
}

func (r *routeRun) exposeDNS(ctx context.Context) error {
	if r.route.Access == "owners" && r.route.Objects.AccessAppID == "" {
		return smerr.New(smerr.CodeInternal, "", "the DNS record is created only after the Access application is recorded")
	}
	if r.route.Access == "owners" {
		if err := r.requireAccessApp(ctx); err != nil {
			return err
		}
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
