package app

import (
	"context"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/jobs"
)

const apiHost = "api.example.test"

// Two route jobs and a node setup are all ingress writers: the lock planner lets one run at a time, and the
// last one still sees the rules of the others.
func TestTwoExposesRacingASetupLeaveTheSSHRuleAndBothRoutes(t *testing.T) {
	rs := newRouteSetting(t)
	first := rs.addRoute(shop, 8080, "public", database.AppRouteProvisioning)
	second := rs.addRoute(apiHost, 8080, "public", database.AppRouteProvisioning)
	exposeFirst := rs.enqueue(appRouteExposeAction, first)
	exposeSecond := rs.enqueue(appRouteExposeAction, second)
	setup := rs.plan()
	handlers := map[string]jobs.Handler{exposeFirst.ID.String(): rs.routes, exposeSecond.ID.String(): rs.routes, setup.ID.String(): rs.handler}

	for range 3 {
		claimed, ok := rs.claim()
		if !ok {
			t.Fatalf("no job to claim (states: %s %s %s)", rs.job(exposeFirst.ID).State, rs.job(exposeSecond.ID).State, rs.job(setup.ID).State)
		}
		if _, concurrent := rs.claim(); concurrent {
			t.Fatalf("a second ingress writer was claimed while %s runs", claimed.Job.ID)
		}
		mustf(t, handlers[claimed.Job.ID.String()].Run(context.Background(), claimed.Lease), "run")
		mustf(t, rs.store.Succeed(context.Background(), claimed.Lease), "Succeed")
		rs.clock.Advance(time.Minute) // the blocked claims were deferred
	}

	rs.wantIngress(apiHost, shop) // sorted by hostname
	for _, route := range []database.AppRoute{first, second} {
		if got := rs.route(route.ID).Phase; got != database.AppRouteActive {
			t.Errorf("%s = %s, want active", route.Hostname, got)
		}
	}
}

func FuzzRouteHostname(f *testing.F) {
	for _, seed := range []string{
		"shop.example.test", "SHOP.Example.Test.", " shop.example.test ", "evil-example.test", "shop.evil-example.test",
		"example.test", ".example.test", "ssh-web-1.example.test", "a..example.test", "-a.example.test", "*.example.test",
		"bücher.example.test", "shop.example.test\x00", strings.Repeat("a", 64) + ".example.test",
		strings.Repeat("a.", 130) + "example.test",
	} {
		f.Add(seed, "example.test")
	}
	f.Add("shop.example.test", "Example.Test.")
	f.Fuzz(func(t *testing.T, hostname, zone string) {
		host, err := routeHostname(hostname, zone)
		if err != nil {
			return
		}
		if host != canonicalHostname(host) {
			t.Errorf("%q is not canonical", host)
		}
		if !strings.HasSuffix(host, "."+canonicalHostname(zone)) || len(host) > 253 || strings.HasPrefix(host, reservedSSHLabelPrefix) {
			t.Errorf("accepted %q for zone %q", host, zone)
		}
		for _, label := range strings.Split(host, ".") {
			if !validDNSLabel(label) {
				t.Errorf("accepted %q with the label %q", host, label)
			}
		}
		if !utf8.ValidString(host) || strings.ContainsAny(host, "*/ \x00") {
			t.Errorf("accepted %q", host)
		}
	})
}
