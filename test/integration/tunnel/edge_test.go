package tunnel

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare/dohfake"
)

// Scenarios of docs/specs/tunnel-edge-readiness.md on the real stack: the enrollment scheduler, the job engine,
// the Access preflight and the cloudflared stand-in, against a Cloudflare resolver (dohfake) and a control-plane
// resolver (systemResolver) that do not serve a new hostname at the same moment. The instance runs on a clock its
// own waits move forward, so a 60 s wait costs no real time.

const hostnameServedLog = "waiting for Cloudflare to publish"

// edgeRig is an enrollment rig whose gate asks the fake DoH resolver.
type edgeRig struct {
	*enrollRig
	doh *dohfake.Fake
}

func newEdgeRig(t *testing.T) *edgeRig {
	t.Helper()
	doh := dohfake.New(t)
	rig := newEnrollRig(t, stackOptions{skewed: true, systemResolver: true, edge: doh.Checker()})
	return &edgeRig{enrollRig: rig, doh: doh}
}

// start begins the enrollment of name and returns its hostname.
func (r *edgeRig) start(name string) string {
	r.t.Helper()
	res, err := r.enroll.Start(context.Background(), r.admin, app.StartTunnelEnrollment{Name: name})
	must(r.t, err)
	if res.Applied == nil {
		r.t.Fatalf("start parked for approval: %+v", res.Pending)
	}
	return res.Applied.Hostname
}

// untilView polls the enrollment until ok accepts its view.
func (r *edgeRig) untilView(name, what string, ok func(app.TunnelEnrollmentView) bool) app.TunnelEnrollmentView {
	r.t.Helper()
	deadline := time.Now().Add(30 * time.Second) //nolint:forbidigo // wall-clock budget of a polling loop
	for time.Now().Before(deadline) {            //nolint:forbidigo // see above
		if v := r.view(name); ok(v) {
			return v
		}
		time.Sleep(10 * time.Millisecond)
	}
	v := r.view(name)
	r.t.Fatalf("enrollment %s never reached %s; phase %q, note %q", name, what, v.Phase, v.Error)
	return app.TunnelEnrollmentView{}
}

func (r *edgeRig) untilNote(name, fragment string) app.TunnelEnrollmentView {
	r.t.Helper()
	return r.untilView(name, "a note with "+fragment, func(v app.TunnelEnrollmentView) bool { return strings.Contains(v.Error, fragment) })
}

func (r *edgeRig) untilAsked(host string, polls int) {
	r.t.Helper()
	deadline := time.Now().Add(30 * time.Second) //nolint:forbidigo // wall-clock budget of a polling loop
	for r.doh.Asked(host) < polls {
		if time.Now().After(deadline) { //nolint:forbidigo // see above
			r.t.Fatalf("Cloudflare's resolver was asked %d times, want %d", r.doh.Asked(host), polls)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// publish serves host at Cloudflare's resolver and at the control plane's.
func (r *edgeRig) publish(host string) {
	r.doh.Set(dohfake.Served)
	r.resolver.serve(host)
}

func TestAnEnrollmentNeverLooksTheNewHostnameUpBeforeCloudflareServesIt(t *testing.T) {
	r := newEdgeRig(t)
	r.doh.PublishAfter(1 << 30)
	host := r.start("vps1")
	r.untilAsked(host, 5)
	view := r.untilNote("vps1", hostnameServedLog)

	if view.Phase != string(database.PhaseDNSCreated) {
		t.Errorf("phase %s while Cloudflare does not serve the hostname, want dns_created", view.Phase)
	}
	if n := r.resolver.lookupsOf(host); n != 0 {
		t.Errorf("%d system lookups of %s before publication (the preflight and cloudflared included), want 0", n, host)
	}
	if n := r.carrierStarts(); n != 0 {
		t.Errorf("%d cloudflared processes started before publication, want 0", n)
	}

	r.publish(host)
	r.until("vps1", string(database.PhaseScanned))
	if r.resolver.lookupsOf(host) == 0 {
		t.Error("the enrollment was scanned without looking the hostname up")
	}
}

func TestAnEnrollmentWaitsForTheHostnameToBeServedAfterSomeQuestions(t *testing.T) {
	r := newEdgeRig(t)
	r.doh.PublishAfter(6)
	host := r.start("vps1")
	r.resolver.serve(host)

	r.until("vps1", string(database.PhaseScanned))
	if got := r.doh.Asked(host); got < 7 {
		t.Errorf("Cloudflare's resolver was asked %d times, want at least 7: the sixth answer was still not published", got)
	}
}

func TestAnEnrollmentThatCannotAskCloudflareWaitsAMinuteAfterTheRecordAndSaysSo(t *testing.T) {
	for _, mode := range []struct {
		name string
		mode dohfake.Mode
	}{{"an HTTP failure", dohfake.Unreachable}, {"a malformed reply", dohfake.Malformed}, {"SERVFAIL", dohfake.ServFail}} {
		t.Run(mode.name, func(t *testing.T) {
			r := newEdgeRig(t)
			r.doh.Set(mode.mode)
			host := r.start("vps1")
			r.resolver.serve(host)

			view := r.untilNote("vps1", "Cloudflare's resolver cannot be asked")
			if strings.Contains(view.Error, hostnameServedLog) {
				t.Errorf("note %q presents an unreachable resolver as an unpublished hostname", view.Error)
			}
			r.until("vps1", string(database.PhaseScanned))

			snap := r.cf.Snapshot()
			created := snap.DNSRecords[0].CreatedOn
			if first := r.resolver.firstLookup(host); first.Sub(created) < time.Minute {
				t.Errorf("first system lookup %s after the record was created, want at least 1m", first.Sub(created))
			}
		})
	}
}

func TestARestartedOrTakenOverEnrollmentStillWaitsForTheHostname(t *testing.T) {
	r := newEdgeRig(t)
	r.doh.PublishAfter(1 << 30)
	host := r.start("vps1")
	r.untilNote("vps1", hostnameServedLog)

	r.stop() // the daemon died before the first dial
	r.resolver.serve(host)
	_, err := r.jobs.Takeover(context.Background(), "test")
	must(t, err)
	r.startScheduler() // the new daemon remembers nothing of the old one's pacing
	asked := r.doh.Asked(host)
	r.untilAsked(host, asked+3)

	if v := r.view("vps1"); v.Phase != string(database.PhaseDNSCreated) {
		t.Errorf("phase %s after the restart, want dns_created", v.Phase)
	}
	if n := r.resolver.lookupsOf(host); n != 0 {
		t.Errorf("%d system lookups after the restart while Cloudflare still did not serve the name, want 0", n)
	}

	r.doh.Set(dohfake.Served)
	r.until("vps1", string(database.PhaseScanned))
}

func TestTheConnectorTokenIsReturnedWheneverTheEnrollmentIsWaiting(t *testing.T) {
	r := newEdgeRig(t)
	r.doh.PublishAfter(1 << 30)
	r.start("vps1")

	deadline := time.Now().Add(30 * time.Second) //nolint:forbidigo // wall-clock budget of a polling loop
	waiting := 0
	for waiting < 5 && time.Now().Before(deadline) { //nolint:forbidigo // see above
		v := r.view("vps1")
		token, err := r.enroll.Token(context.Background(), r.admin, "vps1")
		if v.Phase == string(database.PhaseDNSCreated) {
			waiting++
			if err != nil || token.Reveal() == "" {
				t.Fatalf("the enrollment shows %s and the token request answers %v", v.Phase, err)
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	if waiting == 0 {
		t.Fatal("the enrollment never reached the waiting phase")
	}
}

func TestAServedHostnameThatTheSystemResolverDeniesIsNamedAsACachedNegativeAnswer(t *testing.T) {
	r := newEdgeRig(t)
	r.doh.Set(dohfake.Served) // the system resolver is never told: it cached the NXDOMAIN
	host := r.start("vps1")

	view := r.untilNote("vps1", "cached a negative answer")
	if !strings.Contains(view.Error, "no such host") {
		t.Errorf("note %q lost the original error", view.Error)
	}
	if view.Phase != string(database.PhaseDNSCreated) {
		t.Errorf("phase %s, want dns_created: the enrollment keeps trying", view.Phase)
	}

	r.resolver.serve(host) // the negative answer expired
	r.until("vps1", string(database.PhaseScanned))
}

func TestACarrierThatCannotResolveTheHostnameIsNotMistakenForAPassedPreflight(t *testing.T) {
	r := newEdgeRig(t)
	r.doh.Set(dohfake.Served)
	host := r.start("vps1")
	r.resolver.serveInProcess(host) // the preflight resolves it; the cloudflared child does not

	r.untilView("vps1", "a lookup by the carrier child", func(app.TunnelEnrollmentView) bool { return r.carrierLookups(host) > 0 })
	view := r.untilNote("vps1", "cached a negative answer")
	if !strings.Contains(view.Error, "no such host") {
		t.Errorf("note %q lost the carrier's original error", view.Error)
	}
	if view.Phase != string(database.PhaseDNSCreated) {
		t.Fatalf("phase %s although the carrier could not resolve the hostname", view.Phase)
	}

	r.resolver.serve(host)
	r.until("vps1", string(database.PhaseScanned))
}

// carrierLookups is how many times a cloudflared stand-in looked host up.
func (r *edgeRig) carrierLookups(host string) int {
	return r.resolver.lookupsOf(host) - r.resolver.inProcessLookups(host)
}
