package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/database"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare"
	"github.com/autarquico/supermgmt/internal/secrets"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh"
)

// fakeEdge is Cloudflare's resolver: it does not serve the hostname for the first notYet questions, or
// cannot be asked at all.
type fakeEdge struct {
	mu          sync.Mutex
	notYet      int
	unavailable bool
	asked       int
	diagnosed   bool // a NXDOMAIN from the system resolver is named as a cached negative answer
	slow        time.Duration
	pass        func(time.Duration)
}

func (e *fakeEdge) Published(context.Context, string) (bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.asked++
	if e.slow > 0 {
		e.pass(e.slow)
	}
	switch {
	case e.unavailable:
		return false, fmt.Errorf("%w: proxy authentication required", cloudflare.ErrResolverUnavailable)
	case e.asked <= e.notYet:
		return false, nil
	}
	return true, nil
}

func (e *fakeEdge) publish() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.notYet, e.unavailable = 0, false
}

func (e *fakeEdge) questions() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.asked
}

func (e *fakeEdge) DiagnoseNegativeCache(_ context.Context, host string, lookupErr error) error {
	var dnsErr *net.DNSError
	if !e.diagnosed || !errors.As(lookupErr, &dnsErr) || !dnsErr.IsNotFound {
		return lookupErr
	}
	return smerr.Wrap(lookupErr, smerr.CodeNodeUnreachable, smerr.ReasonTunnelDNSNegativeCache,
		"the local resolver most likely cached a negative answer for "+host)
}

func noSuchHost(host string) error {
	return fmt.Errorf("netguard: resolve %s: %w", host, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true})
}

// useEdge makes the engine ask edge and record its waits instead of taking them. A wait moves the fake
// clock, as the deadlines of the waits are measured on it.
func (ts *tunnelSetting) useEdge(edge *fakeEdge) {
	engine := ts.handler.tunnel
	engine.opts.Edge = edge
	edge.pass = func(d time.Duration) { ts.pass(context.Background(), d) }
	engine.opts.Sleep = func(ctx context.Context, d time.Duration) {
		ts.slept = append(ts.slept, d)
		ts.pass(ctx, d)
	}
}

// pass moves the fake clock and keeps the job's lease alive, as the engine's heartbeat does.
func (ts *tunnelSetting) pass(ctx context.Context, d time.Duration) {
	ts.clock.Advance(d)
	_ = ts.store.Heartbeat(ctx, ts.lease)
}

func (ts *tunnelSetting) sleptTotal() time.Duration {
	var total time.Duration
	for _, d := range ts.slept {
		total += d
	}
	return total
}

// ---- enrollment ----------------------------------------------------------------------------

func TestAnEnrollmentDoesNotScanBeforeCloudflareServesTheHostname(t *testing.T) {
	es := newEnrollSetting(t)
	edge := &fakeEdge{notYet: 1000}
	es.useEdge(edge)
	view := es.start()

	if failures := es.work(); len(failures) != 0 {
		t.Fatalf("the waiting job failed: %v", failures)
	}

	row := es.enrollmentRow(view.ID)
	if row.Phase != database.PhaseDNSCreated || len(es.scanned) != 0 {
		t.Fatalf("phase %s, %d scans: the hostname was looked up before Cloudflare served it", row.Phase, len(es.scanned))
	}
	if !strings.Contains(row.LastError, "waiting for Cloudflare to publish "+row.Hostname) {
		t.Errorf("note = %q, want the wait for Cloudflare's publication", row.LastError)
	}
	if got := es.sleptTotal(); got > enrollmentPublicationBudget {
		t.Errorf("the job waited %s, more than its %s budget", got, enrollmentPublicationBudget)
	}

	edge.publish()
	key := es.nodeComesUp()
	if row = es.settle(view.ID, 3); row.Phase != database.PhaseScanned || row.ScannedHostKey != key {
		t.Fatalf("phase %s after publication, want scanned", row.Phase)
	}
}

func TestAnEnrollmentThatCannotAskCloudflareWaitsAFixedTimeAndSaysSo(t *testing.T) {
	es := newEnrollSetting(t)
	es.useEdge(&fakeEdge{unavailable: true})
	view := es.start()
	es.work()

	row := es.enrollmentRow(view.ID)
	if len(es.scanned) != 0 {
		t.Fatal("the hostname was looked up before the fixed wait after the record's creation")
	}
	if !strings.Contains(row.LastError, "Cloudflare's resolver cannot be asked") || strings.Contains(row.LastError, "cannot ask Cloudflare's resolver") || !strings.Contains(row.LastError, "proxy authentication required") ||
		strings.Contains(row.LastError, "waiting for Cloudflare to publish") {
		t.Errorf("note = %q, want the resolver failure reported as such", row.LastError)
	}

	es.nodeComesUp()
	if row = es.settle(view.ID, 3); row.Phase != database.PhaseScanned {
		t.Fatalf("phase %s once the fixed wait was over, want scanned", row.Phase)
	}
}

func TestTheFallbackNoteLeadsWithWhatToExpectAndCutsOnlyTheCause(t *testing.T) {
	es := newEnrollSetting(t)
	es.useEdge(&fakeEdge{unavailable: true})
	view := es.start()
	es.work()

	got := es.enrollmentRow(view.ID).LastError

	if want := "Cloudflare's resolver cannot be asked, so the first lookup waits until 1m0s after the DNS record was created: "; !strings.HasPrefix(got, want) {
		t.Errorf("note = %q, want it to start with %q", got, want)
	}
	long := fmt.Errorf("%w: %s", cloudflare.ErrResolverUnavailable, strings.Repeat("x", 1000))
	if got := resolverFailure(long); len([]rune(got)) != fallbackCauseLength || strings.Contains(got, "cannot ask") {
		t.Errorf("cause = %q, want it bounded and without the repeated prefix", got)
	}
}

func TestARestartedEnrollmentStillWaitsForTheHostname(t *testing.T) {
	es := newEnrollSetting(t)
	edge := &fakeEdge{notYet: 1000}
	es.useEdge(edge)
	view := es.start()
	es.work()

	es.restart() // a restart or a takeover: nothing of the gate is in memory
	es.nodeComesUp()
	mustf(t, es.sched.Tick(context.Background()), "Tick")
	es.work()

	if row := es.enrollmentRow(view.ID); row.Phase != database.PhaseDNSCreated || len(es.scanned) != 0 {
		t.Fatalf("phase %s, %d scans: the restart skipped the gate", row.Phase, len(es.scanned))
	}
	edge.publish()
	if row := es.settle(view.ID, 3); row.Phase != database.PhaseScanned {
		t.Fatalf("phase %s once published, want scanned", row.Phase)
	}
}

func TestAServedHostnameThatTheSystemResolverDeniesIsNamedAsACachedNegativeAnswer(t *testing.T) {
	es := newEnrollSetting(t)
	es.useEdge(&fakeEdge{diagnosed: true})
	es.svc.opts.Scan = func(_ context.Context, target ssh.Target) (ssh.HostKey, error) {
		return ssh.HostKey{}, fmt.Errorf("cloudflare access preflight: %w", noSuchHost(target.Host))
	}
	view := es.start()
	es.work()

	row := es.enrollmentRow(view.ID)
	if row.Phase != database.PhaseDNSCreated || !strings.Contains(row.LastError, "cached a negative answer") ||
		!strings.Contains(row.LastError, "no such host") {
		t.Errorf("note = %q, want the diagnosis and the original error", row.LastError)
	}
}

// denyingSecrets refuses to store the connector token of an enrollment.
type denyingSecrets struct {
	TunnelSecrets
	deny bool
}

func (d *denyingSecrets) Put(ctx context.Context, name string, plaintext audit.Secret, meta map[string]any) (secrets.Ref, error) {
	if d.deny && strings.HasPrefix(name, enrollmentTokenPrefix) {
		return secrets.Ref{}, errors.New("the secret store is read-only")
	}
	return d.TunnelSecrets.Put(ctx, name, plaintext, meta)
}

func TestTheDNSRecordIsNotRecordedUntilTheConnectorTokenIsStored(t *testing.T) {
	es := newEnrollSetting(t)
	store := &denyingSecrets{TunnelSecrets: es.handler.tunnel.opts.Secrets, deny: true}
	es.handler.tunnel.opts.Secrets = store
	view := es.start()

	if failures := es.work(); len(failures) == 0 {
		t.Fatal("a token that could not be stored did not fail the job")
	}

	row := es.enrollmentRow(view.ID)
	if !provisioningPhase(row.Phase) || row.Objects.DNSRecordID != "" {
		t.Fatalf("phase %s with DNS record %q: the enrollment reached the waiting phase without its token", row.Phase, row.Objects.DNSRecordID)
	}
	_, err := es.svc.Token(context.Background(), es.admin(), "vps1")
	if err == nil || !strings.Contains(err.Error(), "still being built") {
		t.Errorf("token while provisioning: %v, want the provisioning answer", err)
	}

	store.deny = false
	es.tick()
	if row = es.enrollmentRow(view.ID); row.Phase != database.PhaseDNSCreated {
		t.Fatalf("phase %s once the store works, want dns_created", row.Phase)
	}
	es.tokenOf("vps1")
}

func TestTheConnectorTokenIsReadableAsSoonAsTheEnrollmentWaits(t *testing.T) {
	es := newEnrollSetting(t)
	view := es.start()
	es.work()

	if row := es.enrollmentRow(view.ID); row.Phase != database.PhaseDNSCreated {
		t.Fatalf("phase %s, want dns_created", row.Phase)
	}
	es.tokenOf("vps1")
}

// ---- setup ---------------------------------------------------------------------------------

// flakyEdgeDialer fails the dials of the dedicated account over the tunnel the way the carrier does while
// the edge is not ready, and remembers how many questions Cloudflare's resolver had had by the first dial.
type flakyEdgeDialer struct {
	*fakeDialer
	edge     *fakeEdge
	failures int
	err      error
	firstAt  int // questions asked of Cloudflare when the tunnel was first dialled; -1 before
	// anyFirstAt is firstAt for a connection of any user through the tunnel, the admin session included.
	anyFirstAt int
	cost       time.Duration // what a failing dial takes, on the fake clock
	pass       func(time.Duration)
}

func (d *flakyEdgeDialer) For(t ssh.Target) transport.Executor {
	if t.Transport == "cloudflare" {
		d.mu.Lock()
		if d.anyFirstAt < 0 {
			d.anyFirstAt = d.edge.questions()
		}
		d.mu.Unlock()
	}
	if t.Transport == "cloudflare" && t.User == "supermgmt" {
		d.mu.Lock()
		if d.firstAt < 0 {
			d.firstAt = d.edge.questions()
		}
		failing := d.failures > 0
		d.failures--
		d.mu.Unlock()
		if failing {
			return unreachable{d.err}
		}
	}
	return d.fakeDialer.For(t)
}

func (ts *tunnelSetting) flakyTunnel(edge *fakeEdge, failures int, err error) *flakyEdgeDialer {
	d := &flakyEdgeDialer{fakeDialer: ts.dialer, edge: edge, failures: failures, err: err, firstAt: -1, anyFirstAt: -1, pass: func(d time.Duration) { ts.pass(context.Background(), d) }}
	ts.handler.conn = Connector{Remote: d}
	return d
}

func TestASetupWaitsForTheHostnameThenRetriesTheTunnelAndSucceedsOnTheFirstAttempt(t *testing.T) {
	ts := newTunnelSetting(t)
	edge := &fakeEdge{notYet: 20} // 40 s of polling
	ts.useEdge(edge)
	dialer := ts.flakyTunnel(edge, 3, smerr.New(smerr.CodeNodeUnreachable, "", "cloudflare access preflight: connection refused"))
	ts.plan()

	mustf(t, ts.attempt(), "tunnel setup, first attempt")

	if dialer.firstAt <= 20 {
		t.Errorf("the tunnel was dialled after %d questions to Cloudflare, want it only once the hostname was served", dialer.firstAt)
	}
	if got := ts.sleptTotal(); got < 40*time.Second || got > setupStepBudget {
		t.Errorf("waited %s, want the 40 s of the edge plus the retries within %s", got, setupStepBudget)
	}
	ts.wantOneOfEach()
}

func TestASetupThatNeverSeesTheHostnameServedFailsAtItsStepAndASecondAttemptStillWaits(t *testing.T) {
	ts := newTunnelSetting(t)
	edge := &fakeEdge{notYet: 1 << 20}
	ts.useEdge(edge)
	dialer := ts.flakyTunnel(edge, 0, nil)
	ts.plan()

	err := ts.attempt()

	if err == nil || !strings.Contains(err.Error(), "verification over the tunnel") || !strings.Contains(err.Error(), "waiting for Cloudflare to publish") {
		t.Fatalf("error = %v, want the step and the wait for publication", err)
	}
	if dialer.firstAt != -1 {
		t.Fatal("the hostname was dialled before Cloudflare served it")
	}

	interruptAndRequeue(t, ts.fixture, ts.queued.ID) // a restart: the gate comes from the persisted phase
	if err = ts.attempt(); err == nil || dialer.firstAt != -1 {
		t.Fatalf("second attempt: error %v, first dial after %d questions: the gate was skipped", err, dialer.firstAt)
	}
	if ops := ts.operations(); len(ops) != 1 || ops[0].Phase != database.PhaseInstalled {
		t.Fatalf("operations = %+v, want one at phase installed", ops)
	}

	edge.publish()
	interruptAndRequeue(t, ts.fixture, ts.queued.ID)
	mustf(t, ts.attempt(), "attempt once published")
	ts.wantOneOfEach()
}

func TestAFailedTunnelVerificationNamesTheDialFailureAndTheStep(t *testing.T) {
	ts := newTunnelSetting(t)
	edge := &fakeEdge{}
	ts.useEdge(edge)
	ts.flakyTunnel(edge, 1<<20, smerr.New(smerr.CodeNodeUnreachable, "", "Cloudflare Access did not admit the service token"))
	ts.plan()

	err := ts.attempt()

	if err == nil || !strings.Contains(err.Error(), "tunnel setup failed at verification over the tunnel") ||
		!strings.Contains(err.Error(), "did not admit the service token") {
		t.Fatalf("error = %v, want the step and the dial failure", err)
	}
	if strings.Contains(err.Error(), "cannot log in as the dedicated user") {
		t.Errorf("error = %v: a dial failure was reported as a login failure", err)
	}
	if got := ts.sleptTotal(); got > setupStepBudget {
		t.Errorf("retried for %s, past the %s step deadline", got, setupStepBudget)
	}
}

func TestASetupThatCouldNotAskCloudflareSaysSoWhenItsVerificationFails(t *testing.T) {
	ts := newTunnelSetting(t)
	edge := &fakeEdge{unavailable: true, diagnosed: true}
	ts.useEdge(edge)
	ts.flakyTunnel(edge, 1<<20, smerr.Wrap(noSuchHost(ts.hostname()), smerr.CodeNodeUnreachable, "", "cloudflare access preflight"))
	ts.plan()

	err := ts.attempt()

	if err == nil || !strings.Contains(err.Error(), "Cloudflare's resolver could not be asked (proxy authentication required)") ||
		!strings.Contains(err.Error(), "no such host") {
		t.Fatalf("error = %v, want the resolver failure and the lookup failure", err)
	}
	if smerr.CodeOf(err) != smerr.CodeNodeUnreachable {
		t.Errorf("code = %s, want the lookup failure's code kept", smerr.CodeOf(err))
	}
}

func TestASetupVerificationThatTheCarrierRefusesIsNotRetried(t *testing.T) {
	ts := newTunnelSetting(t)
	edge := &fakeEdge{}
	ts.useEdge(edge)
	ts.flakyTunnel(edge, 1<<20, smerr.New(smerr.CodeSSHHostKeyMismatch, "", "host key changed"))
	ts.plan()

	if err := ts.attempt(); err == nil {
		t.Fatal("a host key mismatch did not fail the setup")
	}
	if got := ts.sleptTotal(); got != 0 {
		t.Errorf("waited %s retrying a failure that waiting does not cure", got)
	}
}

func TestASetupWhoseServedHostnameStillFailsToResolveNamesTheCachedNegativeAnswer(t *testing.T) {
	ts := newTunnelSetting(t)
	edge := &fakeEdge{diagnosed: true}
	ts.useEdge(edge)
	ts.flakyTunnel(edge, 1<<20, smerr.Wrap(noSuchHost(ts.hostname()), smerr.CodeNodeUnreachable, "", "cloudflare access preflight"))
	ts.plan()

	err := ts.attempt()

	if err == nil || !strings.Contains(err.Error(), "cached a negative answer") || !strings.Contains(err.Error(), "no such host") {
		t.Fatalf("error = %v, want the diagnosis with the original error", err)
	}
	var coded *smerr.Error
	if !errors.As(err, &coded) || coded.Reason != smerr.ReasonTunnelDNSNegativeCache {
		t.Errorf("error = %v, want the reason %q", err, smerr.ReasonTunnelDNSNegativeCache)
	}
}

func TestTheFallbackWaitCountsFromTheLatestInstantAPersistedCreationTimeCanStandFor(t *testing.T) {
	ts := newTunnelSetting(t)
	ts.useEdge(&fakeEdge{})
	engine := ts.handler.tunnel
	persisted := ts.clock.Now().Add(-resolverFallbackWait)
	budget := engine.newBudget(setupStepBudget)

	note, err := engine.waitOutFallback(context.Background(), persisted, errors.New("resolver down"), budget)

	if err != nil || note != "" {
		t.Fatalf("note %q, err %v: the wait should have completed", note, err)
	}
	if got := ts.sleptTotal(); got != persistedInstantResolution {
		t.Errorf("waited %s, want %s: a creation time rounded down to the millisecond can be that much too early", got, persistedInstantResolution)
	}
}

// ---- elapsed deadlines ------------------------------------------------------------------------

func TestSlowAnswersFromCloudflareDoNotStretchAnEnrollmentJobPastItsBudget(t *testing.T) {
	es := newEnrollSetting(t)
	es.useEdge(&fakeEdge{notYet: 1 << 20, slow: 4 * time.Second})
	es.start()
	begun := es.clock.Now()

	es.work()

	if got := es.clock.Now().Sub(begun); got > enrollmentPublicationBudget+4*time.Second {
		t.Errorf("the job took %s, want about its %s budget (one answer may end after it)", got, enrollmentPublicationBudget)
	}
}

func TestSlowFailingDialsDoNotStretchTheSetupStepPastItsDeadline(t *testing.T) {
	ts := newTunnelSetting(t)
	edge := &fakeEdge{}
	ts.useEdge(edge)
	dialer := ts.flakyTunnel(edge, 1<<20, smerr.New(smerr.CodeNodeUnreachable, "", "cloudflare access preflight: connection refused"))
	dialer.cost = 20 * time.Second
	ts.plan()
	begun := ts.clock.Now()

	err := ts.attempt()

	if err == nil {
		t.Fatal("verification over a tunnel that never carries a stream succeeded")
	}
	if got := ts.clock.Now().Sub(begun); got > setupStepBudget+dialer.cost {
		t.Errorf("the step took %s, want its %s deadline (one attempt may end after it)", got, setupStepBudget)
	}
}

func TestSlowAnswersFromCloudflareDoNotStretchTheSetupWaitPastItsDeadline(t *testing.T) {
	ts := newTunnelSetting(t)
	edge := &fakeEdge{notYet: 1 << 20, slow: 4 * time.Second}
	ts.useEdge(edge)
	ts.flakyTunnel(edge, 0, nil)
	ts.plan()
	begun := ts.clock.Now()

	err := ts.attempt()

	if err == nil || !strings.Contains(err.Error(), "waiting for Cloudflare to publish") {
		t.Fatalf("error = %v, want the wait for publication", err)
	}
	if got := ts.clock.Now().Sub(begun); got > setupStepBudget+edge.slow {
		t.Errorf("the wait took %s, want its %s deadline", got, setupStepBudget)
	}
}

// ---- repair ----------------------------------------------------------------------------------

func TestARepairThatRecreatesTheRecordConnectsOnlyOnceCloudflareServesIt(t *testing.T) {
	ts := newEnabledTunnel(t)
	edge := &fakeEdge{notYet: 20}
	ts.useEdge(edge)
	dialer := ts.flakyTunnel(edge, 0, nil)
	old := ts.operations()[0].Objects
	mustf(t, ts.chaos.CloudflareAPI.DeleteDNSRecord(context.Background(), ts.zoneID(), old.DNSRecordID), "delete DNS record")
	ts.plan()

	mustf(t, ts.attempt(), "repair")

	if dialer.anyFirstAt <= 20 {
		t.Errorf("the hostname was used after %d questions to Cloudflare, want it only once it was served", dialer.anyFirstAt)
	}
	ts.wantOneOfEach()
}

func TestARepairThatLeavesTheRecordAloneDoesNotWaitForCloudflare(t *testing.T) {
	ts := newEnabledTunnel(t)
	edge := &fakeEdge{notYet: 1 << 20}
	ts.useEdge(edge)
	ts.flakyTunnel(edge, 0, nil)
	ts.plan()

	mustf(t, ts.attempt(), "rerun")

	if got := edge.questions(); got != 0 {
		t.Errorf("%d questions to Cloudflare about a record nobody touched, want none", got)
	}
}
