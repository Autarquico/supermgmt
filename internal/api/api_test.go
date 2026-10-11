package api

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/policy"
)

func decodeError(t *testing.T, r reply) wire.Error {
	t.Helper()
	var e wire.ErrorEnvelope
	if err := json.Unmarshal(r.Body, &e); err != nil {
		t.Fatalf("not an error envelope: %s", r.Body)
	}
	return e.Error
}

// unkeyedWrites are the writes that take no Idempotency-Key although they are
// not credential-issuing: a scan that changes nothing, and the two that end a
// credential (revoking twice is already a no-op).
var unkeyedWrites = map[string]bool{
	"POST " + wire.PathNodesSSHHostKey: true,
	"POST " + wire.PathLogout:          true,
	"DELETE " + wire.PathToken:         true,
	"POST " + wire.PathOIDCStart:       true,
	"POST " + wire.PathOIDCDevice:      true,
}

func TestEveryRouteMapsToExactlyOneCatalogActionOrExemption(t *testing.T) {
	h := newHarness(t)
	seen := map[string]bool{}
	for _, rt := range h.server.Routes() {
		key := rt.Method + " " + rt.Pattern
		if seen[key] {
			t.Errorf("%s is registered twice", key)
		}
		seen[key] = true
		_, inCatalog := policy.Lookup(rt.Action)
		exempt := rt.Action == ExemptSelf || rt.Action == ExemptHealth || rt.Action == ExemptAuth
		if inCatalog == exempt { // neither, or (impossibly) both
			t.Errorf("%s maps to %q, which is neither a catalog action nor an exemption", key, rt.Action)
		}
		mutating := rt.Method != http.MethodGet
		wantKey := mutating && !rt.Credential && !unkeyedWrites[key]
		if rt.Keyed != wantKey {
			t.Errorf("%s: keyed = %v, want %v", key, rt.Keyed, wantKey)
		}
	}
}

func TestTheLocalSocketServesTheContract(t *testing.T) {
	h := newHarness(t)
	want := []string{
		"GET " + wire.PathHealthLive, "GET " + wire.PathHealthReady, "GET " + wire.PathMe, "GET " + wire.PathPresence,
		"GET " + wire.PathSSHKey, "POST " + wire.PathPlans, "GET " + wire.PathPlan, "POST " + wire.PathPlanSubmit, "GET " + wire.PathApprovals,
		"GET " + wire.PathJobs, "GET " + wire.PathJob, "POST " + wire.PathJobApprove, "POST " + wire.PathJobReject,
		"POST " + wire.PathJobCancel, "POST " + wire.PathJobResolve, "GET " + wire.PathProviders, "POST " + wire.PathProviders,
		"GET " + wire.PathNodes, "GET " + wire.PathNode, "POST " + wire.PathNodesSSHHostKey, "POST " + wire.PathNodesSSH,
		"PATCH " + wire.PathNode, "DELETE " + wire.PathNode, "POST " + wire.PathNodeProbe, "GET " + wire.PathNodeServices,
		"GET " + wire.PathNodeConnectInfo, "POST " + wire.PathNodeSessions, "POST " + wire.PathNodeSessionEnd,
		"GET " + wire.PathService, "GET " + wire.PathServiceLogs, "POST " + wire.PathServiceStart,
		"POST " + wire.PathServiceStop, "POST " + wire.PathServiceRestart, "GET " + wire.PathEvents,
		"GET " + wire.PathEventStream,
		"POST " + wire.PathOIDCStart, "POST " + wire.PathOIDCExchange, "POST " + wire.PathOIDCDevice,
		"POST " + wire.PathOIDCDevicePoll, "POST " + wire.PathBootstrap, "POST " + wire.PathLogout,
		"GET " + wire.PathTokens, "POST " + wire.PathTokens, "DELETE " + wire.PathToken,
		"POST " + wire.PathSecrets, "POST " + wire.PathMasterKeyRotate, "POST " + wire.PathMasterKeyRetire,
		"POST " + wire.PathMasterKeyExport, "POST " + wire.PathSSHKeyRotate,
		"GET " + wire.PathBackups, "POST " + wire.PathBackups, "POST " + wire.PathEnrollments, "POST " + wire.PathEnroll,
	}
	got := map[string]bool{}
	for _, rt := range h.server.Routes() {
		got[rt.Method+" "+rt.Pattern] = true
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("route %s is not served", w)
		}
	}
	if len(got) != len(want) {
		t.Errorf("serving %d routes, the contract has %d", len(got), len(want))
	}
}

func TestMeIsTheLocalCallerWithItsLocalSocketCredential(t *testing.T) {
	h := newHarness(t)
	r := h.do(http.MethodGet, wire.PathMe, "", nil)
	var env wire.Envelope[wire.Me]
	if err := json.Unmarshal(r.Body, &env); err != nil || r.Status != http.StatusOK {
		t.Fatalf("status %d body %s", r.Status, r.Body)
	}
	if env.Data.IdentityID != h.caller || env.Data.Credential != "local_socket" || env.Data.Roles[0] != "admin" {
		t.Errorf("me = %+v", env.Data)
	}
	if env.Meta.CorrelationID == "" || r.Header.Get(wire.HeaderCorrelationID) != env.Meta.CorrelationID {
		t.Errorf("correlation id missing or inconsistent: %q vs %q", env.Meta.CorrelationID, r.Header.Get(wire.HeaderCorrelationID))
	}
}

func TestAnyAuthorizationHeaderIsUnauthenticated(t *testing.T) {
	h := newHarness(t)
	for _, path := range []string{wire.PathMe, wire.PathHealthLive, "/nowhere"} {
		r := h.do(http.MethodGet, path, "", map[string]string{wire.HeaderAuthorization: "Bearer x"})
		if r.Status != http.StatusUnauthorized || decodeError(t, r).Code != "UNAUTHENTICATED" {
			t.Errorf("%s: status %d body %s", path, r.Status, r.Body)
		}
	}
}

func TestUnknownRoutesAndVerbsAreNotFound(t *testing.T) {
	h := newHarness(t)
	id := h.ids.NewID().String()
	for _, path := range []string{"/api/v1/nope", "/api/v1/services/" + id + "/actions/delete", "/api/v1/services/" + id + "/actions/"} {
		r := h.post(path, "", "k1")
		if r.Status != http.StatusNotFound || decodeError(t, r).Code != "NOT_FOUND" {
			t.Errorf("%s: status %d body %s", path, r.Status, r.Body)
		}
	}
}

func TestMutationsNeedAnIdempotencyKeyAndAValidBody(t *testing.T) {
	h := newHarness(t)
	cases := []struct {
		name, body, key string
	}{
		{"no key", `{"type":"local"}`, ""},
		{"key with a space", `{"type":"local"}`, "a b"},
		{"empty body", "", "k"},
		{"unknown field", `{"type":"local","x":1}`, "k"},
		{"trailing data", `{"type":"local"} {}`, "k"},
		{"not local", `{"type":"proxmox"}`, "k"},
	}
	for _, c := range cases {
		r := h.post(wire.PathProviders, c.body, c.key)
		if r.Status != http.StatusBadRequest || decodeError(t, r).Code != "INVALID_ARGUMENT" {
			t.Errorf("%s: status %d body %s", c.name, r.Status, r.Body)
		}
	}
}

func TestMalformedPathIDsAreRefusedBeforeAnyService(t *testing.T) {
	h := newHarness(t)
	r := h.do(http.MethodGet, "/api/v1/jobs/not-an-id", "", nil)
	if r.Status != http.StatusBadRequest {
		t.Errorf("status %d body %s", r.Status, r.Body)
	}
}

func TestAReplayedRequestReturnsTheSameBytesAndSaysSo(t *testing.T) {
	h := newHarness(t)
	first := h.post(wire.PathProviders, `{"type":"local"}`, "key-1")
	if first.Status != http.StatusCreated && first.Status != http.StatusAccepted {
		t.Fatalf("first: status %d body %s", first.Status, first.Body)
	}
	if first.Header.Get(wire.HeaderIdempotentReplayed) != "" {
		t.Error("the first execution claims to be a replay")
	}
	second := h.post(wire.PathProviders, `{"type":"local"}`, "key-1")
	if second.Status != first.Status || string(second.Body) != string(first.Body) {
		t.Errorf("replay differs:\n%s\n%s", first.Body, second.Body)
	}
	if second.Header.Get(wire.HeaderIdempotentReplayed) != "true" {
		t.Error("replay lacks Idempotent-Replayed: true")
	}
}

func TestTheSameKeyOnAnotherRequestIsAMismatch(t *testing.T) {
	h := newHarness(t)
	h.post(wire.PathProviders, `{"type":"local"}`, "key-2")
	r := h.post("/api/v1/plans/"+h.ids.NewID().String()+"/submit", `{"plan_hash":"x"}`, "key-2")
	e := decodeError(t, r)
	if r.Status != http.StatusConflict || e.Code != "CONFLICT" || e.Reason() != "IDEMPOTENCY_MISMATCH" {
		t.Errorf("status %d body %s", r.Status, r.Body)
	}
}

func TestACallerWithoutRolesIsDeniedByPolicy(t *testing.T) {
	h := newHarness(t, func(o *harnessOptions) { o.roles = nil })
	for _, path := range []string{wire.PathJobs, wire.PathEvents, wire.PathApprovals, wire.PathSSHKey} {
		r := h.do(http.MethodGet, path, "", nil)
		if r.Status != http.StatusForbidden || decodeError(t, r).Code != "POLICY_DENIED" {
			t.Errorf("%s: status %d body %s", path, r.Status, r.Body)
		}
	}
	// Listings filter to what the caller may read, so they are empty, not denied.
	if r := h.do(http.MethodGet, wire.PathNodes, "", nil); r.Status != http.StatusOK || !strings.Contains(string(r.Body), `"items":[]`) {
		t.Errorf("nodes: status %d body %s", r.Status, r.Body)
	}
	// The caller always sees itself.
	if r := h.do(http.MethodGet, wire.PathMe, "", nil); r.Status != http.StatusOK {
		t.Errorf("me: status %d", r.Status)
	}
}

func TestTheSSHKeyIsThePublicHalfOnly(t *testing.T) {
	h := newHarness(t)
	r := h.do(http.MethodGet, wire.PathSSHKey, "", nil)
	var env wire.Envelope[wire.SSHKey]
	_ = json.Unmarshal(r.Body, &env)
	if r.Status != http.StatusOK || env.Data.Ref != "secret://ssh/default" || env.Data.FingerprintSHA256 != "SHA256:x" {
		t.Errorf("status %d body %s", r.Status, r.Body)
	}
}

func TestInternalFailuresDoNotLeakTheirCause(t *testing.T) {
	err := errors.New("open /var/lib/secret.db: permission denied")
	pub := publicError(err)
	if pub.Code != "INTERNAL" || strings.Contains(pub.Message, "secret.db") {
		t.Errorf("public error = %+v", pub)
	}
}

func TestAConnectionFromAnotherUserIsClosedBeforeAnyRequestIsRead(t *testing.T) {
	other := uint32(os.Getuid()) + 1
	h := newHarness(t, func(o *harnessOptions) { o.uid = &other })
	assertRefused(t, h)
}

func TestAFailedPeerLookupClosesTheConnection(t *testing.T) {
	h := newHarness(t, func(o *harnessOptions) {
		o.peer = func(*net.UnixConn) (uint32, error) { return 0, errors.New("injected lookup failure") }
	})
	assertRefused(t, h)
}

func assertRefused(t *testing.T, h *harness) {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://sm"+wire.PathMe, http.NoBody)
	resp, err := h.http.Do(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatalf("the daemon answered a refused peer with status %d", resp.StatusCode)
	}
}

func TestTheSameUserIsAccepted(t *testing.T) {
	h := newHarness(t)
	if r := h.do(http.MethodGet, wire.PathHealthReady, "", nil); r.Status != http.StatusOK {
		t.Errorf("status %d body %s", r.Status, r.Body)
	}
}

type countingResidency struct{ presence, inFlight atomic.Int64 }

func (c *countingResidency) Present() func() {
	c.presence.Add(1)
	return func() { c.presence.Add(-1) }
}

func (c *countingResidency) Begin() func() {
	c.inFlight.Add(1)
	return func() { c.inFlight.Add(-1) }
}

func TestPresenceIsHeldOpenAndCountedUntilTheClientLeaves(t *testing.T) {
	counts := &countingResidency{}
	h := newHarness(t, func(o *harnessOptions) { o.cached = counts })
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://sm"+wire.PathPresence, http.NoBody)
	resp, err := h.http.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("presence: %v", err)
	}
	waitFor(t, func() bool { return counts.presence.Load() == 1 })
	if counts.inFlight.Load() != 0 {
		t.Error("a presence stream counts as in flight")
	}
	cancel()
	_ = resp.Body.Close()
	waitFor(t, func() bool { return counts.presence.Load() == 0 })
}

func TestOneShotRequestsAreCountedWhileTheyRun(t *testing.T) {
	counts := &countingResidency{}
	h := newHarness(t, func(o *harnessOptions) { o.cached = counts })
	h.do(http.MethodGet, wire.PathMe, "", nil)
	if counts.inFlight.Load() != 0 || counts.presence.Load() != 0 {
		t.Errorf("counters did not return to zero: %d %d", counts.inFlight.Load(), counts.presence.Load())
	}
}

func TestShutdownEndsPresenceStreams(t *testing.T) {
	h := newHarness(t)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://sm"+wire.PathPresence, http.NoBody)
	resp, err := h.http.Do(req)
	must(t, err)
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 1<<10)
		for {
			if _, err := resp.Body.Read(buf); err != nil {
				close(done)
				return
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	must(t, h.server.Shutdown(ctx))
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the presence stream survived shutdown")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for range 500 {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not reached")
}

func TestServeAfterShutdownReturnsAndClosesTheListener(t *testing.T) {
	h := newHarness(t)
	must(t, h.server.Shutdown(context.Background()))
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", h.socket+"2")
	must(t, err)
	done := make(chan error, 1)
	go func() { done <- h.server.Serve(l) }()
	select {
	case err := <-done:
		must(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after Shutdown")
	}
	if c, err := (&net.Dialer{}).DialContext(context.Background(), "unix", h.socket+"2"); err == nil {
		_ = c.Close()
		t.Error("the listener is still accepting")
	}
}

func TestASuccessfulCallThatStoredNoRecordIsNeverAnsweredAsSuccess(t *testing.T) {
	h := newHarness(t)
	forgetful := mutation(h.server,
		func(context.Context, app.Caller, input) (app.Submission, error) { return app.Submission{}, nil },
		submitted)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, wire.PathPlans, strings.NewReader("{}"))
	req.Header.Set(wire.HeaderIdempotencyKey, "k")
	rec := httptest.NewRecorder()
	if err := forgetful(rec, req); err == nil {
		t.Fatal("the request was answered although nothing was stored for its key")
	}
	if rec.Body.Len() != 0 {
		t.Errorf("a body was written: %s", rec.Body.String())
	}
}

func TestReadingAPlanIsAuthorizedAsPlanRead(t *testing.T) {
	missing := "/api/v1/plans/" + domainID()
	admin := newHarness(t)
	if r := admin.do(http.MethodGet, missing, "", nil); r.Status != http.StatusNotFound {
		t.Errorf("admin, unknown plan: status %d body %s", r.Status, r.Body)
	}
	nobody := newHarness(t, func(o *harnessOptions) { o.roles = nil })
	if r := nobody.do(http.MethodGet, missing, "", nil); r.Status != http.StatusForbidden {
		t.Errorf("no roles: status %d body %s", r.Status, r.Body)
	}
}

func domainID() string { return domain.UUIDv7Generator{}.NewID().String() }
