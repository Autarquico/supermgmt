package api

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
)

type adminCalls struct {
	mu      sync.Mutex
	calls   []string
	guarded []string
	peers   []int
	held    bool
}

func (c *adminCalls) record(call string, peer int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, call)
	c.peers = append(c.peers, peer)
}

func (c *adminCalls) IssueBootstrapCode(_ context.Context, peer int) (wire.BootstrapCodeIssued, error) {
	c.record("bootstrap-code", peer)
	return wire.BootstrapCodeIssued{Code: "smb_code"}, nil
}

func (c *adminCalls) Grant(ctx context.Context, peer int, r wire.GrantRequest) error {
	c.record("grant:"+r.Role, peer)
	return nil
}

func (c *adminCalls) Load(context.Context) (bool, error) { return c.held, nil }

func (c *adminCalls) Guard(_ context.Context, action string, _ app.Caller) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.guarded = append(c.guarded, action)
	return nil
}

func (c *adminCalls) Complete(_ context.Context, peer int) error {
	c.record("restore-complete", peer)
	return nil
}

type adminHarness struct {
	t      *testing.T
	calls  *adminCalls
	socket string
	http   *http.Client
}

// newAdmin serves the admin socket for the peers lookup reports, admitting
// only the given UIDs.
func newAdmin(t *testing.T, lookup PeerLookup, admitted ...uint32) *adminHarness {
	t.Helper()
	calls := &adminCalls{}
	server, err := NewAdmin(AdminOptions{
		Auth: calls, Hold: calls, IDs: domaintest.NewSequentialIDs(),
		Doctor: func(context.Context) (wire.AdminDoctor, error) { return wire.AdminDoctor{Mode: "server"}, nil },
	})
	must(t, err)
	dir, err := os.MkdirTemp("", "sma")
	must(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "a")
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", socket)
	must(t, err)
	go func() { _ = server.Serve(RestrictToUIDs(listener, admitted, lookup, nil)) }()
	t.Cleanup(func() { _ = server.Shutdown(context.Background()) })
	h := &adminHarness{t: t, calls: calls, socket: socket}
	h.http = &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
	}}
	t.Cleanup(h.http.CloseIdleConnections)
	return h
}

func (h *adminHarness) do(method, path, body string) (int, string, error) {
	req, err := http.NewRequestWithContext(context.Background(), method, "http://admin"+path, bytes.NewBufferString(body))
	must(h.t, err)
	resp, err := h.http.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	payload, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(payload), nil
}

func asPeer(uid uint32) PeerLookup { return func(*net.UnixConn) (uint32, error) { return uid, nil } }

func TestTheAdminSocketServesExactlyTheFourRoutes(t *testing.T) {
	var got []string
	for _, rt := range AdminRoutes() {
		got = append(got, rt.Method+" "+rt.Pattern)
	}
	slices.Sort(got)
	want := []string{
		"GET " + wire.AdminPathDoctor, "POST " + wire.AdminPathBootstrapCode,
		"POST " + wire.AdminPathGrant, "POST " + wire.AdminPathRestoreComplete,
	}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("admin routes = %v, want %v", got, want)
	}
}

func TestTheAdminSocketHasNoKeyRoutesNorAnythingUnderAPIv1(t *testing.T) {
	h := newAdmin(t, asPeer(0), 0)
	for _, probe := range []struct{ method, path string }{
		{http.MethodPost, wire.PathMasterKeyRotate},
		{http.MethodPost, wire.PathMasterKeyRetire},
		{http.MethodPost, wire.PathMasterKeyExport},
		{http.MethodPost, wire.PathSSHKeyRotate},
		{http.MethodPost, wire.PathSecrets},
		{http.MethodGet, wire.PathMe},
		{http.MethodGet, wire.PathJobs},
		{http.MethodPost, wire.PathTokens},
		{http.MethodGet, "/admin/keys"},
		{http.MethodGet, wire.AdminPathBootstrapCode},
	} {
		status, body, err := h.do(probe.method, probe.path, "{}")
		if err != nil || (status != http.StatusNotFound && status != http.StatusMethodNotAllowed) {
			t.Errorf("%s %s: status %d, %v, %s", probe.method, probe.path, status, err, body)
		}
	}
	if len(h.calls.calls) != 0 {
		t.Errorf("a probe reached a service: %v", h.calls.calls)
	}
}

func TestAnotherUserOnTheAdminSocketIsClosedUnread(t *testing.T) {
	h := newAdmin(t, asPeer(4242), 0, 1000)

	status, body, err := h.do(http.MethodPost, wire.AdminPathBootstrapCode, "")

	if err == nil {
		t.Fatalf("the admin socket answered another user: %d %s", status, body)
	}
	if len(h.calls.calls) != 0 {
		t.Errorf("a refused peer reached a service: %v", h.calls.calls)
	}
}

func TestAFailedPeerLookupClosesTheAdminConnection(t *testing.T) {
	h := newAdmin(t, func(*net.UnixConn) (uint32, error) { return 0, errors.New("no credentials") }, 0)

	if _, _, err := h.do(http.MethodGet, wire.AdminPathDoctor, ""); err == nil {
		t.Error("the admin socket answered a peer it could not identify")
	}
}

func TestRootAndTheServiceUserAreServedWithTheirUID(t *testing.T) {
	for _, uid := range []uint32{0, 1000} {
		h := newAdmin(t, asPeer(uid), 0, 1000)

		status, body, err := h.do(http.MethodPost, wire.AdminPathBootstrapCode, "")

		if err != nil || status != http.StatusOK {
			t.Fatalf("uid %d: %d %s %v", uid, status, body, err)
		}
		if !bytes.Contains([]byte(body), []byte("smb_code")) || h.calls.peers[0] != int(uid) {
			t.Errorf("uid %d: body %s, peers %v", uid, body, h.calls.peers)
		}
	}
}

func TestEachAdminWriteIsStampedWithItsActionAndGuardedByTheHold(t *testing.T) {
	h := newAdmin(t, asPeer(0), 0)

	for _, step := range []struct{ path, body string }{
		{wire.AdminPathBootstrapCode, ""},
		{wire.AdminPathGrant, `{"identity_id":"01970000-0000-7000-8000-000000000001","role":"admin"}`},
		{wire.AdminPathRestoreComplete, ""},
	} {
		if status, body, err := h.do(http.MethodPost, step.path, step.body); err != nil || status != http.StatusOK {
			t.Fatalf("%s: %d %s %v", step.path, status, body, err)
		}
	}
	if status, _, err := h.do(http.MethodGet, wire.AdminPathDoctor, ""); err != nil || status != http.StatusOK {
		t.Fatalf("doctor: %d %v", status, err)
	}

	want := []string{app.ActionAdminBootstrapCode, app.ActionAdminGrant, app.ActionRestoreComplete}
	if !slices.Equal(h.calls.guarded, want) {
		t.Errorf("guarded = %v, want %v (reads are not guarded)", h.calls.guarded, want)
	}
}

func TestAMalformedGrantIsRefusedBeforeTheService(t *testing.T) {
	h := newAdmin(t, asPeer(0), 0)

	status, _, err := h.do(http.MethodPost, wire.AdminPathGrant, `{"identity_id":"x","role":"admin","extra":1}`)

	if err != nil || status != http.StatusBadRequest {
		t.Errorf("status %d, %v", status, err)
	}
	if len(h.calls.calls) != 0 {
		t.Errorf("service called: %v", h.calls.calls)
	}
}
