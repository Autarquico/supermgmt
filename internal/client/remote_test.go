package client_test

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/client"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// tlsServer is an HTTPS control plane stand-in with its CA written to disk.
type tlsServer struct {
	*httptest.Server
	caFile string

	mu   sync.Mutex
	seen []received
}

func newTLSServer(t *testing.T, handler http.HandlerFunc) *tlsServer {
	t.Helper()
	s := &tlsServer{}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.seen = append(s.seen, received{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Clone(), body})
		s.mu.Unlock()
		handler(w, r)
	}))
	t.Cleanup(s.Close)
	s.caFile = filepath.Join(t.TempDir(), "ca.pem")
	block := &pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}
	if err := os.WriteFile(s.caFile, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return s
}

func (s *tlsServer) requests() []received {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]received(nil), s.seen...)
}

func (s *tlsServer) remote(token string) client.Remote {
	return client.Remote{URL: s.URL, CAFile: s.caFile, Token: token}
}

func writeEnvelope[T any](w http.ResponseWriter, status int, data T) {
	w.Header().Set("Content-Type", wire.ContentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(wire.Envelope[T]{Data: data})
}

func writeFailure(w http.ResponseWriter, status int, code smerr.Code, message string) {
	w.Header().Set("Content-Type", wire.ContentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(wire.ErrorEnvelope{Error: wire.Error{Code: code, Message: message, CorrelationID: "corr-1"}})
}

func asTyped(err error, target **smerr.Error) bool { return errors.As(err, target) }

func meHandler(w http.ResponseWriter, _ *http.Request) {
	writeEnvelope(w, http.StatusOK, wire.Me{DisplayName: "alex", InstanceMode: "server"})
}

func TestRemoteSendsTheBearerOverHTTPSWithTheProfileCA(t *testing.T) {
	srv := newTLSServer(t, meHandler)
	c, err := client.NewRemote(srv.remote("smt_secret-token-value"), client.Options{})
	if err != nil {
		t.Fatal(err)
	}

	me, err := c.Me(context.Background())

	if err != nil || me.DisplayName != "alex" {
		t.Fatalf("Me = %+v, %v", me, err)
	}
	if got := srv.requests()[0].Header.Get("Authorization"); got != "Bearer smt_secret-token-value" {
		t.Errorf("Authorization = %q", got)
	}
	if !c.Remote() || c.Server() != srv.URL {
		t.Errorf("Remote = %v, Server = %q", c.Remote(), c.Server())
	}
}

func TestRemoteRefusesACertificateNoRootVouchesFor(t *testing.T) {
	srv := newTLSServer(t, meHandler)
	c, err := client.NewRemote(client.Remote{URL: srv.URL, Token: "t"}, client.Options{}) // no ca_file
	if err != nil {
		t.Fatal(err)
	}

	if _, err := c.Me(context.Background()); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("err = %v, want a certificate verification failure", err)
	}
	if n := len(srv.requests()); n != 0 {
		t.Errorf("the server saw %d requests over an untrusted connection", n)
	}
}

func TestRemoteIsHTTPSOnlyAndAnOriginOnly(t *testing.T) {
	for _, raw := range []string{
		"http://mgmt.example.com", "mgmt.example.com", "https://", "https://user:pw@mgmt.example.com",
		"https://mgmt.example.com/api", "https://mgmt.example.com?x=1", "https://mgmt.example.com#top", "ftp://mgmt.example.com",
	} {
		if _, err := client.NewRemote(client.Remote{URL: raw}, client.Options{}); smerr.CodeOf(err) != smerr.CodeInvalidArgument {
			t.Errorf("%q: err = %v, want INVALID_ARGUMENT", raw, err)
		}
	}
	if origin, err := client.ValidateServerURL(" https://mgmt.example.com:8443/ "); err != nil || origin != "https://mgmt.example.com:8443" {
		t.Errorf("origin = %q, %v", origin, err)
	}
}

func TestRemoteRejectsABadCAFile(t *testing.T) {
	dir := t.TempDir()
	garbage := filepath.Join(dir, "garbage.pem")
	if err := os.WriteFile(garbage, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, ca := range map[string]string{"relative": "ca.pem", "missing": filepath.Join(dir, "absent.pem"), "garbage": garbage} {
		if _, err := client.NewRemote(client.Remote{URL: "https://mgmt.example.com", CAFile: ca}, client.Options{}); smerr.CodeOf(err) != smerr.CodeInvalidArgument {
			t.Errorf("%s: err = %v, want INVALID_ARGUMENT", name, err)
		}
	}
}

func TestRemoteNeverFollowsARedirectWithTheBearer(t *testing.T) {
	var elsewhere sync.Mutex
	var leaked []string
	other := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		elsewhere.Lock()
		defer elsewhere.Unlock()
		leaked = append(leaked, r.Header.Get("Authorization"))
	}))
	defer other.Close()
	srv := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/api/v1/me", http.StatusFound)
	})
	c, err := client.NewRemote(srv.remote("smt_token"), client.Options{})
	if err != nil {
		t.Fatal(err)
	}

	_, err = c.Me(context.Background())

	if err == nil || !strings.Contains(err.Error(), "redirected") {
		t.Fatalf("err = %v, want a redirect refusal", err)
	}
	elsewhere.Lock()
	defer elsewhere.Unlock()
	if len(leaked) != 0 {
		t.Errorf("the redirect target was contacted: %q", leaked)
	}
}

func TestRemoteAnUnauthorizedAnswerPointsAtLogin(t *testing.T) {
	srv := newTLSServer(t, func(w http.ResponseWriter, _ *http.Request) {
		writeFailure(w, http.StatusUnauthorized, smerr.CodeUnauthenticated, "token revoked")
	})
	c, _ := client.NewRemote(srv.remote("smt_x"), client.Options{})

	_, err := c.Me(context.Background())

	if smerr.CodeOf(err) != smerr.CodeUnauthenticated || !strings.Contains(err.Error(), "sm login") || client.CorrelationID(err) != "corr-1" {
		t.Errorf("err = %v (correlation %q)", err, client.CorrelationID(err))
	}
}

func TestRateLimitedRequestWaitsRetryAfterAndRepeatsTheSameKey(t *testing.T) {
	var calls int
	srv := newTLSServer(t, func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Retry-After", "3")
			writeFailure(w, http.StatusTooManyRequests, smerr.CodeTimeout, "rate limit exceeded")
			return
		}
		writeEnvelope(w, http.StatusOK, wire.Submission{Job: wire.Job{ID: "job-1"}})
	})
	var slept []time.Duration
	c, _ := client.NewRemote(srv.remote("smt_x"), client.Options{Sleep: func(_ context.Context, d time.Duration) error {
		slept = append(slept, d)
		return nil
	}})

	sub, err := c.CreateBackup(context.Background())

	if err != nil || sub.Job.ID != "job-1" {
		t.Fatalf("sub = %+v, err = %v", sub, err)
	}
	if len(slept) != 1 || slept[0] != 3*time.Second {
		t.Errorf("slept %v, want [3s]", slept)
	}
	seen := srv.requests()
	key := seen[0].Header.Get(wire.HeaderIdempotencyKey)
	if len(seen) != 2 || key == "" || seen[1].Header.Get(wire.HeaderIdempotencyKey) != key {
		t.Errorf("the retry must repeat the Idempotency-Key %q: %+v", key, seen)
	}
}

func TestRateLimitedForTooLongIsReportedNotSlept(t *testing.T) {
	srv := newTLSServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "120")
		writeFailure(w, http.StatusTooManyRequests, smerr.CodeTimeout, "rate limit exceeded")
	})
	c, _ := client.NewRemote(srv.remote("smt_x"), client.Options{Sleep: func(context.Context, time.Duration) error {
		t.Error("slept through a two minute Retry-After")
		return nil
	}})

	_, err := c.Me(context.Background())

	var typed *smerr.Error
	if !asTyped(err, &typed) || typed.Details[client.DetailRetryAfterSeconds] != 120 {
		t.Fatalf("err = %v, want the 120s retry hint in Details", err)
	}
	if !strings.Contains(err.Error(), "2m0s") {
		t.Errorf("message %q does not say how long to wait", err)
	}
}

func TestCredentialRoutesCarryNoIdempotencyKey(t *testing.T) {
	srv := newTLSServer(t, func(w http.ResponseWriter, _ *http.Request) { writeEnvelope(w, http.StatusOK, struct{}{}) })
	c, _ := client.NewRemote(srv.remote("smt_x"), client.Options{})
	ctx := context.Background()

	_, _ = c.CreateToken(ctx, wire.CreateTokenRequest{Name: "ci"})
	_, _ = c.Bootstrap(ctx, wire.BootstrapRequest{Code: "smb_code"})
	_, _ = c.OIDCExchange(ctx, wire.OIDCExchangeRequest{})
	_, _ = c.DevicePoll(ctx, wire.DevicePollRequest{})
	_, _ = c.ExportMasterKey(ctx, wire.ExportKeyRequest{})
	_ = c.RevokeToken(ctx, "0192a000-0000-7000-8000-00000000a001")
	_ = c.Logout(ctx)
	_, _ = c.ImportSecret(ctx, wire.ImportSecretRequest{Name: "n", Value: "v"})

	unkeyed, keyed := 0, 0
	for _, r := range srv.requests() {
		if r.Header.Get(wire.HeaderIdempotencyKey) == "" {
			unkeyed++
		} else {
			keyed++
		}
	}
	if unkeyed != 7 || keyed != 1 {
		t.Errorf("%d requests without a key and %d with one; want 7 and 1 (only the secret import is keyed): %+v", unkeyed, keyed, srv.requests())
	}
}

func TestRemoteAccountCallsUseTheDocumentedRoutes(t *testing.T) {
	srv := newTLSServer(t, func(w http.ResponseWriter, _ *http.Request) { writeEnvelope(w, http.StatusOK, struct{}{}) })
	c, _ := client.NewRemote(srv.remote("smt_x"), client.Options{})
	ctx := context.Background()
	id := "0192a000-0000-7000-8000-00000000a001"

	_, _ = c.ListTokens(ctx)
	_ = c.RevokeToken(ctx, "0192a000-0000-7000-8000-00000000a001")
	_, _ = c.RotateMasterKey(ctx)
	_, _ = c.RetireMasterKey(ctx, wire.RetireKeyRequest{KEKID: "0192a000-0000-7000-8000-00000000a001"})
	_, _ = c.RotateSSHKey(ctx)
	_, _ = c.ListBackups(ctx)
	_, _ = c.DeviceStart(ctx)
	_, _ = c.OIDCStart(ctx, wire.OIDCStartRequest{})

	var got []string
	for _, r := range srv.requests() {
		got = append(got, r.Method+" "+r.Path)
	}
	want := []string{
		"GET " + wire.PathTokens, "DELETE " + wire.Path(wire.PathToken, id), "POST " + wire.PathMasterKeyRotate,
		"POST " + wire.PathMasterKeyRetire, "POST " + wire.PathSSHKeyRotate, "GET " + wire.PathBackups,
		"POST " + wire.PathOIDCDevice, "POST " + wire.PathOIDCStart,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("routes:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
