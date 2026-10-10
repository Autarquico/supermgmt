package client_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func TestReadsCarryNoIdempotencyKeyAndDecodeTheEnvelope(t *testing.T) {
	d := startFakeDaemon(t, func(w http.ResponseWriter, _ *http.Request) {
		respond(w, 200, wire.Page[wire.Node]{Items: []wire.Node{{Name: "web-1"}}, NextCursor: "c2"})
	})
	page, err := d.client(client.Options{}).ListNodes(context.Background(), wire.NodeQuery{
		PageQuery: wire.PageQuery{Limit: 10}, Environment: "production",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].Name != "web-1" || page.NextCursor != "c2" {
		t.Fatalf("page = %+v", page)
	}
	got := d.Requests()[0]
	if got.Method != "GET" || got.Path != "/api/v1/nodes" || got.Query != "environment=production&limit=10" {
		t.Errorf("request = %s %s?%s", got.Method, got.Path, got.Query)
	}
	if key := got.Header.Get(wire.HeaderIdempotencyKey); key != "" {
		t.Errorf("a read sent Idempotency-Key %q", key)
	}
}

func TestMutationsCarryAFreshUUIDv7KeyPerOperation(t *testing.T) {
	d := startFakeDaemon(t, func(w http.ResponseWriter, _ *http.Request) { respond(w, 202, wire.Submission{}) })
	c := d.client(client.Options{})
	id := domain.UUIDv7Generator{}.NewID()
	for range 2 {
		if _, err := c.ServiceAction(context.Background(), id, domain.VerbRestart); err != nil {
			t.Fatal(err)
		}
	}
	reqs := d.Requests()
	keys := []string{reqs[0].Header.Get(wire.HeaderIdempotencyKey), reqs[1].Header.Get(wire.HeaderIdempotencyKey)}
	for _, k := range keys {
		if _, err := domain.ParseID(k); err != nil {
			t.Errorf("key %q is not a UUIDv7: %v", k, err)
		}
	}
	if keys[0] == keys[1] {
		t.Errorf("two operations shared key %q", keys[0])
	}
	if want := "/api/v1/services/" + string(id) + "/actions/restart"; reqs[0].Path != want {
		t.Errorf("path = %s, want %s", reqs[0].Path, want)
	}
}

func TestEveryMutationVerbHasItsLiteralRouteAndOthersAreRefusedLocally(t *testing.T) {
	d := startFakeDaemon(t, func(w http.ResponseWriter, _ *http.Request) { respond(w, 202, wire.Submission{}) })
	c := d.client(client.Options{})
	id := domain.UUIDv7Generator{}.NewID()
	for _, verb := range domain.AllServiceVerbs() {
		if _, err := c.ServiceAction(context.Background(), id, verb); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.ServiceAction(context.Background(), id, "delete"); smerr.CodeOf(err) != smerr.CodeInvalidArgument {
		t.Errorf("unknown verb: got %v, want INVALID_ARGUMENT", err)
	}
	if n := len(d.Requests()); n != 3 {
		t.Errorf("daemon saw %d requests, want 3 (the unknown verb must not be sent)", n)
	}
}

func TestPatchAndDeleteSendIfMatchAndAKey(t *testing.T) {
	d := startFakeDaemon(t, func(w http.ResponseWriter, _ *http.Request) { respond(w, 200, wire.Direct[wire.Node]{}) })
	c := d.client(client.Options{})
	id := domain.UUIDv7Generator{}.NewID()
	name := "renamed"
	if _, err := c.UpdateNode(context.Background(), id, 7, wire.NodePatch{Name: &name}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RemoveNode(context.Background(), id, 8); err != nil {
		t.Fatal(err)
	}
	reqs := d.Requests()
	for i, want := range []struct{ method, ifMatch string }{{"PATCH", "7"}, {"DELETE", "8"}} {
		if reqs[i].Method != want.method || reqs[i].Header.Get(wire.HeaderIfMatch) != want.ifMatch {
			t.Errorf("request %d = %s If-Match %q", i, reqs[i].Method, reqs[i].Header.Get(wire.HeaderIfMatch))
		}
		if reqs[i].Header.Get(wire.HeaderIdempotencyKey) == "" {
			t.Errorf("request %d has no Idempotency-Key", i)
		}
	}
	if string(reqs[0].Body) != `{"name":"renamed"}` {
		t.Errorf("patch body = %s", reqs[0].Body)
	}
}

func TestHostKeyScanIsReadOnlyAndSendsNoKey(t *testing.T) {
	d := startFakeDaemon(t, func(w http.ResponseWriter, _ *http.Request) { respond(w, 200, wire.HostKey{Type: "ssh-ed25519"}) })
	if _, err := d.client(client.Options{}).ScanHostKey(context.Background(), wire.ScanHostKeyRequest{Host: "h", Port: 22}); err != nil {
		t.Fatal(err)
	}
	if key := d.Requests()[0].Header.Get(wire.HeaderIdempotencyKey); key != "" {
		t.Errorf("host-key scan sent Idempotency-Key %q", key)
	}
}

func TestRetryAfterAConnectionDropReusesTheKeyAndTheBytes(t *testing.T) {
	var calls atomic.Int32
	d := startFakeDaemon(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close() // the daemon dies after reading the request
			}
			return
		}
		respond(w, 202, wire.Submission{Job: wire.Job{Type: "service.restart"}})
	})
	id := domain.UUIDv7Generator{}.NewID()
	got, err := d.client(client.Options{}).ServiceAction(context.Background(), id, domain.VerbRestart)
	if err != nil {
		t.Fatal(err)
	}
	if got.Job.Type != "service.restart" {
		t.Errorf("job = %+v", got.Job)
	}
	reqs := d.Requests()
	if len(reqs) != 2 {
		t.Fatalf("daemon saw %d requests, want 2", len(reqs))
	}
	first, second := reqs[0].Header.Get(wire.HeaderIdempotencyKey), reqs[1].Header.Get(wire.HeaderIdempotencyKey)
	if first == "" || first != second || string(reqs[0].Body) != string(reqs[1].Body) {
		t.Errorf("retry changed identity: keys %q/%q, bodies %q/%q", first, second, reqs[0].Body, reqs[1].Body)
	}
}

func TestRetryIsBoundedToOneExtraAttempt(t *testing.T) {
	d := startFakeDaemon(t, func(w http.ResponseWriter, _ *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = conn.Close()
		}
	})
	id := domain.UUIDv7Generator{}.NewID()
	if _, err := d.client(client.Options{}).CancelJob(context.Background(), id, "hash"); err == nil {
		t.Fatal("expected an error")
	}
	if n := len(d.Requests()); n != 2 {
		t.Errorf("daemon saw %d requests, want 2", n)
	}
}

func TestErrorEnvelopeBecomesATypedErrorWithReasonAndCorrelationID(t *testing.T) {
	d := startFakeDaemon(t, func(w http.ResponseWriter, _ *http.Request) {
		respondError(w, 409, smerr.CodeConflict, smerr.ReasonIdempotencyMismatch, "key reused")
	})
	_, err := d.client(client.Options{}).CancelJob(context.Background(), domain.UUIDv7Generator{}.NewID(), "h")
	if !errors.Is(err, smerr.New(smerr.CodeConflict, smerr.ReasonIdempotencyMismatch, "")) {
		t.Fatalf("got %v, want CONFLICT/IDEMPOTENCY_MISMATCH", err)
	}
	if got := client.CorrelationID(err); got != "corr-err" {
		t.Errorf("correlation id = %q", got)
	}
}

func TestUnreadableErrorBodyIsAnInternalErrorNotAPanic(t *testing.T) {
	d := startFakeDaemon(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(502)
		_, _ = w.Write([]byte("<html>bad gateway</html>"))
	})
	_, err := d.client(client.Options{}).Me(context.Background())
	if smerr.CodeOf(err) != smerr.CodeInternal || !strings.Contains(err.Error(), "502") {
		t.Errorf("got %v", err)
	}
}

func TestRequestTimeoutBoundsAHungDaemon(t *testing.T) {
	release := make(chan struct{})
	d := startFakeDaemon(t, func(http.ResponseWriter, *http.Request) { <-release })
	t.Cleanup(func() { close(release) })
	_, err := d.client(client.Options{RequestTimeout: 100 * time.Millisecond}).Me(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want a deadline error", err)
	}
}

func TestPeerWithAnotherUIDIsNeverSentAnything(t *testing.T) {
	d := startFakeDaemon(t, func(w http.ResponseWriter, _ *http.Request) { respond(w, 200, wire.Me{}) })
	c := d.client(client.Options{})
	client.WithExpectedUID(c, uint32(os.Getuid())+1)
	_, err := c.Me(context.Background())
	var refused *client.PeerMismatchError
	if !errors.As(err, &refused) {
		t.Fatalf("got %v, want *PeerMismatchError", err)
	}
	if n := len(d.Requests()); n != 0 {
		t.Errorf("daemon saw %d requests, want 0", n)
	}
}

func TestPeerLookupFailureFailsClosed(t *testing.T) {
	d := startFakeDaemon(t, func(w http.ResponseWriter, _ *http.Request) { respond(w, 200, wire.Me{}) })
	c := d.client(client.Options{})
	client.WithPeerLookup(c, func(*net.UnixConn) (uint32, error) { return 0, errors.New("injected") })
	_, err := c.Me(context.Background())
	var refused *client.PeerMismatchError
	if !errors.As(err, &refused) {
		t.Fatalf("got %v, want *PeerMismatchError", err)
	}
	if n := len(d.Requests()); n != 0 {
		t.Errorf("daemon saw %d requests, want 0", n)
	}
}

func TestMissingDaemonWithoutAutostartIsReportedNotSpawned(t *testing.T) {
	c := client.New(client.Options{Socket: filepath.Join(shortDir(t), "none")})
	_, err := c.Me(context.Background())
	var unavailable *client.DaemonUnavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("got %v, want *DaemonUnavailableError", err)
	}
}

func TestOverlongSocketPathIsAnExplicitErrorNotASilentTruncation(t *testing.T) {
	c := client.New(client.Options{Socket: "/" + strings.Repeat("a", 200)})
	_, err := c.Me(context.Background())
	if smerr.CodeOf(err) != smerr.CodeInvalidArgument || !strings.Contains(err.Error(), "daemon.socket") {
		t.Errorf("got %v", err)
	}
}

func TestAutostartSpawnsOneDaemonForConcurrentRequests(t *testing.T) {
	dir, err := os.MkdirTemp("", "sma")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "s")
	logPath := filepath.Join(dir, "state", "daemon.log")
	t.Setenv(fakeDaemonEnv, socket)
	t.Cleanup(func() {
		_ = os.WriteFile(filepath.Join(dir, stopMarker), nil, 0o600)
		time.Sleep(150 * time.Millisecond) // let the daemon notice before the dir goes
	})

	c := client.New(client.Options{Socket: socket, Autostart: &client.Autostart{
		Executable: os.Args[0], LogPath: logPath, Wait: 10 * time.Second,
	}})
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			me, err := c.Me(context.Background())
			if err != nil || me.DisplayName != "autostarted" {
				t.Errorf("Me = %+v, %v", me, err)
			}
		}()
	}
	wg.Wait()

	log, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(log), "fake-daemon-started"); n != 1 {
		t.Errorf("daemon started %d times, want 1; log:\n%s", n, log)
	}
	if info, err := os.Stat(logPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("daemon log mode = %v, %v; want 0600", info.Mode().Perm(), err)
	}
}

func TestAutostartGivesUpAfterTheWaitAndPointsAtTheLog(t *testing.T) {
	failing, err := exec.LookPath("false")
	if err != nil {
		t.Skip("no false(1) on PATH")
	}
	dir := shortDir(t)
	logPath := filepath.Join(dir, "daemon.log")
	c := client.New(client.Options{Socket: filepath.Join(dir, "none"), Autostart: &client.Autostart{
		Executable: failing, LogPath: logPath, Wait: 300 * time.Millisecond, Poll: 20 * time.Millisecond,
	}})
	_, err = c.Me(context.Background())
	var unavailable *client.DaemonUnavailableError
	if !errors.As(err, &unavailable) || !strings.Contains(err.Error(), logPath) {
		t.Fatalf("got %v, want *DaemonUnavailableError naming %s", err, logPath)
	}
}

func TestPresenceIsHeldAndReconnectsUntilCancelled(t *testing.T) {
	var connections atomic.Int32
	d := startFakeDaemon(t, func(w http.ResponseWriter, r *http.Request) {
		if connections.Add(1) == 1 {
			w.WriteHeader(200) // first stream ends at once, as if the daemon restarted
			return
		}
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.client(client.Options{PresenceRetry: 5 * time.Millisecond}).HoldPresence(ctx) }()

	for range 1000 {
		if connections.Load() >= 2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := connections.Load(); got < 2 {
		t.Fatalf("presence connected %d times, want a reconnect", got)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("HoldPresence returned %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("HoldPresence did not return after cancel")
	}
	for _, r := range d.Requests() {
		if r.Path != wire.PathPresence || r.Header.Get(wire.HeaderIdempotencyKey) != "" {
			t.Errorf("presence request = %s with key %q", r.Path, r.Header.Get(wire.HeaderIdempotencyKey))
		}
	}
}

func TestPresenceKeepsRetryingWhileTheDaemonIsDown(t *testing.T) {
	c := client.New(client.Options{Socket: filepath.Join(shortDir(t), "none"), PresenceRetry: 5 * time.Millisecond})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := c.HoldPresence(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("got %v, want the context error after retrying", err)
	}
}

func TestDecodedResponsesRoundTripEveryReadEndpoint(t *testing.T) {
	d := startFakeDaemon(t, func(w http.ResponseWriter, r *http.Request) {
		respond(w, 200, json.RawMessage(`{"items":[],"next_cursor":""}`))
		_ = r
	})
	c := d.client(client.Options{})
	ctx := context.Background()
	id := domain.UUIDv7Generator{}.NewID()
	if _, err := c.ListServices(ctx, id, wire.PageQuery{}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ListApprovals(ctx, wire.PageQuery{}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ListJobs(ctx, wire.JobQuery{States: []domain.JobState{domain.JobAwaitingApproval}}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ListEvents(ctx, wire.EventQuery{AfterSeq: 5}); err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, r := range d.Requests() {
		paths = append(paths, r.Path+"?"+r.Query)
	}
	want := []string{
		"/api/v1/nodes/" + string(id) + "/services?",
		"/api/v1/approvals?",
		"/api/v1/jobs?state=awaiting_approval",
		"/api/v1/events?after_seq=5",
	}
	if strings.Join(paths, "\n") != strings.Join(want, "\n") {
		t.Errorf("paths:\n%s\nwant:\n%s", strings.Join(paths, "\n"), strings.Join(want, "\n"))
	}
}
