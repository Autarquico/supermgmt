package api

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/database"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func (r *remote) openStream(token string, headers ...string) (*http.Response, *frames) {
	r.t.Helper()
	resp := r.open(http.MethodGet, wire.PathEventStream, token, "", headers...)
	if resp.StatusCode != http.StatusOK {
		r.t.Fatalf("open stream: status %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != wire.ContentTypeEventStream {
		r.t.Fatalf("Content-Type = %q", got)
	}
	f := readFrames(resp)
	if first, ok := f.next(); !ok || first[0] != ": stream open" {
		r.t.Fatalf("first frame = %v, %v", first, ok)
	}
	r.t.Cleanup(func() { _ = resp.Body.Close() })
	return resp, f
}

func (r *remote) revoke(by string, token wire.TokenIssued) {
	r.t.Helper()
	resp := r.request(http.MethodDelete, strings.Replace(wire.PathToken, "{id}", token.Token.ID.String(), 1), by, "")
	if resp.Status != http.StatusOK {
		r.t.Fatalf("revoke: %d %s", resp.Status, resp.Body)
	}
}

func TestTheStreamDeliversNewEventsWithTheirSequenceAsID(t *testing.T) {
	r := newRemote(t)
	_, watcher := r.admin()
	_, actor := r.admin()
	_, frames := r.openStream(watcher.Value)

	r.request(http.MethodPost, wire.PathTokens, actor.Value, `{"name":"x","expires_at":"`+r.expiry()+`"}`)

	frame, ok := frames.next()
	if !ok || len(frame) != 3 || !strings.HasPrefix(frame[0], "id: ") || frame[1] != "event: event" || !strings.Contains(frame[2], `"action":"token.created"`) {
		t.Fatalf("frame = %v, %v", frame, ok)
	}
}

func TestTheStreamResumesAfterLastEventID(t *testing.T) {
	r := newRemote(t)
	_, watcher := r.admin()
	_, frames := r.openStream(watcher.Value, wire.HeaderLastEventID, "0")

	frame, ok := frames.next()

	if !ok || frame[0] != "id: 1" {
		t.Errorf("the first frame after Last-Event-ID 0 is %v, want the first event of the log", frame)
	}
	bad := r.request(http.MethodGet, wire.PathEventStream, watcher.Value, "", wire.HeaderLastEventID, "soon")
	if bad.Status != http.StatusBadRequest {
		t.Errorf("a malformed Last-Event-ID: status %d", bad.Status)
	}
}

func TestTheStreamEndsAfterTheTokenIsRevoked(t *testing.T) {
	r := newRemote(t)
	_, watcher := r.admin()
	_, other := r.admin()
	_, frames := r.openStream(watcher.Value)

	r.revoke(other.Value, watcher)

	all := frames.untilEnd(t, 5*time.Second)
	if got := closedReason(t, all); got != string(smerr.ReasonCredentialRevoked)+"/"+string(smerr.CodeUnauthenticated) {
		t.Errorf("closing frame = %s", got)
	}
}

func TestTheStreamEndsAfterTheRoleIsRemoved(t *testing.T) {
	r := newRemote(t)
	identity, watcher := r.admin()
	_, frames := r.openStream(watcher.Value)

	must(t, r.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM role_bindings WHERE identity_id = ?`, identity)
		return err
	}))

	all := frames.untilEnd(t, 5*time.Second)
	if got := closedReason(t, all); !strings.HasSuffix(got, "/"+string(smerr.CodePolicyDenied)) {
		t.Errorf("closing frame = %s, want POLICY_DENIED", got)
	}
}

func TestARoleChangeEventRevalidatesAtOnceNotAtTheNextTick(t *testing.T) {
	r := newRemote(t, func(o *remoteOptions) {
		o.stream = StreamOptions{Poll: 10 * time.Millisecond, Revalidate: time.Hour, Heartbeat: time.Hour}
	})
	identity, watcher := r.admin()
	_, frames := r.openStream(watcher.Value)

	must(t, r.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM role_bindings WHERE identity_id = ?`, identity); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO events (event_id, timestamp, actor_type, actor_id, source, action, resource_type, severity, result)
			VALUES (?, 1, 'system', ?, 'test', 'role_binding.deleted', 'identity', 'info', 'succeeded')`, r.ids.NewID(), r.ids.NewID())
		return err
	}))

	if got := closedReason(t, frames.untilEnd(t, 5*time.Second)); !strings.HasSuffix(got, "/"+string(smerr.CodePolicyDenied)) {
		t.Errorf("closing frame = %s", got)
	}
}

func TestAnIdentityHasAtMostTheConfiguredNumberOfStreams(t *testing.T) {
	r := newRemote(t, func(o *remoteOptions) {
		o.stream = StreamOptions{Poll: time.Hour, Revalidate: time.Hour, Heartbeat: time.Hour, MaxPerIdentity: 2}
	})
	_, watcher := r.admin()
	_, other := r.admin()
	r.openStream(watcher.Value)
	first, _ := r.openStream(watcher.Value)

	third := r.request(http.MethodGet, wire.PathEventStream, watcher.Value, "")
	elsewhere, _ := r.openStream(other.Value)

	if third.Status != http.StatusTooManyRequests {
		t.Errorf("the third stream: status %d body %s", third.Status, third.Body)
	}
	_ = elsewhere
	_ = first.Body.Close()
	waitFor(t, func() bool {
		resp := r.open(http.MethodGet, wire.PathEventStream, watcher.Value, "")
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode == http.StatusOK
	})
}

func TestShutdownEndsOpenEventStreams(t *testing.T) {
	r := newRemote(t)
	_, watcher := r.admin()
	_, frames := r.openStream(watcher.Value)

	done := make(chan struct{})
	go func() {
		frames.untilEnd(t, 5*time.Second)
		close(done)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	must(t, r.server.Shutdown(ctx))

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the stream survived the shutdown")
	}
}
