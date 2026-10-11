package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func streamRoute(frames ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", wire.ContentTypeEventStream)
		_, _ = fmt.Fprint(w, ": stream open\n\n")
		for _, f := range frames {
			_, _ = fmt.Fprint(w, f)
		}
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}
}

func eventFrame(seq int64, action string) string {
	data, _ := json.Marshal(wire.Event{Seq: seq, Action: action, Timestamp: time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC), Severity: domain.SeverityInfo, Result: domain.ResultSucceeded, CorrelationID: "c-1"})
	return fmt.Sprintf("id: %d\nevent: event\ndata: %s\n\n", seq, data)
}

// followUntil runs sm with args until out has seen want or the stream ends.
func followUntil(t *testing.T, b *remoteBox, want string, args ...string) (*lockedBuffer, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	root := testRoot(b.env)
	out := &lockedBuffer{}
	root.SetIn(strings.NewReader(""))
	root.SetOut(out)
	root.SetErr(&lockedBuffer{})
	root.SetArgs(args)
	errc := make(chan error, 1)
	go func() { errc <- root.ExecuteContext(ctx) }()
	for {
		select {
		case err := <-errc:
			return out, err
		case <-time.After(5 * time.Millisecond):
			if strings.Contains(out.String(), want) {
				cancel()
				return out, <-errc
			}
		}
	}
}

func TestEventsFollowStreamsOverHTTPSWithTheBearer(t *testing.T) {
	b := newRemoteBox(t, routes{
		"GET " + wire.PathEventStream: func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer "+tokenOne {
				replyError(w, 401, smerr.CodeUnauthenticated, "", "no")
				return
			}
			streamRoute(eventFrame(5, "node.probe"), eventFrame(6, "service.restart"))(w, r)
		},
	})
	b.useProfile()
	b.signIn(tokenOne)

	out, _ := followUntil(t, b, "service.restart", "events", "--follow")

	for _, want := range []string{"5  2026-10-10T12:00:00Z  info  node.probe", "6  2026-10-10T12:00:00Z  info  service.restart"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
}

func TestEventsFollowJSONPrintsOneEventPerLine(t *testing.T) {
	b := newRemoteBox(t, routes{"GET " + wire.PathEventStream: streamRoute(eventFrame(7, "node.probe"))})
	b.useProfile()
	b.signIn(tokenOne)

	out, _ := followUntil(t, b, "node.probe", "--json", "events", "--follow")

	var e wire.Event
	if err := json.Unmarshal([]byte(strings.SplitN(out.String(), "\n", 2)[0]), &e); err != nil || e.Seq != 7 {
		t.Errorf("output %q: %v", out.String(), err)
	}
}

func TestEventsFollowResumesAfterTheGivenSequence(t *testing.T) {
	b := newRemoteBox(t, routes{"GET " + wire.PathEventStream: streamRoute(eventFrame(43, "node.probe"))})
	b.useProfile()
	b.signIn(tokenOne)

	_, _ = followUntil(t, b, "node.probe", "events", "--follow", "--after-seq", "42")

	if got := b.requestsTo("GET", wire.PathEventStream)[0].Header.Get(wire.HeaderLastEventID); got != "42" {
		t.Errorf("Last-Event-ID = %q, want 42", got)
	}
}

func TestEventsFollowEndsWhenTheCredentialLosesAccess(t *testing.T) {
	b := newRemoteBox(t, routes{"GET " + wire.PathEventStream: func(w http.ResponseWriter, _ *http.Request) {
		replyError(w, 401, smerr.CodeUnauthenticated, "", "token revoked")
	}})
	b.useProfile()
	b.signIn(tokenOne)

	r := b.run("", "events", "--follow")

	if r.code != exitInternal || !strings.Contains(r.stderr, "sm login") {
		t.Errorf("exit %d, stderr %q", r.code, r.stderr)
	}
}

func TestTUIOptionsFollowARemoteServerAndHoldPresenceOnALocalOne(t *testing.T) {
	b := newRemoteBox(t, routes{"GET " + wire.PathEventStream: streamRoute(eventFrame(9, "node.probe"))})
	b.useProfile()
	b.signIn(tokenOne)
	remote, err := client.NewRemote(client.Remote{URL: b.srv.URL, CAFile: b.caFile, Token: tokenOne}, client.Options{})
	if err != nil {
		t.Fatal(err)
	}

	opts := tuiOptions(remote, target{name: "home"})

	if opts.Follow == nil || opts.Presence != nil || opts.Settings.Server != b.srv.URL || opts.Settings.Profile != "home" {
		t.Fatalf("remote options = %+v", opts)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got := make(chan wire.Event, 1)
	go func() {
		_ = opts.Follow(ctx, func(e wire.Event) error { got <- e; cancel(); return nil })
	}()
	select {
	case e := <-got:
		if e.Seq != 9 {
			t.Errorf("event = %+v", e)
		}
	case <-ctx.Done():
		t.Fatal("the TUI's stream delivered nothing")
	}

	local := tuiOptions(client.New(client.Options{Socket: "/nonexistent.sock"}), target{})
	if local.Presence == nil || local.Follow != nil || local.Settings.Server != "" {
		t.Errorf("local options = %+v; the local daemon is kept resident by presence and unchanged", local)
	}
}
