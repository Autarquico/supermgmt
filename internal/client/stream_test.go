package client_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/client"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// connection scripts one stream connection: the frames to send and whether to
// keep the connection open afterwards.
type connection struct {
	frames []string
	hold   bool
}

func eventFrame(seq int64) string {
	data, _ := json.Marshal(wire.Event{Seq: seq, Action: "node.probe"})
	return fmt.Sprintf("id: %d\nevent: event\ndata: %s\n\n", seq, data)
}

func closedFrame(code smerr.Code) string {
	data, _ := json.Marshal(wire.ErrorEnvelope{Error: wire.Error{Code: code, Message: "stream ended", CorrelationID: "c-9"}})
	return fmt.Sprintf("event: closed\ndata: %s\n\n", data)
}

// streamServer plays the connections in order and records each request's
// Last-Event-ID; a request past the script gets 503.
func streamServer(t *testing.T, script []connection) (*tlsServer, *[]string) {
	t.Helper()
	var mu sync.Mutex
	var resumes []string
	next := 0
	srv := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		resumes = append(resumes, r.Header.Get(wire.HeaderLastEventID))
		i := next
		next++
		mu.Unlock()
		if i >= len(script) {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", wire.ContentTypeEventStream)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(": stream open\n\n"))
		for _, f := range script[i].frames {
			_, _ = w.Write([]byte(f))
		}
		w.(http.Flusher).Flush()
		if script[i].hold {
			<-r.Context().Done()
		}
	})
	return srv, &resumes
}

func noWait(context.Context, time.Duration) error { return nil }

func follow(t *testing.T, srv *tlsServer, opts client.Options, q wire.EventQuery, handle func(wire.Event) error) error {
	t.Helper()
	opts.Sleep = noWait
	c, err := client.NewRemote(srv.remote("smt_x"), opts)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return c.FollowEvents(ctx, q, handle)
}

func TestFollowReconnectsWithLastEventIDAndLosesNothing(t *testing.T) {
	srv, resumes := streamServer(t, []connection{
		{frames: []string{eventFrame(1), eventFrame(2)}},                          // drops after two events
		{frames: []string{eventFrame(3)}},                                         // drops again
		{frames: []string{eventFrame(4), closedFrame(smerr.CodeUnauthenticated)}}, // access lost
	})
	var seqs []int64

	err := follow(t, srv, client.Options{}, wire.EventQuery{}, func(e wire.Event) error {
		seqs = append(seqs, e.Seq)
		return nil
	})

	if smerr.CodeOf(err) != smerr.CodeUnauthenticated {
		t.Fatalf("err = %v, want the UNAUTHENTICATED of the closed frame", err)
	}
	if fmt.Sprint(seqs) != "[1 2 3 4]" {
		t.Errorf("events = %v, want each exactly once, in order", seqs)
	}
	if fmt.Sprint(*resumes) != "[ 2 3]" {
		t.Errorf("Last-Event-ID per connection = %q, want none, then 2, then 3", *resumes)
	}
}

func TestFollowResumesAfterTheRequestedSequence(t *testing.T) {
	srv, resumes := streamServer(t, []connection{{frames: []string{closedFrame(smerr.CodePolicyDenied)}}})

	err := follow(t, srv, client.Options{}, wire.EventQuery{AfterSeq: 41}, func(wire.Event) error { return nil })

	if smerr.CodeOf(err) != smerr.CodePolicyDenied {
		t.Fatalf("err = %v", err)
	}
	if (*resumes)[0] != "41" {
		t.Errorf("Last-Event-ID = %q, want 41", (*resumes)[0])
	}
	if q := srv.requests()[0].Query; q != "" {
		t.Errorf("query %q: after_seq must travel as Last-Event-ID only", q)
	}
}

func TestFollowRetriesAClosedFrameThatIsNotAnAccessFailure(t *testing.T) {
	srv, _ := streamServer(t, []connection{
		{frames: []string{eventFrame(1), closedFrame(smerr.CodeInternal)}},
		{frames: []string{eventFrame(2)}, hold: true},
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, _ := client.NewRemote(srv.remote("smt_x"), client.Options{Sleep: noWait})
	var seqs []int64

	err := c.FollowEvents(ctx, wire.EventQuery{}, func(e wire.Event) error {
		seqs = append(seqs, e.Seq)
		if e.Seq == 2 {
			cancel()
		}
		return nil
	})

	if !errors.Is(err, context.Canceled) || fmt.Sprint(seqs) != "[1 2]" {
		t.Errorf("err = %v, events = %v; want the stream to carry on past an INTERNAL close", err, seqs)
	}
}

func TestFollowStopsOnRefusedAuthentication(t *testing.T) {
	srv := newTLSServer(t, func(w http.ResponseWriter, _ *http.Request) {
		writeFailure(w, http.StatusUnauthorized, smerr.CodeUnauthenticated, "token revoked")
	})

	err := follow(t, srv, client.Options{}, wire.EventQuery{}, func(wire.Event) error { return nil })

	if smerr.CodeOf(err) != smerr.CodeUnauthenticated || len(srv.requests()) != 1 {
		t.Errorf("err = %v after %d requests, want one attempt", err, len(srv.requests()))
	}
}

func TestFollowRetriesAServerThatIsDown(t *testing.T) {
	var calls int
	srv := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", wire.ContentTypeEventStream)
		_, _ = w.Write([]byte(eventFrame(7)))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, _ := client.NewRemote(srv.remote("smt_x"), client.Options{Sleep: noWait})

	err := c.FollowEvents(ctx, wire.EventQuery{}, func(e wire.Event) error {
		cancel()
		return nil
	})

	if !errors.Is(err, context.Canceled) || calls != 3 {
		t.Errorf("err = %v after %d connections; want the third to deliver", err, calls)
	}
}

func TestFollowHonorsRetryAfterOfARateLimitedConnect(t *testing.T) {
	var calls int
	srv := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Retry-After", "7")
			writeFailure(w, http.StatusTooManyRequests, smerr.CodeTimeout, "rate limit exceeded")
			return
		}
		_, _ = w.Write([]byte(eventFrame(1)))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	var waits []time.Duration
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, _ := client.NewRemote(srv.remote("smt_x"), client.Options{Sleep: func(_ context.Context, d time.Duration) error {
		waits = append(waits, d)
		return nil
	}})

	_ = c.FollowEvents(ctx, wire.EventQuery{}, func(wire.Event) error { cancel(); return nil })

	if len(waits) == 0 || waits[0] != 7*time.Second {
		t.Errorf("waits = %v, want the first to be the server's 7s", waits)
	}
}

func TestFollowEndsWithTheHandlersError(t *testing.T) {
	srv, _ := streamServer(t, []connection{{frames: []string{eventFrame(1), eventFrame(2)}, hold: true}})
	stop := errors.New("enough")
	var seen int

	err := follow(t, srv, client.Options{}, wire.EventQuery{}, func(wire.Event) error { seen++; return stop })

	if !errors.Is(err, stop) || seen != 1 {
		t.Errorf("err = %v after %d events", err, seen)
	}
}

func TestFollowDropsASilentConnectionAndReconnects(t *testing.T) {
	srv, resumes := streamServer(t, []connection{
		{frames: []string{eventFrame(5)}, hold: true}, // then silence: no heartbeat
		{frames: []string{eventFrame(6)}, hold: true},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, _ := client.NewRemote(srv.remote("smt_x"), client.Options{Sleep: noWait, StreamIdle: 100 * time.Millisecond})
	var seqs []int64

	_ = c.FollowEvents(ctx, wire.EventQuery{}, func(e wire.Event) error {
		seqs = append(seqs, e.Seq)
		if e.Seq == 6 {
			cancel()
		}
		return nil
	})

	if fmt.Sprint(seqs) != "[5 6]" || (*resumes)[1] != strconv.Itoa(5) {
		t.Errorf("events = %v, resumes = %q; want a reconnect after seq 5", seqs, *resumes)
	}
}
