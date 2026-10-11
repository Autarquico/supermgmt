package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func (rs *routeSet) stream() {
	rs.add(route{method: http.MethodGet, pattern: wire.PathEventStream, action: actionEventRead, longLived: true, do: rs.s.eventStream})
}

// eventStream is GET /events/stream (ADR-0017): the audit log as server-sent
// events, one frame per event with id: <seq>. It resumes after Last-Event-ID,
// else after ?after_seq, else from the end of the log. The credential and
// event.read are re-evaluated every Stream.Revalidate and whenever a
// revocation or a role change passes through; when either fails the stream
// ends, so a token revoked or a role removed cuts a stream that is open.
func (s *Server) eventStream(w http.ResponseWriter, r *http.Request) error {
	if s.db == nil {
		return unavailable("the event stream")
	}
	by := scopeOf(r.Context()).caller
	q, err := wire.ParseEventQuery(r.URL.Query())
	if err != nil {
		return err
	}
	if err := s.allowed(r.Context(), by); err != nil {
		return err
	}
	after, err := s.resumePoint(r, q)
	if err != nil {
		return err
	}
	release, err := s.openStream(by.ID)
	if err != nil {
		return err
	}
	defer release()

	f := &feed{s: s, w: w, rc: http.NewResponseController(w), by: by, query: q, after: after, correlation: correlationOf(r)}
	defer func() { _ = f.rc.SetWriteDeadline(time.Time{}) }()
	h := w.Header()
	h.Set("Content-Type", wire.ContentTypeEventStream)
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	if err := f.send(": stream open\n\n"); err != nil {
		return nil
	}
	f.run(r.Context())
	return nil
}

func (s *Server) allowed(ctx context.Context, by app.Caller) error {
	_, err := s.svc.Queries.RequireRead(ctx, by, actionEventRead, domain.ResourceRef{Type: domain.ResourceEvent})
	return err
}

// resumePoint is the sequence number after which the stream starts.
func (s *Server) resumePoint(r *http.Request, q wire.EventQuery) (int64, error) {
	if last := r.Header.Get(wire.HeaderLastEventID); last != "" {
		seq, err := strconv.ParseInt(last, 10, 64)
		if err != nil || seq < 0 {
			return 0, invalid("%s must be an event sequence number", wire.HeaderLastEventID)
		}
		return seq, nil
	}
	if r.URL.Query().Has(wire.QueryAfterSeq) {
		return q.AfterSeq, nil
	}
	return s.head(r.Context())
}

// head is the sequence number of the newest event, 0 for an empty log.
func (s *Server) head(ctx context.Context) (int64, error) {
	var seq int64
	err := s.db.Reader().QueryRowContext(ctx, `SELECT COALESCE(MAX(seq), 0) FROM events`).Scan(&seq)
	if err != nil {
		return 0, fmt.Errorf("read the end of the event log: %w", err)
	}
	return seq, nil
}

func (s *Server) openStream(id domain.ID) (release func(), err error) {
	s.openMu.Lock()
	defer s.openMu.Unlock()
	if s.open[id] >= s.stream.MaxPerIdentity {
		return nil, &rateLimited{after: time.Second}
	}
	s.open[id]++
	return func() {
		s.openMu.Lock()
		defer s.openMu.Unlock()
		if s.open[id]--; s.open[id] <= 0 {
			delete(s.open, id)
		}
	}, nil
}

// feed is one open event stream.
type feed struct {
	s           *Server
	w           http.ResponseWriter
	rc          *http.ResponseController
	by          app.Caller
	query       wire.EventQuery
	after       int64
	correlation domain.ID
}

func (f *feed) run(ctx context.Context) {
	opt := f.s.stream
	poll, beat, check := time.NewTicker(opt.Poll), time.NewTicker(opt.Heartbeat), time.NewTicker(opt.Revalidate)
	defer poll.Stop()
	defer beat.Stop()
	defer check.Stop()
	for {
		var err error
		select {
		case <-ctx.Done():
			return
		case <-f.s.closing:
			return
		case <-poll.C:
			err = f.deliver(ctx)
		case <-beat.C:
			err = f.send(": keepalive\n\n")
		case <-check.C:
			err = f.s.allowed(ctx, f.by)
		}
		if err != nil {
			f.end(ctx, err)
			return
		}
	}
}

// deliver sends the events after the last one sent, and revalidates at once
// when one of them changes who may read.
func (f *feed) deliver(ctx context.Context) error {
	head, err := f.s.head(ctx)
	if err != nil || head <= f.after {
		return err
	}
	for {
		q := f.query
		q.AfterSeq, q.Cursor, q.Limit = f.after, "", wire.MaxLimit
		page, err := f.s.svc.Queries.Events(ctx, f.by, q)
		if err != nil {
			return err
		}
		revalidate := false
		for _, e := range page.Items {
			if err := f.sendEvent(e); err != nil {
				return err
			}
			f.after = e.Seq
			revalidate = revalidate || changesAccess(e.Action)
		}
		if revalidate {
			if err := f.s.allowed(ctx, f.by); err != nil {
				return err
			}
		}
		if len(page.Items) < wire.MaxLimit {
			return nil
		}
	}
}

func changesAccess(action string) bool {
	return action == "token.revoked" || action == "session.revoked" || strings.HasPrefix(action, "role_binding.")
}

func (f *feed) sendEvent(e wire.Event) error {
	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("encode event: %w", err)
	}
	return f.send(fmt.Sprintf("id: %d\nevent: event\ndata: %s\n\n", e.Seq, data))
}

// end tells the client why the stream stopped, when it still can listen.
func (f *feed) end(ctx context.Context, cause error) {
	public := publicError(cause)
	body, err := json.Marshal(wire.ErrorEnvelope{Error: wire.Error{
		Code: public.Code, Message: public.Message, CorrelationID: f.correlation.String(),
		Details: map[string]any{wire.DetailReason: string(public.Reason)},
	}})
	if err != nil {
		return
	}
	_ = f.send(fmt.Sprintf("event: closed\ndata: %s\n\n", body))
	if public.Code == smerr.CodeInternal {
		f.s.log.WarnContext(ctx, "event stream ended", "error", cause)
	}
}

func (f *feed) send(frame string) error {
	_ = f.rc.SetWriteDeadline(time.Now().Add(f.s.stream.WriteTimeout)) //nolint:forbidigo // network deadlines are wall-clock
	if _, err := f.w.Write([]byte(frame)); err != nil {
		return err
	}
	return f.rc.Flush()
}
