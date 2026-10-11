package client

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const (
	defaultStreamRetry = 250 * time.Millisecond
	defaultStreamIdle  = 60 * time.Second
	maxStreamRetry     = 5 * time.Second
	maxFrameBytes      = 1 << 20

	sseEvent  = "event"
	sseClosed = "closed"
)

// FollowEvents streams audit events (GET /events/stream, ADR-0017) and calls
// handle for each, in order. It reconnects when the connection drops, resuming
// after the last event handled through Last-Event-ID, so no event is lost or
// repeated. It returns when ctx ends, when handle fails, or when the server
// ends the stream for a reason that retrying cannot fix: the credential was
// revoked or lost its permission (the `event: closed` frame), or the request
// itself is refused.
func (c *Client) FollowEvents(ctx context.Context, q wire.EventQuery, handle func(wire.Event) error) error {
	retry := cmpOr(c.opts.StreamRetry, defaultStreamRetry)
	delay := retry
	after := q.AfterSeq
	resumed := q.AfterSeq > 0
	for {
		progressed, err := c.followOnce(ctx, q, &after, &resumed, handle)
		if err != nil && ctx.Err() == nil {
			var terminal *terminalStreamError
			if errors.As(err, &terminal) {
				return terminal.err
			}
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if progressed {
			delay = retry
		}
		var wait time.Duration
		if limited, ok := rateLimitedWait(err); ok {
			wait = limited
		} else {
			wait = delay
			delay = min(delay*2, maxStreamRetry)
		}
		if err := c.sleep(ctx, wait); err != nil {
			return err
		}
	}
}

// terminalStreamError marks an end that must not be retried.
type terminalStreamError struct{ err error }

func (e *terminalStreamError) Error() string { return e.err.Error() }
func (e *terminalStreamError) Unwrap() error { return e.err }

// followOnce runs one connection. progressed says whether it delivered
// anything; the error is the reason it ended.
func (c *Client) followOnce(ctx context.Context, q wire.EventQuery, after *int64, resumed *bool, handle func(wire.Event) error) (bool, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	resp, err := c.openStream(ctx, q, *after, *resumed)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()
	silence := cmpOr(c.opts.StreamIdle, defaultStreamIdle)
	idle := time.AfterFunc(silence, cancel)
	defer idle.Stop()
	if resp.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
		return false, classifyStreamRefusal(response{
			status: resp.StatusCode, payload: payload, retryAfter: retryAfterOf(resp.Header),
		}, c)
	}
	progressed := false
	err = readFrames(&touchReader{r: resp.Body, timer: idle, every: silence}, func(f frame) error {
		progressed = true
		switch f.event {
		case sseEvent:
			var e wire.Event
			if err := json.Unmarshal([]byte(f.data), &e); err != nil {
				return fmt.Errorf("unreadable event frame: %w", err)
			}
			if err := handle(e); err != nil {
				return &terminalStreamError{err: err}
			}
			*after, *resumed = e.Seq, true
		case sseClosed:
			return closedFrameError(f.data)
		}
		return nil
	})
	return progressed, err
}

func (c *Client) openStream(ctx context.Context, q wire.EventQuery, after int64, resumed bool) (*http.Response, error) {
	query := q.Values()
	query.Del(wire.QueryAfterSeq)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+wire.PathEventStream, http.NoBody)
	if err != nil {
		return nil, &terminalStreamError{err: fmt.Errorf("build request: %w", err)}
	}
	req.URL.RawQuery = query.Encode()
	req.Header.Set("Accept", wire.ContentTypeEventStream)
	if resumed {
		req.Header.Set(wire.HeaderLastEventID, strconv.FormatInt(after, 10))
	}
	c.authorize(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, unwrapTransport(err)
	}
	return resp, nil
}

// classifyStreamRefusal decides whether a non-200 answer is worth a retry:
// authentication and permission failures and malformed requests are not.
func classifyStreamRefusal(resp response, c *Client) error {
	err := c.failure(resp)
	if resp.status == http.StatusTooManyRequests || resp.status >= http.StatusInternalServerError {
		return err
	}
	return &terminalStreamError{err: err}
}

func rateLimitedWait(err error) (time.Duration, bool) {
	var typed *smerr.Error
	if !errors.As(err, &typed) {
		return 0, false
	}
	seconds, ok := typed.Details[DetailRetryAfterSeconds].(int)
	if !ok {
		return 0, false
	}
	return time.Duration(seconds) * time.Second, true
}

// closedFrameError reads the error envelope of an `event: closed` frame.
// A lost credential or permission ends the follow; anything else (a server
// restart, an internal error) is retried.
func closedFrameError(data string) error {
	var envelope wire.ErrorEnvelope
	if err := json.Unmarshal([]byte(data), &envelope); err != nil || envelope.Error.Code == "" {
		return errors.New("the server ended the event stream")
	}
	err := decodeError(http.StatusOK, []byte(data))
	switch envelope.Error.Code { //nolint:exhaustive // every other code is retried
	case smerr.CodeUnauthenticated, smerr.CodePolicyDenied:
		return &terminalStreamError{err: err}
	}
	return err
}

// touchReader restarts the idle timer on every read: a stream that stays
// silent past the timer is cut by cancelling its request.
type touchReader struct {
	r     io.Reader
	timer *time.Timer
	every time.Duration
}

func (t *touchReader) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if n > 0 {
		t.timer.Reset(t.every)
	}
	return n, err
}

// frame is one server-sent event.
type frame struct{ event, data string }

// readFrames parses a text/event-stream body (comments and unknown fields are
// skipped) and calls handle for every complete frame, until the body ends.
func readFrames(body io.Reader, handle func(frame) error) error {
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64<<10), maxFrameBytes)
	var current frame
	var data []string
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if len(data) > 0 || current.event != "" {
				current.data = strings.Join(data, "\n")
				if current.event == "" {
					current.event = "message"
				}
				if err := handle(current); err != nil {
					return err
				}
			}
			current, data = frame{}, nil
			continue
		}
		field, value, _ := strings.Cut(line, ":")
		value = strings.TrimPrefix(value, " ")
		switch field {
		case "event":
			current.event = value
		case "data":
			data = append(data, value)
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return io.ErrUnexpectedEOF
}
