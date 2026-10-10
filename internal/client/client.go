// Package client is the typed client of the daemon's local API (spec §23,
// ADR-0014). The CLI and the TUI use it for everything: it dials the Unix
// socket, verifies the daemon's peer credentials before sending a byte,
// starts the daemon when none is running, and keeps one Idempotency-Key per
// logical mutation across retries.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/tui"
)

const (
	defaultRequestTimeout = 30 * time.Second
	maxResponseBytes      = 16 << 20
	attempts              = 2
	apiHost               = "sm"
)

// DetailCorrelationID is the Details key under which a failed request's
// correlation ID travels in the returned *smerr.Error.
const DetailCorrelationID = "correlation_id"

// Options configure a Client. Only Socket is required.
type Options struct {
	// Socket is the daemon's Unix socket path.
	Socket string
	// Autostart, when set, spawns the daemon if nothing listens on Socket.
	Autostart *Autostart
	// RequestTimeout bounds a request whose context has no deadline.
	RequestTimeout time.Duration
	// IDs issues Idempotency-Keys; the default is a UUIDv7 generator.
	IDs domain.IDGenerator
	// PresenceRetry is the first reconnect delay of HoldPresence.
	PresenceRetry time.Duration
	// TempDir is where isolated known_hosts directories are created.
	TempDir string
}

// Client talks to one daemon. It is safe for concurrent use.
type Client struct {
	opts Options
	http *http.Client
	ids  domain.IDGenerator
	uid  uint32

	peer      peerLookup
	autostart autostarter
}

var _ tui.API = (*Client)(nil)

// New returns a Client; it does not connect until the first request.
func New(opts Options) *Client {
	c := &Client{opts: opts, ids: opts.IDs, peer: peerUID, uid: uint32(os.Getuid())} //nolint:gosec // uid is never negative
	if c.ids == nil {
		c.ids = domain.UUIDv7Generator{}
	}
	c.http = &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return c.dial(ctx) },
	}}
	return c
}

// request describes one API call. Mutations (POST, PATCH, DELETE) carry an
// Idempotency-Key unless unkeyed is set.
type request struct {
	method  string
	path    string
	query   url.Values
	body    any
	ifMatch string
	unkeyed bool
}

func get(path string, query url.Values) request {
	return request{method: http.MethodGet, path: path, query: query}
}

func post(path string, body any) request {
	return request{method: http.MethodPost, path: path, body: body}
}

func call[T any](ctx context.Context, c *Client, r request) (T, error) {
	var zero T
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cmpOr(c.opts.RequestTimeout, defaultRequestTimeout))
		defer cancel()
	}
	body, err := encodeBody(r.body)
	if err != nil {
		return zero, err
	}
	key := ""
	if r.method != http.MethodGet && !r.unkeyed {
		key = string(c.ids.NewID())
	}
	status, payload, err := c.send(ctx, r, body, key)
	if err != nil {
		return zero, err
	}
	if status >= http.StatusBadRequest {
		return zero, decodeError(status, payload)
	}
	var envelope wire.Envelope[T]
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return zero, smerr.Wrap(err, smerr.CodeInternal, "", "daemon sent an unreadable response")
	}
	return envelope.Data, nil
}

// send performs the request, retrying once on a transport failure with the
// same key and the same bytes, so the daemon replays instead of repeating.
func (c *Client) send(ctx context.Context, r request, body []byte, key string) (int, []byte, error) {
	var lastErr error
	for range attempts {
		status, payload, err := c.roundTrip(ctx, r, body, key)
		if err == nil {
			return status, payload, nil
		}
		lastErr = err
		if !retryable(ctx, err) {
			break
		}
	}
	return 0, nil, lastErr
}

func (c *Client) roundTrip(ctx context.Context, r request, body []byte, key string) (int, []byte, error) {
	target := "http://" + apiHost + r.path
	if len(r.query) > 0 {
		target += "?" + r.query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, r.method, target, bytes.NewReader(body))
	if err != nil {
		return 0, nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", wire.ContentType)
	if body != nil {
		req.Header.Set("Content-Type", wire.ContentType)
	}
	if key != "" {
		req.Header.Set(wire.HeaderIdempotencyKey, key)
	}
	if r.ifMatch != "" {
		req.Header.Set(wire.HeaderIfMatch, r.ifMatch)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, unwrapTransport(err)
	}
	defer func() { _ = resp.Body.Close() }()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, payload, nil
}

// retryable reports whether err is a connection-level failure worth one more
// try. The caller's own cancellation and our refusals to talk are final.
func retryable(ctx context.Context, err error) bool {
	var unavailable *DaemonUnavailableError
	var refused *PeerMismatchError
	return ctx.Err() == nil && !errors.As(err, &unavailable) && !errors.As(err, &refused)
}

// unwrapTransport lifts our typed dial errors out of *url.Error.
func unwrapTransport(err error) error {
	var unavailable *DaemonUnavailableError
	var refused *PeerMismatchError
	switch {
	case errors.As(err, &unavailable):
		return unavailable
	case errors.As(err, &refused):
		return refused
	}
	return err
}

func encodeBody(v any) ([]byte, error) {
	if v == nil {
		return nil, nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}
	return b, nil
}

func decodeError(status int, payload []byte) error {
	var envelope wire.ErrorEnvelope
	if err := json.Unmarshal(payload, &envelope); err != nil || envelope.Error.Code == "" {
		return smerr.New(smerr.CodeInternal, "", fmt.Sprintf("daemon answered HTTP %d without an error body", status))
	}
	typed := envelope.Error.Err()
	details := make(map[string]any, len(typed.Details)+1)
	for k, v := range typed.Details {
		details[k] = v
	}
	if envelope.Error.CorrelationID != "" {
		details[DetailCorrelationID] = envelope.Error.CorrelationID
	}
	typed.Details = details
	return typed
}

// CorrelationID returns the correlation ID of a failed API call, or "".
func CorrelationID(err error) string {
	var typed *smerr.Error
	if !errors.As(err, &typed) {
		return ""
	}
	id, _ := typed.Details[DetailCorrelationID].(string)
	return id
}

func cmpOr[T comparable](v, fallback T) T {
	var zero T
	if v == zero {
		return fallback
	}
	return v
}
