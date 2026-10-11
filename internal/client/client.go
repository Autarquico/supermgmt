// Package client is the typed client of the control plane API (spec §23,
// ADR-0014, ADR-0017). The CLI and the TUI use it for everything. Locally it
// dials the daemon's Unix socket, verifies the daemon's peer credentials
// before sending a byte and starts the daemon when none is running; remotely
// it speaks HTTPS with a bearer token. Either way it keeps one
// Idempotency-Key per logical mutation across retries.
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
	"strconv"
	"strings"
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

	// maxRetryAfter is the longest 429 wait a request sits out by itself;
	// a longer one is reported so the caller decides.
	maxRetryAfter = 10 * time.Second
)

// DetailCorrelationID is the Details key under which a failed request's
// correlation ID travels in the returned *smerr.Error.
const DetailCorrelationID = "correlation_id"

// DetailRetryAfterSeconds is the Details key of a rate-limited request: how
// long the server asked the caller to wait.
const DetailRetryAfterSeconds = "retry_after_seconds"

// Options configure a Client. Socket is required unless the client is built
// with NewRemote.
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
	// StreamRetry is the first reconnect delay of FollowEvents.
	StreamRetry time.Duration
	// StreamIdle is how long FollowEvents tolerates silence (the server sends
	// a heartbeat every 15s) before it drops the connection and reconnects.
	StreamIdle time.Duration
	// Sleep waits between retries (default: a context-aware timer).
	Sleep func(ctx context.Context, d time.Duration) error
	// TempDir is where isolated known_hosts directories are created.
	TempDir string
}

// Client talks to one control plane. It is safe for concurrent use.
type Client struct {
	opts Options
	http *http.Client
	ids  domain.IDGenerator
	uid  uint32

	// base is the scheme and host every request path is appended to; token,
	// when set, is the bearer credential (remote clients only).
	base   string
	token  string
	remote bool

	peer      peerLookup
	autostart autostarter
}

var _ tui.API = (*Client)(nil)

// New returns a Client of the local daemon; it does not connect until the
// first request.
func New(opts Options) *Client {
	c := &Client{opts: opts, ids: opts.IDs, peer: peerUID, uid: uint32(os.Getuid()), base: "http://" + apiHost} //nolint:gosec // uid is never negative
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

// postUnkeyed is a POST to a route that rejects (or never replays) an
// Idempotency-Key: login, credential issuing and key export.
func postUnkeyed(path string, body any) request {
	r := post(path, body)
	r.unkeyed = true
	return r
}

// response is what came back, before any interpretation.
type response struct {
	status     int
	payload    []byte
	retryAfter time.Duration
	location   string
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
	resp, err := c.send(ctx, r, body, key)
	if err != nil {
		return zero, err
	}
	if err := c.failure(resp); err != nil {
		return zero, err
	}
	var envelope wire.Envelope[T]
	if err := json.Unmarshal(resp.payload, &envelope); err != nil {
		return zero, smerr.Wrap(err, smerr.CodeInternal, "", "server sent an unreadable response")
	}
	return envelope.Data, nil
}

// failure turns a non-success response into the error callers branch on.
func (c *Client) failure(resp response) error {
	switch {
	case resp.status == http.StatusTooManyRequests:
		return rateLimited(resp.retryAfter)
	case resp.status >= http.StatusMultipleChoices && resp.status < http.StatusBadRequest:
		return smerr.New(smerr.CodeInternal, "", "the server redirected the request"+redirectHint(resp.location)+": check the profile URL")
	case resp.status >= http.StatusBadRequest:
		err := decodeError(resp.status, resp.payload)
		if resp.status == http.StatusUnauthorized && c.remote {
			return withHint(err, "sign in with `sm login`")
		}
		return err
	}
	return nil
}

func redirectHint(location string) string {
	if location == "" {
		return ""
	}
	if u, err := url.Parse(location); err == nil && u.Host != "" {
		return " to " + u.Scheme + "://" + u.Host
	}
	return ""
}

func rateLimited(after time.Duration) error {
	err := smerr.New(smerr.CodeTimeout, "", fmt.Sprintf("the server is rate limiting this client; retry in %s", after.Round(time.Second)))
	err.Details = map[string]any{DetailRetryAfterSeconds: int(after.Seconds())}
	return err
}

func withHint(err error, hint string) error {
	var typed *smerr.Error
	if !errors.As(err, &typed) {
		return err
	}
	clone := *typed
	clone.Message = strings.TrimSuffix(typed.Message, ".") + " (" + hint + ")"
	return &clone
}

// send performs the request. A transport failure is retried once, and so is a
// 429 whose Retry-After is short, always with the same key and the same
// bytes, so the server replays instead of repeating.
func (c *Client) send(ctx context.Context, r request, body []byte, key string) (response, error) {
	var lastErr error
	var last response
	for range attempts {
		resp, err := c.roundTrip(ctx, r, body, key)
		switch {
		case err == nil && resp.status == http.StatusTooManyRequests && resp.retryAfter <= maxRetryAfter:
			last = resp
			if err := c.sleep(ctx, resp.retryAfter); err != nil {
				return response{}, err
			}
			continue
		case err == nil:
			return resp, nil
		}
		lastErr = err
		if !retryable(ctx, err) {
			break
		}
	}
	if lastErr == nil {
		return last, nil
	}
	return response{}, lastErr
}

func (c *Client) roundTrip(ctx context.Context, r request, body []byte, key string) (response, error) {
	target := c.base + r.path
	if len(r.query) > 0 {
		target += "?" + r.query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, r.method, target, bytes.NewReader(body))
	if err != nil {
		return response{}, fmt.Errorf("build request: %w", err)
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
	c.authorize(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return response{}, unwrapTransport(err)
	}
	defer func() { _ = resp.Body.Close() }()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return response{}, err
	}
	return response{
		status: resp.StatusCode, payload: payload,
		retryAfter: retryAfterOf(resp.Header), location: resp.Header.Get("Location"),
	}, nil
}

// authorize adds the bearer credential of a signed-in remote client.
func (c *Client) authorize(req *http.Request) {
	if c.token != "" {
		req.Header.Set(wire.HeaderAuthorization, "Bearer "+c.token)
	}
}

// retryAfterOf reads Retry-After in seconds; a missing or malformed value is
// one second, since a 429 always means "not now".
func retryAfterOf(h http.Header) time.Duration {
	seconds, err := strconv.Atoi(strings.TrimSpace(h.Get("Retry-After")))
	if err != nil || seconds < 1 {
		return time.Second
	}
	return time.Duration(seconds) * time.Second
}

func (c *Client) sleep(ctx context.Context, d time.Duration) error {
	if c.opts.Sleep != nil {
		return c.opts.Sleep(ctx, d)
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
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
		return smerr.New(smerr.CodeInternal, "", fmt.Sprintf("server answered HTTP %d without an error body", status))
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
