// Package cloudflare is a typed client for the parts of the Cloudflare v4 API
// that reaching a node through a tunnel needs (ADR-0037): remotely managed
// tunnels, DNS records, Access applications, reusable policies and service
// tokens. Every call goes through a netguard client, the bearer token never
// leaves the Authorization header, and nothing the API says is echoed
// unsanitised.
package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/autarquico/supermgmt/internal/audit"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/netguard"
)

const (
	// DefaultBaseURL is the production API.
	DefaultBaseURL = "https://api.cloudflare.com/client/v4"

	defaultTimeout = 30 * time.Second
	userAgent      = "supermgmt"

	pageSize      = 100
	maxPages      = 100
	maxMessageLen = 300
	maxMessages   = 3

	// Response caps (ADR-0028); netguard's own cap is the ceiling.
	ceilingBody   = 16 << 20
	maxObjectBody = 256 << 10
	maxListBody   = 4 << 20
)

// Option adjusts a client built by New.
type Option func(*settings)

type settings struct {
	timeout time.Duration
	guard   []netguard.Option
}

// WithHTTPTimeout bounds each request (default 30s).
func WithHTTPTimeout(d time.Duration) Option { return func(s *settings) { s.timeout = d } }

// WithNetguardOptions passes options to the netguard client. Tests use it for
// netguard.WithTestDialer and WithRootCAs; production code passes none.
func WithNetguardOptions(opts ...netguard.Option) Option {
	return func(s *settings) { s.guard = append(s.guard, opts...) }
}

// APIError is a non-success answer from Cloudflare.
type APIError struct {
	Status int
	// CFCode is the first error code of the answer, 0 when there was none.
	CFCode int
	// Message is Cloudflare's text, token-free, control-free and truncated.
	Message string
	// HasBody is true when the answer was a Cloudflare error document, which
	// separates a definite refusal from a failing proxy.
	HasBody bool
	// RetryAfter is the delay a 429 asked for, when it said.
	RetryAfter time.Duration
}

func (e *APIError) Error() string {
	switch {
	case e.Message == "":
		return fmt.Sprintf("cloudflare: HTTP %d", e.Status)
	case e.CFCode != 0:
		return fmt.Sprintf("cloudflare: HTTP %d (code %d): %s", e.Status, e.CFCode, e.Message)
	}
	return fmt.Sprintf("cloudflare: HTTP %d: %s", e.Status, e.Message)
}

// ErrorCode maps the status to the SuperMgmt error model, the same way for
// every call: 401 and 403 are a credential problem, 404 and 409 keep their
// meaning, 429 and 5xx are the provider's fault.
func (e *APIError) ErrorCode() smerr.Code {
	if e.conflict() {
		return smerr.CodeConflict
	}
	switch e.Status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return smerr.CodeUnauthenticated
	case http.StatusNotFound:
		return smerr.CodeNotFound
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		return smerr.CodeInvalidArgument
	}
	return smerr.CodeProviderError
}

// Retryable reports whether the same request may succeed later.
func (e *APIError) Retryable() bool {
	return e.Status == http.StatusTooManyRequests || e.Status >= 500
}

// IsNotFound reports a 404 from Cloudflare.
func IsNotFound(err error) bool { return statusIs(err, http.StatusNotFound) }

// conflictCodes are the Cloudflare codes for "that name is taken" that do not
// come with a 409: a tunnel name already in use, a DNS record that already exists.
var conflictCodes = []int{1013, 81053, 81057, 81058}

func (e *APIError) conflict() bool {
	return e.Status == http.StatusConflict || slices.Contains(conflictCodes, e.CFCode)
}

// IsConflict reports that Cloudflare refused because the name or hostname is taken.
func IsConflict(err error) bool {
	var api *APIError
	return errors.As(err, &api) && api.conflict()
}

func statusIs(err error, status int) bool {
	var api *APIError
	return errors.As(err, &api) && api.Status == status
}

// outcomeUnknown means the request was sent and its answer was lost or unusable.
type outcomeUnknown struct {
	msg string
	err error
}

func (e *outcomeUnknown) Error() string {
	if e.err == nil {
		return e.msg
	}
	return e.msg + ": " + e.err.Error()
}

func (e *outcomeUnknown) Unwrap() error { return e.err }

// IsAmbiguous reports that a mutation may have been applied although the call
// failed: the answer was lost, cut, unreadable or a 5xx. The caller looks the
// object up by name before it creates again. Refusals (4xx, 429), invalid
// input and requests the filter blocked are definite: nothing was applied.
func IsAmbiguous(err error) bool {
	var unknown *outcomeUnknown
	if errors.As(err, &unknown) {
		return true
	}
	var api *APIError
	return errors.As(err, &api) && (api.Status >= 500 || api.Status/100 == 2)
}

// Client talks to one Cloudflare account.
type Client struct {
	base      *url.URL
	accountID string
	token     string
	http      *http.Client
}

// New returns a client for the account at baseURL ("" is DefaultBaseURL). The
// token is sent only to that origin, only in the Authorization header, and no
// redirect is ever followed.
func New(baseURL, accountID string, token audit.Secret, opts ...Option) (*Client, error) {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	base, err := parseBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	if !validID(accountID) {
		return nil, errors.New("cloudflare: account_id is not a Cloudflare identifier")
	}
	if token.Reveal() == "" || strings.ContainsFunc(token.Reveal(), func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
		return nil, errors.New("cloudflare: the API token is empty or malformed")
	}
	s := settings{timeout: defaultTimeout}
	for _, opt := range opts {
		opt(&s)
	}
	hc := netguard.NewClient(netguard.Allow{}, nil, s.timeout, ceilingBody, s.guard...)
	return &Client{base: base, accountID: accountID, token: token.Reveal(), http: hc}, nil
}

func parseBaseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	switch {
	case err != nil:
		return nil, errors.New("cloudflare: base URL is not a URL")
	case u.Scheme != "https":
		return nil, errors.New("cloudflare: base URL must use https")
	case u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "":
		return nil, errors.New("cloudflare: base URL must be https://host[:port][/path]")
	case u.Path != "" && (!strings.HasPrefix(u.Path, "/") || strings.HasSuffix(u.Path, "/") || strings.Contains(u.Path, "//")):
		return nil, errors.New("cloudflare: base URL path must be absolute without a trailing slash")
	}
	return &url.URL{Scheme: "https", Host: u.Host, Path: u.Path}, nil
}

// do sends one request and returns the decoded envelope of a successful answer.
func (c *Client) do(ctx context.Context, method, path string, q url.Values, in any, limit int64) (envelope, error) {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return envelope{}, fmt.Errorf("cloudflare: encode request: %w", err)
		}
		body = bytes.NewReader(b)
	}
	u := *c.base
	u.Path = c.base.Path + path
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return envelope{}, fmt.Errorf("cloudflare: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return envelope{}, c.sendError(method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	switch {
	case err != nil:
		return envelope{}, &outcomeUnknown{msg: fmt.Sprintf("cloudflare: read answer to %s %s", method, path), err: c.scrub(err)}
	case int64(len(data)) > limit:
		return envelope{}, &outcomeUnknown{msg: fmt.Sprintf("cloudflare: %s %s", method, path), err: netguard.ErrBodyTooLarge}
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return envelope{}, c.apiError(resp, data)
	}
	env, err := decodeEnvelope(data)
	if err != nil {
		return envelope{}, &outcomeUnknown{msg: fmt.Sprintf("cloudflare: %s %s", method, path), err: err}
	}
	if !env.Success {
		return envelope{}, c.failure(resp.StatusCode, env, true)
	}
	return env, nil
}

// sendError wraps a transport failure. A request the filter refused was never
// sent; any other failure may have been.
func (c *Client) sendError(method, path string, err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	err = c.scrub(err)
	wrapped := fmt.Errorf("cloudflare: %s %s: %w", method, path, err)
	if errors.Is(err, netguard.ErrBlocked) || errors.Is(err, netguard.ErrRedirect) {
		return wrapped
	}
	return &outcomeUnknown{msg: fmt.Sprintf("cloudflare: %s %s", method, path), err: err}
}

// scrub returns err with the token removed from its text.
func (c *Client) scrub(err error) error {
	if !strings.Contains(err.Error(), c.token) {
		return err
	}
	return errors.New(c.sanitize(err.Error()))
}

func (c *Client) apiError(resp *http.Response, body []byte) error {
	env, err := decodeEnvelope(body)
	e := &APIError{Status: resp.StatusCode}
	if err == nil {
		e = c.failure(resp.StatusCode, env, false)
	}
	if seconds, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && seconds > 0 && seconds <= 3600 {
		e.RetryAfter = time.Duration(seconds) * time.Second
	}
	return e
}

func (c *Client) failure(status int, env envelope, success2xx bool) *APIError {
	e := &APIError{Status: status, HasBody: true}
	var messages []string
	for i, w := range env.Errors {
		if i == 0 {
			e.CFCode = w.Code
		}
		if i < maxMessages && w.Message != "" {
			messages = append(messages, w.Message)
		}
	}
	e.Message = c.sanitize(strings.Join(messages, "; "))
	if success2xx && e.Message == "" {
		e.Message = "the API reported failure"
	}
	return e
}

// sanitize makes a server message safe to show: the token removed, control
// characters dropped, length bounded.
func (c *Client) sanitize(s string) string {
	s = strings.ReplaceAll(s, c.token, "[redacted]")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	if r := []rune(s); len(r) > maxMessageLen {
		s = string(r[:maxMessageLen])
	}
	return strings.TrimSpace(s)
}

func invalid(format string, args ...any) error {
	return smerr.New(smerr.CodeInvalidArgument, "", "cloudflare: "+fmt.Sprintf(format, args...))
}

// listAll reads every page of a list endpoint. The page count comes from
// Cloudflare but the loop is bounded by maxPages whatever it says.
func listAll[T any](ctx context.Context, c *Client, path string, q url.Values, decode func([]byte) ([]T, error)) ([]T, error) {
	var all []T
	for page := 1; ; page++ {
		if page > maxPages {
			return nil, fmt.Errorf("cloudflare: GET %s exceeds %d pages", path, maxPages)
		}
		paged := url.Values{}
		for k, v := range q {
			paged[k] = v
		}
		paged.Set("page", strconv.Itoa(page))
		paged.Set("per_page", strconv.Itoa(pageSize))
		env, err := c.do(ctx, http.MethodGet, path, paged, nil, maxListBody)
		if err != nil {
			return nil, err
		}
		items, err := decode(env.Result)
		if err != nil {
			return nil, fmt.Errorf("cloudflare: GET %s: %w", path, err)
		}
		all = append(all, items...)
		if page >= env.Info.TotalPages || len(items) == 0 {
			return all, nil
		}
	}
}

// account is the path prefix of the account's resources.
func (c *Client) account(rest string) string { return "/accounts/" + c.accountID + rest }
