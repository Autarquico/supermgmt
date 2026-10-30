package proxmox

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/netguard"
)

// DefaultTimeout bounds every request of a client built without
// WithHTTPTimeout. Task correlation widens its window by it (CorrelationWindow).
const DefaultTimeout = 30 * time.Second

const (
	apiPrefix        = "/api2/json"
	defaultMaxBody   = 16 << 20
	taskPageSize     = 100
	maxTaskPages     = 1000
	shutdownTimeoutS = 240 // below DeadlineShutdown and DeadlineReboot
	maxMessageBytes  = 300
	relayPort        = "8006"
	relayIdleConns   = 2
	relayIdleTimeout = 30 * time.Second
)

var aclPathPattern = regexp.MustCompile(`^/[A-Za-z0-9_./-]*$`)

// Option adjusts a client built by New.
type Option func(*settings)

type settings struct {
	timeout time.Duration
	maxBody int64
	guard   []netguard.Option
	dial    func(ctx context.Context) (net.Conn, error)
	name    string
}

// WithHTTPTimeout bounds each request (default 30s). Correlation windows
// (CorrelationWindow) must be computed with the same value.
func WithHTTPTimeout(d time.Duration) Option { return func(s *settings) { s.timeout = d } }

// WithNetguardOptions passes options to the netguard client. Tests use it for
// netguard.WithTestDialer; production code passes none.
func WithNetguardOptions(opts ...netguard.Option) Option {
	return func(s *settings) { s.guard = append(s.guard, opts...) }
}

// WithDialer makes the client reach PVE through dial instead of the network:
// every connection it opens is one dial returns, whatever address the request
// names. The caller owns what dial does (a relay session on the node, say), so
// netguard does not apply; New then requires a CA and a server name, and
// ignores its endpoint argument.
func WithDialer(dial func(ctx context.Context) (net.Conn, error)) Option {
	return func(s *settings) { s.dial = dial }
}

// WithServerName is the name the certificate must carry (a DNS name or an IP
// literal) when the client has a dialer. Requests go to https://<name>:8006.
func WithServerName(name string) Option { return func(s *settings) { s.name = name } }

// APIError is a non-2xx answer from PVE.
type APIError struct {
	Status  int
	Message string // PVE's message, token-free and truncated; may be empty
	// HasBody is true when the answer was a PVE JSON error document, which is
	// what separates a definite refusal from a failing proxy (ADR-0025).
	HasBody bool
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("proxmox: HTTP %d", e.Status)
	}
	return fmt.Sprintf("proxmox: HTTP %d: %s", e.Status, e.Message)
}

type client struct {
	base  string
	auth  string
	token string
	http  *http.Client
}

// IdleCloser is implemented by clients that hold connections between requests.
type IdleCloser interface{ CloseIdle() }

// CloseIdle drops the connections the client keeps open. A client replaced by
// the daemon is closed through it, which ends the relays it still holds.
func (c *client) CloseIdle() { c.http.CloseIdleConnections() }

// New returns a client for the PVE API at endpoint (https://host:8006). caPEM
// is the CA that signed the server certificate; empty means the system roots.
// token is "<user>@<realm>!<tokenid>=<secret>" and is only ever sent in the
// Authorization header.
func New(endpoint string, caPEM []byte, token audit.Secret, opts ...Option) (Client, error) {
	s := settings{timeout: DefaultTimeout, maxBody: defaultMaxBody}
	for _, opt := range opts {
		opt(&s)
	}
	value := token.Reveal()
	if !strings.Contains(value, "!") || !strings.Contains(value, "=") {
		return nil, errors.New("proxmox: token must look like user@realm!tokenid=secret")
	}
	if s.dial != nil {
		return newRelayed(caPEM, value, s)
	}
	base, err := parseEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	guard := s.guard
	if len(caPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("proxmox: ca_file holds no PEM certificate")
		}
		guard = append([]netguard.Option{netguard.WithRootCAs(pool)}, guard...)
	}
	allow := netguard.Allow{AllowAllPrivate: true}
	return &client{
		base:  base,
		auth:  "PVEAPIToken=" + value,
		token: value,
		http:  netguard.NewClient(allow, nil, s.timeout, s.maxBody, guard...),
	}, nil
}

// newRelayed builds the client of a dialer: TLS is verified against caPEM and
// name, and the base URL comes from the name alone, never from an answer.
func newRelayed(caPEM []byte, token string, s settings) (Client, error) {
	if s.name == "" || strings.ContainsAny(s.name, "/@?#[] ") {
		return nil, errors.New("proxmox: a dialer needs a valid server name")
	}
	roots := x509.NewCertPool()
	if len(caPEM) == 0 || !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("proxmox: a dialer needs a PEM CA certificate")
	}
	dial := s.dial
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            func(ctx context.Context, _, _ string) (net.Conn, error) { return dial(ctx) },
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: s.name},
		TLSHandshakeTimeout:    s.timeout,
		ResponseHeaderTimeout:  s.timeout,
		MaxResponseHeaderBytes: 64 << 10,
		MaxIdleConns:           relayIdleConns,
		MaxIdleConnsPerHost:    relayIdleConns,
		IdleConnTimeout:        relayIdleTimeout,
	}
	return &client{
		base:  "https://" + net.JoinHostPort(s.name, relayPort),
		auth:  "PVEAPIToken=" + token,
		token: token,
		http: &http.Client{
			Transport: netguard.Guard(transport, s.maxBody),
			Timeout:   s.timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("proxmox: redirects are not followed")
			},
		},
	}, nil
}

func parseEndpoint(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", errors.New("proxmox: endpoint is not a URL")
	}
	switch {
	case u.Scheme != "https":
		return "", errors.New("proxmox: endpoint must use https")
	case u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "":
		return "", errors.New("proxmox: endpoint must be https://host[:port]")
	case u.Path != "" && u.Path != "/":
		return "", errors.New("proxmox: endpoint must not have a path")
	}
	return "https://" + u.Host, nil
}

func (c *client) Version(ctx context.Context) (Version, error) {
	data, err := c.get(ctx, "/version", nil)
	if err != nil {
		return Version{}, err
	}
	var v struct{ Version, Release string }
	if err := json.Unmarshal(data, &v); err != nil || v.Version == "" {
		return Version{}, errors.New("proxmox: unreadable /version answer")
	}
	return Version{Version: v.Version, Release: v.Release}, nil
}

func (c *client) Resources(ctx context.Context) (Inventory, error) {
	inventory, _, err := c.ResourcesAt(ctx)
	return inventory, err
}

// DatedInventory is implemented by clients that report PVE's clock along with
// the inventory, so the sync learns the clock skew without another request.
type DatedInventory interface {
	// ResourcesAt is Resources plus the answer's Date header. The time is
	// zero when the header is missing or unreadable: unknown, never "in sync".
	ResourcesAt(ctx context.Context) (Inventory, time.Time, error)
}

func (c *client) ResourcesAt(ctx context.Context) (Inventory, time.Time, error) {
	env, date, err := c.getEnvelope(ctx, "/cluster/resources", nil)
	if err != nil {
		return Inventory{}, time.Time{}, err
	}
	inventory, err := decodeInventory(env.Data)
	return inventory, date, err
}

func (c *client) PathPermissions(ctx context.Context, path string) (Privileges, error) {
	if !aclPathPattern.MatchString(path) {
		return nil, fmt.Errorf("proxmox: invalid ACL path %q", path)
	}
	data, err := c.get(ctx, "/access/permissions", url.Values{"path": {path}})
	if err != nil {
		return nil, err
	}
	return decodePathPrivileges(path, data)
}

func (c *client) Task(ctx context.Context, u UPID) (TaskStatus, error) {
	parsed, err := ParseUPID(u.Raw)
	if err != nil {
		return TaskStatus{}, err
	}
	data, err := c.get(ctx, "/nodes/"+parsed.Node+"/tasks/"+url.PathEscape(parsed.Raw)+"/status", nil)
	if err != nil {
		return TaskStatus{}, err
	}
	status, err := decodeTaskStatus(parsed, data)
	status.ExitStatus = c.sanitize(status.ExitStatus)
	return status, err
}

// Tasks lists a node's tasks, reading every page.
func (c *client) Tasks(ctx context.Context, node string, f TaskFilter) ([]TaskStatus, error) {
	if !nodeNamePattern.MatchString(node) {
		return nil, fmt.Errorf("proxmox: invalid node name %q", node)
	}
	var all []TaskStatus
	for start, page := 0, 0; ; page++ {
		if page == maxTaskPages {
			return nil, fmt.Errorf("proxmox: node %s task list exceeds %d pages", node, maxTaskPages)
		}
		env, _, err := c.getEnvelope(ctx, "/nodes/"+node+"/tasks", taskQuery(f, start))
		if err != nil {
			return nil, err
		}
		tasks, rows, err := decodeTaskList(env.Data)
		if err != nil {
			return nil, err
		}
		for i := range tasks {
			tasks[i].ExitStatus = c.sanitize(tasks[i].ExitStatus)
		}
		all = append(all, tasks...)
		start += rows
		if rows == 0 || (env.Total > 0 && start >= env.Total.int()) {
			return all, nil
		}
	}
}

func taskQuery(f TaskFilter, start int) url.Values {
	// source=all: by default PVE lists only archived (finished) tasks, which
	// would hide the one that is still running.
	q := url.Values{"start": {strconv.Itoa(start)}, "limit": {strconv.Itoa(taskPageSize)}, "source": {"all"}}
	if f.VMID > 0 {
		q.Set("vmid", strconv.Itoa(f.VMID))
	}
	if f.TypeName != "" {
		q.Set("typefilter", f.TypeName)
	}
	if f.User != "" {
		// PVE matches userfilter against the user of a task without its token
		// id, so a token's tasks are asked for by user and matched on the full
		// id locally (Correlate).
		user, _, _ := strings.Cut(f.User, "!")
		q.Set("userfilter", user)
	}
	if !f.Since.IsZero() {
		q.Set("since", strconv.FormatInt(f.Since.Unix(), 10))
	}
	if !f.Until.IsZero() {
		q.Set("until", strconv.FormatInt(f.Until.Unix(), 10))
	}
	return q
}

func validVerb(verb string) bool {
	switch verb {
	case "start", "stop", "shutdown", "reboot":
		return true
	}
	return false
}

// Power posts a power verb to a guest and classifies the outcome (ADR-0025).
// It sends exactly one request and never retries.
func (c *client) Power(ctx context.Context, g GuestRef, verb string) (UPID, PowerOutcome, error) {
	if !validVerb(verb) || g.VMID <= 0 || !nodeNamePattern.MatchString(g.Node) ||
		(g.Type != GuestQEMU && g.Type != GuestLXC) {
		return UPID{}, PowerRejected, fmt.Errorf("proxmox: invalid power request %q on %+v", verb, g)
	}
	path := fmt.Sprintf("/nodes/%s/%s/%d/status/%s", g.Node, g.Type, g.VMID, verb)
	var form url.Values
	if verb == "shutdown" || verb == "reboot" {
		form = url.Values{"timeout": {strconv.Itoa(shutdownTimeoutS)}}
	}
	status, body, err := c.do(ctx, http.MethodPost, path, nil, form)
	if err != nil {
		if errors.Is(err, netguard.ErrBlocked) {
			return UPID{}, PowerRejected, err // refused before any connection
		}
		return UPID{}, PowerUncertain, err
	}
	if status >= 400 && status < 500 || status >= 500 && isPVEError(body) {
		return UPID{}, PowerRejected, c.apiError(status, body)
	}
	if status < 200 || status >= 300 {
		return UPID{}, PowerUncertain, c.apiError(status, body)
	}
	u, err := parseUPIDAnswer(body)
	if err != nil {
		return UPID{}, PowerUncertain, err
	}
	if err := c.checkTaskOf(u, g, verb); err != nil {
		return UPID{}, PowerUncertain, err
	}
	return u, PowerAccepted, nil
}

// checkTaskOf refuses a UPID that cannot be the task of the request just sent:
// the request may have been accepted all the same, so the outcome is
// uncertain and correlation, not this answer, decides.
func (c *client) checkTaskOf(u UPID, g GuestRef, verb string) error {
	taskType, err := TaskType(g.Type, verb)
	if err != nil {
		return err
	}
	user, _, _ := strings.Cut(c.token, "=")
	if u.Node != g.Node || u.Type != taskType || u.ID != strconv.Itoa(g.VMID) || u.User != user {
		return errors.New("proxmox: the task id in the power answer is not the task of this request")
	}
	return nil
}

func parseUPIDAnswer(body []byte) (UPID, error) {
	var env struct{ Data string }
	if err := json.Unmarshal(body, &env); err != nil {
		return UPID{}, errors.New("proxmox: power answer is not JSON")
	}
	u, err := ParseUPID(env.Data)
	if err != nil {
		return UPID{}, errors.New("proxmox: power answer carries no valid UPID")
	}
	return u, nil
}

// pveErrorBody is the document PVE sends with an error: a message and/or
// per-parameter errors.
type pveErrorBody struct {
	Message string            `json:"message"`
	Errors  map[string]string `json:"errors"`
}

func parsePVEError(body []byte) (pveErrorBody, bool) {
	var e pveErrorBody
	if err := json.Unmarshal(body, &e); err != nil {
		return pveErrorBody{}, false
	}
	return e, strings.TrimSpace(e.Message) != "" || len(e.Errors) > 0
}

func isPVEError(body []byte) bool {
	_, ok := parsePVEError(body)
	return ok
}

func (c *client) get(ctx context.Context, path string, q url.Values) (json.RawMessage, error) {
	env, _, err := c.getEnvelope(ctx, path, q)
	return env.Data, err
}

// getEnvelope also returns PVE's Date header: the zero time when it is
// missing or unreadable.
func (c *client) getEnvelope(ctx context.Context, path string, q url.Values) (envelope, time.Time, error) {
	status, header, body, err := c.exchange(ctx, http.MethodGet, path, q, nil)
	if err != nil {
		return envelope{}, time.Time{}, err
	}
	if status < 200 || status >= 300 {
		return envelope{}, time.Time{}, c.apiError(status, body)
	}
	var env envelope
	if err := json.Unmarshal(body, &env); err != nil || len(env.Data) == 0 {
		return envelope{}, time.Time{}, fmt.Errorf("proxmox: GET %s: unreadable answer", path)
	}
	date, _ := http.ParseTime(header.Get("Date"))
	return env, date, nil
}

func (c *client) do(ctx context.Context, method, path string, q, form url.Values) (int, []byte, error) {
	status, _, body, err := c.exchange(ctx, method, path, q, form)
	return status, body, err
}

func (c *client) exchange(ctx context.Context, method, path string, q, form url.Values) (int, http.Header, []byte, error) {
	target := c.base + apiPrefix + path
	if len(q) > 0 {
		target += "?" + q.Encode()
	}
	var payload io.Reader
	if form != nil {
		payload = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, target, payload)
	if err != nil {
		return 0, nil, nil, c.scrub(err)
	}
	req.Header.Set("Authorization", c.auth)
	req.Header.Set("Accept", "application/json")
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, nil, c.scrub(fmt.Errorf("proxmox: %s %s: %w", method, path, err))
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, nil, c.scrub(fmt.Errorf("proxmox: %s %s: read answer: %w", method, path, err))
	}
	return resp.StatusCode, resp.Header, body, nil
}

func (c *client) apiError(status int, body []byte) error {
	e := &APIError{Status: status}
	if parsed, ok := parsePVEError(body); ok {
		e.HasBody = true
		e.Message = c.sanitize(parsed.Message)
	}
	return e
}

// sanitize makes text from PVE safe to keep and show: control sequences go,
// then the token, and only then is it shortened (a cut through the middle of
// the token would otherwise leave a prefix of it in the text).
func (c *client) sanitize(s string) string {
	return truncate(c.redact(plainLine(s)), maxMessageBytes)
}

// terminalEscape matches ANSI escape sequences (CSI, OSC and two-byte forms).
var terminalEscape = regexp.MustCompile(`\x1b(\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(\x07|\x1b\\)?|.?)`)

// plainLine is s as one line of printable text: escape sequences are removed,
// every other control character becomes a space, and runs of spaces collapse.
func plainLine(s string) string {
	s = terminalEscape.ReplaceAllString(s, "")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	return strings.Join(strings.Fields(s), " ")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}

// redact removes the whole token value and, separately, its secret part.
func (c *client) redact(s string) string {
	s = strings.ReplaceAll(s, c.token, audit.Redacted)
	if _, secret, ok := strings.Cut(c.token, "="); ok && secret != "" {
		s = strings.ReplaceAll(s, secret, audit.Redacted)
	}
	return s
}

// scrubbed keeps the error chain but renders without the token.
type scrubbed struct {
	msg string
	err error
}

func (e *scrubbed) Error() string { return e.msg }
func (e *scrubbed) Unwrap() error { return e.err }

func (c *client) scrub(err error) error {
	msg := err.Error()
	if redacted := c.redact(msg); redacted != msg {
		return &scrubbed{msg: redacted, err: err}
	}
	return err
}
