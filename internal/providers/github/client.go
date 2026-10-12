package github

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/netguard"
)

const (
	defaultTimeout = 30 * time.Second
	apiVersion     = "2022-11-28"
	userAgent      = "supermgmt"

	defaultPerPage = 100
	maxPages       = 100
	maxMessageLen  = 300

	// Response caps per endpoint (ADR-0028); netguard's own cap is the ceiling.
	ceilingBody      = 16 << 20
	maxRepoBody      = 256 << 10
	maxRepoListBody  = 4 << 20
	maxCheckRunsBody = 4 << 20
	maxRunBody       = 1 << 20
	maxAttestBody    = 8 << 20
)

var (
	segmentPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)
	commitPattern  = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestPattern  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// ErrNoWorkflowRun means a check suite does not belong to a GitHub Actions run.
var ErrNoWorkflowRun = errors.New("github: check suite has no workflow run")

// Option adjusts a client built by New.
type Option func(*settings)

type settings struct {
	timeout time.Duration
	guard   []netguard.Option
}

// WithHTTPTimeout bounds each request (default 30s).
func WithHTTPTimeout(d time.Duration) Option { return func(s *settings) { s.timeout = d } }

// WithNetguardOptions passes options to the netguard client. Tests use it for
// netguard.WithTestDialer; production code passes none.
func WithNetguardOptions(opts ...netguard.Option) Option {
	return func(s *settings) { s.guard = append(s.guard, opts...) }
}

// APIError is a non-2xx answer from GitHub.
type APIError struct {
	Status  int
	Message string // GitHub's message, token-free and truncated; may be empty
	// RateLimited is true when the answer says the rate limit is exhausted;
	// ResetsAt is when it renews, if GitHub said.
	RateLimited bool
	ResetsAt    time.Time
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("github: HTTP %d", e.Status)
	}
	return fmt.Sprintf("github: HTTP %d: %s", e.Status, e.Message)
}

type client struct {
	base  *url.URL
	token string
	http  *http.Client
}

// New returns a read-only client for the GitHub API at apiURL (default
// https://api.github.com; GitHub Enterprise Server: https://host/api/v3).
// caPEM is the CA that signed a private server certificate; empty means the
// system roots. The token is sent only to the exact origin of apiURL, and only
// ever in the Authorization header.
func New(apiURL string, caPEM []byte, token audit.Secret, opts ...Option) (Client, error) {
	base, err := parseAPIURL(apiURL)
	if err != nil {
		return nil, err
	}
	if token.Reveal() == "" {
		return nil, errors.New("github: token is empty")
	}
	s := settings{timeout: defaultTimeout}
	for _, opt := range opts {
		opt(&s)
	}
	guard := s.guard
	if len(caPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("github: ca_file holds no PEM certificate")
		}
		guard = append([]netguard.Option{netguard.WithRootCAs(pool)}, guard...)
	}
	api := originOf(base)
	allow := netguard.Allow{
		AllowAllPrivate: true,
		Redirects:       netguard.RedirectPolicy{Max: maxRedirects, Hosts: []string{base.Hostname()}},
	}
	hc := netguard.NewClient(allow, nil, s.timeout, ceilingBody, guard...)
	hc.Transport = originScoped{next: hc.Transport, api: api, authorization: "Bearer " + token.Reveal()}
	guarded, pinned := hc.CheckRedirect, pinRedirects(api, maxRedirects)
	hc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if err := pinned(req, via); err != nil {
			return err
		}
		return guarded(req, via)
	}
	return &client{base: base, token: token.Reveal(), http: hc}, nil
}

func parseAPIURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("github: api_url is not a URL")
	}
	switch {
	case u.Scheme != "https":
		return nil, errors.New("github: api_url must use https")
	case u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "":
		return nil, errors.New("github: api_url must be https://host[:port][/path]")
	case u.Path != "" && (!strings.HasPrefix(u.Path, "/") || strings.HasSuffix(u.Path, "/") || strings.Contains(u.Path, "//")):
		return nil, errors.New("github: api_url path must be absolute without a trailing slash")
	}
	return &url.URL{Scheme: "https", Host: u.Host, Path: u.Path}, nil
}

type wireRepo struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Owner struct {
		Login string `json:"login"`
		ID    int64  `json:"id"`
	} `json:"owner"`
	HTMLURL       string `json:"html_url"`
	DefaultBranch string `json:"default_branch"`
	Private       bool   `json:"private"`
}

func (w wireRepo) repo() (Repo, error) {
	if w.ID <= 0 || w.Owner.ID <= 0 || w.Owner.Login == "" || w.Name == "" {
		return Repo{}, errors.New("github: repository answer lacks ids or names")
	}
	return Repo{
		ID: w.ID, OwnerID: w.Owner.ID, Owner: w.Owner.Login, Name: w.Name,
		URL: w.HTMLURL, DefaultBranch: w.DefaultBranch, Private: w.Private,
	}, nil
}

func (c *client) Repository(ctx context.Context, id int64) (Repo, error) {
	if id <= 0 {
		return Repo{}, fmt.Errorf("github: invalid repository id %d", id)
	}
	body, _, err := c.get(ctx, "/repositories/"+strconv.FormatInt(id, 10), nil, maxRepoBody)
	if err != nil {
		return Repo{}, err
	}
	var w wireRepo
	if err := json.Unmarshal(body, &w); err != nil {
		return Repo{}, errors.New("github: unreadable repository answer")
	}
	repo, err := w.repo()
	if err == nil && repo.ID != id {
		return Repo{}, errors.New("github: the answer is for another repository")
	}
	return repo, err
}

// Repositories lists the repositories the token can read, one page at a time.
func (c *client) Repositories(ctx context.Context, page Page) ([]Repo, Page, error) {
	body, next, err := c.getPage(ctx, "/user/repos", nil, maxRepoListBody, page)
	if err != nil {
		return nil, Page{}, err
	}
	var list []wireRepo
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, Page{}, errors.New("github: unreadable repository list")
	}
	repos := make([]Repo, 0, len(list))
	for _, w := range list {
		repo, err := w.repo()
		if err != nil {
			return nil, Page{}, err
		}
		repos = append(repos, repo)
	}
	return repos, next, nil
}

type wireCheckRun struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Status      string    `json:"status"`
	Conclusion  string    `json:"conclusion"`
	HeadSHA     string    `json:"head_sha"`
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at"`
	App         struct {
		ID int64 `json:"id"`
	} `json:"app"`
	CheckSuite struct {
		ID int64 `json:"id"`
	} `json:"check_suite"`
}

// CheckRuns lists every check run on the commit, every attempt included
// (filter=all), reading all pages.
func (c *client) CheckRuns(ctx context.Context, r Repo, sha string) ([]CheckRun, error) {
	base, err := repoPath(r)
	if err != nil {
		return nil, err
	}
	if !commitPattern.MatchString(sha) {
		return nil, fmt.Errorf("github: invalid commit sha %q", sha)
	}
	var runs []CheckRun
	for page, n := (Page{Number: 1}), 0; page.Number != 0; n++ {
		if n == maxPages {
			return nil, fmt.Errorf("github: check runs exceed %d pages", maxPages)
		}
		body, next, err := c.getPage(ctx, base+"/commits/"+sha+"/check-runs", url.Values{"filter": {"all"}}, maxCheckRunsBody, page)
		if err != nil {
			return nil, err
		}
		var doc struct {
			CheckRuns []wireCheckRun `json:"check_runs"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			return nil, errors.New("github: unreadable check runs answer")
		}
		for _, w := range doc.CheckRuns {
			runs = append(runs, CheckRun{
				ID: w.ID, Name: w.Name, AppID: w.App.ID, Status: w.Status, Conclusion: w.Conclusion,
				HeadSHA: w.HeadSHA, SuiteID: w.CheckSuite.ID, StartedAt: w.StartedAt, CompletedAt: w.CompletedAt,
			})
		}
		page = next
	}
	return runs, nil
}

type wireWorkflowRun struct {
	ID         int64  `json:"id"`
	RunAttempt int64  `json:"run_attempt"`
	Path       string `json:"path"`
	HeadBranch string `json:"head_branch"`
	HeadSHA    string `json:"head_sha"`
	Event      string `json:"event"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion"`
}

// WorkflowRun resolves a check suite to its GitHub Actions run. A suite with
// no run yields ErrNoWorkflowRun.
func (c *client) WorkflowRun(ctx context.Context, r Repo, suiteID int64) (WorkflowRun, error) {
	base, err := repoPath(r)
	if err != nil {
		return WorkflowRun{}, err
	}
	if suiteID <= 0 {
		return WorkflowRun{}, fmt.Errorf("github: invalid check suite id %d", suiteID)
	}
	q := url.Values{"check_suite_id": {strconv.FormatInt(suiteID, 10)}}
	body, _, err := c.get(ctx, base+"/actions/runs", q, maxRunBody)
	if err != nil {
		return WorkflowRun{}, err
	}
	var doc struct {
		Runs []wireWorkflowRun `json:"workflow_runs"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return WorkflowRun{}, errors.New("github: unreadable workflow runs answer")
	}
	switch len(doc.Runs) {
	case 0:
		return WorkflowRun{}, ErrNoWorkflowRun
	case 1:
		w := doc.Runs[0]
		return WorkflowRun(w), nil
	}
	return WorkflowRun{}, fmt.Errorf("github: check suite %d maps to %d workflow runs", suiteID, len(doc.Runs))
}

// Attestations returns the Sigstore bundles GitHub holds for a digest
// ("sha256:<hex>"), first page only. No attestation is an empty list, not an
// error: the verifier decides what its absence means.
func (c *client) Attestations(ctx context.Context, r Repo, digest string) ([]json.RawMessage, error) {
	base, err := repoPath(r)
	if err != nil {
		return nil, err
	}
	if !digestPattern.MatchString(digest) {
		return nil, fmt.Errorf("github: invalid digest %q", digest)
	}
	body, _, err := c.get(ctx, base+"/attestations/"+digest, nil, maxAttestBody)
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.Status == http.StatusNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var doc struct {
		Attestations []struct {
			Bundle json.RawMessage `json:"bundle"`
		} `json:"attestations"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, errors.New("github: unreadable attestations answer")
	}
	bundles := make([]json.RawMessage, 0, len(doc.Attestations))
	for _, a := range doc.Attestations {
		if len(a.Bundle) == 0 {
			return nil, errors.New("github: attestation without a bundle")
		}
		bundles = append(bundles, a.Bundle)
	}
	return bundles, nil
}

// repoPath is the API path prefix of a repository, from its validated names.
func repoPath(r Repo) (string, error) {
	if !validSegment(r.Owner) || !validSegment(r.Name) {
		return "", fmt.Errorf("github: invalid repository %q/%q", r.Owner, r.Name)
	}
	return "/repos/" + r.Owner + "/" + r.Name, nil
}

func validSegment(s string) bool { return segmentPattern.MatchString(s) && s != "." && s != ".." }

// getPage reads one page of a list endpoint and returns the next page, if any,
// from the Link header. The Link URL itself is never followed.
func (c *client) getPage(ctx context.Context, path string, q url.Values, limit int64, page Page) ([]byte, Page, error) {
	if page.Number <= 0 {
		page.Number = 1
	}
	if page.PerPage <= 0 || page.PerPage > defaultPerPage {
		page.PerPage = defaultPerPage
	}
	paged := url.Values{}
	for k, v := range q {
		paged[k] = v
	}
	paged.Set("per_page", strconv.Itoa(page.PerPage))
	paged.Set("page", strconv.Itoa(page.Number))
	body, header, err := c.get(ctx, path, paged, limit)
	if err != nil {
		return nil, Page{}, err
	}
	return body, nextPage(header.Get("Link"), page), nil
}

// nextPage reads rel="next" from a Link header. Only a page number above the
// current one counts, so a hostile header cannot make a caller loop.
func nextPage(link string, current Page) Page {
	for _, entry := range strings.Split(link, ",") {
		target, params, ok := strings.Cut(entry, ";")
		if !ok || !strings.Contains(params, `rel="next"`) {
			continue
		}
		u, err := url.Parse(strings.Trim(strings.TrimSpace(target), "<>"))
		if err != nil {
			continue
		}
		if n, err := strconv.Atoi(u.Query().Get("page")); err == nil && n > current.Number {
			return Page{Number: n, PerPage: current.PerPage}
		}
	}
	return Page{}
}

// get sends one GET to the API and returns the body, capped at limit bytes.
func (c *client) get(ctx context.Context, path string, q url.Values, limit int64) ([]byte, http.Header, error) {
	u := *c.base
	u.Path = c.base.Path + path
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("github: build request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", apiVersion)
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.http.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, nil, fmt.Errorf("github: GET %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	switch {
	case err != nil:
		return nil, nil, fmt.Errorf("github: read answer to GET %s: %w", path, err)
	case int64(len(body)) > limit:
		return nil, nil, fmt.Errorf("github: GET %s: %w", path, netguard.ErrBodyTooLarge)
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return nil, nil, c.apiError(resp, body)
	}
	return body, resp.Header, nil
}

func (c *client) apiError(resp *http.Response, body []byte) error {
	var doc struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(body, &doc)
	e := &APIError{Status: resp.StatusCode, Message: c.sanitize(doc.Message)}
	if (resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests) &&
		resp.Header.Get("X-RateLimit-Remaining") == "0" {
		e.RateLimited = true
		if reset, err := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64); err == nil {
			e.ResetsAt = time.Unix(reset, 0).UTC()
		}
	}
	return e
}

// sanitize makes a server message safe to show: the token removed, control
// characters dropped, length bounded.
func (c *client) sanitize(s string) string {
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
