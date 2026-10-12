package github

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/netguard"
	"github.com/autarquico/supermgmt/internal/providers/github/ghfake"
)

const (
	testTimeout = 2 * time.Second
	commitA     = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

func newClientFor(t *testing.T, f *ghfake.Fake, token string) *client {
	t.Helper()
	c, err := New(f.Endpoint(), f.CAPEM(), audit.Secret(token),
		WithHTTPTimeout(testTimeout), WithNetguardOptions(netguard.WithTestDialer(f.Dial)))
	if err != nil {
		t.Fatal(err)
	}
	return c.(*client)
}

func newEnv(t *testing.T) (*ghfake.Fake, *client) {
	t.Helper()
	f := ghfake.New(t)
	return f, newClientFor(t, f, f.Token())
}

func assertNothingRejected(t *testing.T, f *ghfake.Fake) {
	t.Helper()
	if rejected := f.Rejected(); len(rejected) != 0 {
		t.Errorf("the client left the fake's contract: %v", rejected)
	}
}

func TestNew_RejectsBadInput(t *testing.T) {
	tests := []struct {
		name, url, token string
		ca               []byte
	}{
		{"http", "http://api.github.com", "t", nil},
		{"no host", "https://", "t", nil},
		{"userinfo", "https://u:p@api.github.com", "t", nil},
		{"query", "https://api.github.com?x=1", "t", nil},
		{"fragment", "https://api.github.com#x", "t", nil},
		{"trailing slash", "https://ghe.example.com/api/v3/", "t", nil},
		{"double slash", "https://ghe.example.com/api//v3", "t", nil},
		{"not a url", "://", "t", nil},
		{"empty token", "https://api.github.com", "", nil},
		{"CA without PEM", "https://api.github.com", "t", []byte("junk")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.url, tc.ca, audit.Secret(tc.token)); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
	for _, ok := range []string{"https://api.github.com", "https://ghe.example.com:8443/api/v3"} {
		if _, err := New(ok, nil, "t"); err != nil {
			t.Errorf("New(%q) = %v", ok, err)
		}
	}
}

func TestRepository_ReturnsGitHubsIdentifiers(t *testing.T) {
	f, c := newEnv(t)
	f.AddRepo(ghfake.Repo{ID: 42, OwnerID: 7, Owner: "acme", Name: "shop", Private: true})
	got, err := c.Repository(context.Background(), 42)
	if err != nil {
		t.Fatal(err)
	}
	want := Repo{ID: 42, OwnerID: 7, Owner: "acme", Name: "shop", URL: "https://github.com/acme/shop", DefaultBranch: "main", Private: true}
	if got != want {
		t.Errorf("Repository = %+v, want %+v", got, want)
	}
	assertNothingRejected(t, f)
}

func TestRepository_Failures(t *testing.T) {
	f, c := newEnv(t)
	if _, err := c.Repository(context.Background(), 0); err == nil {
		t.Error("id 0 must be refused before any request")
	}
	_, err := c.Repository(context.Background(), 99)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusNotFound {
		t.Fatalf("err = %v, want APIError 404", err)
	}
	if len(f.Requests()) != 1 {
		t.Errorf("requests = %d, want 1", len(f.Requests()))
	}
}

func TestRepositories_PaginateThroughTheLinkHeader(t *testing.T) {
	f, c := newEnv(t)
	for i := 1; i <= 5; i++ {
		f.AddRepo(ghfake.Repo{ID: int64(i), OwnerID: 7, Owner: "acme", Name: "r" + strconv.Itoa(i)})
	}
	var ids []int64
	page := Page{PerPage: 2}
	for pages := 0; ; pages++ {
		if pages > 5 {
			t.Fatal("pagination does not terminate")
		}
		repos, next, err := c.Repositories(context.Background(), page)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range repos {
			ids = append(ids, r.ID)
		}
		if next.Number == 0 {
			break
		}
		if next.PerPage != 2 {
			t.Errorf("next.PerPage = %d, want 2", next.PerPage)
		}
		page = next
	}
	if fmt.Sprint(ids) != "[1 2 3 4 5]" {
		t.Errorf("ids = %v", ids)
	}
	assertNothingRejected(t, f)
}

func TestRepositories_DefaultsToTheLargestPage(t *testing.T) {
	f, c := newEnv(t)
	f.AddRepo(ghfake.Repo{ID: 1, OwnerID: 7, Owner: "acme", Name: "r"})
	if _, _, err := c.Repositories(context.Background(), Page{PerPage: 5000}); err != nil {
		t.Fatal(err)
	}
	q := f.Requests()[0].Query
	if q.Get("per_page") != "100" || q.Get("page") != "1" {
		t.Errorf("query = %v", q)
	}
}

func TestNextPage_IgnoresHostileLinkHeaders(t *testing.T) {
	cur := Page{Number: 2, PerPage: 10}
	tests := []struct {
		name, link string
		want       int
	}{
		{"next", `<https://x/y?page=3>; rel="next", <https://x/y?page=9>; rel="last"`, 3},
		{"no next", `<https://x/y?page=1>; rel="prev"`, 0},
		{"going backwards", `<https://x/y?page=1>; rel="next"`, 0},
		{"same page", `<https://x/y?page=2>; rel="next"`, 0},
		{"no page", `<https://x/y>; rel="next"`, 0},
		{"junk", `;;,,<>`, 0},
		{"empty", ``, 0},
	}
	for _, tc := range tests {
		if got := nextPage(tc.link, cur).Number; got != tc.want {
			t.Errorf("%s: next = %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestClient_RejectsAWrongToken(t *testing.T) {
	f := ghfake.New(t)
	c := newClientFor(t, f, "github_pat_wrong_token_value")
	_, err := c.Repository(context.Background(), 1)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusUnauthorized {
		t.Fatalf("err = %v, want APIError 401", err)
	}
	if strings.Contains(err.Error(), "wrong_token") {
		t.Errorf("the token leaked into %q", err)
	}
}

func TestClient_RateLimitIsReportedWithItsReset(t *testing.T) {
	f, c := newEnv(t)
	f.ExhaustRateLimit()
	_, err := c.Repository(context.Background(), 1)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || !apiErr.RateLimited || apiErr.Status != http.StatusForbidden {
		t.Fatalf("err = %v, want a rate-limited APIError", err)
	}
	if apiErr.ResetsAt.IsZero() {
		t.Error("ResetsAt is empty")
	}
}

func TestClient_SendsGitHubHeadersAndTheToken(t *testing.T) {
	f, c := newEnv(t)
	var accept, version, agent string
	f.Handle("GET /probe", nil, func(w http.ResponseWriter, r *http.Request) {
		accept, version, agent = r.Header.Get("Accept"), r.Header.Get("X-GitHub-Api-Version"), r.Header.Get("User-Agent")
		ghfake.WriteJSON(w, map[string]bool{"ok": true})
	})
	if _, _, err := c.get(context.Background(), "/probe", nil, 1<<10); err != nil {
		t.Fatal(err)
	}
	if accept != "application/vnd.github+json" || version != apiVersion || agent != userAgent {
		t.Errorf("headers = %q %q %q", accept, version, agent)
	}
	if got := f.Requests()[0].Authorization; got != "Bearer "+f.Token() {
		t.Errorf("Authorization = %q", got)
	}
}

func TestClient_TokenNeverOffOrigin(t *testing.T) {
	f, c := newEnv(t)
	f.Redirect("/start", "https://"+ghfake.ServerIP+":8443/final")
	if _, _, err := c.get(context.Background(), "/start", nil, 1<<10); !errors.Is(err, netguard.ErrRedirect) {
		t.Fatalf("err = %v, want netguard.ErrRedirect", err)
	}
	for _, r := range f.Requests() {
		if r.Host != ghfake.ServerIP {
			t.Errorf("a request reached %q", r.Host)
		}
	}
	if len(f.Requests()) != 1 {
		t.Errorf("requests = %d, want 1", len(f.Requests()))
	}
}

func TestClient_TokenNeverInErrors(t *testing.T) {
	f, c := newEnv(t)
	f.Handle("GET /echo", nil, func(w http.ResponseWriter, r *http.Request) {
		ghfake.WriteError(w, http.StatusBadRequest, "bad credential "+strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")+"\x1b[31m")
	})
	_, _, err := c.get(context.Background(), "/echo", nil, 1<<10)
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), f.Token()) || strings.ContainsRune(err.Error(), '\x1b') {
		t.Errorf("unsafe error text %q", err)
	}
	if !strings.Contains(apiErr.Message, "[redacted]") {
		t.Errorf("message = %q, want the token redacted", apiErr.Message)
	}
}

func TestClient_TransportErrorsDoNotCarryTheToken(t *testing.T) {
	f := ghfake.New(t)
	c, err := New(f.Endpoint(), f.CAPEM(), audit.Secret(f.Token()), WithHTTPTimeout(testTimeout),
		WithNetguardOptions(netguard.WithTestDialer(func(string, string) (net.Conn, error) {
			return nil, errors.New("connection refused")
		})))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Repository(context.Background(), 1)
	if err == nil || strings.Contains(err.Error(), f.Token()) {
		t.Fatalf("err = %v", err)
	}
}

func TestClient_AnswersLargerThanTheEndpointCapAreRefused(t *testing.T) {
	f, c := newEnv(t)
	f.Handle("GET /big", nil, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 2048)))
	})
	_, _, err := c.get(context.Background(), "/big", nil, 1024)
	if !errors.Is(err, netguard.ErrBodyTooLarge) {
		t.Fatalf("err = %v, want ErrBodyTooLarge", err)
	}
}

func TestFake_RejectsMissingTokenUnknownPathsAndUnknownParameters(t *testing.T) {
	f := ghfake.New(t)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(f.CAPEM())
	hc := &http.Client{Transport: &http.Transport{
		DialContext:     func(_ context.Context, network, addr string) (net.Conn, error) { return f.Dial(network, addr) },
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}}
	do := func(path, authorization string) int {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, f.Endpoint()+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if authorization != "" {
			req.Header.Set("Authorization", authorization)
		}
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	bearer := "Bearer " + f.Token()
	tests := []struct {
		name, path, auth string
		want             int
	}{
		{"no token", "/user/repos", "", http.StatusUnauthorized},
		{"wrong token", "/user/repos", "Bearer nope", http.StatusUnauthorized},
		{"unknown path", "/orgs/acme", bearer, http.StatusNotFound},
		{"unknown parameter", "/user/repos?sort=updated", bearer, http.StatusUnprocessableEntity},
		{"oversized page", "/user/repos?per_page=101", bearer, http.StatusUnprocessableEntity},
		{"known", "/user/repos", bearer, http.StatusOK},
	}
	for _, tc := range tests {
		if got := do(tc.path, tc.auth); got != tc.want {
			t.Errorf("%s: status = %d, want %d", tc.name, got, tc.want)
		}
	}
	if rejected := f.Rejected(); len(rejected) != 2 {
		t.Errorf("rejected = %v, want the unknown path and the unknown parameter", rejected)
	}
}

func jsonOf(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCheckRuns_ReadsEveryPageOfEveryAttempt(t *testing.T) {
	f, c := newEnv(t)
	repo := Repo{Owner: "acme", Name: "shop"}
	const total = 205
	f.Handle("GET /repos/{owner}/{repo}/commits/{sha}/check-runs", []string{"filter", "per_page", "page"}, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("filter") != "all" {
			ghfake.WriteError(w, http.StatusUnprocessableEntity, "filter=all is required to see older attempts")
			return
		}
		lo, hi, ok := ghfake.Paginate(w, r, total)
		if !ok {
			return
		}
		runs := make([]map[string]any, 0, hi-lo)
		for i := lo; i < hi; i++ {
			runs = append(runs, map[string]any{
				"id": i + 1, "name": "ci", "status": "completed", "conclusion": "success", "head_sha": commitA,
				"started_at": "2026-10-12T10:00:00Z", "completed_at": "2026-10-12T10:05:00Z",
				"app": map[string]any{"id": 15368}, "check_suite": map[string]any{"id": 900 + i},
			})
		}
		ghfake.WriteJSON(w, map[string]any{"total_count": total, "check_runs": runs})
	})
	runs, err := c.CheckRuns(context.Background(), repo, commitA)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != total {
		t.Fatalf("runs = %d, want %d", len(runs), total)
	}
	first := runs[0]
	want := CheckRun{
		ID: 1, Name: "ci", AppID: 15368, Status: "completed", Conclusion: "success", HeadSHA: commitA, SuiteID: 900,
		StartedAt: time.Date(2026, 10, 12, 10, 0, 0, 0, time.UTC), CompletedAt: time.Date(2026, 10, 12, 10, 5, 0, 0, time.UTC),
	}
	if first != want {
		t.Errorf("first = %+v, want %+v", first, want)
	}
	assertNothingRejected(t, f)
}

func TestCheckRuns_RefusesBadInput(t *testing.T) {
	_, c := newEnv(t)
	for _, tc := range []struct {
		repo Repo
		sha  string
	}{
		{Repo{Owner: "acme", Name: "shop"}, "main"},
		{Repo{Owner: "acme", Name: "shop"}, strings.ToUpper(commitA)},
		{Repo{Owner: "../x", Name: "shop"}, commitA},
		{Repo{Owner: "acme", Name: ".."}, commitA},
		{Repo{}, commitA},
	} {
		if _, err := c.CheckRuns(context.Background(), tc.repo, tc.sha); err == nil {
			t.Errorf("CheckRuns(%+v, %q) must fail", tc.repo, tc.sha)
		}
	}
}

func TestWorkflowRun(t *testing.T) {
	f, c := newEnv(t)
	repo := Repo{Owner: "acme", Name: "shop"}
	f.Handle("GET /repos/{owner}/{repo}/actions/runs", []string{"check_suite_id"}, func(w http.ResponseWriter, r *http.Request) {
		runs := []map[string]any{}
		switch r.URL.Query().Get("check_suite_id") {
		case "900":
			runs = append(runs, map[string]any{
				"id": 5, "run_attempt": 2, "path": ".github/workflows/ci.yml", "head_branch": "main",
				"head_sha": commitA, "event": "push", "status": "completed", "conclusion": "success",
			})
		case "901":
			runs = append(runs, map[string]any{"id": 6}, map[string]any{"id": 7})
		}
		ghfake.WriteJSON(w, map[string]any{"total_count": len(runs), "workflow_runs": runs})
	})
	got, err := c.WorkflowRun(context.Background(), repo, 900)
	if err != nil {
		t.Fatal(err)
	}
	want := WorkflowRun{ID: 5, RunAttempt: 2, Path: ".github/workflows/ci.yml", HeadBranch: "main", HeadSHA: commitA, Event: "push", Status: "completed", Conclusion: "success"}
	if got != want {
		t.Errorf("WorkflowRun = %+v, want %+v", got, want)
	}
	if _, err := c.WorkflowRun(context.Background(), repo, 902); !errors.Is(err, ErrNoWorkflowRun) {
		t.Errorf("suite without a run: err = %v, want ErrNoWorkflowRun", err)
	}
	if _, err := c.WorkflowRun(context.Background(), repo, 901); err == nil {
		t.Error("a suite mapping to two runs must be refused")
	}
	if _, err := c.WorkflowRun(context.Background(), repo, 0); err == nil {
		t.Error("suite id 0 must be refused")
	}
	assertNothingRejected(t, f)
}

func TestAttestations(t *testing.T) {
	f, c := newEnv(t)
	repo := Repo{Owner: "acme", Name: "shop"}
	digest := "sha256:" + strings.Repeat("ab", 32)
	f.Handle("GET /repos/{owner}/{repo}/attestations/{digest}", nil, func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("digest") != digest {
			ghfake.WriteError(w, http.StatusNotFound, "Not Found")
			return
		}
		ghfake.WriteJSON(w, map[string]any{"attestations": []map[string]any{{"bundle": map[string]string{"mediaType": "bundle"}}}})
	})
	bundles, err := c.Attestations(context.Background(), repo, digest)
	if err != nil || len(bundles) != 1 || string(jsonOf(t, json.RawMessage(bundles[0]))) != `{"mediaType":"bundle"}` {
		t.Fatalf("bundles = %s, err = %v", bundles, err)
	}
	none, err := c.Attestations(context.Background(), repo, "sha256:"+strings.Repeat("cd", 32))
	if err != nil || len(none) != 0 {
		t.Errorf("unknown digest: %v, %v; want an empty list", none, err)
	}
	for _, bad := range []string{"", "sha256:xyz", "sha1:" + strings.Repeat("a", 40), "sha256:" + strings.Repeat("AB", 32)} {
		if _, err := c.Attestations(context.Background(), repo, bad); err == nil {
			t.Errorf("digest %q must be refused", bad)
		}
	}
}
