// Command ghsim is the GitHub world of the M4 e2e tests, in one container: the fake GitHub REST
// API (ghfake) behind a TLS listener, a virtual Sigstore whose attestations and trusted root the
// tests hand out, a webhook sender, and an OCI registry. The tests drive it over /sim/*.
//
// `ghsim app` is also the workload the tests deploy (the image holds this very binary).
//
// It is test infrastructure: nothing here ships in a release.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/registry"

	"github.com/autarquico/supermgmt/internal/providers/github/ghfake"
)

const usage = "usage: ghsim serve -cert FILE -key FILE [-listen ADDR] [-registry-listen ADDR] | app | probe URL"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "app":
		err = runApp()
	case "probe":
		err = probe(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q\n%s", os.Args[1], usage)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ghsim:", err)
		os.Exit(1)
	}
}

// ---- the simulator ---------------------------------------------------------------------------

// simTB lets ghfake, which is written for *testing.T, run in a server: a failed check becomes a
// panic the control handler turns into a 422, never a dead simulator.
type simTB struct {
	testing.TB
}

type simFailure string

func (simTB) Helper()                           {}
func (simTB) Fatal(args ...any)                 { panic(simFailure(fmt.Sprint(args...))) }
func (simTB) Fatalf(format string, args ...any) { panic(simFailure(fmt.Sprintf(format, args...))) }
func (simTB) Cleanup(func())                    {}

// sim is the GitHub side: the fake API and the virtual Sigstore.
type sim struct {
	fake     *ghfake.Fake
	oidc     *ghfake.OIDCIssuer
	issuer   string // the public origin of the OIDC issuer
	checks   *ghfake.Checks
	attests  *ghfake.Attestations
	sigstore *ghfake.Sigstore
	tb       simTB
	mu       sync.Mutex // the fake registers one thing at a time
}

func newSim(issuer string) *sim {
	var tb simTB
	f := ghfake.New(tb)
	return &sim{
		fake: f, oidc: ghfake.NewOIDCIssuer(tb), issuer: issuer,
		checks: f.ServeChecks(), attests: ghfake.ServeAttestations(f), sigstore: ghfake.NewSigstore(tb), tb: tb,
	}
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := fs.String("listen", ":443", "TLS address of the GitHub API and the /sim control API")
	registryListen := fs.String("registry-listen", ":5000", "TLS address of the OCI registry")
	oidcListen := fs.String("oidc-listen", ":8444", "TLS address of the Actions OIDC issuer")
	oidcIssuer := fs.String("oidc-issuer", "https://ghsim.test:8444", "public origin of the Actions OIDC issuer")
	cert := fs.String("cert", "", "TLS certificate file")
	key := fs.String("key", "", "TLS private key file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cert == "" || *key == "" {
		return errors.New("serve needs -cert and -key")
	}
	s := newSim(*oidcIssuer)
	proxy, err := s.githubProxy()
	if err != nil {
		return err
	}
	oidcProxy, err := s.oidcProxy()
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("/sim/", s.control())
	mux.Handle("/", proxy)

	quiet := log.New(io.Discard, "", 0)
	servers := []*http.Server{
		{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second},
		{Addr: *oidcListen, Handler: oidcProxy, ReadHeaderTimeout: 10 * time.Second},
		{Addr: *registryListen, Handler: registry.New(registry.Logger(quiet)), ReadHeaderTimeout: 10 * time.Second},
	}
	failed := make(chan error, len(servers))
	for _, srv := range servers {
		go func() { failed <- srv.ListenAndServeTLS(*cert, *key) }()
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, os.Interrupt)
	select {
	case err := <-failed:
		return err
	case <-stop:
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, srv := range servers {
		_ = srv.Shutdown(ctx)
	}
	return nil
}

// githubProxy exposes the fake, which listens under a throwaway CA and answers for ghfake.ServerIP
// only, under this listener's certificate: clients verify the name they dial.
func (s *sim) githubProxy() (http.Handler, error) {
	return fakeProxy(s.fake.Endpoint(), ghfake.ServerIP, s.fake.CAPEM(), s.fake.Dial, nil)
}

// oidcProxy exposes the Actions issuer on the public origin: its discovery document names the
// issuer by the address ghfake gave it, so that name is replaced by the origin the daemon is told.
func (s *sim) oidcProxy() (http.Handler, error) {
	local := []byte(s.oidc.Issuer())
	public := []byte(s.issuer)
	rewrite := func(resp *http.Response) error {
		if resp.Request.URL.Path != "/.well-known/openid-configuration" {
			return nil
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		body = bytes.ReplaceAll(body, local, public)
		resp.Body = io.NopCloser(bytes.NewReader(body))
		resp.ContentLength = int64(len(body))
		resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
		return nil
	}
	return fakeProxy(s.oidc.Issuer(), ghfake.OIDCServerIP, s.oidc.CAPEM(), s.oidc.Dial, rewrite)
}

// fakeProxy forwards to a ghfake server wherever it listens: dial reaches it, and its certificate
// is verified for serverName under caPEM.
func fakeProxy(endpoint, serverName string, caPEM []byte, dial func(network, address string) (net.Conn, error), modify func(*http.Response) error) (http.Handler, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("the fake's CA is unreadable")
	}
	target, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	return &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) { r.SetURL(target); r.Out.Host = target.Host },
		Transport: &http.Transport{
			DialContext:     func(context.Context, string, string) (net.Conn, error) { return dial("tcp", "") },
			TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: serverName, MinVersion: tls.VersionTLS12},
		},
		ModifyResponse: modify,
		ErrorLog:       log.New(io.Discard, "", 0),
	}, nil
}

// ---- the control API ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// control is /sim/*: the tests set the GitHub world up and read what the product asked of it.
func (s *sim) control() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /sim/health", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, map[string]bool{"ok": true}) })
	mux.HandleFunc("GET /sim/trusted-root", s.trustedRoot)
	mux.HandleFunc("GET /sim/requests", s.requests)
	mux.HandleFunc("POST /sim/repos", s.addRepo)
	mux.HandleFunc("POST /sim/files", s.addFile)
	mux.HandleFunc("POST /sim/check-runs", s.addCheckRun)
	mux.HandleFunc("POST /sim/workflow-runs", s.addWorkflowRun)
	mux.HandleFunc("POST /sim/attestations", s.addAttestation)
	mux.HandleFunc("POST /sim/webhooks", s.sendWebhook)
	mux.HandleFunc("POST /sim/oidc-tokens", s.signOIDCToken)
	return mux
}

// guarded decodes a strict JSON body into the handler's request type and answers 422 for a
// malformed body or a registration the fake refuses.
func guarded[T any](s *sim, apply func(T)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req T
		dec := json.NewDecoder(io.LimitReader(r.Body, 8<<20))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
			return
		}
		if err := s.try(func() { apply(req) }); err != nil {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

// try runs a registration and turns the fake's failure into an error.
func (s *sim) try(register func()) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer func() {
		if r := recover(); r != nil {
			failure, ok := r.(simFailure)
			if !ok {
				panic(r)
			}
			err = errors.New(string(failure))
		}
	}()
	register()
	return nil
}

type repoRequest struct {
	ID            int64  `json:"id"`
	OwnerID       int64  `json:"owner_id"`
	Owner         string `json:"owner"`
	Name          string `json:"name"`
	DefaultBranch string `json:"default_branch"`
	Private       bool   `json:"private"`
}

func (s *sim) addRepo(w http.ResponseWriter, r *http.Request) {
	guarded(s, func(q repoRequest) {
		s.fake.AddRepo(ghfake.Repo{ID: q.ID, OwnerID: q.OwnerID, Owner: q.Owner, Name: q.Name, DefaultBranch: q.DefaultBranch, Private: q.Private})
	})(w, r)
}

type fileRequest struct {
	RepoID  int64  `json:"repo_id"`
	Commit  string `json:"commit"`
	Path    string `json:"path"`
	Content string `json:"content"`
}

func (s *sim) addFile(w http.ResponseWriter, r *http.Request) {
	guarded(s, func(q fileRequest) { s.fake.AddFile(q.RepoID, q.Commit, q.Path, []byte(q.Content)) })(w, r)
}

type checkRunRequest struct {
	RepoID     int64  `json:"repo_id"`
	Commit     string `json:"commit"`
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	AppID      int64  `json:"app_id"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion"`
	SuiteID    int64  `json:"suite_id"`
}

func (s *sim) addCheckRun(w http.ResponseWriter, r *http.Request) {
	guarded(s, func(q checkRunRequest) {
		now := time.Now().UTC() //nolint:forbidigo // the fake GitHub host's own clock
		run := ghfake.CheckRun{ID: q.ID, Name: q.Name, AppID: q.AppID, Status: q.Status, Conclusion: q.Conclusion, SuiteID: q.SuiteID, StartedAt: now.Add(-time.Minute)}
		if q.Status == "completed" {
			run.CompletedAt = now
		}
		s.checks.AddCheckRun(q.RepoID, q.Commit, run)
	})(w, r)
}

type workflowRunRequest struct {
	RepoID     int64  `json:"repo_id"`
	SuiteID    int64  `json:"suite_id"`
	ID         int64  `json:"id"`
	RunAttempt int64  `json:"run_attempt"`
	Path       string `json:"path"`
	HeadBranch string `json:"head_branch"`
	HeadSHA    string `json:"head_sha"`
	Event      string `json:"event"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion"`
}

func (s *sim) addWorkflowRun(w http.ResponseWriter, r *http.Request) {
	guarded(s, func(q workflowRunRequest) {
		s.checks.AddWorkflowRun(q.RepoID, q.SuiteID, ghfake.WorkflowRun{
			ID: q.ID, RunAttempt: q.RunAttempt, Path: q.Path, HeadBranch: q.HeadBranch, HeadSHA: q.HeadSHA,
			Event: q.Event, Status: q.Status, Conclusion: q.Conclusion,
		})
	})(w, r)
}

type attestationRequest struct {
	Digest       string `json:"digest"`
	Owner        string `json:"owner"`
	Repo         string `json:"repo"`
	RepositoryID int64  `json:"repository_id"`
	WorkflowPath string `json:"workflow_path"`
	Branch       string `json:"branch"`
	CommitSHA    string `json:"commit_sha"`
	RunID        int64  `json:"run_id"`
	RunAttempt   int64  `json:"run_attempt"`
}

func (s *sim) addAttestation(w http.ResponseWriter, r *http.Request) {
	guarded(s, func(q attestationRequest) {
		bundle := s.sigstore.Attest(s.tb, q.Digest, ghfake.Build{
			Owner: q.Owner, Repo: q.Repo, RepositoryID: q.RepositoryID, WorkflowPath: q.WorkflowPath,
			Branch: q.Branch, CommitSHA: q.CommitSHA, RunID: q.RunID, RunAttempt: q.RunAttempt,
		})
		s.attests.Add(q.Owner, q.Repo, q.Digest, bundle)
	})(w, r)
}

// signOIDCToken signs the claims as the Actions issuer; the issuer claim defaults to the public origin.
func (s *sim) signOIDCToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Claims map[string]any `json:"claims"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil || len(req.Claims) == 0 {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "claims are required"})
		return
	}
	if _, ok := req.Claims["iss"]; !ok {
		req.Claims["iss"] = s.issuer
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": s.oidc.Sign(req.Claims)})
}

// trustedRoot is the virtual Sigstore as a trusted_root.json: what the daemons under test trust.
func (s *sim) trustedRoot(w http.ResponseWriter, _ *http.Request) {
	var doc []byte
	if err := s.try(func() { doc = s.sigstore.TrustedRootJSON(s.tb) }); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(doc)
}

// requests lists what the product asked the fake API, and what the fake refused.
func (s *sim) requests(w http.ResponseWriter, _ *http.Request) {
	type seen struct {
		Method string `json:"method"`
		Path   string `json:"path"`
		Query  string `json:"query"`
	}
	var all []seen
	for _, r := range s.fake.Requests() {
		all = append(all, seen{Method: r.Method, Path: r.Path, Query: r.Query.Encode()})
	}
	writeJSON(w, http.StatusOK, map[string]any{"requests": all, "rejected": s.fake.Rejected()})
}

// ---- the workload ---------------------------------------------------------------------------

// runApp is the deployed service: it listens on :8080 and answers /health. The image carries
// /etc/app/version and, for a build that must fail its health check, /etc/app/unhealthy.
func runApp() error {
	version := readTrim("/etc/app/version", "unknown")
	_, err := os.Stat("/etc/app/unhealthy")
	unhealthy := err == nil
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		if unhealthy {
			http.Error(w, "unhealthy build "+version, http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "ok "+version+"\n")
	})
	mux.HandleFunc("GET /", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, version+"\n") })
	srv := &http.Server{Addr: ":8080", Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	return srv.ListenAndServe()
}

func readTrim(path, fallback string) string {
	raw, err := os.ReadFile(path) //nolint:gosec // test image: fixed paths baked into the container
	if err != nil {
		return fallback
	}
	return strings.TrimSpace(string(raw))
}

// probe is the image's HEALTHCHECK command: exit 0 when the URL answers 2xx.
func probe(args []string) error {
	if len(args) != 1 {
		return errors.New("probe takes one URL")
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, args[0], nil) //nolint:gosec // test image HEALTHCHECK probes its own fixed URL
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req) //nolint:gosec // same fixed URL
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s answered %d", args[0], resp.StatusCode)
	}
	return nil
}
