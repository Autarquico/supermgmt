package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

var later = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

const (
	tokenOne = "smt_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_AbCd"
	tokenTwo = "smt_ZyXwVuTsRqPoNmLkJiHgFeDcBa9876543210-_ZyXw"
)

// remoteBox is a sandboxed user with a fake HTTPS control plane. The
// environment has no PATH, so the credential store is the 0600 file.
type remoteBox struct {
	t      *testing.T
	dir    string
	env    []string
	srv    *httptest.Server
	caFile string

	mu   sync.Mutex
	reqs []sentRequest
}

type routes = map[string]http.HandlerFunc

func newRemoteBox(t *testing.T, handlers routes) *remoteBox {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b := &remoteBox{t: t, dir: dir, env: []string{"HOME=" + dir, "XDG_CONFIG_HOME=" + filepath.Join(dir, "xdg"), envNoAutostart + "=1"}}
	serve := router(handlers)
	b.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		b.mu.Lock()
		b.reqs = append(b.reqs, sentRequest{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Clone(), string(body)})
		b.mu.Unlock()
		serve(w, r)
	}))
	t.Cleanup(b.srv.Close)
	b.caFile = filepath.Join(dir, "ca.pem")
	block := &pem.Block{Type: "CERTIFICATE", Bytes: b.srv.Certificate().Raw}
	writeFile(t, b.caFile, string(pem.EncodeToMemory(block)))
	return b
}

func (b *remoteBox) requests() []sentRequest {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]sentRequest(nil), b.reqs...)
}

// requestsTo lists the recorded requests of one route.
func (b *remoteBox) requestsTo(method, path string) []sentRequest {
	var out []sentRequest
	for _, r := range b.requests() {
		if r.Method == method && r.Path == path {
			out = append(out, r)
		}
	}
	return out
}

func testRoot(env []string, extra ...*cobra.Command) *cobra.Command {
	root := &cobra.Command{Use: "sm", SilenceUsage: true, SilenceErrors: true, Args: noArgs}
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return usageErrorf("%s", err) })
	root.PersistentFlags().String("config", "", "")
	root.PersistentFlags().Bool("json", false, "")
	root.PersistentFlags().String("log-level", "info", "")
	supplied := map[string]bool{}
	for _, c := range extra {
		supplied[c.Name()] = true
	}
	for _, c := range clientCommands(env) {
		if !supplied[c.Name()] { // the test supplies its own
			root.AddCommand(c)
		}
	}
	root.AddCommand(extra...)
	return root
}

func execRoot(env []string, stdin string, args []string, extra ...*cobra.Command) result {
	root := testRoot(env, extra...)
	var out, errOut bytes.Buffer
	root.SetIn(strings.NewReader(stdin))
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(args)
	err := root.ExecuteContext(context.Background())
	if err != nil {
		asJSON, _ := root.PersistentFlags().GetBool("json")
		reportError(&errOut, err, asJSON)
	}
	return result{exitCode(err), out.String(), errOut.String()}
}

func (b *remoteBox) run(stdin string, args ...string) result {
	return execRoot(b.env, stdin, args)
}

func (b *remoteBox) runLogin(deps loginDeps, stdin string, args ...string) result {
	return execRoot(b.env, stdin, append([]string{"login"}, args...), newLoginCmd(b.env, deps))
}

// useProfile adds and selects the profile "home" for the fake server.
func (b *remoteBox) useProfile() {
	b.t.Helper()
	if r := b.run("", "profile", "add", "home", "--url", b.srv.URL, "--ca-file", b.caFile, "--use"); r.code != 0 {
		b.t.Fatalf("profile add: %d %s", r.code, r.stderr)
	}
}

func (b *remoteBox) signIn(token string) {
	b.t.Helper()
	if _, err := credentialStore(b.env).Set(context.Background(), "home", token); err != nil {
		b.t.Fatal(err)
	}
}

func (b *remoteBox) storedToken() string {
	token, _ := credentialStore(b.env).Get(context.Background(), "home")
	return token
}

func meRoute(token string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if token != "" && r.Header.Get("Authorization") != "Bearer "+token {
			replyError(w, http.StatusUnauthorized, smerr.CodeUnauthenticated, "", "invalid credential")
			return
		}
		reply(w, 200, wire.Me{IdentityID: "0192a000-0000-7000-8000-00000000a001", DisplayName: "alex", InstanceMode: "server"})
	}
}

func assertNoSecret(t *testing.T, secret string, r result) {
	t.Helper()
	if strings.Contains(r.stdout, secret) || strings.Contains(r.stderr, secret) {
		t.Errorf("the secret %q appeared in the output:\nstdout: %s\nstderr: %s", secret, r.stdout, r.stderr)
	}
}

// ---- sm profile ----------------------------------------------------------------------------

func TestProfileAddListUseRemove(t *testing.T) {
	b := newRemoteBox(t, nil)

	add := b.run("", "profile", "add", "home", "--url", b.srv.URL+"/", "--ca-file", b.caFile)
	if add.code != 0 {
		t.Fatalf("add: %d %s", add.code, add.stderr)
	}
	b.run("", "profile", "add", "work", "--url", "https://work.example.com")
	b.signIn(tokenOne)

	list := b.run("", "--json", "profile", "list")
	var views []profileView
	if err := json.Unmarshal([]byte(list.stdout), &views); err != nil || len(views) != 2 {
		t.Fatalf("list = %q, %v", list.stdout, err)
	}
	if !views[0].Current || views[0].Name != "home" || views[0].LoggedIn == nil || !*views[0].LoggedIn || *views[1].LoggedIn {
		t.Errorf("views = %+v; want home current and signed in, work not", views)
	}
	if views[0].URL != b.srv.URL {
		t.Errorf("the URL must be stored as an origin: %q", views[0].URL)
	}
	if human := b.run("", "profile", "list"); !strings.Contains(human.stdout, "SIGNED IN") || !strings.Contains(human.stdout, "*") {
		t.Errorf("human list:\n%s", human.stdout)
	}

	if use := b.run("", "profile", "use", "work"); use.code != 0 {
		t.Fatalf("use: %s", use.stderr)
	}
	if again := b.run("", "profile", "add", "work", "--url", "https://x.example.com"); again.code != 1 {
		t.Errorf("duplicate add: exit %d, %q", again.code, again.stderr)
	}
	if rm := b.run("", "profile", "remove", "home"); rm.code != 0 {
		t.Fatalf("remove: %s", rm.stderr)
	}
	if b.storedToken() != "" {
		t.Errorf("removing a profile left its credential behind")
	}
	if missing := b.run("", "profile", "use", "home"); missing.code != 1 || !strings.Contains(missing.stderr, `no profile named "home"`) {
		t.Errorf("use removed: %d %q", missing.code, missing.stderr)
	}
}

func TestProfilesFileIsOwnerOnly(t *testing.T) {
	b := newRemoteBox(t, nil)
	b.useProfile()

	info, err := os.Stat(profilesFile(b.env))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("profiles.yaml mode = %04o, want 0600", info.Mode().Perm())
	}
	if data, _ := os.ReadFile(profilesFile(b.env)); strings.Contains(string(data), "token") {
		t.Errorf("the profiles file mentions a token:\n%s", data)
	}
}

func TestProfileAddValidatesBeforeWriting(t *testing.T) {
	b := newRemoteBox(t, nil)
	tests := [][]string{
		{"profile", "add", "p"},
		{"profile", "add", "p", "--url", "http://mgmt.example.com"},
		{"profile", "add", "p", "--url", "https://mgmt.example.com", "--ca-file", filepath.Join(b.dir, "absent.pem")},
		{"profile", "add", "p", "--url", "https://mgmt.example.com", "--local"},
		{"profile", "add", "Bad Name", "--url", "https://mgmt.example.com"},
		{"profile", "add", "p", "--config-file", "/x"},
	}
	for _, args := range tests {
		if r := b.run("", args...); r.code != exitUsage {
			t.Errorf("%v: exit %d, %q", args, r.code, r.stderr)
		}
	}
	if _, err := os.Stat(profilesFile(b.env)); err == nil {
		t.Error("a refused add created the profiles file")
	}
}

// ---- remote commands --------------------------------------------------------------------------

func TestRemoteCommandsSendTheStoredBearer(t *testing.T) {
	b := newRemoteBox(t, routes{
		"GET " + wire.PathNodes: func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer "+tokenOne {
				replyError(w, 401, smerr.CodeUnauthenticated, "", "no")
				return
			}
			reply(w, 200, wire.Page[wire.Node]{Items: []wire.Node{{Name: "web-1"}}})
		},
	})
	b.useProfile()
	b.signIn(tokenOne)

	r := b.run("", "--log-level", "debug", "nodes", "list")

	if r.code != 0 || !strings.Contains(r.stdout, "web-1") {
		t.Fatalf("exit %d: %s %s", r.code, r.stdout, r.stderr)
	}
	assertNoSecret(t, tokenOne, r)
	for _, kv := range b.env {
		if strings.Contains(kv, tokenOne) {
			t.Errorf("the token is in the environment: %q", kv)
		}
	}
}

func TestRemoteCommandWithoutLoginPointsAtLogin(t *testing.T) {
	b := newRemoteBox(t, routes{
		"GET " + wire.PathNodes: func(w http.ResponseWriter, _ *http.Request) {
			replyError(w, 401, smerr.CodeUnauthenticated, "", "missing bearer token")
		},
	})
	b.useProfile()

	r := b.run("", "nodes", "list")

	if r.code != exitInternal || !strings.Contains(r.stderr, "sm login") {
		t.Errorf("exit %d, stderr %q; want the hint to sign in", r.code, r.stderr)
	}
	if got := b.requests()[0].Header.Get("Authorization"); got != "" {
		t.Errorf("sent %q without a stored credential", got)
	}
}

func TestExplicitConfigBeatsTheCurrentRemoteProfile(t *testing.T) {
	local := newFakeAPI(t, router(routes{
		"GET " + wire.PathMe: func(w http.ResponseWriter, _ *http.Request) { reply(w, 200, wire.Me{DisplayName: "local-alex"}) },
	}))
	b := newRemoteBox(t, nil)
	b.env = local.Env
	if r := execRoot(local.Env, "", []string{"profile", "add", "home", "--url", b.srv.URL, "--ca-file", b.caFile, "--use"}); r.code != 0 {
		t.Fatalf("profile add: %s", r.stderr)
	}

	r := execRoot(local.Env, "", append(append([]string{}, local.Args...), "status"))

	if len(b.requests()) != 0 || len(local.Requests()) == 0 {
		t.Errorf("--config must keep the command local: remote saw %d, local saw %d (exit %d, %s)", len(b.requests()), len(local.Requests()), r.code, r.stderr)
	}
}

func TestLocalProfileUsesItsConfigFile(t *testing.T) {
	local := newFakeAPI(t, router(routes{
		"GET " + wire.PathMe: func(w http.ResponseWriter, _ *http.Request) { reply(w, 200, wire.Me{DisplayName: "local-alex"}) },
	}))
	configFile := local.Args[1]
	if r := execRoot(local.Env, "", []string{"profile", "add", "laptop", "--local", "--config-file", configFile, "--use"}); r.code != 0 {
		t.Fatalf("profile add: %s", r.stderr)
	}

	r := execRoot(local.Env, "", []string{"status"})

	if len(local.Requests()) == 0 {
		t.Errorf("a local profile must reach its daemon (exit %d, %s)", r.code, r.stderr)
	}
}

func TestM1LocalModeIsUnchangedWithoutProfiles(t *testing.T) {
	local := newFakeAPI(t, router(routes{
		"GET " + wire.PathNodes: func(w http.ResponseWriter, _ *http.Request) { reply(w, 200, wire.Page[wire.Node]{}) },
	}))

	if r := local.run("nodes", "list"); r.code != 0 {
		t.Errorf("exit %d: %s", r.code, r.stderr)
	}
	if h := local.Requests()[0].Header.Get("Authorization"); h != "" {
		t.Errorf("the local socket got an Authorization header %q", h)
	}
}

// ---- sm login: loopback -----------------------------------------------------------------------

type loginServer struct {
	b        *remoteBox
	start    wire.OIDCStartRequest
	exchange wire.OIDCExchangeRequest
}

func newLoginServer(t *testing.T, token string) *loginServer {
	t.Helper()
	l := &loginServer{}
	l.b = newRemoteBox(t, routes{
		"POST " + wire.PathOIDCStart: func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewDecoder(r.Body).Decode(&l.start)
			reply(w, 200, wire.OIDCStart{AuthorizationURL: l.b.srv.URL + "/authorize?client=sm", State: "state-1"})
		},
		"POST " + wire.PathOIDCExchange: func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewDecoder(r.Body).Decode(&l.exchange)
			reply(w, 200, wire.LoginSession{Token: token, IdentityID: "0192a000-0000-7000-8000-00000000a001", ExpiresAt: later})
		},
		"GET " + wire.PathMe: meRoute(token),
	})
	l.b.useProfile()
	return l
}

// browser sends the redirect with query to the redirect URI the login chose.
func (l *loginServer) browser(query string) func(context.Context, string) error {
	return func(ctx context.Context, _ string) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.start.RedirectURI+"?"+query, http.NoBody)
		if err != nil {
			return err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		return resp.Body.Close()
	}
}

func TestLoginLoopbackFlowUsesPKCEAndStoresTheSessionOutOfSight(t *testing.T) {
	l := newLoginServer(t, tokenOne)
	deps := loginDeps{openBrowser: l.browser("code=idp-code&state=state-1"), sleep: sleepContext}

	r := l.b.runLogin(deps, "")

	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	if !strings.HasPrefix(l.start.RedirectURI, "http://127.0.0.1:") || !strings.HasSuffix(l.start.RedirectURI, "/callback") {
		t.Errorf("redirect_uri = %q, want a 127.0.0.1 loopback callback", l.start.RedirectURI)
	}
	sum := sha256.Sum256([]byte(l.exchange.CodeVerifier))
	if want := base64.RawURLEncoding.EncodeToString(sum[:]); l.start.CodeChallenge != want {
		t.Errorf("code_challenge %q is not S256(code_verifier) = %q", l.start.CodeChallenge, want)
	}
	if l.exchange.Code != "idp-code" || l.exchange.State != "state-1" || l.exchange.Client != "sm" {
		t.Errorf("exchange = %+v", l.exchange)
	}
	if l.b.storedToken() != tokenOne {
		t.Errorf("stored token = %q", l.b.storedToken())
	}
	assertNoSecret(t, tokenOne, r)
	for _, want := range []string{"signed in to home as alex", "credential kept in"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, r.stdout)
		}
	}
	if !strings.Contains(r.stderr, "/authorize") {
		t.Errorf("the URL to open was not printed: %q", r.stderr)
	}
	for _, path := range []string{wire.PathOIDCStart, wire.PathOIDCExchange} {
		if k := l.b.requestsTo("POST", path)[0].Header.Get(wire.HeaderIdempotencyKey); k != "" {
			t.Errorf("%s carried Idempotency-Key %q", path, k)
		}
	}
	assertMode(t, filepath.Join(filepath.Dir(localPaths(l.b.env).Config), "credentials.json"), 0o600)
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != want {
		t.Errorf("%s mode = %04o, want %04o", path, info.Mode().Perm(), want)
	}
}

func TestLoginCallbackPortIsHonored(t *testing.T) {
	l := newLoginServer(t, tokenOne)
	probe, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()
	deps := loginDeps{openBrowser: l.browser("code=c&state=state-1"), sleep: sleepContext}

	r := l.b.runLogin(deps, "", "--callback-port", fmt.Sprint(port))

	if r.code != 0 || l.start.RedirectURI != fmt.Sprintf("http://127.0.0.1:%d/callback", port) {
		t.Errorf("exit %d, redirect_uri %q, stderr %s", r.code, l.start.RedirectURI, r.stderr)
	}
}

func TestLoginFailsClearlyWhenTheCallbackPortIsTaken(t *testing.T) {
	l := newLoginServer(t, tokenOne)
	taken, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()

	r := l.b.runLogin(loginDeps{sleep: sleepContext}, "", "--callback-port", fmt.Sprint(taken.Addr().(*net.TCPAddr).Port))

	if r.code != exitUsage || len(l.b.requestsTo("POST", wire.PathOIDCStart)) != 0 {
		t.Errorf("exit %d (%s); the login must stop before contacting the server", r.code, r.stderr)
	}
}

func TestLoginIgnoresARedirectCarryingAnotherState(t *testing.T) {
	l := newLoginServer(t, tokenOne)
	deps := loginDeps{openBrowser: l.browser("code=stolen&state=someone-elses"), sleep: sleepContext, callbackTimeout: 300 * time.Millisecond}

	r := l.b.runLogin(deps, "")

	if r.code == 0 || len(l.b.requestsTo("POST", wire.PathOIDCExchange)) != 0 {
		t.Errorf("exit %d; a foreign state must never be exchanged", r.code)
	}
	if l.b.storedToken() != "" {
		t.Error("a credential was stored")
	}
}

func TestLoginReportsAProviderRefusal(t *testing.T) {
	l := newLoginServer(t, tokenOne)
	deps := loginDeps{openBrowser: l.browser("error=access_denied&state=state-1"), sleep: sleepContext}

	r := l.b.runLogin(deps, "")

	if r.code == 0 || !strings.Contains(r.stderr, "access_denied") {
		t.Errorf("exit %d, stderr %q", r.code, r.stderr)
	}
}

func TestLoginWithoutAProfileExplainsHowToAddOne(t *testing.T) {
	b := newRemoteBox(t, nil)

	r := b.runLogin(loginDeps{sleep: sleepContext}, "")

	if r.code != exitUsage || !strings.Contains(r.stderr, "sm profile add") {
		t.Errorf("exit %d, stderr %q", r.code, r.stderr)
	}
}

func TestLoginNoBrowserOnlyPrintsTheURL(t *testing.T) {
	l := newLoginServer(t, tokenOne)
	opened := false
	deps := loginDeps{openBrowser: func(ctx context.Context, u string) error {
		opened = true
		return l.browser("code=c&state=state-1")(ctx, u)
	}, sleep: sleepContext}
	// --no-browser: nothing opens, so the redirect never arrives; cancel quickly.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	root := testRoot(l.b.env, newLoginCmd(l.b.env, deps))
	var errOut bytes.Buffer
	root.SetOut(io.Discard)
	root.SetErr(&errOut)
	root.SetArgs([]string{"login", "--no-browser"})

	_ = root.ExecuteContext(ctx)

	if opened || !strings.Contains(errOut.String(), "/authorize") {
		t.Errorf("opened = %v, stderr %q", opened, errOut.String())
	}
}

// ---- sm login --device --------------------------------------------------------------------------

func TestLoginDeviceFlowPollsByTransactionAndHonorsSlowDown(t *testing.T) {
	var polls []wire.DevicePollRequest
	statuses := []wire.DevicePoll{
		{Status: wire.DevicePending},
		{Status: wire.DeviceSlowDown},
		{Status: wire.DeviceComplete, Session: &wire.LoginSession{Token: tokenTwo, ExpiresAt: later}},
	}
	b := newRemoteBox(t, routes{
		"POST " + wire.PathOIDCDevice: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.DeviceStart{
				TransactionID: "txn-1", UserCode: "WDJB-MJHT", VerificationURI: "https://idp.example.com/device",
				IntervalSeconds: 2, ExpiresAt: later,
			})
		},
		"POST " + wire.PathOIDCDevicePoll: func(w http.ResponseWriter, r *http.Request) {
			var req wire.DevicePollRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			polls = append(polls, req)
			reply(w, 200, statuses[len(polls)-1])
		},
		"GET " + wire.PathMe: meRoute(tokenTwo),
	})
	b.useProfile()
	var waits []time.Duration
	deps := loginDeps{sleep: func(_ context.Context, d time.Duration) error { waits = append(waits, d); return nil }}

	r := b.runLogin(deps, "", "--device")

	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	if fmt.Sprint(waits) != "[2s 2s 7s]" {
		t.Errorf("waits = %v, want the interval, then the interval, then +5s after slow_down", waits)
	}
	for _, p := range polls {
		if p.TransactionID != "txn-1" || p.Client != "sm" {
			t.Errorf("poll = %+v", p)
		}
	}
	if !strings.Contains(r.stderr, "WDJB-MJHT") || !strings.Contains(r.stderr, "https://idp.example.com/device") {
		t.Errorf("the user code and URL were not shown: %q", r.stderr)
	}
	if b.storedToken() != tokenTwo {
		t.Errorf("stored token = %q", b.storedToken())
	}
	assertNoSecret(t, tokenTwo, r)
}

func TestLoginDeviceFlowSurfacesAnExpiredOrConsumedTransaction(t *testing.T) {
	b := newRemoteBox(t, routes{
		"POST " + wire.PathOIDCDevice: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.DeviceStart{TransactionID: "t", UserCode: "AB", VerificationURI: "https://idp/d", IntervalSeconds: 1, ExpiresAt: later})
		},
		"POST " + wire.PathOIDCDevicePoll: func(w http.ResponseWriter, _ *http.Request) {
			replyError(w, 409, smerr.CodeConflict, "", "the login was already completed")
		},
	})
	b.useProfile()

	r := b.runLogin(loginDeps{sleep: func(context.Context, time.Duration) error { return nil }}, "", "--device")

	if r.code == 0 || !strings.Contains(r.stderr, "already completed") || b.storedToken() != "" {
		t.Errorf("exit %d, stderr %q, stored %q", r.code, r.stderr, b.storedToken())
	}
}

func TestLoginDeviceFlowStopsWhenTheCodeExpires(t *testing.T) {
	b := newRemoteBox(t, routes{
		"POST " + wire.PathOIDCDevice: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.DeviceStart{TransactionID: "t", UserCode: "AB", VerificationURI: "https://idp/d", IntervalSeconds: 1, ExpiresAt: domain.SystemClock{}.Now().Add(150 * time.Millisecond)})
		},
	})
	b.useProfile()

	r := b.runLogin(loginDeps{sleep: sleepContext}, "", "--device")

	if r.code == 0 || !strings.Contains(r.stderr, "expired") {
		t.Errorf("exit %d, stderr %q", r.code, r.stderr)
	}
}

// ---- sm login --bootstrap and --token-stdin ------------------------------------------------------

func TestLoginBootstrapReadsTheCodeFromStdinAndKeepsItOutOfEverything(t *testing.T) {
	const code = "smb_bootstrapcodebootstrapcodebootstrapcode12"
	var got wire.BootstrapRequest
	b := newRemoteBox(t, routes{
		"POST " + wire.PathBootstrap: func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewDecoder(r.Body).Decode(&got)
			reply(w, 200, wire.Bootstrapped{IdentityID: "0192a000-0000-7000-8000-00000000a001", Session: &wire.LoginSession{Token: tokenOne, ExpiresAt: later}})
		},
		"GET " + wire.PathMe: meRoute(tokenOne),
	})
	b.useProfile()

	r := b.runLogin(loginDeps{sleep: sleepContext}, code+"\n", "--bootstrap", "--display-name", "Root")

	if r.code != 0 || got.Code != code || got.DisplayName != "Root" {
		t.Fatalf("exit %d, request %+v, stderr %s", r.code, got, r.stderr)
	}
	assertNoSecret(t, code, r)
	assertNoSecret(t, tokenOne, r)
	if b.storedToken() != tokenOne {
		t.Errorf("stored = %q", b.storedToken())
	}
	if k := b.requestsTo("POST", wire.PathBootstrap)[0].Header.Get(wire.HeaderIdempotencyKey); k != "" {
		t.Errorf("bootstrap carried Idempotency-Key %q", k)
	}
}

func TestLoginBootstrapOnAnOIDCServerSendsTheHeldSession(t *testing.T) {
	var bearer string
	b := newRemoteBox(t, routes{
		"POST " + wire.PathBootstrap: func(w http.ResponseWriter, r *http.Request) {
			bearer = r.Header.Get("Authorization")
			reply(w, 200, wire.Bootstrapped{IdentityID: "0192a000-0000-7000-8000-00000000a001"})
		},
		"GET " + wire.PathMe: meRoute(tokenOne),
	})
	b.useProfile()
	b.signIn(tokenOne)

	r := b.runLogin(loginDeps{sleep: sleepContext}, "smb_code\n", "--bootstrap")

	if r.code != 0 || bearer != "Bearer "+tokenOne {
		t.Errorf("exit %d, bearer %q, stderr %s", r.code, bearer, r.stderr)
	}
}

func TestLoginTokenStdinStoresAVerifiedAPIToken(t *testing.T) {
	b := newRemoteBox(t, routes{"GET " + wire.PathMe: meRoute(tokenTwo)})
	b.useProfile()

	r := b.runLogin(loginDeps{sleep: sleepContext}, tokenTwo+"\n", "--token-stdin")

	if r.code != 0 || b.storedToken() != tokenTwo {
		t.Fatalf("exit %d, stored %q, stderr %s", r.code, b.storedToken(), r.stderr)
	}
	assertNoSecret(t, tokenTwo, r)
	profiles, _ := client.LoadProfiles(profilesFile(b.env))
	if profiles.Profiles["home"].Auth != client.AuthToken {
		t.Errorf("auth = %q, want token", profiles.Profiles["home"].Auth)
	}
}

func TestLoginTokenStdinStoresNothingTheServerRefuses(t *testing.T) {
	b := newRemoteBox(t, routes{"GET " + wire.PathMe: meRoute(tokenOne)})
	b.useProfile()

	r := b.runLogin(loginDeps{sleep: sleepContext}, tokenTwo+"\n", "--token-stdin")

	if r.code == 0 || b.storedToken() != "" {
		t.Errorf("exit %d, stored %q", r.code, b.storedToken())
	}
	assertNoSecret(t, tokenTwo, r)
}

func TestLoginModesAreAlternatives(t *testing.T) {
	b := newRemoteBox(t, nil)
	b.useProfile()

	if r := b.runLogin(loginDeps{sleep: sleepContext}, "", "--device", "--bootstrap"); r.code != exitUsage {
		t.Errorf("exit %d", r.code)
	}
}

// ---- sm logout -----------------------------------------------------------------------------------

func TestLogoutRevokesTheSessionAndForgetsTheCredential(t *testing.T) {
	b := newRemoteBox(t, routes{
		"POST " + wire.PathLogout: func(w http.ResponseWriter, r *http.Request) { reply(w, 200, struct{}{}) },
	})
	b.useProfile()
	b.signIn(tokenOne)

	r := b.run("", "logout")

	if r.code != 0 || b.storedToken() != "" {
		t.Fatalf("exit %d, stored %q, %s", r.code, b.storedToken(), r.stderr)
	}
	req := b.requestsTo("POST", wire.PathLogout)
	if len(req) != 1 || req[0].Header.Get("Authorization") != "Bearer "+tokenOne {
		t.Errorf("logout requests = %+v", req)
	}
	if again := b.run("", "logout"); again.code != 0 || !strings.Contains(again.stdout, "not signed in") {
		t.Errorf("second logout: %d %q", again.code, again.stdout)
	}
}

func TestLogoutForgetsTheCredentialEvenWhenTheServerCannotRevoke(t *testing.T) {
	b := newRemoteBox(t, routes{
		"POST " + wire.PathLogout: func(w http.ResponseWriter, _ *http.Request) {
			replyError(w, 401, smerr.CodeUnauthenticated, "", "already revoked")
		},
	})
	b.useProfile()
	b.signIn(tokenOne)

	r := b.run("", "logout")

	if r.code != 0 || b.storedToken() != "" || !strings.Contains(r.stderr, "warning") {
		t.Errorf("exit %d, stored %q, stderr %q", r.code, b.storedToken(), r.stderr)
	}
}

// ---- sm tokens -------------------------------------------------------------------------------------

func TestTokensCreatePrintsTheValueOnceOnStdoutAndNeverRepeatsIt(t *testing.T) {
	var got wire.CreateTokenRequest
	b := newRemoteBox(t, routes{
		"POST " + wire.PathTokens: func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewDecoder(r.Body).Decode(&got)
			reply(w, 201, wire.TokenIssued{
				Token: wire.Token{ID: "0192a000-0000-7000-8000-00000000a009", Name: got.Name, ExpiresAt: got.ExpiresAt},
				Value: tokenTwo,
			})
		},
		"GET " + wire.PathTokens: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Page[wire.Token]{Items: []wire.Token{{ID: "0192a000-0000-7000-8000-00000000a009", Name: "ci", Scopes: []string{"service.*"}, ExpiresAt: later}}})
		},
	})
	b.useProfile()
	b.signIn(tokenOne)

	create := b.run("", "tokens", "create", "--name", "ci", "--expires-in", "30d", "--scope", "service.restart")

	if create.code != 0 || create.stdout != tokenTwo+"\n" {
		t.Fatalf("exit %d, stdout %q (must be the value alone), stderr %s", create.code, create.stdout, create.stderr)
	}
	if !strings.Contains(create.stderr, "only time") {
		t.Errorf("stderr %q does not warn the value is shown once", create.stderr)
	}
	if got.Name != "ci" || fmt.Sprint(got.Scopes) != "[service.restart]" {
		t.Errorf("request = %+v", got)
	}
	if d := time.Until(got.ExpiresAt); d < 29*24*time.Hour || d > 30*24*time.Hour+time.Minute {
		t.Errorf("expires_at is %s from now, want 30 days", d)
	}
	if k := b.requestsTo("POST", wire.PathTokens)[0].Header.Get(wire.HeaderIdempotencyKey); k != "" {
		t.Errorf("token creation carried Idempotency-Key %q", k)
	}

	list := b.run("", "tokens", "list")
	assertNoSecret(t, tokenTwo, list)
	if !strings.Contains(list.stdout, "active") || !strings.Contains(list.stdout, "service.*") {
		t.Errorf("list:\n%s", list.stdout)
	}
}

func TestTokensCreateRefusesBadExpiryBeforeAnyRequest(t *testing.T) {
	b := newRemoteBox(t, nil)
	b.useProfile()
	b.signIn(tokenOne)
	cases := [][]string{
		{"--name", "x", "--expires-in", "400d"},
		{"--name", "x", "--expires-in", "0d"},
		{"--name", "x", "--expires-in", "soon"},
		{"--name", "x", "--expires-in", "-1h"},
		{"--name", "x", "--expires-at", "yesterday"},
		{"--name", "x", "--expires-at", "2001-01-01T00:00:00Z"},
		{"--expires-in", "30d"},
	}
	for _, args := range cases {
		if r := b.run("", append([]string{"tokens", "create"}, args...)...); r.code != exitUsage {
			t.Errorf("%v: exit %d, %q", args, r.code, r.stderr)
		}
	}
	if n := len(b.requests()); n != 0 {
		t.Errorf("%d requests were sent", n)
	}
}

func TestTokensRevoke(t *testing.T) {
	id := "0192a000-0000-7000-8000-00000000a009"
	b := newRemoteBox(t, routes{
		"DELETE " + wire.Path(wire.PathToken, id): func(w http.ResponseWriter, _ *http.Request) { reply(w, 200, struct{}{}) },
	})
	b.useProfile()
	b.signIn(tokenOne)

	r := b.run("", "tokens", "revoke", id)

	if r.code != 0 || !strings.Contains(r.stdout, id) {
		t.Errorf("exit %d: %s %s", r.code, r.stdout, r.stderr)
	}
	if bad := b.run("", "tokens", "revoke", "nope"); bad.code != exitUsage {
		t.Errorf("malformed id: exit %d", bad.code)
	}
}
