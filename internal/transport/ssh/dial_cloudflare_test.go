package ssh

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// The test binary doubles as a fake cloudflared: when it is started as
// `<exe> access ssh ...` it records argv and environment under $HOME and then
// behaves as $HOME/fake.json says. The real child environment has no PATH, so
// no script interpreter could be found; re-executing the test binary needs none.
func TestMain(m *testing.M) {
	if len(os.Args) >= 3 && os.Args[1] == "access" && os.Args[2] == "ssh" {
		runFakeCloudflared()
		return
	}
	code := m.Run()
	if trustedRoot != "" {
		_ = os.RemoveAll(trustedRoot)
	}
	os.Exit(code)
}

var (
	trustedRoot string
	fakePath    string
	trustedErr  error
	trustedOnce sync.Once
)

// trustedSetup makes, once per run, a private directory under the package and
// a copy of the test binary in it. t.TempDir and go test's build directory
// live under /tmp on Linux, which the trust check refuses, so a binary that
// must be judged on its own merits cannot live there.
func trustedSetup(t *testing.T) {
	t.Helper()
	trustedOnce.Do(func() {
		var self, dir string
		if self, trustedErr = os.Executable(); trustedErr != nil {
			return
		}
		if dir, trustedErr = os.MkdirTemp(".", ".trusted-"); trustedErr != nil {
			return
		}
		if trustedRoot, trustedErr = filepath.Abs(dir); trustedErr != nil {
			return
		}
		fakePath = filepath.Join(trustedRoot, "cloudflared")
		trustedErr = copyExecutable(self, fakePath)
	})
	if trustedErr != nil {
		t.Fatal(trustedErr)
	}
}

// exe is the fake cloudflared.
func exe(t *testing.T) string {
	t.Helper()
	trustedSetup(t)
	return fakePath
}

// trustedDir is a fresh private directory the trust check accepts.
func trustedDir(t *testing.T) string {
	t.Helper()
	trustedSetup(t)
	dir, err := os.MkdirTemp(trustedRoot, "t-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func copyExecutable(from, to string) error {
	src, err := os.Open(from)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.OpenFile(to, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		return err
	}
	return dst.Close()
}

type fakeBehaviour struct {
	Mode    string // "" forward; "silent" never speaks; "die" prints Stderr and exits 3; "ignoreterm" ignores SIGTERM
	Forward string // address of the SSH server to bridge to
	Stderr  string
}

type fakeRecord struct {
	PID  int
	Argv []string
	Env  []string
}

func runFakeCloudflared() {
	home := os.Getenv("HOME")
	rec, _ := json.Marshal(fakeRecord{PID: os.Getpid(), Argv: os.Args, Env: os.Environ()})
	_ = os.WriteFile(filepath.Join(home, "record-"+strconv.Itoa(os.Getpid())+".json"), rec, 0o600)
	var b fakeBehaviour
	raw, _ := os.ReadFile(filepath.Join(home, "fake.json"))
	_ = json.Unmarshal(raw, &b)
	if b.Stderr != "" {
		_, _ = io.WriteString(os.Stderr, b.Stderr)
	}
	switch b.Mode {
	case "spawn": // a carrier with a child of its own, in the same process group
		if os.Getenv("FAKE_GRANDCHILD") == "" {
			grandchild := exec.CommandContext(context.Background(), os.Args[0], "access", "ssh")
			grandchild.Env = append(os.Environ(), "FAKE_GRANDCHILD=1")
			_ = grandchild.Start()
		}
		time.Sleep(time.Hour)
	case "die":
		os.Exit(3)
	case "ignoreterm":
		signal.Ignore(syscall.SIGTERM)
		time.Sleep(time.Hour)
	case "silent":
		time.Sleep(time.Hour)
	}
	conn, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", b.Forward)
	if err != nil {
		os.Exit(4)
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(conn, os.Stdin); done <- struct{}{} }()
	go func() { _, _ = io.Copy(os.Stdout, conn); done <- struct{}{} }()
	<-done
	os.Exit(0)
}

const (
	testTunnelHost = "ssh.example.com"
	testTokenID    = "abcd1234.access"
	testTokenValue = "s3cr3tvalue9f8e7d6c"
)

type fixedToken struct{ err error }

func (f fixedToken) AccessToken(context.Context) (AccessToken, error) {
	return AccessToken{ClientID: testTokenID, ClientSecret: audit.Secret(testTokenValue)}, f.err
}

// handlerTransport serves requests from a handler, so the preflight needs
// neither a network nor TLS.
type handlerTransport struct{ h http.Handler }

func (t handlerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	t.h.ServeHTTP(rec, r)
	return rec.Result(), nil
}

func admitting() *http.Client {
	return &http.Client{Transport: handlerTransport{http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})}}
}

func setFake(t *testing.T, home string, b fakeBehaviour) {
	t.Helper()
	raw, _ := json.Marshal(b)
	if err := os.WriteFile(filepath.Join(home, "fake.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func records(t *testing.T, home string) []fakeRecord {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(home, "record-*.json"))
	var out []fakeRecord
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var r fakeRecord
		if err := json.Unmarshal(raw, &r); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func gone(pid int) bool { return errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) }

func waitGone(t *testing.T, pid int) {
	t.Helper()
	eventually(t, "child "+strconv.Itoa(pid)+" reaped", func() bool { return gone(pid) })
}

type tunnelRig struct {
	rig
	home   string
	dialer *CloudflareDialer
}

func newTunnelRig(t *testing.T, cfg PoolConfig, preflight *http.Client) tunnelRig {
	t.Helper()
	r := newRig(t, cfg, nil)
	home := t.TempDir()
	setFake(t, home, fakeBehaviour{Forward: r.server.listener.Addr().String()})
	d := NewCloudflareDialer(CloudflareConfig{
		Path: exe(t), HomeDir: home, Tokens: fixedToken{}, Preflight: preflight, KillGrace: 200 * time.Millisecond,
	})
	r.pool.UseDialer(domain.TransportCloudflare, d)
	return tunnelRig{rig: r, home: home, dialer: d}
}

func (r tunnelRig) tunnelTarget() Target {
	t := r.target()
	t.Transport, t.TunnelHostname = domain.TransportCloudflare, testTunnelHost
	return t
}

func (r tunnelRig) runTunnel(t *testing.T, cmd string) (string, error) {
	t.Helper()
	res, err := r.pool.For(r.tunnelTarget()).Run(context.Background(), templatesRead(cmd))
	return string(res.Stdout), err
}

func TestTunnelSpawnsCloudflaredWithExactArgvAndEnvironment(t *testing.T) {
	r := newTunnelRig(t, defaultConfig(), admitting())
	out, err := r.runTunnel(t, "hello")
	if err != nil || out != "ran: hello" {
		t.Fatalf("out = %q, err = %v", out, err)
	}
	recs := records(t, r.home)
	if len(recs) != 1 {
		t.Fatalf("%d children, want 1", len(recs))
	}
	if want := []string{exe(t), "access", "ssh", "--hostname", testTunnelHost}; !slices.Equal(recs[0].Argv, want) {
		t.Errorf("argv = %q, want %q", recs[0].Argv, want)
	}
	want := []string{"HOME=" + r.home, "TUNNEL_SERVICE_TOKEN_ID=" + testTokenID, "TUNNEL_SERVICE_TOKEN_SECRET=" + testTokenValue}
	env := slices.Clone(recs[0].Env)
	slices.Sort(env)
	if !slices.Equal(env, want) {
		t.Errorf("env = %q, want exactly %q", env, want)
	}
	if strings.Contains(strings.Join(recs[0].Argv, " "), testTokenValue) {
		t.Error("the service token reached argv")
	}
}

func TestTunnelPreflightSendsTheServiceTokenHeaders(t *testing.T) {
	var gotID, gotSecret, gotURL string
	client := &http.Client{Transport: handlerTransport{http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		gotID, gotSecret, gotURL = req.Header.Get("CF-Access-Client-Id"), req.Header.Get("CF-Access-Client-Secret"), req.URL.String()
	})}}
	r := newTunnelRig(t, defaultConfig(), client)
	if _, err := r.runTunnel(t, "x"); err != nil {
		t.Fatal(err)
	}
	if gotID != testTokenID || gotSecret != testTokenValue || gotURL != "https://"+testTunnelHost+"/" {
		t.Errorf("preflight sent id=%q secret-ok=%v url=%q", gotID, gotSecret == testTokenValue, gotURL)
	}
}

func TestTunnelRefusesWithoutSpawningWhenAccessRedirectsToLogin(t *testing.T) {
	client := &http.Client{Transport: handlerTransport{http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, "https://team.cloudflareaccess.com/cdn-cgi/access/login/"+testTunnelHost, http.StatusFound)
	})}}
	r := newTunnelRig(t, defaultConfig(), client)
	_, err := r.runTunnel(t, "x")
	requireCode(t, err, smerr.CodeNodeUnreachable)
	if !strings.Contains(err.Error(), "Access did not admit the service token") {
		t.Errorf("error = %v", err)
	}
	if n := len(records(t, r.home)); n != 0 {
		t.Errorf("%d children started, want none", n)
	}
	if strings.Contains(err.Error(), testTokenValue) {
		t.Error("the error carries the token")
	}
}

func TestTunnelDoesNotRefuseOtherRedirects(t *testing.T) {
	client := &http.Client{Transport: handlerTransport{http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, "https://elsewhere.example.net/", http.StatusFound)
	})}}
	r := newTunnelRig(t, defaultConfig(), client)
	if _, err := r.runTunnel(t, "x"); err != nil {
		t.Fatal(err)
	}
}

func TestMissingCloudflaredIsCapabilityUnavailable(t *testing.T) {
	r := newRig(t, defaultConfig(), nil)
	d := NewCloudflareDialer(CloudflareConfig{SearchDirs: []string{t.TempDir()}, Tokens: fixedToken{}, Preflight: admitting()})
	r.pool.UseDialer(domain.TransportCloudflare, d)
	target := r.target()
	target.Transport, target.TunnelHostname = domain.TransportCloudflare, testTunnelHost
	_, err := r.pool.For(target).Run(context.Background(), templatesRead("x"))
	requireCode(t, err, smerr.CodeCapabilityUnavailable)
	if !strings.Contains(err.Error(), "cloudflared") {
		t.Errorf("error does not name cloudflared: %v", err)
	}
	_, err = r.pool.ScanHostKey(context.Background(), target)
	requireCode(t, err, smerr.CodeCapabilityUnavailable)
}

func TestCloudflaredPathMustBeAbsoluteAndExecutable(t *testing.T) {
	notExec := filepath.Join(t.TempDir(), "cloudflared")
	if err := os.WriteFile(notExec, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"cloudflared", "./cloudflared", notExec} {
		d := NewCloudflareDialer(CloudflareConfig{Path: path, Tokens: fixedToken{}, Preflight: admitting()})
		_, err := d.DialContext(context.Background(), Target{Transport: domain.TransportCloudflare, TunnelHostname: testTunnelHost})
		if err == nil {
			t.Errorf("path %q accepted", path)
		}
	}
}

func TestTunnelRejectsUnknownTransportsAndHostilesHostnamesBeforeAnyProcess(t *testing.T) {
	r := newTunnelRig(t, defaultConfig(), admitting())
	hostile := []string{
		"", "-oProxyCommand=x.example.com", "a b.example.com", "host.example.com\n", "%h.example.com",
		"HOST.example.com", "single", "1.2.3.4", "x.example.com.", "a@b.example.com", "x/y.example.com",
	}
	for _, h := range hostile {
		target := r.tunnelTarget()
		target.TunnelHostname = h
		_, err := r.pool.For(target).Run(context.Background(), templatesRead("x"))
		requireCode(t, err, smerr.CodeInvalidArgument)
	}
	target := r.tunnelTarget()
	target.Transport = "wireguard"
	_, err := r.pool.For(target).Run(context.Background(), templatesRead("x"))
	requireCode(t, err, smerr.CodeInvalidArgument)
	if n := len(records(t, r.home)); n != 0 {
		t.Errorf("%d children started for invalid targets", n)
	}
}

func TestTunnelEnforcesThePinnedHostKeyAndReapsTheChild(t *testing.T) {
	r := newTunnelRig(t, defaultConfig(), admitting())
	target := r.tunnelTarget()
	target.HostKey = strings.TrimSpace(string(marshalAuthorized(newSigner(t))))
	_, err := r.pool.For(target).Run(context.Background(), templatesRead("x"))
	requireCode(t, err, smerr.CodeSSHHostKeyMismatch)
	recs := records(t, r.home)
	if len(recs) != 1 {
		t.Fatalf("%d children", len(recs))
	}
	waitGone(t, recs[0].PID)
}

func TestScanHostKeyOverTheTunnel(t *testing.T) {
	r := newTunnelRig(t, defaultConfig(), admitting())
	key, err := r.pool.ScanHostKey(context.Background(), r.tunnelTarget())
	if err != nil {
		t.Fatal(err)
	}
	if key.Authorized != r.server.pinned() {
		t.Errorf("scanned %q, want %q", key.Authorized, r.server.pinned())
	}
	recs := records(t, r.home)
	if len(recs) != 1 {
		t.Fatalf("%d children", len(recs))
	}
	waitGone(t, recs[0].PID)
}

func TestConnectionsAreKeyedByTransport(t *testing.T) {
	r := newTunnelRig(t, defaultConfig(), admitting())
	if _, err := r.run("direct"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.runTunnel(t, "tunnel"); err != nil {
		t.Fatal(err)
	}
	if got := r.server.connections.Load(); got != 2 {
		t.Fatalf("%d SSH connections, want one per transport", got)
	}
	if _, err := r.run("direct again"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.runTunnel(t, "tunnel again"); err != nil {
		t.Fatal(err)
	}
	if got := r.server.connections.Load(); got != 2 {
		t.Errorf("%d SSH connections after reuse, want 2", got)
	}

	// A hostname change replaces the tunnel peer: the old child goes away.
	before := records(t, r.home)
	r.pool.InvalidateNode(r.nodeID)
	eventually(t, "old child reaped", func() bool { return gone(before[0].PID) })
}

func TestPoolCloseReapsTheChild(t *testing.T) {
	r := newTunnelRig(t, defaultConfig(), admitting())
	if _, err := r.runTunnel(t, "x"); err != nil {
		t.Fatal(err)
	}
	recs := records(t, r.home)
	r.pool.Close()
	waitGone(t, recs[0].PID)
}

func TestIdleEvictionReapsTheChild(t *testing.T) {
	cfg := defaultConfig()
	cfg.IdleConnectionTTL = time.Second
	r := newTunnelRig(t, cfg, admitting())
	if _, err := r.runTunnel(t, "x"); err != nil {
		t.Fatal(err)
	}
	recs := records(t, r.home)
	r.clock.Advance(time.Minute)
	waitGone(t, recs[0].PID)
}

func TestTunnelChildOutlivesTheDialContext(t *testing.T) {
	r := newTunnelRig(t, defaultConfig(), admitting())
	ctx, cancel := context.WithCancel(context.Background())
	if _, err := r.pool.For(r.tunnelTarget()).Run(ctx, templatesRead("one")); err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err := r.runTunnel(t, "two"); err != nil {
		t.Fatalf("the connection died with the dial context: %v", err)
	}
	if got := r.server.connections.Load(); got != 1 {
		t.Errorf("%d SSH connections, want the first reused", got)
	}
}

func TestChildDyingDuringHandshakeIsReapedAndItsStderrIsScrubbed(t *testing.T) {
	r := newTunnelRig(t, defaultConfig(), admitting())
	setFake(t, r.home, fakeBehaviour{Mode: "die", Stderr: "ERR connect failed secret=" + testTokenValue + " id " + testTokenID + "\x1b[31m token: abc123\n"})
	_, err := r.runTunnel(t, "x")
	requireCode(t, err, smerr.CodeNodeUnreachable)
	text := err.Error()
	for _, leak := range []string{testTokenValue, testTokenID, "abc123", "\x1b"} {
		if strings.Contains(text, leak) {
			t.Errorf("error leaks %q: %s", leak, text)
		}
	}
	if !strings.Contains(text, "connect failed") {
		t.Errorf("error lost the carrier's reason: %s", text)
	}
	waitGone(t, records(t, r.home)[0].PID)
}

func TestHandshakeTimeoutKillsASilentChild(t *testing.T) {
	cfg := defaultConfig()
	cfg.ConnectTimeout = 2 * time.Second
	r := newTunnelRig(t, cfg, admitting())
	setFake(t, r.home, fakeBehaviour{Mode: "silent"})
	_, err := r.runTunnel(t, "x")
	requireCode(t, err, smerr.CodeNodeUnreachable)
	waitGone(t, records(t, r.home)[0].PID)
}

func TestParseAccessToken(t *testing.T) {
	good, err := ParseAccessToken(" id.access:secretvalue\n")
	if err != nil || good.ClientID != "id.access" || good.ClientSecret.Reveal() != "secretvalue" {
		t.Fatalf("got %+v, %v", good, err)
	}
	for _, bad := range []string{"", "nocolon", ":secret", "id:", "id:sec ret", "id:sec\x00ret", "id:sec\nret"} {
		if _, err := ParseAccessToken(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestSanitizeDiagnosticBoundsLengthAndMasksSecrets(t *testing.T) {
	got := sanitizeDiagnostic("a "+testTokenValue+"\n\t"+strings.Repeat("x", 1000), testTokenValue)
	if strings.Contains(got, testTokenValue) || strings.ContainsAny(got, "\n\t") || len([]rune(got)) > diagnosticRunes+3 {
		t.Errorf("got %q", got)
	}
}

func TestTailBufferWithholdsTheHeadAfterTruncation(t *testing.T) {
	b := tailBuffer{margin: 8}
	b.write([]byte(strings.Repeat("a", stderrKeep)))
	b.write([]byte("0123456789"))
	got := b.String()
	if len(got) != stderrKeep-8 || !strings.HasSuffix(got, "0123456789") {
		t.Errorf("len = %d", len(got))
	}
}

func startTestChild(t *testing.T, b fakeBehaviour, grace time.Duration) (*childConn, string) {
	t.Helper()
	home := t.TempDir()
	setFake(t, home, b)
	c, err := startChild(childSpec{
		path: exe(t), hostname: testTunnelHost, home: home, grace: grace,
		token: AccessToken{ClientID: testTokenID, ClientSecret: audit.Secret(testTokenValue)},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, home
}

func TestChildConnDeadlinesUnblockReadAndWrite(t *testing.T) {
	c, _ := startTestChild(t, fakeBehaviour{Mode: "silent"}, time.Second)
	read := make(chan error, 1)
	go func() {
		_, err := c.Read(make([]byte, 1))
		read <- err
	}()
	time.Sleep(50 * time.Millisecond)
	if err := c.SetReadDeadline(wall.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-read:
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			t.Errorf("read error = %v, want a timeout", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("read stayed blocked past its deadline")
	}

	// A silent child never reads stdin: fill the pipe until a write blocks.
	if err := c.SetWriteDeadline(wall.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	wrote := make(chan error, 1)
	go func() {
		_, err := c.Write(make([]byte, 4<<20))
		wrote <- err
	}()
	select {
	case err := <-wrote:
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			t.Errorf("write error = %v, want a timeout", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("write stayed blocked past its deadline")
	}
}

func TestChildConnCloseIsIdempotentAndConcurrent(t *testing.T) {
	c, _ := startTestChild(t, fakeBehaviour{Mode: "silent"}, time.Second)
	pid := c.pid()
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.Close(); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if !gone(pid) {
		t.Error("Close returned before the child was reaped")
	}
	if err := c.Close(); err != nil {
		t.Error(err)
	}
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Error("read after Close succeeded")
	}
}

func TestChildConnCloseUnblocksAReader(t *testing.T) {
	c, _ := startTestChild(t, fakeBehaviour{Mode: "silent"}, time.Second)
	read := make(chan error, 1)
	go func() {
		_, err := c.Read(make([]byte, 1))
		read <- err
	}()
	time.Sleep(50 * time.Millisecond)
	_ = c.Close()
	select {
	case <-read:
	case <-time.After(3 * time.Second):
		t.Fatal("Close left a reader blocked")
	}
}

func TestChildConnEscalatesToKillWhenSIGTERMIsIgnored(t *testing.T) {
	c, home := startTestChild(t, fakeBehaviour{Mode: "ignoreterm"}, 150*time.Millisecond)
	eventually(t, "child recorded", func() bool { return len(records(t, home)) == 1 })
	time.Sleep(100 * time.Millisecond) // let it install the handler
	start := wall.Now()
	_ = c.Close()
	if took := wall.Now().Sub(start); took < 100*time.Millisecond {
		t.Errorf("Close took %v: SIGKILL escalation did not wait for the grace period", took)
	}
	if !gone(c.pid()) {
		t.Error("child survived Close")
	}
}

var wall domain.SystemClock
