package ssh

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func answering(status int, location string) *http.Client {
	return &http.Client{Transport: handlerTransport{http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if location != "" {
			w.Header().Set("Location", location)
		}
		w.WriteHeader(status)
	})}}
}

// SEC-2: the preflight follows cloudflared's own rule (302 to the login path)
// and also refuses 401 and 403, never spawning for them.
func TestPreflightRefusesWhatCloudflaredWouldTurnIntoALoginFlow(t *testing.T) {
	cases := map[string]*http.Client{
		"relative login location":      answering(http.StatusFound, "/cdn-cgi/access/login/"+testTunnelHost+"?kid=1"),
		"login path on another domain": answering(http.StatusFound, "https://login.example.net/cdn-cgi/access/login/x"),
		"401":                          answering(http.StatusUnauthorized, ""),
		"403":                          answering(http.StatusForbidden, ""),
	}
	for name, client := range cases {
		t.Run(name, func(t *testing.T) {
			r := newTunnelRig(t, defaultConfig(), client)
			_, err := r.runTunnel(t, "x")
			requireCode(t, err, smerr.CodeNodeUnreachable)
			if !strings.Contains(err.Error(), "Access did not admit the service token") {
				t.Errorf("error = %v", err)
			}
			if n := len(records(t, r.home)); n != 0 {
				t.Errorf("%d children started, want none", n)
			}
		})
	}
}

func TestPreflightDoesNotRefuseWhatCloudflaredWouldAccept(t *testing.T) {
	cases := map[string]*http.Client{
		"302 to an Access host but not the login path": answering(http.StatusFound, "https://team.cloudflareaccess.com/other"),
		"301 to the login path":                        answering(http.StatusMovedPermanently, "/cdn-cgi/access/login/x"),
		"404":                                          answering(http.StatusNotFound, ""),
	}
	for name, client := range cases {
		t.Run(name, func(t *testing.T) {
			r := newTunnelRig(t, defaultConfig(), client)
			if _, err := r.runTunnel(t, "x"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// SEC-5: the daemon hands the Access token only to a cloudflared that nobody
// else can replace.
func TestCloudflaredThatOthersCanReplaceIsNotTrusted(t *testing.T) {
	write := func(dir string, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(dir, "cloudflared")
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	t.Run("group writable binary", func(t *testing.T) {
		_, err := resolveCloudflared(CloudflareConfig{Path: write(t.TempDir(), 0o775)})
		requireTrust(t, err, "writable by group or others")
	})
	t.Run("world writable binary", func(t *testing.T) {
		_, err := resolveCloudflared(CloudflareConfig{Path: write(t.TempDir(), 0o757)})
		requireTrust(t, err, "writable by group or others")
	})
	t.Run("world writable directory", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "bin")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		path := write(dir, 0o755)
		if err := os.Chmod(dir, 0o777); err != nil {
			t.Fatal(err)
		}
		_, err := resolveCloudflared(CloudflareConfig{Path: path})
		requireTrust(t, err, "writable by others")
	})
	t.Run("a symlink is judged by its target", func(t *testing.T) {
		bad := write(t.TempDir(), 0o775)
		link := filepath.Join(t.TempDir(), "cloudflared")
		if err := os.Symlink(bad, link); err != nil {
			t.Fatal(err)
		}
		_, err := resolveCloudflared(CloudflareConfig{Path: link})
		requireTrust(t, err, "writable by group or others")
	})
	t.Run("a symlink in a directory others can write is not trusted", func(t *testing.T) { // SEC-5
		target := write(t.TempDir(), 0o755)
		linkDir := filepath.Join(t.TempDir(), "bin")
		if err := os.Mkdir(linkDir, 0o700); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(linkDir, "cloudflared")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(linkDir, 0o777); err != nil {
			t.Fatal(err)
		}
		_, err := resolveCloudflared(CloudflareConfig{Path: link})
		requireTrust(t, err, "writable by others")
	})
	t.Run("a binary swapped after construction is refused at the dial", func(t *testing.T) { // SEC-5
		path := write(t.TempDir(), 0o755)
		d := NewCloudflareDialer(CloudflareConfig{Path: path})
		if d.pathErr != nil {
			t.Fatal(d.pathErr)
		}
		if err := os.Chmod(path, 0o777); err != nil {
			t.Fatal(err)
		}
		_, err := d.DialContext(context.Background(), Target{Transport: domain.TransportCloudflare, TunnelHostname: testTunnelHost})
		requireTrust(t, err, "writable by group or others")
	})
	t.Run("the search skips an untrusted candidate and names it when nothing else is found", func(t *testing.T) {
		dir := t.TempDir()
		write(dir, 0o775)
		_, err := resolveCloudflared(CloudflareConfig{SearchDirs: []string{dir}})
		requireTrust(t, err, "writable by group or others")
	})
	t.Run("an owned, private binary is accepted", func(t *testing.T) {
		path := write(t.TempDir(), 0o755)
		if got, err := resolveCloudflared(CloudflareConfig{Path: path}); err != nil || got != path {
			t.Errorf("got %q, %v", got, err)
		}
	})
}

func requireTrust(t *testing.T, err error, reason string) {
	t.Helper()
	requireCode(t, err, smerr.CodeCapabilityUnavailable)
	if !strings.Contains(err.Error(), "not trusted") || !strings.Contains(err.Error(), reason) {
		t.Errorf("error = %v, want reason %q", err, reason)
	}
}

func TestOnlyAnAbsentCloudflaredIsMissing(t *testing.T) {
	_, err := resolveCloudflared(CloudflareConfig{SearchDirs: []string{t.TempDir()}})
	if !CloudflaredMissing(err) {
		t.Errorf("an empty search directory: %v is not reported as missing", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cloudflared"), []byte("#!/bin/sh\n"), 0o775); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "cloudflared"), 0o775); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveCloudflared(CloudflareConfig{SearchDirs: []string{dir}}); err == nil || CloudflaredMissing(err) {
		t.Errorf("a refused binary: %v must not be reported as missing", err)
	}
}

// Followup of the code review: the configured HOME is tightened to 0700.
func TestAConfiguredHomeDirectoryIsTightenedToPrivate(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	if err := os.Mkdir(home, 0o755); err != nil {
		t.Fatal(err)
	}
	d := NewCloudflareDialer(CloudflareConfig{Path: exe(t), HomeDir: home})
	if _, err := d.homeDir(); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(home); err != nil || info.Mode().Perm() != 0o700 {
		t.Errorf("mode = %v, %v", info.Mode().Perm(), err)
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewCloudflareDialer(CloudflareConfig{Path: exe(t), HomeDir: file}).homeDir()
	requireCode(t, err, smerr.CodeCapabilityUnavailable) // not an internal error: the operator can fix it
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(home, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewCloudflareDialer(CloudflareConfig{Path: exe(t), HomeDir: link}).homeDir(); err == nil {
		t.Error("a symlink was accepted as the home directory")
	}
}

// CODE-6: the termination signal reaches the carrier's own children.
func TestCloseTerminatesTheWholeProcessGroup(t *testing.T) {
	c, home := startTestChild(t, fakeBehaviour{Mode: "spawn"}, time.Second)
	eventually(t, "child and grandchild recorded", func() bool { return len(records(t, home)) == 2 })
	recs := records(t, home)
	_ = c.Close()
	for _, rec := range recs {
		waitGone(t, rec.PID)
	}
}

// slowCloseConn is a carrier whose Close takes time, like cloudflared exiting
// slowly after SIGTERM.
type slowCloseConn struct {
	net.Conn
	delay time.Duration
	gate  <-chan struct{}
}

func (c slowCloseConn) Close() error {
	if c.gate != nil {
		<-c.gate
	}
	time.Sleep(c.delay)
	return c.Conn.Close()
}

type slowCloseDialer struct {
	delay time.Duration
	gate  <-chan struct{}
}

func (d slowCloseDialer) DialContext(ctx context.Context, t Target) (net.Conn, error) {
	nc, err := directDialer{}.DialContext(ctx, t)
	if err != nil {
		return nil, err
	}
	return slowCloseConn{Conn: nc, delay: d.delay, gate: d.gate}, nil
}

func cloudflareTarget(t Target, id domain.ID) Target {
	t.NodeID, t.Transport, t.TunnelHostname = id, domain.TransportCloudflare, testTunnelHost
	return t
}

// CODE-2: a carrier that is slow to exit delays nobody but its own closer.
func TestASlowCarrierCloseDoesNotBlockThePool(t *testing.T) {
	gate := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(gate) }) }
	t.Cleanup(release)
	r := newRig(t, defaultConfig(), nil)
	r.pool.UseDialer(domain.TransportCloudflare, slowCloseDialer{gate: gate})
	ids := domaintest.NewSequentialIDs()
	a, b := cloudflareTarget(r.target(), ids.NewID()), cloudflareTarget(r.target(), ids.NewID())
	for _, target := range []Target{a, b} {
		if _, err := r.pool.For(target).Run(context.Background(), templatesRead("x")); err != nil {
			t.Fatal(err)
		}
	}

	invalidated := make(chan struct{})
	go func() { r.pool.Invalidate(a.NodeID, a.User); close(invalidated) }()
	time.Sleep(100 * time.Millisecond) // Invalidate is now stuck closing a's carrier

	done := make(chan error, 1)
	go func() {
		r.pool.State(a.NodeID)
		_, err := r.pool.For(b).Run(context.Background(), templatesRead("x"))
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the pool is blocked while a carrier closes")
	}
	select {
	case <-invalidated:
		t.Fatal("Invalidate returned before the carrier was closed")
	default:
	}
	release()
	<-invalidated
}

func TestPoolCloseClosesSlowCarriersInParallel(t *testing.T) {
	const delay, nodes = 300 * time.Millisecond, 4
	r := newRig(t, defaultConfig(), nil)
	r.pool.UseDialer(domain.TransportCloudflare, slowCloseDialer{delay: delay})
	ids := domaintest.NewSequentialIDs()
	for range nodes {
		if _, err := r.pool.For(cloudflareTarget(r.target(), ids.NewID())).Run(context.Background(), templatesRead("x")); err != nil {
			t.Fatal(err)
		}
	}
	start := wall.Now()
	r.pool.Close()
	if took := wall.Now().Sub(start); took >= delay*2 {
		t.Errorf("Close took %v for %d carriers of %v each: not parallel", took, nodes, delay)
	}
}
