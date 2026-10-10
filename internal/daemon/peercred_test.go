package daemon

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api"
)

// The *PeerCred* tests run only where a second OS user exists (CI job
// daemon-linux-peer, `make test-daemon-peer`): SM_PEER_OTHER_USER names it and
// SM_PEER_SM_BIN is a built sm every user can execute.

func peerEnv(t *testing.T) (user, bin string) {
	t.Helper()
	user, bin = os.Getenv("SM_PEER_OTHER_USER"), os.Getenv("SM_PEER_SM_BIN")
	if user == "" || bin == "" {
		t.Skip("SM_PEER_OTHER_USER and SM_PEER_SM_BIN are not set")
	}
	return user, bin
}

// openSocketDir is a directory and a socket every user may reach, so that the
// peer-credential check, not the file mode, is what refuses the other user.
func openSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "smp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "s")
}

func listenOpen(t *testing.T, socket string) net.Listener {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	if err := os.Chmod(socket, 0o666); err != nil {
		t.Fatal(err)
	}
	return l
}

func TestDaemonRefusesAnotherUserPeerCred(t *testing.T) {
	user, _ := peerEnv(t)
	if _, err := exec.LookPath("perl"); err != nil {
		t.Skip("perl is needed to speak raw HTTP as the other user")
	}
	socket := openSocketDir(t)
	var served atomic.Int64
	srv := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { served.Add(1) })}
	l := api.RestrictToUID(listenOpen(t, socket), uint32(os.Getuid()), api.PeerUID, nil)
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })

	script := `use IO::Socket::UNIX; my $s = IO::Socket::UNIX->new(Peer => $ARGV[0]) or exit 3;
print $s "GET /api/v1/me HTTP/1.0\r\n\r\n"; my $got = <$s>; print defined $got ? "answered" : "closed";`
	out, err := exec.CommandContext(context.Background(), "sudo", "-n", "-u", user, "perl", "-e", script, socket).CombinedOutput()
	if err != nil {
		t.Fatalf("running as %s: %v: %s", user, err, out)
	}
	if string(out) != "closed" || served.Load() != 0 {
		t.Errorf("output %q, %d requests served; want the connection closed unread", out, served.Load())
	}
}

func TestClientRefusesAnotherUsersListenerPeerCred(t *testing.T) {
	user, bin := peerEnv(t)
	socket := openSocketDir(t)
	l := listenOpen(t, socket)
	var bytesRead atomic.Int64
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			timer := time.AfterFunc(2*time.Second, func() { _ = c.Close() })
			n, _ := c.Read(make([]byte, 1))
			timer.Stop()
			bytesRead.Add(int64(n))
			_ = c.Close()
		}
	}()
	cfg := filepath.Join(filepath.Dir(socket), "config.yaml")
	body := "version: 1\ninstance:\n  mode: local\ndaemon:\n  socket: " + socket + "\n"
	if err := os.WriteFile(cfg, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(context.Background(), "sudo", "-n", "-u", user, "env", "HOME="+filepath.Dir(socket), "SM_NO_AUTOSTART=1", bin, "--config", cfg, "status")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("sm talked to a listener owned by another user: %s", out)
	}
	time.Sleep(100 * time.Millisecond)
	if bytesRead.Load() != 0 {
		t.Errorf("the client sent %d bytes to the other user's listener", bytesRead.Load())
	}
}
