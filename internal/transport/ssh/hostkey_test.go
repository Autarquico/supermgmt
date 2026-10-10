package ssh

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func TestScanHostKeyReturnsTheServersKeyWithoutAuthenticating(t *testing.T) {
	server := startServer(t, newSigner(t), nil)
	got, err := ScanHostKey(context.Background(), "127.0.0.1", server.port())
	if err != nil {
		t.Fatal(err)
	}
	want := server.currentHostKey().PublicKey()
	if got.Authorized != server.pinned() || got.Type != "ssh-ed25519" || got.FingerprintSHA256 != cryptossh.FingerprintSHA256(want) {
		t.Errorf("scan = %+v", got)
	}
	if strings.ContainsAny(got.Authorized, "\n") {
		t.Errorf("authorized key has a newline: %q", got.Authorized)
	}
	if n := server.authAttempts.Load(); n != 0 {
		t.Errorf("a scan attempted authentication %d times", n)
	}
}

func TestScannedKeyIsAcceptedAsAPin(t *testing.T) {
	r := newRig(t, defaultConfig(), nil)
	scanned, err := ScanHostKey(context.Background(), "127.0.0.1", r.server.port())
	if err != nil {
		t.Fatal(err)
	}
	target := r.target()
	target.HostKey = scanned.Authorized
	if _, err := r.pool.For(target).Run(context.Background(), templatesRead("x")); err != nil {
		t.Fatalf("a scanned key must be usable as the pin: %v", err)
	}
}

func TestScanHostKeyFailures(t *testing.T) {
	t.Run("closed port", func(t *testing.T) {
		_, err := ScanHostKey(context.Background(), "127.0.0.1", closedPort(t))
		requireCode(t, err, smerr.CodeNodeUnreachable)
	})
	t.Run("not an SSH server", func(t *testing.T) {
		l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		go func() {
			c, err := l.Accept()
			if err == nil {
				_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
				_ = c.Close()
			}
		}()
		_, err = ScanHostKey(context.Background(), "127.0.0.1", l.Addr().(*net.TCPAddr).Port)
		requireCode(t, err, smerr.CodeNodeUnreachable)
	})
	t.Run("silent server honors the context", func(t *testing.T) {
		l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		go func() {
			c, err := l.Accept()
			if err == nil {
				defer c.Close()
				time.Sleep(2 * time.Second)
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		_, err = ScanHostKey(ctx, "127.0.0.1", l.Addr().(*net.TCPAddr).Port)
		requireCode(t, err, smerr.CodeTimeout)
	})
}

func TestScanHostKeyRejectsHostileInput(t *testing.T) {
	for _, host := range []string{"", "-oProxyCommand=x", "a b", "user@host", "a/b", "h\nost"} {
		_, err := ScanHostKey(context.Background(), host, 22)
		requireCode(t, err, smerr.CodeInvalidArgument)
	}
	for _, port := range []int{0, -1, 65536} {
		_, err := ScanHostKey(context.Background(), "127.0.0.1", port)
		requireCode(t, err, smerr.CodeInvalidArgument)
	}
}
