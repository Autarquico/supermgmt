package ssh

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

type failingTransport struct{ err error }

func (f failingTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, f.err }

func TestACarrierThatDiesBeforeTheNodeSpeaksIsACarrierFailure(t *testing.T) {
	for name, behaviour := range map[string]fakeBehaviour{
		"cloudflared exits":              {Mode: "die", Stderr: "ERR Unable to reach the origin service"},
		"cloudflared cannot open stream": {Forward: "127.0.0.1:1"},
	} {
		t.Run(name, func(t *testing.T) {
			r := newTunnelRig(t, defaultConfig(), admitting())
			setFake(t, r.home, behaviour)
			_, err := r.runTunnel(t, "x")
			requireCode(t, err, smerr.CodeNodeUnreachable)
			if !IsCarrierFailure(err) {
				t.Errorf("IsCarrierFailure(%v) = false, want true", err)
			}
		})
	}
}

func TestAnUnreachableAccessEndpointIsACarrierFailure(t *testing.T) {
	client := &http.Client{Transport: failingTransport{errors.New("dial tcp: no route to host")}}
	r := newTunnelRig(t, defaultConfig(), client)
	_, err := r.runTunnel(t, "x")
	if !IsCarrierFailure(err) {
		t.Errorf("IsCarrierFailure(%v) = false, want true", err)
	}
	if strings.Contains(err.Error(), testTokenValue) {
		t.Error("the error carries the token")
	}
}

func TestOtherTunnelFailuresAreNotCarrierFailures(t *testing.T) {
	t.Run("Access refusal", func(t *testing.T) {
		r := newTunnelRig(t, defaultConfig(), answering(http.StatusForbidden, ""))
		_, err := r.runTunnel(t, "x")
		requireCode(t, err, smerr.CodeNodeUnreachable)
		if IsCarrierFailure(err) {
			t.Errorf("an Access refusal is a carrier failure: %v", err)
		}
	})
	t.Run("host key mismatch", func(t *testing.T) {
		r := newTunnelRig(t, defaultConfig(), admitting())
		target := r.tunnelTarget()
		target.HostKey = strings.TrimSpace(string(marshalAuthorized(newSigner(t))))
		_, err := r.pool.For(target).Run(context.Background(), templatesRead("x"))
		requireCode(t, err, smerr.CodeSSHHostKeyMismatch)
		if IsCarrierFailure(err) {
			t.Errorf("a host key mismatch is a carrier failure: %v", err)
		}
	})
	t.Run("handshake timeout", func(t *testing.T) {
		cfg := defaultConfig()
		cfg.ConnectTimeout = 300 * time.Millisecond
		r := newTunnelRig(t, cfg, admitting())
		setFake(t, r.home, fakeBehaviour{Mode: "silent"})
		_, err := r.runTunnel(t, "x")
		if IsCarrierFailure(err) {
			t.Errorf("a timeout is a carrier failure: %v", err)
		}
	})
	t.Run("missing cloudflared", func(t *testing.T) {
		d := NewCloudflareDialer(CloudflareConfig{Path: "/nonexistent/cloudflared", Tokens: fixedToken{}})
		_, err := d.DialContext(context.Background(), Target{Transport: "cloudflare", TunnelHostname: testTunnelHost})
		if err == nil || IsCarrierFailure(err) {
			t.Errorf("a missing cloudflared is a carrier failure: %v", err)
		}
	})
}

// A node that spoke and then dropped the stream is the node's doing, not the
// carrier's: the guard is the dialler's own record that the node was heard.
func TestAStreamThatEndsAfterTheNodeSpokeIsNotACarrierFailure(t *testing.T) {
	t.Run("the node says its banner and hangs up", func(t *testing.T) {
		l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.Close() })
		go func() {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			_, _ = io.WriteString(conn, "SSH-2.0-test\r\n")
			_ = conn.Close()
		}()
		r := newTunnelRig(t, defaultConfig(), admitting())
		setFake(t, r.home, fakeBehaviour{Forward: l.Addr().String()})
		_, err = r.runTunnel(t, "x")
		requireCode(t, err, smerr.CodeNodeUnreachable)
		if IsCarrierFailure(err) {
			t.Errorf("a node dropping the login after it spoke is a carrier failure: %v", err)
		}
	})
	t.Run("the node refuses the key", func(t *testing.T) {
		r := newTunnelRig(t, defaultConfig(), admitting())
		r.pool.creds = &staticCreds{signer: newSigner(t)}
		_, err := r.runTunnel(t, "x")
		requireCode(t, err, smerr.CodeNodeUnreachable)
		if !strings.Contains(err.Error(), "authentication failed for user supermgmt") {
			t.Fatalf("err = %v, want an authentication failure", err)
		}
		if IsCarrierFailure(err) {
			t.Errorf("an authentication failure through the tunnel is a carrier failure: %v", err)
		}
		if !IsAuthRejected(err) {
			t.Errorf("an authentication failure is not marked as a refusal of the offered keys: %v", err)
		}
	})
}

func TestClassificationNeedsTheMarkAndTheCode(t *testing.T) {
	cause := errors.New("EOF")
	marked := CarrierFailure(cause)
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"marked and unreachable", smerr.Wrap(marked, smerr.CodeNodeUnreachable, "", "ssh handshake"), true},
		{"unreachable without the mark", smerr.Wrap(cause, smerr.CodeNodeUnreachable, "", "ssh handshake"), false},
		{"marked but another code", smerr.Wrap(marked, smerr.CodeSSHHostKeyMismatch, "", "ssh host key"), false},
		{"marked but cancelled", smerr.Wrap(CarrierFailure(context.Canceled), smerr.CodeNodeUnreachable, "", "ssh handshake"), false},
		{"marked but past its deadline", smerr.Wrap(CarrierFailure(context.DeadlineExceeded), smerr.CodeNodeUnreachable, "", "ssh handshake"), false},
		{"nil", nil, false},
	}
	for _, tc := range tests {
		if got := IsCarrierFailure(tc.err); got != tc.want {
			t.Errorf("%s: IsCarrierFailure = %v, want %v", tc.name, got, tc.want)
		}
	}
}
