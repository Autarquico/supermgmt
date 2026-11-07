package systemd

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// failingSession is a session that cannot run anything, as when the dial or the login failed.
type failingSession struct{ err error }

func (f failingSession) Run(context.Context, templates.Command) (transport.Result, error) {
	return transport.Result{}, f.err
}

func TestAVerificationThatCannotDialKeepsItsCauseAndDoesNotBlameTheLogin(t *testing.T) {
	dnsErr := &net.DNSError{Err: "no such host", Name: "ssh-web-1.example.test", IsNotFound: true}
	dial := smerr.Wrap(dnsErr, smerr.CodeNodeUnreachable, "", "cloudflare access preflight: lookup ssh-web-1.example.test: no such host")

	err := Verify(context.Background(), failingSession{dial}, verifyParams())

	var got *net.DNSError
	if !errors.As(err, &got) {
		t.Fatalf("the cause was dropped: %v", err)
	}
	if smerr.CodeOf(err) != smerr.CodeNodeUnreachable {
		t.Errorf("code = %s, want the dial failure's NODE_UNREACHABLE", smerr.CodeOf(err))
	}
	if strings.Contains(err.Error(), "cannot log in as the dedicated user") || !strings.Contains(err.Error(), "no such host") {
		t.Errorf("error = %q, want the dial failure and no blame on the login", err)
	}
}

func TestOnlyASSHAuthenticationFailureIsReportedAsALoginFailure(t *testing.T) {
	refused := ssh.AuthRejected(errors.New("ssh: unable to authenticate, attempted methods [none publickey]"))

	err := Verify(context.Background(), failingSession{smerr.Wrap(refused, smerr.CodeNodeUnreachable, "", "ssh handshake")}, verifyParams())

	if err == nil || !strings.Contains(err.Error(), "cannot log in as the dedicated user") {
		t.Fatalf("error = %v, want the login failure", err)
	}
	if !ssh.IsAuthRejected(err) {
		t.Error("the authentication failure was not kept as the cause")
	}
	if smerr.CodeOf(err) != smerr.CodeCapabilityUnavailable {
		t.Errorf("code = %s, want CAPABILITY_UNAVAILABLE as before", smerr.CodeOf(err))
	}
}
