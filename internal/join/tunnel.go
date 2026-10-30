package join

import (
	"context"
	"fmt"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/runtimes/systemd"
	"github.com/autarquico/supermgmt/internal/transport"
)

// TunnelHost is the node as `sm join --tunnel` sees it: a Host that can also
// install packages and units as root, locally.
type TunnelHost interface {
	Host
	// PreflightTunnel fails, before anything changes, when this process cannot
	// finish: not root, no systemd, no apt-get, no useradd.
	PreflightTunnel() error
	// Executor runs rendered setup steps as root on this machine.
	Executor() transport.Executor
}

// TunnelRequest is what the operator's line carries. Both values are public.
type TunnelRequest struct {
	InstanceID    string
	AuthorizedKey string
}

// TunnelJoiner prepares a node that only the Cloudflare Tunnel will reach
// (ADR-0039). It never calls a SuperMgmt server.
type TunnelJoiner struct{ Host TunnelHost }

// Run checks everything before it changes anything, reads the connector token
// through readToken, installs cloudflared with the token, provisions the
// dedicated account, and returns the host key fingerprint for the operator to
// compare. Every step converges, so running it again is safe; a different
// token replaces the old one.
func (j TunnelJoiner) Run(ctx context.Context, r TunnelRequest, readToken func() (audit.Secret, error)) (string, error) {
	enrolled := wire.Enrolled{SSHUser: config.DefaultSSHUser, AuthorizedKey: r.AuthorizedKey, InstanceID: domain.ID(r.InstanceID)}
	if _, err := systemd.AuthorizedKeys(enrolled.SSHUser, enrolled.AuthorizedKey, r.InstanceID); err != nil {
		return "", err
	}
	if err := j.Host.PreflightTunnel(); err != nil {
		return "", err
	}
	hostKey, err := readHostKey(j.Host)
	if err != nil {
		return "", err
	}
	if _, err := checkAccount(j.Host, enrolled.SSHUser); err != nil {
		return "", err
	}
	if err := systemd.CheckTunnelInstallable(ctx, j.Host.Executor()); err != nil {
		return "", err
	}
	token, err := readToken()
	if err != nil {
		return "", err
	}
	params := systemd.TunnelParams{Token: token}
	if err := params.Validate(); err != nil {
		return "", err
	}
	if err := systemd.InstallTunnel(ctx, j.Host.Executor(), params); err != nil {
		return "", fmt.Errorf("install the Cloudflare connector: %w", err)
	}
	if err := Provision(ctx, j.Host, enrolled); err != nil {
		return "", err
	}
	return cryptossh.FingerprintSHA256(hostKey), nil
}
