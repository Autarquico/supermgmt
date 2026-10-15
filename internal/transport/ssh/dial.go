package ssh

import (
	"context"
	"net"
	"strconv"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// Dialer opens the byte stream an SSH handshake runs over. The stream carries
// no trust: host-key pinning, credentials and every template are applied on
// top of it exactly as for a direct connection (ADR-0037).
type Dialer interface {
	// DialContext's ctx bounds the dial only. Once it returns a connection,
	// the connection's lifetime is the caller's, not ctx's.
	DialContext(ctx context.Context, t Target) (net.Conn, error)
}

// Diagnoser is implemented by a connection that can say, already sanitized,
// why its carrier failed. It is read after Close.
type Diagnoser interface{ Diagnostics() string }

// directDialer reaches the node's SSH port over TCP.
type directDialer struct{}

func (directDialer) DialContext(ctx context.Context, t Target) (net.Conn, error) {
	addr := net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	nc, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, unreachable("connect to node", err)
	}
	return nc, nil
}

// validateTransport rejects unknown transports and invalid tunnel hostnames
// before any process starts or any address is resolved.
func validateTransport(t Target) error {
	if !t.Transport.Valid() {
		return smerr.New(smerr.CodeInvalidArgument, "", "unknown ssh transport")
	}
	if t.Transport.Effective() == domain.TransportCloudflare {
		if err := domain.ValidateDNSName(t.TunnelHostname); err != nil {
			return smerr.New(smerr.CodeInvalidArgument, "", "invalid tunnel hostname: "+err.Error())
		}
	}
	return nil
}

// UseDialer installs the dialer for a transport, replacing any earlier one.
// Wiring calls it before the pool serves commands; the direct dialer is built in.
func (p *Pool) UseDialer(transport domain.Transport, d Dialer) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.dialers[transport.Effective()] = d
}

func (p *Pool) dialerFor(t Target) (Dialer, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	d, ok := p.dialers[t.Transport.Effective()]
	if !ok {
		return nil, smerr.New(smerr.CodeCapabilityUnavailable, "",
			"no dialer is configured for transport "+string(t.Transport.Effective()))
	}
	return d, nil
}

// ScanHostKey reads the key a node presents over the target's transport.
func (p *Pool) ScanHostKey(ctx context.Context, t Target) (HostKey, error) {
	if err := validateEndpoint(t.Host, t.Port); err != nil {
		return HostKey{}, err
	}
	if err := validateTransport(t); err != nil {
		return HostKey{}, err
	}
	d, err := p.dialerFor(t)
	if err != nil {
		return HostKey{}, err
	}
	return scanHostKey(ctx, d, t)
}
