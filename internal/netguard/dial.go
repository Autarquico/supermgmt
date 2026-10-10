package netguard

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"
)

// dialer resolves a host once, vets every address, and connects to a vetted
// IP, directly or through a CONNECT proxy (§21.1 steps 2 and 8). Filtering at
// dial time, on the address actually used, is what makes DNS rebinding and
// redirects to internal hosts harmless.
type dialer struct {
	allow   Allow
	proxy   *url.URL
	timeout time.Duration
	lookup  lookupFunc
	dialRaw func(network, address string) (net.Conn, error) // nil: real network
	rootCAs *x509.CertPool                                  // https proxy trust; nil: system
}

type lookupFunc func(ctx context.Context, host string) ([]netip.Addr, error)

func lookupHost(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

func (d *dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBlocked, err)
	}
	ips, err := d.vetted(ctx, host)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, ip := range ips {
		conn, err := d.connect(ctx, network, ip, port)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// vetted resolves host and returns its addresses only if every one passes the
// filter: a name that also answers with a denied address is refused whole.
func (d *dialer) vetted(ctx context.Context, host string) ([]netip.Addr, error) {
	ips, err := d.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("netguard: %s did not resolve", host)
	}
	for _, ip := range ips {
		if err := d.allow.permit(ip); err != nil {
			return nil, err
		}
	}
	return ips, nil
}

func (d *dialer) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, nil
	}
	ips, err := d.lookup(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("netguard: resolve %s: %w", host, err)
	}
	return ips, nil
}

func (d *dialer) connect(ctx context.Context, network string, ip netip.Addr, port string) (net.Conn, error) {
	target := net.JoinHostPort(ip.WithZone("").String(), port)
	if d.proxy == nil {
		return d.raw(ctx, network, target)
	}
	return d.tunnel(ctx, target)
}

func (d *dialer) raw(ctx context.Context, network, address string) (net.Conn, error) {
	if d.dialRaw != nil {
		return d.dialRaw(network, address)
	}
	return (&net.Dialer{Timeout: d.timeout}).DialContext(ctx, network, address)
}

// tunnel opens a CONNECT tunnel to the pinned target through the proxy. The
// proxy address is admin configuration and is not filtered.
func (d *dialer) tunnel(ctx context.Context, target string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	conn, err := d.dialProxy(ctx)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if err := d.handshake(conn, target); err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func (d *dialer) dialProxy(ctx context.Context) (net.Conn, error) {
	port := d.proxy.Port()
	switch d.proxy.Scheme {
	case "http":
		if port == "" {
			port = "80"
		}
		return d.raw(ctx, "tcp", net.JoinHostPort(d.proxy.Hostname(), port))
	case "https":
		if port == "" {
			port = "443"
		}
		conn, err := d.raw(ctx, "tcp", net.JoinHostPort(d.proxy.Hostname(), port))
		if err != nil {
			return nil, err
		}
		cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: d.proxy.Hostname(), RootCAs: d.rootCAs}
		tlsConn := tls.Client(conn, cfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("netguard: proxy TLS: %w", err)
		}
		return tlsConn, nil
	}
	return nil, fmt.Errorf("netguard: unsupported proxy scheme %q", d.proxy.Scheme)
}

func (d *dialer) handshake(conn net.Conn, target string) error {
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: target},
		Host:   target,
		Header: http.Header{},
	}
	if u := d.proxy.User; u != nil {
		pass, _ := u.Password()
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(u.Username()+":"+pass)))
	}
	if err := req.Write(conn); err != nil {
		return fmt.Errorf("netguard: proxy CONNECT: %w", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return fmt.Errorf("netguard: proxy CONNECT: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("netguard: proxy refused CONNECT: %s", resp.Status)
	}
	if br.Buffered() > 0 {
		return errors.New("netguard: proxy sent data before the tunnel was used")
	}
	return nil
}
