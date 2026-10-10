// Package netguard is the outbound request filter of spec §21.1: resolve
// once, normalize, refuse metadata, loopback, link-local, multicast and
// reserved addresses for every caller, refuse private and special ranges
// unless the caller's allowlist names them, then dial the vetted IP while TLS
// verifies the original hostname. Ambient proxy variables are never read.
package netguard

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"
)

// Refusals a caller can branch on with errors.Is.
var (
	// ErrBlocked means the filter refused the request: scheme, userinfo or a
	// destination address (§21.1 steps 1-5).
	ErrBlocked = errors.New("netguard: destination refused")
	// ErrRedirect means a redirect was refused (§21.1 step 6).
	ErrRedirect = errors.New("netguard: redirect refused")
	// ErrBodyTooLarge means the response body exceeded the cap (§21.1 step 7).
	ErrBodyTooLarge = errors.New("netguard: response body too large")
)

// RedirectPolicy says which redirects a client may follow (§21.1 step 6).
type RedirectPolicy struct {
	// Max is the number of redirects allowed; 0 disables them.
	Max int
	// Hosts lists the only hosts a redirect may go to.
	Hosts []string
}

// Allow is a caller's allowlist (§21.1 step 5). The always-denied ranges of
// step 3 cannot be allowed by any field.
type Allow struct {
	PrivateCIDRs    []netip.Prefix // health checks: health.allowed_private_cidrs
	AllowAllPrivate bool           // provider endpoints, including OIDC IdPs
	AllowHTTP       bool           // health checks only
	Redirects       RedirectPolicy
}

// Option adjusts a client. The production code passes none.
type Option func(*options)

type options struct {
	dial    func(network, address string) (net.Conn, error)
	rootCAs *x509.CertPool
}

// WithTestDialer replaces the final dial after filtering, so tests can reach a
// local server. It exists for tests only: no production caller passes it, and
// the filter still runs on the address the request resolved to.
func WithTestDialer(dial func(network, address string) (net.Conn, error)) Option {
	return func(o *options) { o.dial = dial }
}

// WithTestRootCAs trusts the given roots instead of the system pool, so tests
// can serve TLS from a throwaway CA. Test only, like WithTestDialer.
func WithTestRootCAs(pool *x509.CertPool) Option {
	return func(o *options) { o.rootCAs = pool }
}

// NewClient returns an http.Client that applies the filter on every dial,
// caps response bodies at maxBody and uses proxy (nil: direct) via CONNECT to
// the pinned IP.
func NewClient(a Allow, proxy *url.URL, timeout time.Duration, maxBody int64, opts ...Option) *http.Client {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	return newClient(a, proxy, timeout, maxBody, lookupHost, o)
}

func newClient(a Allow, proxy *url.URL, timeout time.Duration, maxBody int64, lookup lookupFunc, o options) *http.Client {
	d := &dialer{allow: a, proxy: proxy, timeout: timeout, lookup: lookup, dialRaw: o.dial, rootCAs: o.rootCAs}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            d.DialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: o.rootCAs},
		TLSHandshakeTimeout:    timeout,
		ResponseHeaderTimeout:  timeout,
		MaxResponseHeaderBytes: 64 << 10,
	}
	return &http.Client{
		Transport:     &guardedTransport{next: transport, allowHTTP: a.AllowHTTP, maxBody: maxBody},
		Timeout:       timeout,
		CheckRedirect: a.Redirects.check,
	}
}
