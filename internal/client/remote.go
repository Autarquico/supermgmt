package client

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const (
	tlsHandshakeTimeout   = 10 * time.Second
	responseHeaderTimeout = 30 * time.Second
	maxCAFileBytes        = 1 << 20
)

// Remote says where a server is and how to trust and authenticate to it
// (spec §8.4 client profiles, §23.1).
type Remote struct {
	// URL is the server origin: https://host[:port].
	URL string
	// CAFile, when set, is a PEM bundle trusted in addition to the system
	// roots (a private CA or a self-managed certificate).
	CAFile string
	// Token is the bearer credential; empty before the first login.
	Token string
}

// NewRemote returns a Client of the server at r. It speaks HTTPS only, with
// TLS 1.2 or newer, never follows a redirect (a redirect must not carry the
// bearer elsewhere) and does not connect until the first request.
func NewRemote(r Remote, opts Options) (*Client, error) {
	base, err := ValidateServerURL(r.URL)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := tlsConfigFor(r.CAFile)
	if err != nil {
		return nil, err
	}
	c := New(opts)
	c.base, c.token, c.remote = base, r.Token, true
	c.http = &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			TLSClientConfig:       tlsConfig,
			TLSHandshakeTimeout:   tlsHandshakeTimeout,
			ResponseHeaderTimeout: responseHeaderTimeout,
			ForceAttemptHTTP2:     true,
		},
	}
	return c, nil
}

// Remote reports whether c talks to a server rather than the local daemon.
func (c *Client) Remote() bool { return c.remote }

// Server is the origin of a remote client ("" for the local daemon).
func (c *Client) Server() string {
	if !c.remote {
		return ""
	}
	return c.base
}

// ValidateServerURL returns the normalized origin of a server URL. Only https
// is accepted, so a token never travels in clear text; a path, query,
// fragment or credentials in the URL are refused rather than ignored.
func ValidateServerURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	switch {
	case err != nil:
		return "", smerr.New(smerr.CodeInvalidArgument, "", fmt.Sprintf("server URL %q: %v", raw, err))
	case u.Scheme != "https":
		return "", smerr.New(smerr.CodeInvalidArgument, "", fmt.Sprintf("server URL %q must use https: tokens never travel in clear text", raw))
	case u.Hostname() == "":
		return "", smerr.New(smerr.CodeInvalidArgument, "", fmt.Sprintf("server URL %q has no host", raw))
	case u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/"):
		return "", smerr.New(smerr.CodeInvalidArgument, "", fmt.Sprintf("server URL %q must be an origin like https://host[:port]", raw))
	}
	return "https://" + u.Host, nil
}

func tlsConfigFor(caFile string) (*tls.Config, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if caFile != "" {
		pem, err := readCAFile(caFile)
		if err != nil {
			return nil, err
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, smerr.New(smerr.CodeInvalidArgument, "", fmt.Sprintf("ca_file %s holds no PEM certificate", caFile))
		}
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}, nil
}

func readCAFile(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, smerr.New(smerr.CodeInvalidArgument, "", fmt.Sprintf("ca_file %s must be an absolute path", path))
	}
	f, err := os.Open(path) //nolint:gosec // the operator's own profile names this file
	if err != nil {
		return nil, smerr.New(smerr.CodeInvalidArgument, "", fmt.Sprintf("cannot read ca_file: %v", err))
	}
	defer func() { _ = f.Close() }()
	pem, err := io.ReadAll(io.LimitReader(f, maxCAFileBytes+1))
	if err != nil {
		return nil, smerr.New(smerr.CodeInvalidArgument, "", fmt.Sprintf("cannot read ca_file: %v", err))
	}
	if len(pem) > maxCAFileBytes {
		return nil, smerr.New(smerr.CodeInvalidArgument, "", fmt.Sprintf("ca_file %s is larger than %d bytes", path, maxCAFileBytes))
	}
	return pem, nil
}
