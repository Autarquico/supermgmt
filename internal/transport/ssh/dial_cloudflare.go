package ssh

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/netguard"
)

// AccessTokenRef is where the runtime Access service token lives
// (`client_id:client_secret`, ADR-0037).
const AccessTokenRef = "secret://cloudflare/access-service-token"

// AccessToken is the Cloudflare Access service token the dialler presents.
type AccessToken struct {
	ClientID     string
	ClientSecret audit.Secret
}

// ParseAccessToken reads the stored `client_id:client_secret` form. Control
// characters are refused: both halves travel in the child's environment.
func ParseAccessToken(stored string) (AccessToken, error) {
	id, secret, ok := strings.Cut(strings.TrimSpace(stored), ":")
	if !ok || id == "" || secret == "" || strings.ContainsFunc(id+secret, func(r rune) bool { return r < 0x21 || r == 0x7f }) {
		return AccessToken{}, smerr.New(smerr.CodeInvalidArgument, "", "the Cloudflare Access service token must be client_id:client_secret")
	}
	return AccessToken{ClientID: id, ClientSecret: audit.Secret(secret)}, nil
}

// AccessTokenSource resolves the service token at dial time (the app wires the
// secrets store behind it). Errors pass through unchanged.
type AccessTokenSource interface {
	AccessToken(ctx context.Context) (AccessToken, error)
}

// defaultCloudflaredDirs is searched, in order, when no path is configured. The
// inherited PATH is never consulted.
var defaultCloudflaredDirs = []string{"/usr/local/bin", "/opt/homebrew/bin", "/usr/bin"}

// CloudflareConfig configures the cloudflare dialler.
type CloudflareConfig struct {
	// Path is the absolute path of cloudflared. Empty searches SearchDirs.
	Path string
	// SearchDirs replaces the default fixed list.
	SearchDirs []string
	// HomeDir is a private directory the daemon owns, used as the child's HOME.
	// Empty creates a temporary one, removed by Close.
	HomeDir string
	Tokens  AccessTokenSource
	// Preflight sends the Access probe; nil builds a netguard client.
	Preflight *http.Client
	// KillGrace is the time between SIGTERM and SIGKILL (default 3s).
	KillGrace time.Duration
}

// CloudflareDialer reaches a node through `cloudflared access ssh`.
type CloudflareDialer struct {
	path      string
	pathErr   error
	tokens    AccessTokenSource
	preflight *http.Client
	grace     time.Duration

	homeMu  sync.Mutex
	home    string
	ownHome bool
}

// NewCloudflareDialer resolves cloudflared once. A missing binary is not a
// construction failure: every dial then fails with CAPABILITY_UNAVAILABLE, so
// the daemon starts on hosts without it and only tunnel nodes are affected.
func NewCloudflareDialer(cfg CloudflareConfig) *CloudflareDialer {
	d := &CloudflareDialer{tokens: cfg.Tokens, preflight: cfg.Preflight, grace: cfg.KillGrace, home: cfg.HomeDir}
	if d.grace <= 0 {
		d.grace = 3 * time.Second
	}
	if d.preflight == nil {
		d.preflight = netguard.NewClient(netguard.Allow{}, nil, 15*time.Second, 64<<10)
	}
	d.path, d.pathErr = resolveCloudflared(cfg)
	return d
}

// LocateCloudflared finds cloudflared where the dialler would look for it, so
// the doctor reports what a dial will use. A missing binary is
// CAPABILITY_UNAVAILABLE naming it.
func LocateCloudflared() (string, error) { return resolveCloudflared(CloudflareConfig{}) }

func resolveCloudflared(cfg CloudflareConfig) (string, error) {
	missing := smerr.New(smerr.CodeCapabilityUnavailable, "", "cloudflared is not installed on the control plane: install it to use the cloudflare transport")
	candidates := []string{cfg.Path}
	if cfg.Path == "" {
		dirs := cfg.SearchDirs
		if dirs == nil {
			dirs = defaultCloudflaredDirs
		}
		candidates = candidates[:0]
		for _, dir := range dirs {
			candidates = append(candidates, filepath.Join(dir, "cloudflared"))
		}
	} else if !filepath.IsAbs(cfg.Path) {
		return "", smerr.New(smerr.CodeInvalidArgument, "", "the cloudflared path must be absolute")
	}
	for _, c := range candidates {
		if !filepath.IsAbs(c) {
			continue
		}
		if info, err := os.Stat(c); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
			return c, nil
		}
	}
	return "", missing
}

// Close removes the HOME directory the dialler created. Live connections are
// owned by the pool and closed there.
func (d *CloudflareDialer) Close() {
	d.homeMu.Lock()
	defer d.homeMu.Unlock()
	if d.ownHome {
		_ = os.RemoveAll(d.home)
		d.home, d.ownHome = "", false
	}
}

func (d *CloudflareDialer) homeDir() (string, error) {
	d.homeMu.Lock()
	defer d.homeMu.Unlock()
	if d.home == "" {
		dir, err := os.MkdirTemp("", "supermgmt-cloudflared-home-")
		if err != nil {
			return "", smerr.Wrap(err, smerr.CodeInternal, "", "create the cloudflared home directory")
		}
		d.home, d.ownHome = dir, true
		return dir, nil
	}
	if err := os.MkdirAll(d.home, 0o700); err != nil {
		return "", smerr.Wrap(err, smerr.CodeInternal, "", "create the cloudflared home directory")
	}
	return d.home, nil
}

// DialContext validates, checks that Access admits the token, then spawns the
// child. ctx bounds the preflight only; the child lives with the connection.
func (d *CloudflareDialer) DialContext(ctx context.Context, t Target) (net.Conn, error) {
	if t.Transport.Effective() != domain.TransportCloudflare {
		return nil, smerr.New(smerr.CodeInvalidArgument, "", "the cloudflare dialer needs transport cloudflare")
	}
	if err := validateTransport(t); err != nil {
		return nil, err
	}
	if d.pathErr != nil {
		return nil, d.pathErr
	}
	if d.tokens == nil {
		return nil, smerr.New(smerr.CodeCapabilityUnavailable, "", "no Cloudflare Access service token source is configured")
	}
	token, err := d.tokens.AccessToken(ctx)
	if err != nil {
		return nil, err
	}
	if err := d.checkAdmitted(ctx, t.TunnelHostname, token); err != nil {
		return nil, err
	}
	home, err := d.homeDir()
	if err != nil {
		return nil, err
	}
	return startChild(childSpec{
		path: d.path, hostname: t.TunnelHostname, home: home, token: token, grace: d.grace,
	})
}

// checkAdmitted sends the service-token headers to the tunnel hostname the way
// cloudflared will, and refuses when Access answers with its login redirect:
// cloudflared would then try to open a browser.
func (d *CloudflareDialer) checkAdmitted(ctx context.Context, hostname string, token AccessToken) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+hostname+"/", nil)
	if err != nil {
		return smerr.Wrap(err, smerr.CodeInvalidArgument, "", "invalid tunnel hostname")
	}
	req.Header.Set("CF-Access-Client-Id", token.ClientID)
	req.Header.Set("CF-Access-Client-Secret", token.ClientSecret.Reveal())
	client := *d.preflight
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctxError("cloudflare access preflight", ctx.Err())
		}
		return unreachable("cloudflare access preflight", sanitizedError{err, token})
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	if isAccessLogin(resp) {
		return smerr.New(smerr.CodeNodeUnreachable, "", "Cloudflare Access did not admit the service token for "+hostname+
			": check that the token is in the application's service policy")
	}
	return nil
}

// isAccessLogin recognises Access's redirect to its login page.
func isAccessLogin(resp *http.Response) bool {
	switch resp.StatusCode {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
	default:
		return false
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		return false
	}
	host := strings.ToLower(loc.Hostname())
	return host == "cloudflareaccess.com" || strings.HasSuffix(host, ".cloudflareaccess.com")
}

// sanitizedError hides the token from an error that could echo a request.
type sanitizedError struct {
	err   error
	token AccessToken
}

func (e sanitizedError) Error() string {
	return sanitizeDiagnostic(e.err.Error(), e.token.ClientID, e.token.ClientSecret.Reveal())
}

func (e sanitizedError) Unwrap() error { return e.err }
