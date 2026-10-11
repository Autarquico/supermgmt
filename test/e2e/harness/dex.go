//go:build e2e

package harness

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// DexImage is pinned by digest (v2.45.1; the W0 spike, scratchpad m2/dex-spike.md).
const DexImage = "ghcr.io/dexidp/dex:v2.45.1@sha256:8499afd690c437f52301efd2b05b2455da5bd2dfc20332cd697dc9937f808462"

// DexHost is the name the IdP is reached by, from containers and from the issuer URL: the issuer
// must resolve for the SuperMgmt server too (spike finding 3).
const DexHost = "dex"

// DexUser is the one static password user; the password hash below is bcrypt("password").
const (
	DexUser         = "admin@example.com"
	DexPassword     = "password"
	dexPasswordHash = "$2y$10$6g4EvNEgaNOPZMNFkfzPT.jrUA/5Tv2o6f01VUI43t9kgtSGps1wa"
)

// Dex is a running identity provider on the docker network.
type Dex struct {
	Container    *Container
	Issuer       string
	ClientID     string
	ClientSecret string
	CallbackPort int
	hostPort     int
	ca           *CA
}

// FreePort returns a TCP port on 127.0.0.1 that was free a moment ago.
func FreePort(t testing.TB) int {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

// StartDex runs Dex with a static confidential client whose loopback redirect is registered on a
// fixed port (Dex rejects other ports for confidential clients) and with /device/callback, behind
// a certificate from ca. The issuer sits at the root path (spike finding 2).
func StartDex(t testing.TB, net *Network, ca *CA) *Dex {
	t.Helper()
	d := &Dex{Issuer: "https://" + DexHost + ":5556", ClientID: "supermgmt", CallbackPort: FreePort(t), ca: ca}
	d.ClientSecret = "e2e-" + strings.ToLower(rand.Text())
	dir := t.TempDir()
	pair := ca.Issue(t, []string{DexHost}, nil)
	certPath, keyPath := pair.WriteTo(t, dir, "dex")
	_ = os.Chmod(keyPath, 0o644) // throwaway key; the dex user must read it
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(d.config()), 0o644); err != nil {
		t.Fatal(err)
	}
	d.Container = Start(t, RunOptions{
		Image: DexImage, Network: net.Name, Aliases: []string{DexHost}, Publish: []string{"5556"},
		Cmd:   []string{"dex", "serve", "/etc/dex/config.yaml"},
		Files: map[string]string{"/etc/dex/config.yaml": cfgPath, "/etc/dex/dex.crt": certPath, "/etc/dex/dex.key": keyPath},
	})
	d.hostPort = d.Container.HostPort("5556")
	d.waitReady(t)
	return d
}

func (d *Dex) config() string {
	return fmt.Sprintf(`issuer: %s
storage:
  type: memory
web:
  https: 0.0.0.0:5556
  tlsCert: /etc/dex/dex.crt
  tlsKey: /etc/dex/dex.key
oauth2:
  skipApprovalScreen: true
  grantTypes: ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"]
staticClients:
  - id: %s
    name: SuperMgmt
    secret: %s
    redirectURIs: ["http://127.0.0.1:%d/callback", "/device/callback"]
enablePasswordDB: true
staticPasswords:
  - email: %s
    hash: %q
    username: admin
    userID: "08a8684b-db88-4b73-90a9-3cd1661f5466"
`, d.Issuer, d.ClientID, d.ClientSecret, d.CallbackPort, DexUser, dexPasswordHash)
}

func (d *Dex) waitReady(t testing.TB) {
	t.Helper()
	b := d.NewBrowser()
	deadline := Now().Add(time.Minute)
	for Now().Before(deadline) {
		resp, err := b.do(context.Background(), http.MethodGet, d.Issuer+"/.well-known/openid-configuration", nil)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("dex did not become ready\n%s", tail(d.Container.Logs(), 2000))
}

// Browser is the person's browser: it follows redirects through Dex, submits the login form and
// stops at the first redirect that leaves Dex.
type Browser struct {
	client *http.Client
	dex    *Dex
}

// NewBrowser returns a browser with its own cookie jar that resolves the IdP name to the
// published port and trusts only the test CA.
func (d *Dex) NewBrowser() *Browser {
	jar, _ := cookiejar.New(nil)
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: d.ca.Pool(), MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if host, _, err := net.SplitHostPort(addr); err == nil && host == DexHost {
				addr = net.JoinHostPort("127.0.0.1", strconv.Itoa(d.hostPort))
			}
			return dialer.DialContext(ctx, network, addr)
		},
	}
	return &Browser{dex: d, client: &http.Client{
		Jar: jar, Transport: transport, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// SignIn opens an authorization URL and signs in as the Dex user. A redirect that leaves Dex
// (the loopback callback of `sm login`) is requested and its status returned.
func (b *Browser) SignIn(ctx context.Context, authURL string) (int, error) {
	return b.walk(ctx, authURL)
}

// ApproveDevice enters the user code on the verification page and signs in.
func (b *Browser) ApproveDevice(ctx context.Context, verificationURI, userCode string) (int, error) {
	u, err := url.Parse(verificationURI)
	if err != nil {
		return 0, err
	}
	verify := u.Scheme + "://" + u.Host + "/device/auth/verify_code"
	resp, err := b.do(ctx, http.MethodPost, verify, url.Values{"user_code": {userCode}})
	if err != nil {
		return 0, err
	}
	return b.follow(ctx, resp, verify)
}

func (b *Browser) walk(ctx context.Context, target string) (int, error) {
	resp, err := b.do(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, err
	}
	return b.follow(ctx, resp, target)
}

const maxHops = 12

func (b *Browser) follow(ctx context.Context, resp *http.Response, current string) (int, error) {
	for range maxHops {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		base, _ := url.Parse(current)
		switch {
		case resp.StatusCode >= 300 && resp.StatusCode < 400:
			loc, err := resp.Location()
			if err != nil {
				return resp.StatusCode, err
			}
			next := base.ResolveReference(loc)
			if next.Hostname() != DexHost {
				leave, err := b.do(ctx, http.MethodGet, next.String(), nil)
				if err != nil {
					return 0, fmt.Errorf("callback %s: %w", next.Redacted(), err)
				}
				_ = leave.Body.Close()
				return leave.StatusCode, nil
			}
			current = next.String()
			resp, err = b.do(ctx, http.MethodGet, current, nil)
			if err != nil {
				return 0, err
			}
		case resp.StatusCode == http.StatusOK && bytes.Contains(body, []byte(`name="login"`)):
			var err error
			resp, err = b.do(ctx, http.MethodPost, current, url.Values{"login": {DexUser}, "password": {DexPassword}})
			if err != nil {
				return 0, err
			}
		case resp.StatusCode == http.StatusOK && strings.HasSuffix(base.Path, "/device/callback"):
			return resp.StatusCode, nil // Dex's own "you can close this window" page
		default:
			return resp.StatusCode, fmt.Errorf("unexpected page %s (%d): %.300s", base.Path, resp.StatusCode, body)
		}
	}
	return 0, fmt.Errorf("too many redirects from %s", current)
}

func (b *Browser) do(ctx context.Context, method, target string, form url.Values) (*http.Response, error) {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, err
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	return b.client.Do(req)
}
