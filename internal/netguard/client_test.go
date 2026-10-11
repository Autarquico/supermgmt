package netguard

import (
	"bufio"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testTimeout = 2 * time.Second
	testMaxBody = 1 << 10
)

// reaching records every address the filter let through and connects each to
// the test server instead.
type reaching struct {
	mu        sync.Mutex
	addresses []string
	target    string
}

func (r *reaching) dial(network, address string) (net.Conn, error) {
	r.mu.Lock()
	r.addresses = append(r.addresses, address)
	r.mu.Unlock()
	return (&net.Dialer{}).DialContext(context.Background(), network, r.target)
}

func (r *reaching) reached() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.addresses...)
}

func serve(t *testing.T, h http.Handler) (*httptest.Server, *reaching) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv, &reaching{target: srv.Listener.Addr().String()}
}

func fixedLookup(answers map[string][]string) lookupFunc {
	return func(_ context.Context, host string) ([]netip.Addr, error) {
		var out []netip.Addr
		for _, a := range answers[host] {
			out = append(out, netip.MustParseAddr(a))
		}
		if out == nil {
			return nil, errors.New("no such host")
		}
		return out, nil
	}
}

func get(c *http.Client, rawURL string) (string, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return string(body), err
}

func okHandler(body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body) })
}

func TestProductionClientCannotReachLoopback(t *testing.T) {
	var hits atomic.Int32
	count := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) })
	plain := httptest.NewServer(count)
	defer plain.Close()
	secure := httptest.NewTLSServer(count)
	defer secure.Close()

	client := NewClient(Allow{AllowAllPrivate: true, AllowHTTP: true}, nil, testTimeout, testMaxBody)
	port := plain.Listener.Addr().(*net.TCPAddr).Port
	targets := []string{
		plain.URL,
		secure.URL,
		"http://localhost:" + strconv.Itoa(port),
		"http://[::1]:" + strconv.Itoa(port),
		"http://127.1:" + strconv.Itoa(port),
		"http://[::ffff:127.0.0.1]:" + strconv.Itoa(port),
		"http://169.254.169.254/latest/meta-data",
	}
	for _, target := range targets {
		if _, err := get(client, target); !errors.Is(err, ErrBlocked) {
			t.Errorf("GET %s = %v, want ErrBlocked", target, err)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("a loopback server was reached %d times", hits.Load())
	}
}

func TestTestDialerDoesNotBypassTheFilter(t *testing.T) {
	srv, r := serve(t, okHandler("secret"))
	client := NewClient(Allow{AllowAllPrivate: true, AllowHTTP: true}, nil, testTimeout, testMaxBody, WithTestDialer(r.dial))

	if _, err := get(client, srv.URL); !errors.Is(err, ErrBlocked) {
		t.Fatalf("loopback with test dialer = %v, want ErrBlocked", err)
	}
	if got := r.reached(); len(got) != 0 {
		t.Fatalf("test dialer was called for a refused address: %v", got)
	}
	body, err := get(client, "http://10.0.0.7:8080/")
	if err != nil || body != "secret" {
		t.Fatalf("private address through test dialer = %q, %v", body, err)
	}
	if got := r.reached(); len(got) != 1 || got[0] != "10.0.0.7:8080" {
		t.Fatalf("dialed %v, want the vetted 10.0.0.7:8080", got)
	}
}

func TestRequestRules(t *testing.T) {
	_, r := serve(t, okHandler("ok"))
	tests := []struct {
		name    string
		allow   Allow
		url     string
		blocked bool
	}{
		{"http refused by default", Allow{AllowAllPrivate: true}, "http://10.0.0.7/", true},
		{"http allowed for health checks", Allow{AllowAllPrivate: true, AllowHTTP: true}, "http://10.0.0.7/", false},
		{"userinfo refused", Allow{AllowAllPrivate: true, AllowHTTP: true}, "http://user:pw@10.0.0.7/", true},
		{"other schemes refused", Allow{AllowAllPrivate: true, AllowHTTP: true}, "ftp://10.0.0.7/", true},
		{"private refused without allowlist", Allow{AllowHTTP: true}, "http://10.0.0.7/", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewClient(tt.allow, nil, testTimeout, testMaxBody, WithTestDialer(r.dial))
			_, err := get(client, tt.url)
			if tt.blocked != errors.Is(err, ErrBlocked) || (!tt.blocked && err != nil) {
				t.Fatalf("GET %s: err = %v, want blocked=%v", tt.url, err, tt.blocked)
			}
		})
	}
}

func TestDialResolvesOnceAndPinsTheVettedIP(t *testing.T) {
	_, r := serve(t, okHandler("ok"))
	var lookups atomic.Int32
	lookup := func(ctx context.Context, host string) ([]netip.Addr, error) {
		lookups.Add(1)
		return fixedLookup(map[string][]string{"app.example": {"203.0.113.9", "10.0.0.8"}})(ctx, host)
	}
	client := newClient(Allow{AllowAllPrivate: true, AllowHTTP: true}, nil, testTimeout, testMaxBody, lookup, options{dial: r.dial})

	if _, err := get(client, "http://app.example:8080/"); err != nil {
		t.Fatal(err)
	}
	if lookups.Load() != 1 {
		t.Fatalf("lookups = %d, want 1", lookups.Load())
	}
	if got := r.reached(); len(got) != 1 || got[0] != "203.0.113.9:8080" {
		t.Fatalf("dialed %v, want the first vetted IP", got)
	}
}

func TestDialRefusesRebindingToInternalAddresses(t *testing.T) {
	_, r := serve(t, okHandler("ok"))
	answers := map[string][]string{"rebind.example": {"8.8.8.8"}}
	var mu sync.Mutex
	lookup := func(ctx context.Context, host string) ([]netip.Addr, error) {
		mu.Lock()
		defer mu.Unlock()
		return fixedLookup(answers)(ctx, host)
	}
	client := newClient(Allow{AllowAllPrivate: true, AllowHTTP: true}, nil, testTimeout, testMaxBody, lookup, options{dial: r.dial})
	client.Transport.(*guardedTransport).next.(*http.Transport).DisableKeepAlives = true

	if _, err := get(client, "http://rebind.example/"); err != nil {
		t.Fatalf("first answer is public: %v", err)
	}
	for _, evil := range [][]string{{"127.0.0.1"}, {"169.254.169.254"}, {"8.8.8.8", "127.0.0.1"}, {"::ffff:127.0.0.1"}} {
		mu.Lock()
		answers["rebind.example"] = evil
		mu.Unlock()
		before := len(r.reached())
		if _, err := get(client, "http://rebind.example/"); !errors.Is(err, ErrBlocked) {
			t.Errorf("answer %v: err = %v, want ErrBlocked", evil, err)
		}
		if len(r.reached()) != before {
			t.Errorf("answer %v: a connection was opened", evil)
		}
	}
}

func TestDialFailsWhenNameDoesNotResolve(t *testing.T) {
	client := newClient(Allow{AllowAllPrivate: true, AllowHTTP: true}, nil, testTimeout, testMaxBody, fixedLookup(nil), options{})
	if _, err := get(client, "http://nowhere.example/"); err == nil {
		t.Fatal("want an error for an unresolvable name")
	}
}

func TestTLSVerifiesTheOriginalHostname(t *testing.T) {
	srv := httptest.NewTLSServer(okHandler("secure"))
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	r := &reaching{target: srv.Listener.Addr().String()}
	lookup := fixedLookup(map[string][]string{"example.com": {"10.0.0.9"}, "evil.test": {"10.0.0.9"}})
	client := newClient(Allow{AllowAllPrivate: true}, nil, testTimeout, testMaxBody, lookup, options{dial: r.dial, rootCAs: pool})

	body, err := get(client, "https://example.com/")
	if err != nil || body != "secure" {
		t.Fatalf("certificate is valid for example.com: %q, %v", body, err)
	}
	if _, err := get(client, "https://evil.test/"); err == nil {
		t.Fatal("a certificate for another name must be refused")
	}
}

func TestRedirects(t *testing.T) {
	build := func() func(Allow) *http.Client {
		mux := http.NewServeMux()
		mux.HandleFunc("/end", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "end") })
		mux.HandleFunc("/hop", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/end", http.StatusFound) })
		mux.HandleFunc("/chain", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/hop", http.StatusFound) })
		mux.HandleFunc("/loopback", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://127.0.0.1:1/", http.StatusFound)
		})
		mux.HandleFunc("/foreign", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://10.9.9.9/end", http.StatusFound)
		})
		srv := httptest.NewServer(mux)
		t.Cleanup(srv.Close)
		r := &reaching{target: srv.Listener.Addr().String()}
		return func(a Allow) *http.Client {
			a.AllowAllPrivate, a.AllowHTTP = true, true
			return NewClient(a, nil, testTimeout, testMaxBody, WithTestDialer(r.dial))
		}
	}()
	host := "10.0.0.7"

	t.Run("disabled by default", func(t *testing.T) {
		if _, err := get(build(Allow{}), "http://"+host+"/hop"); !errors.Is(err, ErrRedirect) {
			t.Fatalf("err = %v, want ErrRedirect", err)
		}
	})
	t.Run("allowed to a listed host within the limit", func(t *testing.T) {
		c := build(Allow{Redirects: RedirectPolicy{Max: 2, Hosts: []string{host}}})
		if body, err := get(c, "http://"+host+"/chain"); err != nil || body != "end" {
			t.Fatalf("got %q, %v", body, err)
		}
	})
	t.Run("too many", func(t *testing.T) {
		c := build(Allow{Redirects: RedirectPolicy{Max: 1, Hosts: []string{host}}})
		if _, err := get(c, "http://"+host+"/chain"); !errors.Is(err, ErrRedirect) {
			t.Fatalf("err = %v, want ErrRedirect", err)
		}
	})
	t.Run("host not listed", func(t *testing.T) {
		c := build(Allow{Redirects: RedirectPolicy{Max: 3, Hosts: []string{host}}})
		if _, err := get(c, "http://"+host+"/foreign"); !errors.Is(err, ErrRedirect) {
			t.Fatalf("err = %v, want ErrRedirect", err)
		}
	})
	t.Run("listed host is filtered again when dialed", func(t *testing.T) {
		c := build(Allow{Redirects: RedirectPolicy{Max: 3, Hosts: []string{host, "127.0.0.1"}}})
		if _, err := get(c, "http://"+host+"/loopback"); !errors.Is(err, ErrBlocked) {
			t.Fatalf("err = %v, want ErrBlocked", err)
		}
	})
}

func TestRedirectCannotDowngradeScheme(t *testing.T) {
	downgrade := &RedirectPolicy{Max: 3, Hosts: []string{"10.0.0.7"}}
	https, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://10.0.0.7/a", nil)
	http1, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://10.0.0.7/b", nil)
	if err := downgrade.check(http1, []*http.Request{https}); !errors.Is(err, ErrRedirect) {
		t.Fatalf("https to http = %v, want ErrRedirect", err)
	}
	if err := downgrade.check(https, []*http.Request{https}); err != nil {
		t.Fatalf("https to https = %v", err)
	}
}

func TestResponseBodyCap(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := len(r.URL.Query().Get("n"))
		if r.URL.Query().Get("chunked") != "" {
			w.(http.Flusher).Flush()
		}
		_, _ = io.WriteString(w, strings.Repeat("a", n))
	})
	_, r := serve(t, handler)
	client := NewClient(Allow{AllowAllPrivate: true, AllowHTTP: true}, nil, testTimeout, 10, WithTestDialer(r.dial))
	url := func(n int, chunked bool) string {
		q := "?n=" + strings.Repeat("x", n)
		if chunked {
			q += "&chunked=1"
		}
		return "http://10.0.0.7/" + q
	}

	for _, chunked := range []bool{false, true} {
		if body, err := get(client, url(10, chunked)); err != nil || len(body) != 10 {
			t.Errorf("chunked=%v at the cap: %d bytes, %v", chunked, len(body), err)
		}
		if _, err := get(client, url(11, chunked)); !errors.Is(err, ErrBodyTooLarge) {
			t.Errorf("chunked=%v over the cap: err = %v, want ErrBodyTooLarge", chunked, err)
		}
	}
}

func TestTimeoutAppliesToSlowServers(t *testing.T) {
	release := make(chan struct{})
	_, r := serve(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	t.Cleanup(func() { close(release) }) // runs before the server closes
	client := NewClient(Allow{AllowAllPrivate: true, AllowHTTP: true}, nil, 100*time.Millisecond, testMaxBody, WithTestDialer(r.dial))

	_, err := get(client, "http://10.0.0.7/")
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("err = %v, want a timeout", err)
	}
}

// fakeProxy accepts CONNECT, records its target and tunnels to upstream.
type fakeProxy struct {
	listener net.Listener
	upstream string
	status   int
	mu       sync.Mutex
	targets  []string
	auth     []string
}

func startFakeProxy(t *testing.T, upstream string, status int) *fakeProxy {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeProxy{listener: l, upstream: upstream, status: status}
	t.Cleanup(func() { _ = l.Close() })
	go p.accept()
	return p
}

func (p *fakeProxy) accept() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			return
		}
		go p.serve(conn)
	}
}

func (p *fakeProxy) serve(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	p.mu.Lock()
	p.targets = append(p.targets, req.Host)
	p.auth = append(p.auth, req.Header.Get("Proxy-Authorization"))
	p.mu.Unlock()
	if p.status != http.StatusOK {
		_, _ = io.WriteString(conn, "HTTP/1.1 "+strconv.Itoa(p.status)+" no\r\nContent-Length: 0\r\n\r\n")
		return
	}
	up, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", p.upstream)
	if err != nil {
		return
	}
	defer up.Close()
	_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n")
	go func() { _, _ = io.Copy(up, br); _ = up.Close() }()
	_, _ = io.Copy(conn, up)
}

func (p *fakeProxy) seen() ([]string, []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.targets...), append([]string(nil), p.auth...)
}

func TestProxyReceivesConnectToThePinnedIP(t *testing.T) {
	upstream := httptest.NewServer(okHandler("via proxy"))
	defer upstream.Close()
	proxy := startFakeProxy(t, upstream.Listener.Addr().String(), http.StatusOK)
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")

	proxyURL := &url.URL{Scheme: "http", User: url.UserPassword("u", "p"), Host: proxy.listener.Addr().String()}
	lookup := fixedLookup(map[string][]string{"app.example": {"10.0.0.8"}})
	client := newClient(Allow{AllowAllPrivate: true, AllowHTTP: true}, proxyURL, testTimeout, testMaxBody, lookup, options{})

	body, err := get(client, "http://app.example:8080/")
	if err != nil || body != "via proxy" {
		t.Fatalf("got %q, %v", body, err)
	}
	targets, auth := proxy.seen()
	if len(targets) != 1 || targets[0] != "10.0.0.8:8080" {
		t.Fatalf("CONNECT targets = %v, want the pinned 10.0.0.8:8080", targets)
	}
	if len(auth) != 1 || !strings.HasPrefix(auth[0], "Basic ") {
		t.Fatalf("Proxy-Authorization = %v", auth)
	}
}

func TestProxyIsNotUsedForRefusedDestinations(t *testing.T) {
	proxy := startFakeProxy(t, "127.0.0.1:1", http.StatusOK)
	proxyURL := &url.URL{Scheme: "http", Host: proxy.listener.Addr().String()}
	client := newClient(Allow{AllowAllPrivate: true, AllowHTTP: true}, proxyURL, testTimeout, testMaxBody,
		fixedLookup(map[string][]string{"internal.example": {"127.0.0.1"}}), options{})

	for _, target := range []string{"http://internal.example/", "http://169.254.169.254/"} {
		if _, err := get(client, target); !errors.Is(err, ErrBlocked) {
			t.Errorf("GET %s = %v, want ErrBlocked", target, err)
		}
	}
	if targets, _ := proxy.seen(); len(targets) != 0 {
		t.Fatalf("the proxy was asked to connect to %v", targets)
	}
}

func TestProxyRefusalFailsTheRequest(t *testing.T) {
	proxy := startFakeProxy(t, "127.0.0.1:1", http.StatusForbidden)
	proxyURL := &url.URL{Scheme: "http", Host: proxy.listener.Addr().String()}
	client := newClient(Allow{AllowAllPrivate: true, AllowHTTP: true}, proxyURL, testTimeout, testMaxBody, lookupHost, options{})
	if _, err := get(client, "http://10.0.0.8/"); err == nil {
		t.Fatal("want an error when the proxy refuses CONNECT")
	}
}

func TestUnsupportedProxySchemeFailsClosed(t *testing.T) {
	client := NewClient(Allow{AllowAllPrivate: true, AllowHTTP: true}, &url.URL{Scheme: "socks5", Host: "127.0.0.1:1080"}, testTimeout, testMaxBody)
	if _, err := get(client, "http://10.0.0.8/"); err == nil {
		t.Fatal("want an error for an unsupported proxy scheme")
	}
}
