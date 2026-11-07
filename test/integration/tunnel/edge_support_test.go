package tunnel

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
)

// skewClock is the wall clock plus every wait the instance asked for: a sleep costs no real time but the
// instance sees it pass. Real time keeps flowing, so schedulers and polling loops still make progress.
type skewClock struct {
	skew atomic.Int64
}

func (c *skewClock) Now() time.Time {
	return domain.SystemClock{}.Now().Add(time.Duration(c.skew.Load()))
}

func (c *skewClock) sleep(_ context.Context, d time.Duration) {
	c.skew.Add(int64(d))
}

// systemResolver is the resolver of the control plane, which answers NXDOMAIN for a name until the test serves
// it: either because Cloudflare has not published it for the resolver's upstream yet, or because it cached the
// negative answer. The Access preflight looks names up in it directly; the cloudflared stand-in, a separate
// process, reads the same list from its HOME.
type systemResolver struct {
	home string

	now func() time.Time
	mu  sync.Mutex
	// served are the names the carrier children resolve (the file); inProcess the ones the preflight does.
	served    []string
	inProcess []string
	lookups   map[string]int
	first     map[string]time.Time
}

func newSystemResolver(home string, now func() time.Time) *systemResolver {
	r := &systemResolver{home: home, now: now, lookups: map[string]int{}, first: map[string]time.Time{}}
	r.write()
	return r
}

func (r *systemResolver) write() {
	_ = os.WriteFile(filepath.Join(r.home, "resolver"), []byte(strings.Join(r.served, "\n")+"\n"), 0o600)
}

// serve makes host resolve from now on, for the preflight and the carrier alike.
func (r *systemResolver) serve(host string) {
	r.serveInProcess(host)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.served = append(r.served, host)
	r.write()
}

// serveInProcess makes host resolve for the preflight only: the carrier still gets NXDOMAIN.
func (r *systemResolver) serveInProcess(host string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.inProcess = append(r.inProcess, host)
}

// firstLookup is when the control plane's process first looked host up; zero if it never did.
func (r *systemResolver) firstLookup(host string) time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.first[host]
}

func (r *systemResolver) lookup(host string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lookups[host]++
	if _, seen := r.first[host]; !seen {
		r.first[host] = r.now()
	}
	for _, h := range r.inProcess {
		if h == host {
			return nil
		}
	}
	return &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func (r *systemResolver) inProcessLookups(host string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lookups[host]
}

// lookupsOf is every lookup of host made by the control plane's own process and by the carrier children.
func (r *systemResolver) lookupsOf(host string) int {
	r.mu.Lock()
	n := r.lookups[host]
	r.mu.Unlock()
	raw, _ := os.ReadFile(filepath.Join(r.home, "lookups"))
	for _, line := range strings.Fields(string(raw)) {
		if line == host {
			n++
		}
	}
	return n
}

// preflightClient is the Access probe of the dialler. Without a modelled resolver it is a stub that answers
// like Access; with one it is a real HTTP client that looks the hostname up in the resolver before it
// connects, so a lookup before publication is observable and an NXDOMAIN reaches the dialler as the
// *net.DNSError the system resolver gives.
func (s *stack) preflightClient() *http.Client {
	if s.resolver == nil {
		return s.preflight()
	}
	access := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.denyAccess.Load() && s.admits(r.Header.Get("CF-Access-Client-Id"), r.Header.Get("CF-Access-Client-Secret")) {
			return
		}
		w.Header().Set("Location", "https://team.cloudflareaccess.com/cdn-cgi/access/login/"+r.Host)
		w.WriteHeader(http.StatusFound)
	}))
	s.t.Cleanup(access.Close)
	transport := access.Client().Transport.(*http.Transport).Clone() //nolint:forcetypeassert // httptest's client is an *http.Transport
	transport.TLSClientConfig.ServerName = "example.com"             // the name httptest's certificate is valid for
	transport.DialContext = func(ctx context.Context, _, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if err := s.resolver.lookup(host); err != nil {
			return nil, err
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", access.Listener.Addr().String())
	}
	return &http.Client{Transport: transport}
}
