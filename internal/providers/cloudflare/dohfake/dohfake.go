// Package dohfake is Cloudflare's DNS-over-HTTPS resolver (the JSON API of cloudflare-dns.com) as the
// publication gate sees it, with the states a hostname goes through on a real account: not served yet,
// served, NODATA, a broken resolver, an unreachable one and a stale positive answer. It is a test double
// that serves HTTPS on a throwaway CA; no production package imports it.
package dohfake

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"

	"github.com/autarquico/supermgmt/internal/netguard"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare"
)

const (
	typeA    = 1
	typeAAAA = 28

	statusServFail = 2
	statusNXDomain = 3
)

// Mode is how the resolver answers every question.
type Mode int

const (
	// NotServed answers NXDOMAIN; PublishAfter makes it serve after some questions.
	NotServed Mode = iota
	// Served answers an A record.
	Served
	// NoData answers NOERROR without records.
	NoData
	// ServFail answers SERVFAIL.
	ServFail
	// Unreachable answers HTTP 503, as a proxy or captive portal in the way would.
	Unreachable
	// Malformed answers a body that is not DNS-over-HTTPS JSON.
	Malformed
	// Stale keeps answering the A record of a hostname that is no longer served (a cached positive answer).
	Stale
)

// Fake is the resolver.
type Fake struct {
	srv *httptest.Server

	mu        sync.Mutex
	mode      Mode
	notYet    int
	thenServe bool
	polls     int
	hostPoll  map[string]int
}

// New starts the fake, serving nothing yet. It is stopped when the test ends.
func New(t testing.TB) *Fake {
	t.Helper()
	f := &Fake{hostPoll: map[string]int{}}
	f.srv = httptest.NewTLSServer(f)
	t.Cleanup(f.srv.Close)
	return f
}

// Set changes how the resolver answers from now on.
func (f *Fake) Set(m Mode) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mode, f.notYet, f.thenServe = m, 0, false
}

// PublishAfter answers NXDOMAIN to the next n questions of an A record, then serves.
func (f *Fake) PublishAfter(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mode, f.notYet, f.thenServe = NotServed, n, true
}

// Polls is how many questions the resolver has answered, A and AAAA alike.
func (f *Fake) Polls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.polls
}

// Asked is how many questions named host.
func (f *Fake) Asked(host string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hostPoll[host]
}

// Checker is a publication checker that asks this fake.
func (f *Fake) Checker(opts ...cloudflare.PublicationOption) *cloudflare.PublicationChecker {
	pool := x509.NewCertPool()
	pool.AddCert(f.srv.Certificate())
	dial := netguard.WithTestDialer(func(network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).Dial(network, f.srv.Listener.Addr().String())
	})
	resolve := netguard.WithTestResolver(func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("104.16.0.1")}, nil
	})
	all := append([]cloudflare.PublicationOption{
		cloudflare.WithResolverURL("https://example.com/dns-query"),
		cloudflare.WithResolverNetguard(netguard.WithRootCAs(pool), dial, resolve),
	}, opts...)
	return cloudflare.NewPublicationChecker(all...)
}

func (f *Fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var qtype int
	_, _ = fmt.Sscan(r.URL.Query().Get("type"), &qtype)
	host := r.URL.Query().Get("name")

	f.mu.Lock()
	f.polls++
	f.hostPoll[host]++
	if f.mode == NotServed && qtype == typeA {
		if f.notYet == 0 && f.thenServe {
			f.mode = Served
		} else if f.notYet > 0 {
			f.notYet--
		}
	}
	mode := f.mode
	f.mu.Unlock()

	switch mode {
	case Unreachable:
		w.WriteHeader(http.StatusServiceUnavailable)
	case Malformed:
		_, _ = w.Write([]byte("<html>sign in to the network</html>"))
	case ServFail:
		_, _ = fmt.Fprintf(w, `{"Status":%d}`, statusServFail)
	case NoData:
		_, _ = w.Write([]byte(`{"Status":0}`))
	case Served, Stale:
		if qtype != typeA {
			_, _ = w.Write([]byte(`{"Status":0}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"Status": 0,
			"Answer": []map[string]any{{"name": host, "type": typeA, "TTL": 60, "data": "104.16.1.1"}},
		})
	case NotServed:
		_, _ = fmt.Fprintf(w, `{"Status":%d}`, statusNXDomain)
	}
}
