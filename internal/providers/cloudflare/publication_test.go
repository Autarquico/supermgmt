package cloudflare

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/netguard"
)

const publishedHost = "ssh-a.example.com"

// dohFake answers the JSON API from a table keyed by query type; a missing
// type is NOERROR without answers (NODATA).
type dohFake struct {
	status map[int]int    // DNS status by type, default 0
	body   map[int]string // JSON "Answer"/"Authority" fragment by type
	http   int            // HTTP status override, 0: 200
	raw    string         // whole body override
	delay  time.Duration
}

func (f *dohFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-r.Context().Done():
			return
		}
	}
	if f.http != 0 {
		w.WriteHeader(f.http)
		return
	}
	if f.raw != "" {
		_, _ = w.Write([]byte(f.raw))
		return
	}
	var qtype int
	_, _ = fmt.Sscan(r.URL.Query().Get("type"), &qtype)
	extra := f.body[qtype]
	if extra != "" {
		extra = "," + extra
	}
	_, _ = fmt.Fprintf(w, `{"Status":%d%s}`, f.status[qtype], extra)
}

func answer(qtype int, data string) string {
	return fmt.Sprintf(`"Answer":[{"name":%q,"type":%d,"TTL":60,"data":%q}]`, publishedHost, qtype, data)
}

func soa(ttl uint32, minimum uint32) string {
	return fmt.Sprintf(`"Authority":[{"name":"example.com","type":6,"TTL":%d,"data":"ns.cloudflare.com. dns.cloudflare.com. 2345 10000 2400 604800 %d"}]`, ttl, minimum)
}

func newChecker(t *testing.T, f *dohFake, opts ...PublicationOption) *PublicationChecker {
	t.Helper()
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	guard := netguard.WithTestDialer(func(network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).Dial(network, srv.Listener.Addr().String())
	})
	resolver := netguard.WithTestResolver(func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("104.16.0.1")}, nil
	})
	opts = append([]PublicationOption{
		WithResolverURL("https://example.com/dns-query"),
		WithResolverNetguard(netguard.WithRootCAs(pool), guard, resolver),
	}, opts...)
	return NewPublicationChecker(opts...)
}

func TestPublishedOutcomes(t *testing.T) {
	tests := []struct {
		name    string
		fake    dohFake
		want    bool
		wantErr bool
	}{
		{name: "A answer", fake: dohFake{body: map[int]string{1: answer(1, "104.16.1.1")}}, want: true},
		{name: "AAAA answer only", fake: dohFake{body: map[int]string{28: answer(28, "2606::1")}}, want: true},
		{name: "NXDOMAIN", fake: dohFake{status: map[int]int{1: 3, 28: 3}}},
		{name: "NODATA", fake: dohFake{}},
		{name: "CNAME without address", fake: dohFake{body: map[int]string{1: answer(5, "x.cfargotunnel.com.")}}},
		{name: "A answer without data", fake: dohFake{body: map[int]string{1: answer(1, "")}}, wantErr: true},
		{name: "A answer with invalid data", fake: dohFake{body: map[int]string{1: answer(1, "not-an-ip")}}, wantErr: true},
		{name: "A answer with IPv6 data", fake: dohFake{body: map[int]string{1: answer(1, "2606::1")}}, wantErr: true},
		{name: "AAAA answer with IPv4 data", fake: dohFake{body: map[int]string{28: answer(28, "104.16.1.1")}}, wantErr: true},
		{name: "missing status", fake: dohFake{raw: `{"Answer":[]}`}, wantErr: true},
		{name: "null status", fake: dohFake{raw: `{"Status":null}`}, wantErr: true},
		{name: "null body", fake: dohFake{raw: `null`}, wantErr: true},
		{name: "error object", fake: dohFake{raw: `{"error":"authentication required"}`}, wantErr: true},
		{name: "SERVFAIL", fake: dohFake{status: map[int]int{1: 2, 28: 2}}, wantErr: true},
		{name: "A not yet, AAAA SERVFAIL", fake: dohFake{status: map[int]int{1: 3, 28: 2}}, wantErr: true},
		{name: "A SERVFAIL, AAAA answer", fake: dohFake{status: map[int]int{1: 2}, body: map[int]string{28: answer(28, "2606::1")}}, want: true},
		{name: "HTTP 503", fake: dohFake{http: 503}, wantErr: true},
		{name: "captive portal HTML", fake: dohFake{raw: "<html>login</html>"}, wantErr: true},
		{name: "empty body", fake: dohFake{raw: " "}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newChecker(t, &tt.fake).Published(ctx(t), publishedHost)
			if got != tt.want {
				t.Errorf("published = %v, want %v", got, tt.want)
			}
			if errors.Is(err, ErrResolverUnavailable) != tt.wantErr || (err != nil) != tt.wantErr {
				t.Errorf("err = %v, want unavailable = %v", err, tt.wantErr)
			}
		})
	}
}

func TestPublishedSlowResolverIsUnavailable(t *testing.T) {
	c := newChecker(t, &dohFake{delay: 5 * time.Second}, WithResolverTimeout(50*time.Millisecond))
	_, err := c.Published(ctx(t), publishedHost)
	if !errors.Is(err, ErrResolverUnavailable) {
		t.Fatalf("err = %v, want ErrResolverUnavailable", err)
	}
}

func TestPublishedHonoursCancellation(t *testing.T) {
	c := newChecker(t, &dohFake{delay: 5 * time.Second})
	cctx, cancel := context.WithCancel(ctx(t))
	time.AfterFunc(50*time.Millisecond, cancel)
	_, err := c.Published(cctx, publishedHost)
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrResolverUnavailable) {
		t.Fatalf("err = %v, want context.Canceled alone", err)
	}
}

func TestPublishedUnreachableEndpoint(t *testing.T) {
	c := NewPublicationChecker(WithResolverURL("https://example.com/dns-query"), WithResolverNetguard(
		netguard.WithTestResolver(func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("no such host") })))
	if _, err := c.Published(ctx(t), publishedHost); !errors.Is(err, ErrResolverUnavailable) {
		t.Fatalf("err = %v, want ErrResolverUnavailable", err)
	}
}

func TestPublishedSendsTheNameAndType(t *testing.T) {
	var got []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.URL.Query().Get("name")+"/"+r.URL.Query().Get("type")+"/"+r.Header.Get("Accept"))
		_, _ = w.Write([]byte(`{"Status":3}`))
	}))
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	c := NewPublicationChecker(WithResolverURL("https://example.com/dns-query"), WithResolverNetguard(
		netguard.WithRootCAs(pool),
		netguard.WithTestDialer(func(network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).Dial(network, srv.Listener.Addr().String())
		}),
		netguard.WithTestResolver(func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("104.16.0.1")}, nil
		})))
	if _, err := c.Published(ctx(t), publishedHost); err != nil {
		t.Fatal(err)
	}
	want := []string{publishedHost + "/1/application/dns-json", publishedHost + "/28/application/dns-json"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("requests = %v, want %v", got, want)
	}
}

var errNXDomain = fmt.Errorf("netguard: resolve %s: %w", publishedHost, &net.DNSError{Err: "no such host", Name: publishedHost, IsNotFound: true})

func TestDiagnoseNegativeCache(t *testing.T) {
	served := map[int]string{1: answer(1, "104.16.1.1")}
	tests := []struct {
		name      string
		fake      dohFake
		lookupErr error
		diagnosed bool
		wantTTL   string // substring of the message; "" means no figure
	}{
		{name: "min is the SOA minimum", fake: dohFake{body: map[int]string{1: served[1], 6: soa(3600, 1800)}}, lookupErr: errNXDomain, diagnosed: true, wantTTL: "30m0s"},
		{name: "min is the record TTL", fake: dohFake{body: map[int]string{1: served[1], 6: soa(300, 1800)}}, lookupErr: errNXDomain, diagnosed: true, wantTTL: "5m0s"},
		{name: "SOA unreadable gives no figure", fake: dohFake{body: map[int]string{1: served[1]}}, lookupErr: errNXDomain, diagnosed: true},
		{name: "not published yet", fake: dohFake{}, lookupErr: errNXDomain},
		{name: "resolver cannot be asked", fake: dohFake{http: 500}, lookupErr: errNXDomain},
		{name: "lookup failed otherwise", fake: dohFake{body: served}, lookupErr: errors.New("i/o timeout")},
		{name: "no error", fake: dohFake{body: served}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := newChecker(t, &tt.fake).DiagnoseNegativeCache(ctx(t), publishedHost, tt.lookupErr)
			if !tt.diagnosed {
				if !errors.Is(err, tt.lookupErr) || errors.As(err, new(*smerr.Error)) {
					t.Fatalf("err = %v, want the original untouched", err)
				}
				return
			}
			var e *smerr.Error
			if !errors.As(err, &e) || e.Reason != smerr.ReasonTunnelDNSNegativeCache || e.Code != smerr.CodeNodeUnreachable {
				t.Fatalf("err = %v, want TUNNEL_DNS_NEGATIVE_CACHE", err)
			}
			if !errors.Is(err, tt.lookupErr) {
				t.Error("the original error is not wrapped")
			}
			msg := e.Message
			for _, want := range []string{"negative answer", publishedHost, "router's or upstream resolver's"} {
				if !strings.Contains(msg, want) {
					t.Errorf("message %q lacks %q", msg, want)
				}
			}
			if tt.wantTTL == "" && strings.Contains(msg, "it can last") {
				t.Errorf("message %q gives a figure without an SOA", msg)
			}
			if tt.wantTTL != "" && !strings.Contains(msg, "about "+tt.wantTTL) {
				t.Errorf("message %q lacks %q", msg, tt.wantTTL)
			}
		})
	}
}
