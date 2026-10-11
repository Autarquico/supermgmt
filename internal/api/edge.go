package api

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// Headers a trusted proxy sets (spec §23.1).
const (
	headerForwardedFor   = "X-Forwarded-For"
	headerForwardedProto = "X-Forwarded-Proto"
)

// Proxy is the trust boundary of `server.tls.mode: proxy` (ADR-0017): the
// forwarding headers are believed only from a peer inside the trusted
// prefixes, or on a Unix listener, whose file permissions already decide who
// can connect. A loopback peer gets no trust of its own.
type Proxy struct {
	trusted []netip.Prefix
}

// NewProxy parses server.trusted_proxies: addresses or CIDRs.
func NewProxy(entries []string) (*Proxy, error) {
	p := &Proxy{}
	for _, entry := range entries {
		prefix, err := netip.ParsePrefix(entry)
		if err != nil {
			addr, addrErr := netip.ParseAddr(entry)
			if addrErr != nil {
				return nil, fmt.Errorf("trusted proxy %q is neither an address nor a CIDR", entry)
			}
			prefix = netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen())
		}
		p.trusted = append(p.trusted, prefix.Masked())
	}
	if len(p.trusted) == 0 {
		return nil, fmt.Errorf("proxy mode needs at least one trusted proxy")
	}
	return p, nil
}

func (p *Proxy) trusts(addr netip.Addr) bool {
	for _, prefix := range p.trusted {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// clientOf is the address of the requester. In direct mode (p == nil) and for
// a peer that is not a trusted proxy it is the TCP peer, and forwarding
// headers are ignored whatever they say. From a trusted proxy the proto must
// be https (anything else, including no header, is a 400) and the address is
// the first X-Forwarded-For entry, read from the right, that is not itself a
// trusted proxy.
func (p *Proxy) clientOf(r *http.Request) (netip.Addr, error) {
	peer, unixPeer := peerOf(r)
	if p == nil || (!unixPeer && !p.trusts(peer)) {
		return peer, nil
	}
	if !forwardedHTTPS(r.Header.Values(headerForwardedProto)) {
		return netip.Addr{}, smerr.New(smerr.CodeInvalidArgument, "", headerForwardedProto+" must be https: the proxy must terminate TLS")
	}
	return p.forwardedClient(r.Header.Values(headerForwardedFor), peer)
}

func forwardedHTTPS(values []string) bool {
	if len(values) == 0 {
		return false
	}
	for _, value := range values {
		for _, proto := range strings.Split(value, ",") {
			if !strings.EqualFold(strings.TrimSpace(proto), "https") {
				return false
			}
		}
	}
	return true
}

func (p *Proxy) forwardedClient(values []string, peer netip.Addr) (netip.Addr, error) {
	var chain []string
	for _, value := range values {
		chain = append(chain, strings.Split(value, ",")...)
	}
	client := peer
	for i := len(chain) - 1; i >= 0; i-- {
		addr, err := netip.ParseAddr(strings.TrimSpace(chain[i]))
		if err != nil {
			return netip.Addr{}, smerr.New(smerr.CodeInvalidArgument, "", headerForwardedFor+" is malformed")
		}
		client = addr.Unmap()
		if !p.trusts(client) {
			break
		}
	}
	return client, nil
}

// peerOf is the address of the connection's other end. unixPeer is true on a
// Unix listener, which has no address.
func peerOf(r *http.Request) (addr netip.Addr, unixPeer bool) {
	if local, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok && local.Network() == "unix" {
		return netip.Addr{}, true
	}
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, false
	}
	return ap.Addr().Unmap(), false
}

// bucketRate is a token bucket: capacity burst, refilled at perMinute.
type bucketRate struct {
	perMinute float64
	burst     float64
}

// Fixed in M2 (ADR-0017): configurable limits would need new config keys.
var (
	authRate  = bucketRate{perMinute: 10, burst: 5}
	writeRate = bucketRate{perMinute: 60, burst: 20}
)

const maxBuckets = 10_000

type bucket struct {
	tokens float64
	at     time.Time
}

// limiter rate-limits by key. Its memory is bounded: past maxBuckets it drops
// the buckets that are full again, then arbitrary ones.
type limiter struct {
	rate    bucketRate
	now     func() time.Time
	mu      sync.Mutex
	buckets map[string]*bucket
}

func newLimiter(rate bucketRate, now func() time.Time) *limiter {
	return &limiter{rate: rate, now: now, buckets: map[string]*bucket{}}
}

// allow takes a token for key. When none is left it reports how long until
// one is.
func (l *limiter) allow(key string) (ok bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, found := l.buckets[key]
	if !found {
		l.makeRoom(now)
		b = &bucket{tokens: l.rate.burst, at: now}
		l.buckets[key] = b
	}
	b.tokens = min(l.rate.burst, b.tokens+now.Sub(b.at).Minutes()*l.rate.perMinute)
	b.at = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	missing := 1 - b.tokens
	return false, time.Duration(missing / l.rate.perMinute * float64(time.Minute))
}

func (l *limiter) makeRoom(now time.Time) {
	if len(l.buckets) < maxBuckets {
		return
	}
	for key, b := range l.buckets {
		if b.tokens+now.Sub(b.at).Minutes()*l.rate.perMinute >= l.rate.burst {
			delete(l.buckets, key)
		}
	}
	for key := range l.buckets {
		if len(l.buckets) < maxBuckets {
			return
		}
		delete(l.buckets, key)
	}
}
