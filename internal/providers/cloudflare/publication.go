package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/netguard"
)

const (
	// DefaultResolverURL is Cloudflare's DNS-over-HTTPS resolver. It is the
	// only resolver asked: Cloudflare already holds the hostnames (they are in
	// the operator's zone), so asking it discloses nothing new.
	DefaultResolverURL = "https://cloudflare-dns.com/dns-query"

	publicationTimeout = 5 * time.Second
	maxResolverBody    = 64 << 10

	dnsTypeA    = 1
	dnsTypeSOA  = 6
	dnsTypeAAAA = 28

	dnsStatusOK       = 0
	dnsStatusNXDomain = 3
)

// ErrResolverUnavailable means Cloudflare's resolver could not be asked or its
// answer was unusable (SERVFAIL, HTTP or TLS failure, malformed reply,
// timeout). It says nothing about whether the hostname is published.
var ErrResolverUnavailable = errors.New("cloudflare: cannot ask Cloudflare's resolver")

// PublicationChecker asks Cloudflare's resolver whether a hostname is served.
type PublicationChecker struct {
	endpoint string
	timeout  time.Duration
	http     *http.Client
}

// PublicationOption adjusts a checker built by NewPublicationChecker.
type PublicationOption func(*PublicationChecker, *[]netguard.Option)

// WithResolverURL replaces DefaultResolverURL. Tests point it at a fake.
func WithResolverURL(u string) PublicationOption {
	return func(c *PublicationChecker, _ *[]netguard.Option) { c.endpoint = u }
}

// WithResolverTimeout bounds each request (default 5s).
func WithResolverTimeout(d time.Duration) PublicationOption {
	return func(c *PublicationChecker, _ *[]netguard.Option) { c.timeout = d }
}

// WithResolverNetguard passes options to the netguard client; tests use it for
// netguard.WithTestDialer, WithRootCAs and WithTestResolver.
func WithResolverNetguard(opts ...netguard.Option) PublicationOption {
	return func(_ *PublicationChecker, g *[]netguard.Option) { *g = append(*g, opts...) }
}

// NewPublicationChecker returns a checker that goes through a netguard client.
func NewPublicationChecker(opts ...PublicationOption) *PublicationChecker {
	c := &PublicationChecker{endpoint: DefaultResolverURL, timeout: publicationTimeout}
	var guard []netguard.Option
	for _, opt := range opts {
		opt(c, &guard)
	}
	c.http = netguard.NewClient(netguard.Allow{}, nil, c.timeout, maxResolverBody, guard...)
	return c
}

// Published reports whether Cloudflare's resolver answers for host with an A
// or AAAA record. NXDOMAIN and NODATA are (false, nil): not yet. When the
// resolver cannot be asked the error wraps ErrResolverUnavailable; when ctx
// ends it is ctx's error.
func (c *PublicationChecker) Published(ctx context.Context, host string) (bool, error) {
	var unavailable error
	for _, qtype := range []int{dnsTypeA, dnsTypeAAAA} {
		reply, err := c.query(ctx, host, qtype)
		switch {
		case err != nil:
			if ctx.Err() != nil {
				return false, ctx.Err()
			}
			unavailable = err
		case reply.answers(qtype):
			return true, nil
		}
	}
	return false, unavailable
}

// DiagnoseNegativeCache turns lookupErr, a failed system lookup of host, into
// a TUNNEL_DNS_NEGATIVE_CACHE error when it was NXDOMAIN while Cloudflare's
// resolver has answers. In every other case, including a resolver that cannot
// be asked, it returns lookupErr unchanged. The new error wraps lookupErr.
func (c *PublicationChecker) DiagnoseNegativeCache(ctx context.Context, host string, lookupErr error) error {
	var dnsErr *net.DNSError
	if lookupErr == nil || !errors.As(lookupErr, &dnsErr) || !dnsErr.IsNotFound {
		return lookupErr
	}
	if published, err := c.Published(ctx, host); err != nil || !published {
		return lookupErr
	}
	msg := fmt.Sprintf("the local resolver most likely cached a negative answer for %s, which Cloudflare already publishes", host)
	if ttl, ok := c.negativeTTL(ctx, host); ok {
		msg += fmt.Sprintf("; it can last about %s", ttl)
	}
	msg += "; flushing this workstation's DNS cache may leave a router's or upstream resolver's cache in place"
	return smerr.Wrap(lookupErr, smerr.CodeNodeUnreachable, smerr.ReasonTunnelDNSNegativeCache, msg)
}

// negativeTTL is the lifetime of a negative answer for host: min(SOA TTL, SOA
// MINIMUM), RFC 2308 section 5.
func (c *PublicationChecker) negativeTTL(ctx context.Context, host string) (time.Duration, bool) {
	reply, err := c.query(ctx, host, dnsTypeSOA)
	if err != nil {
		return 0, false
	}
	for _, rr := range append(reply.Answer, reply.Authority...) {
		if rr.Type != dnsTypeSOA {
			continue
		}
		fields := strings.Fields(rr.Data)
		if len(fields) != 7 {
			continue
		}
		minimum, err := strconv.ParseUint(fields[6], 10, 32)
		if err != nil {
			continue
		}
		return time.Duration(min(uint64(rr.TTL), minimum)) * time.Second, true
	}
	return 0, false
}

type dohRecord struct {
	Type int    `json:"type"`
	TTL  uint32 `json:"TTL"`
	Data string `json:"data"`
}

type dohReply struct {
	Status    int         `json:"Status"`
	Answer    []dohRecord `json:"Answer"`
	Authority []dohRecord `json:"Authority"`
}

func (r dohReply) answers(qtype int) bool {
	for _, rr := range r.Answer {
		if rr.Type == qtype {
			return true
		}
	}
	return false
}

// decodeDoH reads a JSON DNS answer. Only NOERROR and NXDOMAIN are usable.
func decodeDoH(data []byte) (dohReply, error) {
	var r dohReply
	if err := json.Unmarshal(data, &r); err != nil {
		return dohReply{}, fmt.Errorf("malformed reply: %w", err)
	}
	if r.Status != dnsStatusOK && r.Status != dnsStatusNXDomain {
		return dohReply{}, fmt.Errorf("resolver status %d", r.Status)
	}
	if r.Status == dnsStatusNXDomain {
		r.Answer = nil
	}
	return r, nil
}

func (c *PublicationChecker) query(ctx context.Context, host string, qtype int) (dohReply, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	q := url.Values{"name": {host}, "type": {strconv.Itoa(qtype)}}
	sep := "?"
	if strings.Contains(c.endpoint, "?") {
		sep = "&"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+sep+q.Encode(), nil)
	if err != nil {
		return dohReply{}, fmt.Errorf("%w: %w", ErrResolverUnavailable, err)
	}
	req.Header.Set("Accept", "application/dns-json")
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.http.Do(req)
	if err != nil {
		return dohReply{}, fmt.Errorf("%w: %w", ErrResolverUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return dohReply{}, fmt.Errorf("%w: HTTP %d", ErrResolverUnavailable, resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return dohReply{}, fmt.Errorf("%w: %w", ErrResolverUnavailable, err)
	}
	reply, err := decodeDoH(data)
	if err != nil {
		return dohReply{}, fmt.Errorf("%w: %w", ErrResolverUnavailable, err)
	}
	return reply, nil
}
