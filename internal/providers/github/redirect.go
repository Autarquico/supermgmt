package github

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/autarquico/supermgmt/internal/netguard"
)

// maxRedirects bounds the redirects one request may follow (ADR-0028).
const maxRedirects = 3

// origin is the identity a redirect and the Authorization header are pinned
// to: scheme, host and effective port, compared exactly. netguard's host
// allowlist is not enough: it ignores the port when the entry has none and
// knows nothing of the scheme beyond the hop before.
type origin struct {
	scheme string
	host   string
	port   string
}

func originOf(u *url.URL) origin {
	scheme := strings.ToLower(u.Scheme)
	port := u.Port()
	if port == "" {
		port = defaultPort(scheme)
	}
	return origin{scheme: scheme, host: strings.ToLower(u.Hostname()), port: port}
}

func defaultPort(scheme string) string {
	switch scheme {
	case "https":
		return "443"
	case "http":
		return "80"
	}
	return ""
}

func (o origin) String() string { return o.scheme + "://" + o.host + ":" + o.port }

// pinRedirects is an http.Client.CheckRedirect that follows at most limit
// redirects, each to exactly the API origin and without userinfo. The address
// the redirect dials is still filtered by netguard.
func pinRedirects(api origin, limit int) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		switch {
		case len(via) > limit:
			return fmt.Errorf("%w: more than %d redirects", netguard.ErrRedirect, limit)
		case req.URL.User != nil:
			return fmt.Errorf("%w: redirect target carries credentials", netguard.ErrRedirect)
		case originOf(req.URL) != api:
			return fmt.Errorf("%w: %s is not the API origin", netguard.ErrRedirect, originOf(req.URL))
		}
		return nil
	}
}

// originScoped attaches the Authorization header to requests for the API
// origin and strips any other, so a request that ever reaches another origin
// carries no credentials, whatever decided to send it.
type originScoped struct {
	next          http.RoundTripper
	api           origin
	authorization string
}

func (t originScoped) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	if originOf(req.URL) == t.api {
		req.Header.Set("Authorization", t.authorization)
	} else {
		req.Header.Del("Authorization")
	}
	return t.next.RoundTrip(req)
}
