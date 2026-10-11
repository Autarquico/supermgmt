package netguard

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

// guardedTransport applies the request-level rules of §21.1: scheme and
// userinfo (step 1) and the body cap (step 7). It sees every hop of a redirect
// chain, so the rules hold for redirected requests too.
type guardedTransport struct {
	next      http.RoundTripper
	allowHTTP bool
	maxBody   int64
}

func (t *guardedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.checkRequest(req); err != nil {
		return nil, err
	}
	resp, err := t.next.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.ContentLength > t.maxBody {
		_ = resp.Body.Close()
		return nil, ErrBodyTooLarge
	}
	resp.Body = &cappedBody{rc: resp.Body, left: t.maxBody}
	return resp, nil
}

func (t *guardedTransport) checkRequest(req *http.Request) error {
	u := req.URL
	switch {
	case u.User != nil:
		return fmt.Errorf("%w: userinfo in URL", ErrBlocked)
	case u.Hostname() == "":
		return fmt.Errorf("%w: no host", ErrBlocked)
	case u.Scheme == "https", u.Scheme == "http" && t.allowHTTP:
		return nil
	}
	return fmt.Errorf("%w: scheme %q", ErrBlocked, u.Scheme)
}

// cappedBody fails, rather than truncates, when the body outgrows its cap.
type cappedBody struct {
	rc   io.ReadCloser
	left int64
}

func (b *cappedBody) Read(p []byte) (int, error) {
	if b.left <= 0 {
		var probe [1]byte
		n, err := b.rc.Read(probe[:])
		if n > 0 {
			return 0, ErrBodyTooLarge
		}
		return 0, err
	}
	if int64(len(p)) > b.left {
		p = p[:b.left]
	}
	n, err := b.rc.Read(p)
	b.left -= int64(n)
	return n, err
}

func (b *cappedBody) Close() error { return b.rc.Close() }

// check is the http.Client.CheckRedirect of a policy: bounded count, same
// scheme as the hop before, and only to listed hosts. The destination address
// is filtered again when the redirected request dials.
func (p RedirectPolicy) check(req *http.Request, via []*http.Request) error {
	switch {
	case p.Max == 0:
		return fmt.Errorf("%w: redirects are disabled", ErrRedirect)
	case len(via) > p.Max:
		return fmt.Errorf("%w: more than %d redirects", ErrRedirect, p.Max)
	case req.URL.Scheme != via[len(via)-1].URL.Scheme:
		return fmt.Errorf("%w: scheme change to %s", ErrRedirect, req.URL.Scheme)
	case !p.allowsHost(req.URL.Host):
		return fmt.Errorf("%w: host %s is not allowed", ErrRedirect, req.URL.Host)
	}
	return nil
}

func (p RedirectPolicy) allowsHost(hostport string) bool {
	host := hostport
	if i := strings.LastIndex(hostport, ":"); i >= 0 && !strings.HasSuffix(hostport, "]") {
		host = hostport[:i]
	}
	for _, h := range p.Hosts {
		if strings.EqualFold(h, hostport) || strings.EqualFold(h, host) {
			return true
		}
	}
	return false
}
