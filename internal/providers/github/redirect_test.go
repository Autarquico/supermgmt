package github

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"testing"

	"github.com/autarquico/supermgmt/internal/netguard"
	"github.com/autarquico/supermgmt/internal/providers/github/ghfake"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func viaOf(t *testing.T, hops int) []*http.Request {
	t.Helper()
	via := make([]*http.Request, hops)
	for i := range via {
		via[i] = &http.Request{URL: mustURL(t, "https://api.github.com/hop")}
	}
	return via
}

func TestRedirect_OriginPinned(t *testing.T) {
	api := originOf(mustURL(t, "https://api.github.com"))
	check := pinRedirects(api, maxRedirects)
	tests := []struct {
		name   string
		target string
		hops   int
		refuse bool
	}{
		{"same origin", "https://api.github.com/repositories/1", 1, false},
		{"explicit default port", "https://api.github.com:443/x", 1, false},
		{"host case", "https://API.GitHub.com/x", 1, false},
		{"third redirect", "https://api.github.com/x", 3, false},
		{"fourth redirect", "https://api.github.com/x", 4, true},
		{"suffix confusion", "https://api.github.com.evil/x", 1, true},
		{"prefix confusion", "https://evilapi.github.com/x", 1, true},
		{"subdomain", "https://x.api.github.com/x", 1, true},
		{"sibling github host", "https://uploads.github.com/x", 1, true},
		{"userinfo host trick", "https://api.github.com@evil.example/x", 1, true},
		{"userinfo on the right host", "https://u:p@api.github.com/x", 1, true},
		{"scheme change", "http://api.github.com/x", 1, true},
		{"other port", "https://api.github.com:8443/x", 1, true},
		{"private address", "https://10.0.0.5/x", 1, true},
		{"metadata address", "https://169.254.169.254/latest", 1, true},
		{"loopback", "https://127.0.0.1/x", 1, true},
		{"loopback v6", "https://[::1]/x", 1, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := check(&http.Request{URL: mustURL(t, tc.target)}, viaOf(t, tc.hops))
			if tc.refuse != (err != nil) {
				t.Fatalf("refused = %v (%v), want %v", err != nil, err, tc.refuse)
			}
			if err != nil && !errors.Is(err, netguard.ErrRedirect) {
				t.Errorf("error %v does not wrap netguard.ErrRedirect", err)
			}
		})
	}
}

func TestRedirect_NonDefaultPortOriginIsPinnedToThatPort(t *testing.T) {
	check := pinRedirects(originOf(mustURL(t, "https://ghe.example.com:8443/api/v3")), maxRedirects)
	for target, refuse := range map[string]bool{
		"https://ghe.example.com:8443/api/v3/x": false,
		"https://ghe.example.com/x":             true,
		"https://ghe.example.com:9443/x":        true,
	} {
		err := check(&http.Request{URL: mustURL(t, target)}, viaOf(t, 1))
		if refuse != (err != nil) {
			t.Errorf("%s: refused = %v, want %v", target, err != nil, refuse)
		}
	}
}

type captureTransport struct{ got *http.Request }

func (c *captureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	c.got = req
	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Request: req}, nil
}

func TestOriginScoped_AttachesTokenOnlyOnTheAPIOrigin(t *testing.T) {
	api := originOf(mustURL(t, "https://api.github.com"))
	tests := []struct {
		name, target, preset, want string
	}{
		{"api origin", "https://api.github.com/x", "", "Bearer secret"},
		{"api origin replaces a preset value", "https://api.github.com/x", "Bearer other", "Bearer secret"},
		{"other host", "https://api.github.com.evil/x", "", ""},
		{"other host strips a preset value", "https://evil.example/x", "Bearer secret", ""},
		{"other port", "https://api.github.com:8443/x", "", ""},
		{"other scheme", "http://api.github.com/x", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			next := &captureTransport{}
			rt := originScoped{next: next, api: api, authorization: "Bearer secret"}
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, tc.target, nil)
			if err != nil {
				t.Fatal(err)
			}
			if tc.preset != "" {
				req.Header.Set("Authorization", tc.preset)
			}
			if _, err := rt.RoundTrip(req); err != nil {
				t.Fatal(err)
			}
			if got := next.got.Header.Get("Authorization"); got != tc.want {
				t.Errorf("Authorization sent = %q, want %q", got, tc.want)
			}
			if tc.preset != "" && req.Header.Get("Authorization") != tc.preset {
				t.Error("the caller's request was modified")
			}
		})
	}
}

// chain makes /hop/1 … /hop/n redirect in sequence to /final.
func chain(f *ghfake.Fake, n int) {
	for i := 1; i <= n; i++ {
		next := "/final"
		if i < n {
			next = "/hop/" + strconv.Itoa(i+1)
		}
		f.Redirect("/hop/"+strconv.Itoa(i), next)
	}
	f.Handle("GET /final", nil, func(w http.ResponseWriter, _ *http.Request) { ghfake.WriteJSON(w, map[string]bool{"ok": true}) })
}

func TestRedirect_FollowsUpToThreeSameOriginHopsWithTheToken(t *testing.T) {
	f, c := newEnv(t)
	chain(f, maxRedirects)
	if _, _, err := c.get(context.Background(), "/hop/1", nil, 1<<10); err != nil {
		t.Fatal(err)
	}
	reqs := f.Requests()
	if len(reqs) != maxRedirects+1 {
		t.Fatalf("requests = %d, want %d", len(reqs), maxRedirects+1)
	}
	for _, r := range reqs {
		if r.Authorization != "Bearer "+f.Token() {
			t.Errorf("%s was sent without the token (%q)", r.Path, r.Authorization)
		}
	}
}

func TestRedirect_FourthHopIsRefused(t *testing.T) {
	f, c := newEnv(t)
	chain(f, maxRedirects+1)
	_, _, err := c.get(context.Background(), "/hop/1", nil, 1<<10)
	if !errors.Is(err, netguard.ErrRedirect) {
		t.Fatalf("err = %v, want netguard.ErrRedirect", err)
	}
	if got := len(f.Requests()); got != maxRedirects+1 {
		t.Errorf("requests = %d, want %d (the refused hop is never requested)", got, maxRedirects+1)
	}
}

func TestRedirect_OffOriginTargetsAreRefusedBeforeAnyRequest(t *testing.T) {
	for _, target := range []string{
		"https://" + ghfake.ServerIP + ":8443/final", // other port
		"http://" + ghfake.ServerIP + "/final",       // scheme change
		"https://127.0.0.1/final",                    // loopback
		"https://10.0.0.5/final",                     // another private address
		"https://169.254.169.254/final",              // metadata
		"https://u:p@" + ghfake.ServerIP + "/final",  // credentials
		"https://" + ghfake.ServerIP + ".evil/final", // suffix confusion
	} {
		t.Run(target, func(t *testing.T) {
			f, c := newEnv(t)
			f.Redirect("/start", target)
			_, _, err := c.get(context.Background(), "/start", nil, 1<<10)
			if !errors.Is(err, netguard.ErrRedirect) {
				t.Fatalf("err = %v, want netguard.ErrRedirect", err)
			}
			if got := len(f.Requests()); got != 1 {
				t.Errorf("requests = %d, want 1: nothing may be requested off-origin", got)
			}
		})
	}
}
