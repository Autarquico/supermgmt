package api

import (
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
)

func TestSocketAdmitsAnMCPClientToken(t *testing.T) {
	f := newM5Fixture(t)
	r := f.do(http.MethodGet, wire.PathMe, m5MCPToken, "")
	if r.Status != http.StatusOK {
		t.Fatalf("status %d: %s", r.Status, r.Body)
	}
	if me := decodeData[wire.Me](t, r); me.IdentityID != f.mcp.ID || me.Credential != f.mcp.Credential.Kind {
		t.Errorf("caller = %s via %s, want the mcp client %s via %s", me.IdentityID, me.Credential, f.mcp.ID, f.mcp.Credential.Kind)
	}
}

func TestSocketWithoutATokenIsStillTheLocalUser(t *testing.T) {
	f := newM5Fixture(t)
	r := f.do(http.MethodGet, wire.PathMe, "", "")
	if me := decodeData[wire.Me](t, r); r.Status != http.StatusOK || me.IdentityID != f.admin.ID {
		t.Errorf("status %d caller %s, want the local user %s", r.Status, me.IdentityID, f.admin.ID)
	}
}

func TestSocketRefusesEveryOtherTokenKindWithoutResolvingIt(t *testing.T) {
	f := newM5Fixture(t)
	for _, token := range []string{"sms_session", "smt_apitoken", "smb_bootstrap", "smj_join", "eyJhbGciOiJSUzI1NiJ9.e30.sig", "garbage"} {
		if r := f.do(http.MethodGet, wire.PathMe, token, ""); r.Status != http.StatusUnauthorized {
			t.Errorf("%q: status %d, want 401", token, r.Status)
		}
	}
	if seen := f.tokens.resolved(); len(seen) != 0 {
		t.Errorf("the MCP resolver was asked about %v, want nothing", seen)
	}
}

func TestSocketWithoutAnMCPResolverRefusesMCPTokens(t *testing.T) {
	f := newM5Fixture(t, func(o *m5Options) { o.noMCPTokens = true })
	if r := f.do(http.MethodGet, wire.PathMe, m5MCPToken, ""); r.Status != http.StatusUnauthorized {
		t.Errorf("status %d: %s, want 401", r.Status, r.Body)
	}
}

func TestSocketRefusesAnMCPTokenTheResolverRejects(t *testing.T) {
	f := newM5Fixture(t)
	if r := f.do(http.MethodGet, wire.PathMe, "smm_revoked", ""); r.Status != http.StatusUnauthorized {
		t.Errorf("status %d: %s, want 401", r.Status, r.Body)
	}
}

func TestSocketMCPWritesBeyondTheBucketAreRateLimitedPerIdentity(t *testing.T) {
	f := newM5Fixture(t)
	// An invalid body fails after admission, so only the bucket decides the first 429.
	write := func(token string) reply {
		return f.do(http.MethodPost, wire.PathPlans, token, `{}`, wire.HeaderIdempotencyKey, f.ids.NewID().String())
	}
	for i := 0; i < int(writeRate.burst); i++ {
		if r := write(m5MCPToken); r.Status == http.StatusTooManyRequests {
			t.Fatalf("write %d of %d was limited", i+1, int(writeRate.burst))
		}
	}
	limited := write(m5MCPToken)
	if limited.Status != http.StatusTooManyRequests {
		t.Fatalf("write beyond the bucket: status %d, want 429", limited.Status)
	}
	if after, err := strconv.Atoi(limited.Header.Get("Retry-After")); err != nil || after < 1 {
		t.Errorf("Retry-After = %q, want at least 1 second", limited.Header.Get("Retry-After"))
	}
	if r := f.do(http.MethodGet, wire.PathMe, m5MCPToken, ""); r.Status != http.StatusOK {
		t.Errorf("a read while limited: status %d, want 200 (reads are not charged)", r.Status)
	}
	if r := write(""); r.Status == http.StatusTooManyRequests {
		t.Error("the local user shares the MCP client's bucket")
	}
	f.clock.Advance(time.Minute)
	if r := write(m5MCPToken); r.Status == http.StatusTooManyRequests {
		t.Error("still limited after the bucket refilled")
	}
}

func TestLocalUserWritesOnTheSocketAreNotLimited(t *testing.T) {
	f := newM5Fixture(t)
	for i := 0; i < 3*int(writeRate.burst); i++ {
		r := f.do(http.MethodPost, wire.PathPlans, "", `{}`, wire.HeaderIdempotencyKey, f.ids.NewID().String())
		if r.Status == http.StatusTooManyRequests {
			t.Fatalf("local write %d was limited", i+1)
		}
	}
}

func TestHTTPSRefusesALocalMCPTokenWithoutResolvingIt(t *testing.T) {
	f := newM5Fixture(t, func(o *m5Options) { o.https = true })
	r := f.do(http.MethodGet, wire.PathMe, m5MCPToken, "")
	if r.Status != http.StatusUnauthorized {
		t.Errorf("status %d: %s, want 401", r.Status, r.Body)
	}
	if seen := f.tokens.resolved(); len(seen) != 0 {
		t.Errorf("the resolver was asked about %v, want nothing", seen)
	}
}

func TestHTTPSRefusesAnOAuthAccessTokenOnTheAPI(t *testing.T) {
	f := newM5Fixture(t, func(o *m5Options) { o.https = true; o.realTokens = true })
	for _, route := range []struct{ method, path string }{
		{http.MethodGet, wire.PathMe},
		{http.MethodGet, wire.PathMCPClients},
		{http.MethodPost, wire.PathPlans},
	} {
		r := f.do(route.method, route.path, "eyJhbGciOiJSUzI1NiIsInR5cCI6ImF0K2p3dCJ9.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIn0.c2ln", "{}")
		if r.Status != http.StatusUnauthorized {
			t.Errorf("%s %s: status %d: %s, want 401", route.method, route.path, r.Status, r.Body)
		}
	}
}

func TestOptionsKeepTheMCPPiecesOnTheirTransport(t *testing.T) {
	f := newM5Fixture(t)
	handler := http.NotFoundHandler()
	for name, o := range map[string]Options{
		"MCP token resolver on HTTPS":    {Resolver: f.tokens, MCPResolver: f.tokens},
		"remote endpoint on the socket":  {Identity: f.admin.ID, MCPRemote: handler, MCPRemotePaths: []string{"/mcp"}},
		"remote endpoint without paths":  {Resolver: f.tokens, MCPRemote: handler},
		"remote paths without a handler": {Resolver: f.tokens, MCPRemotePaths: []string{"/mcp"}},
	} {
		o.Services, o.IDs = f.svc, f.ids
		if _, err := New(o); err == nil {
			t.Errorf("%s: New accepted it", name)
		}
	}
}

func TestRemoteMCPHandlerIsMountedVerbatimOnItsPaths(t *testing.T) {
	var gotPath, gotAuth string
	remote := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.Path, r.Header.Get(wire.HeaderAuthorization)
		w.WriteHeader(http.StatusTeapot)
	})
	paths := []string{wire.MCPPath, wire.WellKnownProtectedResource, wire.WellKnownProtectedResourceMCP}
	f := newM5Fixture(t, func(o *m5Options) { o.https = true; o.remote = remote; o.remotePaths = paths })
	for _, path := range paths {
		r := f.do(http.MethodPost, path, "an-oauth-token", "{}")
		if r.Status != http.StatusTeapot || gotPath != path || gotAuth != "Bearer an-oauth-token" {
			t.Errorf("%s: status %d path %q auth %q, want the handler's answer to the untouched request", path, r.Status, gotPath, gotAuth)
		}
		if r.Header.Get("Cache-Control") != "" {
			t.Errorf("%s: the API pipeline touched the response (Cache-Control %q)", path, r.Header.Get("Cache-Control"))
		}
	}
	if seen := f.tokens.resolved(); len(seen) != 0 {
		t.Errorf("the API resolver saw %v on /mcp", seen)
	}
	if r := f.do(http.MethodGet, wire.MCPPath+"/other", "", ""); r.Status != http.StatusNotFound {
		t.Errorf("/mcp/other: status %d, want 404", r.Status)
	}
}
