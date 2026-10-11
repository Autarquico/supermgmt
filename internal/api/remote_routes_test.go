package api

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func TestBearerAdmission(t *testing.T) {
	r := newRemote(t)
	_, issued := r.admin()

	cases := []struct {
		name    string
		token   string
		headers []string
		status  int
	}{
		{"no credential", "", nil, http.StatusUnauthorized},
		{"a token nobody issued", "smt_" + strings.Repeat("A", 43), nil, http.StatusUnauthorized},
		{"not a token", "garbage", nil, http.StatusUnauthorized},
		{"two Authorization headers", issued.Value, []string{wire.HeaderAuthorization, "Bearer " + issued.Value}, http.StatusUnauthorized},
		{"the right token", issued.Value, nil, http.StatusOK},
	}
	for _, tc := range cases {
		resp := r.request(http.MethodGet, wire.PathMe, tc.token, "", tc.headers...)
		if resp.Status != tc.status {
			t.Errorf("%s: status %d body %s", tc.name, resp.Status, resp.Body)
		}
		if tc.status == http.StatusUnauthorized && resp.Header.Get("WWW-Authenticate") != "Bearer" {
			t.Errorf("%s: no WWW-Authenticate challenge", tc.name)
		}
	}
}

func TestMeIsTheTokensIdentityWithItsCredentialKind(t *testing.T) {
	r := newRemote(t)
	identity, issued := r.admin()

	resp := r.request(http.MethodGet, wire.PathMe, issued.Value, "")

	var env wire.Envelope[wire.Me]
	if err := json.Unmarshal(resp.Body, &env); err != nil || resp.Status != http.StatusOK {
		t.Fatalf("status %d body %s", resp.Status, resp.Body)
	}
	if env.Data.IdentityID != identity || env.Data.Credential != "api_token" || env.Data.InstanceMode != "server" {
		t.Errorf("me = %+v", env.Data)
	}
}

func TestProbesAndLoginNeedNoToken(t *testing.T) {
	r := newRemote(t)
	for _, path := range []string{wire.PathHealthLive, wire.PathHealthReady} {
		if resp := r.request(http.MethodGet, path, "", ""); resp.Status != http.StatusOK {
			t.Errorf("%s: status %d", path, resp.Status)
		}
	}
	// Login reaches the service, which says OIDC is not configured: not 401.
	resp := r.request(http.MethodPost, wire.PathOIDCDevice, "", "")
	if resp.Status == http.StatusUnauthorized {
		t.Errorf("device start asked for a token: %s", resp.Body)
	}
}

func TestARevokedTokenFailsTheNextRequest(t *testing.T) {
	r := newRemote(t)
	_, issued := r.admin()
	if resp := r.request(http.MethodGet, wire.PathMe, issued.Value, ""); resp.Status != http.StatusOK {
		t.Fatalf("before revoke: %d", resp.Status)
	}

	revoked := r.request(http.MethodDelete, strings.Replace(wire.PathToken, "{id}", issued.Token.ID.String(), 1), issued.Value, "")
	after := r.request(http.MethodGet, wire.PathMe, issued.Value, "")

	if revoked.Status != http.StatusOK {
		t.Fatalf("revoke: %d %s", revoked.Status, revoked.Body)
	}
	if e := decodeError(t, after); after.Status != http.StatusUnauthorized || e.Reason() != smerr.ReasonCredentialRevoked {
		t.Errorf("after revoke: status %d body %s", after.Status, after.Body)
	}
}

func TestEveryResponseCarriesTheSecurityHeadersAndNoCORS(t *testing.T) {
	r := newRemote(t)
	_, issued := r.admin()
	for _, resp := range []reply{
		r.request(http.MethodGet, wire.PathHealthLive, "", ""),
		r.request(http.MethodGet, wire.PathMe, "", ""),
		r.request(http.MethodGet, wire.PathMe, issued.Value, ""),
		r.request(http.MethodGet, "/nowhere", "", ""),
	} {
		for header, want := range map[string]string{
			"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
		} {
			if got := resp.Header.Get(header); got != want {
				t.Errorf("status %d: %s = %q, want %q", resp.Status, header, got, want)
			}
		}
		if resp.Header.Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("status %d: CORS header present", resp.Status)
		}
	}
}

func TestOversizedBodiesAreRefusedPerRoute(t *testing.T) {
	r := newRemote(t)
	_, issued := r.admin()
	huge := `{"redirect_uri":"` + strings.Repeat("a", maxAuthBodyBytes) + `"}`

	login := r.request(http.MethodPost, wire.PathOIDCStart, "", huge)
	tokens := r.request(http.MethodPost, wire.PathTokens, issued.Value, `{"name":"`+strings.Repeat("a", maxBodyBytes)+`"}`)

	for name, resp := range map[string]reply{"login": login, "tokens": tokens} {
		if resp.Status != http.StatusBadRequest || decodeError(t, resp).Code != smerr.CodeInvalidArgument {
			t.Errorf("%s: status %d body %.120s", name, resp.Status, resp.Body)
		}
	}
}

func TestLoginRoutesAreRateLimitedPerAddress(t *testing.T) {
	r := newRemote(t)
	var last reply
	allowed := 0
	for range 8 {
		last = r.request(http.MethodPost, wire.PathOIDCDevice, "", "")
		if last.Status != http.StatusTooManyRequests {
			allowed++
		}
	}
	if allowed != int(authRate.burst) {
		t.Errorf("%d requests passed, want the burst of %v", allowed, authRate.burst)
	}
	if last.Status != http.StatusTooManyRequests || last.Header.Get("Retry-After") == "" {
		t.Fatalf("status %d, Retry-After %q", last.Status, last.Header.Get("Retry-After"))
	}

	r.clock.Advance(time.Minute)

	if resp := r.request(http.MethodPost, wire.PathOIDCDevice, "", ""); resp.Status == http.StatusTooManyRequests {
		t.Error("still limited a minute later")
	}
}

func TestWritesAreRateLimitedPerIdentityButReadsAreNot(t *testing.T) {
	r := newRemote(t)
	_, issued := r.admin()
	_, other := r.admin()
	limited := 0
	for range int(writeRate.burst) + 5 {
		if resp := r.request(http.MethodDelete, strings.Replace(wire.PathToken, "{id}", other.Token.ID.String(), 1), issued.Value, ""); resp.Status == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited == 0 {
		t.Error("an identity wrote past its burst")
	}
	if resp := r.request(http.MethodGet, wire.PathMe, issued.Value, ""); resp.Status != http.StatusOK {
		t.Errorf("a read after the writes: %d", resp.Status)
	}
	if resp := r.request(http.MethodGet, wire.PathTokens, other.Value, ""); resp.Status == http.StatusTooManyRequests {
		t.Error("another identity was limited")
	}
}

func TestCredentialIssuingRoutesRejectAnIdempotencyKeyAndStoreNoAnswer(t *testing.T) {
	r := newRemote(t)
	_, issued := r.admin()
	body := map[string]string{
		wire.PathTokens:         `{"name":"ci","expires_at":"` + r.expiry() + `"}`,
		wire.PathBootstrap:      `{"code":"smb_x","display_name":"x"}`,
		wire.PathEnrollments:    `{"max_nodes":1}`,
		wire.PathEnroll:         `{"token":"smj_x"}`,
		wire.PathOIDCExchange:   `{"code":"c","state":"s","code_verifier":"v"}`,
		wire.PathOIDCDevicePoll: `{"transaction_id":"t"}`,
	}
	for path, payload := range body {
		keyed := r.request(http.MethodPost, path, issued.Value, payload, wire.HeaderIdempotencyKey, "k-"+path)
		r.clock.Advance(time.Minute)
		if e := decodeError(t, keyed); keyed.Status != http.StatusBadRequest || e.Code != smerr.CodeInvalidArgument {
			t.Errorf("%s with a key: status %d body %s", path, keyed.Status, keyed.Body)
		}
		r.request(http.MethodPost, path, issued.Value, payload)
		r.clock.Advance(time.Minute) // the login routes are rate limited
		if n := r.idempotencyRecords(); n != 0 {
			t.Fatalf("%s left %d idempotency records", path, n)
		}
	}
}

func TestATokenIsIssuedOnceWithItsValue(t *testing.T) {
	r := newRemote(t)
	_, issued := r.admin()
	payload := `{"name":"deploy","expires_at":"` + r.expiry() + `"}`

	created := r.request(http.MethodPost, wire.PathTokens, issued.Value, payload)
	listed := r.request(http.MethodGet, wire.PathTokens, issued.Value, "")

	var made wire.Envelope[wire.TokenIssued]
	if err := json.Unmarshal(created.Body, &made); err != nil || created.Status != http.StatusCreated || !strings.HasPrefix(made.Data.Value, "smt_") {
		t.Fatalf("create: status %d body %s", created.Status, created.Body)
	}
	if strings.Contains(string(listed.Body), made.Data.Value) {
		t.Error("the listing repeats the token value")
	}
	if resp := r.request(http.MethodGet, wire.PathMe, made.Data.Value, ""); resp.Status != http.StatusOK {
		t.Errorf("the new token does not authenticate: %d", resp.Status)
	}
}

func TestEnrollmentIsUnavailableWhileItsPortIsNil(t *testing.T) {
	r := newRemote(t, func(o *remoteOptions) { o.noEnroll = true })
	_, issued := r.admin()

	create := r.request(http.MethodPost, wire.PathEnrollments, issued.Value, `{"max_nodes":1}`)
	enroll := r.request(http.MethodPost, wire.PathEnroll, "", `{"token":"smj_x"}`)

	for name, resp := range map[string]reply{"create": create, "enroll": enroll} {
		if resp.Status != http.StatusUnprocessableEntity || decodeError(t, resp).Code != smerr.CodeCapabilityUnavailable {
			t.Errorf("%s: status %d body %s", name, resp.Status, resp.Body)
		}
	}
}

func TestRoutesOfThePortsThatAreNotWiredAreUnavailable(t *testing.T) {
	r := newRemote(t)
	_, issued := r.admin()
	for _, path := range []string{wire.PathSecrets, wire.PathMasterKeyRotate, wire.PathMasterKeyRetire, wire.PathSSHKeyRotate, wire.PathBackups} {
		resp := r.request(http.MethodPost, path, issued.Value, `{}`, wire.HeaderIdempotencyKey, "k")
		if resp.Status != http.StatusUnprocessableEntity {
			t.Errorf("%s: status %d body %s", path, resp.Status, resp.Body)
		}
	}
}

func TestExportIsNotServedOverHTTPS(t *testing.T) {
	r := newRemote(t)
	_, issued := r.admin()

	resp := r.request(http.MethodPost, wire.PathMasterKeyExport, issued.Value, `{"kek_id":"x"}`)

	if resp.Status != http.StatusNotFound {
		t.Errorf("status %d body %s", resp.Status, resp.Body)
	}
	for _, rt := range r.server.Routes() {
		if rt.UnixOnly {
			t.Errorf("%s %s is unix-only but served over HTTPS", rt.Method, rt.Pattern)
		}
	}
}

func TestEveryWriteOfACatalogActionIsGuardedByTheHoldWithItsAction(t *testing.T) {
	r := newRemote(t)
	_, issued := r.admin()

	r.request(http.MethodPost, wire.PathTokens, issued.Value, `{"name":"a","expires_at":"`+r.expiry()+`"}`)
	r.request(http.MethodGet, wire.PathMe, issued.Value, "")
	r.request(http.MethodPost, wire.PathOIDCDevice, "", "")
	r.request(http.MethodPost, wire.PathBackups, issued.Value, "", wire.HeaderIdempotencyKey, "k")

	if got := r.hold.actions(); !slices.Equal(got, []string{"token.create", "backup.create"}) {
		t.Errorf("guarded actions = %v; reads, login and the exempt routes are not guarded", got)
	}
}

func TestDuringHoldWritesAreRefusedButLoginAndReadsAreNot(t *testing.T) {
	r := newRemote(t)
	_, issued := r.admin()
	r.setHold(true)
	payload := `{"name":"a","expires_at":"` + r.expiry() + `"}`

	write := r.request(http.MethodPost, wire.PathTokens, issued.Value, payload)
	read := r.request(http.MethodGet, wire.PathMe, issued.Value, "")
	login := r.request(http.MethodPost, wire.PathOIDCStart, "", `{"redirect_uri":"http://127.0.0.1:1/callback","code_challenge":"c"}`)
	own := r.request(http.MethodGet, wire.PathTokens, issued.Value, "")

	if e := decodeError(t, write); write.Status != http.StatusConflict || e.Reason() != smerr.ReasonRestoreHold {
		t.Errorf("write: status %d body %s", write.Status, write.Body)
	}
	if read.Status != http.StatusOK || own.Status != http.StatusOK {
		t.Errorf("reads: %d %d", read.Status, own.Status)
	}
	if e := decodeError(t, login); e.Reason() == smerr.ReasonRestoreHold {
		t.Errorf("login was refused by the hold: %s", login.Body)
	}
}

func TestSpoofedForwardingHeadersAreIgnoredFromAnUntrustedPeer(t *testing.T) {
	proxy, err := NewProxy([]string{"10.0.0.0/8"})
	must(t, err)
	r := newRemote(t, func(o *remoteOptions) { o.proxy = proxy })

	resp := r.request(http.MethodPost, wire.PathEnroll, "", `{"token":"smj_x"}`,
		headerForwardedFor, "9.9.9.9", headerForwardedProto, "http")

	if resp.Status != http.StatusOK {
		t.Fatalf("status %d body %s: a spoofed proto from an untrusted peer must be ignored, not rejected", resp.Status, resp.Body)
	}
	if got := r.enroll.lastSource(); got != netip.MustParseAddr("127.0.0.1") {
		t.Errorf("source = %s, want the TCP peer; X-Forwarded-For was believed", got)
	}
}

func TestForwardingHeadersAreHonoredFromATrustedProxy(t *testing.T) {
	proxy, err := NewProxy([]string{"127.0.0.1", "10.0.0.0/8"})
	must(t, err)
	r := newRemote(t, func(o *remoteOptions) { o.proxy = proxy })
	enroll := func(headers ...string) reply {
		return r.request(http.MethodPost, wire.PathEnroll, "", `{"token":"smj_x"}`, headers...)
	}

	chain := enroll(headerForwardedFor, "6.6.6.6, 9.9.9.9, 10.1.2.3", headerForwardedProto, "https")
	plain := enroll(headerForwardedProto, "http", headerForwardedFor, "9.9.9.9")
	missing := enroll(headerForwardedFor, "9.9.9.9")
	mixed := enroll(headerForwardedProto, "https,http", headerForwardedFor, "9.9.9.9")
	garbage := enroll(headerForwardedProto, "https", headerForwardedFor, "not-an-address")

	if chain.Status != http.StatusOK || r.enroll.lastSource() != netip.MustParseAddr("9.9.9.9") {
		t.Errorf("chain: status %d source %s; want the first address that is not a trusted proxy", chain.Status, r.enroll.lastSource())
	}
	for name, resp := range map[string]reply{"proto http": plain, "no proto": missing, "mixed proto": mixed, "malformed chain": garbage} {
		if resp.Status != http.StatusBadRequest || decodeError(t, resp).Code != smerr.CodeInvalidArgument {
			t.Errorf("%s: status %d body %s", name, resp.Status, resp.Body)
		}
	}
}

func TestLoopbackGetsNoTrustInProxyMode(t *testing.T) {
	proxy, err := NewProxy([]string{"10.0.0.0/8"})
	must(t, err)
	r := newRemote(t, func(o *remoteOptions) { o.proxy = proxy })

	resp := r.request(http.MethodGet, wire.PathMe, "", "")

	if resp.Status != http.StatusUnauthorized {
		t.Errorf("a loopback peer reached /me without a token: %d", resp.Status)
	}
}

func TestSpoofedClientAddressesShareTheRealPeersRateLimit(t *testing.T) {
	proxy, err := NewProxy([]string{"10.0.0.0/8"})
	must(t, err)
	r := newRemote(t, func(o *remoteOptions) { o.proxy = proxy })
	limited := 0

	for i := range 8 {
		resp := r.request(http.MethodPost, wire.PathOIDCDevice, "", "", headerForwardedFor, "9.9.9."+string(rune('1'+i)))
		if resp.Status == http.StatusTooManyRequests {
			limited++
		}
	}

	if limited == 0 {
		t.Error("rotating X-Forwarded-For bypassed the per-address limit")
	}
}
