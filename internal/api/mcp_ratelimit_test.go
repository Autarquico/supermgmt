package api

import (
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
)

// behindProxy makes the request come from the address, through the trusted
// proxy that remoteRig.do connects from.
func behindProxy(address string) []string {
	return []string{"X-Forwarded-Proto", "https", "X-Forwarded-For", address}
}

func newRemoteRigBehindProxy(t *testing.T, opts ...func(*remoteRigOptions)) *remoteRig {
	t.Helper()
	proxy, err := NewProxy([]string{"198.51.100.7"})
	must(t, err)
	return newRemoteRig(t, append(opts, func(o *remoteRigOptions) { o.proxy = proxy })...)
}

func TestRemote_InvalidTokenFloodFromOneAddressStopsAtTheBucketBeforeVerification(t *testing.T) {
	rig := newRemoteRig(t, func(o *remoteRigOptions) { o.introspection = true })
	rig.registerFakeClient()
	burst := int(authRate.burst)

	var unauthorized, limited int
	for i := 0; i < burst*4; i++ {
		switch rec := rig.do(http.MethodPost, wire.MCPPath, "forged-"+strconv.Itoa(i)); rec.Code {
		case http.StatusUnauthorized:
			unauthorized++
		case http.StatusTooManyRequests:
			limited++
			if rec.Header().Get("Retry-After") == "" {
				t.Fatal("429 without Retry-After")
			}
		default:
			t.Fatalf("request %d: status %d", i, rec.Code)
		}
	}
	if unauthorized != burst || limited != burst*3 {
		t.Errorf("got %d x 401 and %d x 429, want %d and %d", unauthorized, limited, burst, burst*3)
	}
	if calls := rig.fake.IntrospectionCalls(); calls != burst {
		t.Errorf("introspection calls = %d, want %d (frozen at the bucket size)", calls, burst)
	}
}

func TestRemote_PerAddressBucketAlsoGuardsTheMetadataPaths(t *testing.T) {
	rig := newRemoteRig(t)
	for i := 0; i < int(authRate.burst); i++ {
		rig.do(http.MethodGet, wire.WellKnownProtectedResourceMCP, "")
	}
	for _, path := range []string{wire.WellKnownProtectedResource, wire.MCPPath} {
		if rec := rig.do(http.MethodGet, path, ""); rec.Code != http.StatusTooManyRequests {
			t.Errorf("%s: status %d, want 429 once the address bucket is spent", path, rec.Code)
		}
	}
}

func TestRemote_APerAddressBucketDoesNotLimitAnotherAddress(t *testing.T) {
	rig := newRemoteRigBehindProxy(t)
	for i := 0; i < int(authRate.burst); i++ {
		rig.do(http.MethodPost, wire.MCPPath, "forged", behindProxy("203.0.113.1")...)
	}
	if rec := rig.do(http.MethodPost, wire.MCPPath, "forged", behindProxy("203.0.113.1")...); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status %d, want the first address limited", rec.Code)
	}
	if rec := rig.do(http.MethodPost, wire.MCPPath, "forged", behindProxy("203.0.113.2")...); rec.Code != http.StatusUnauthorized {
		t.Errorf("another address: status %d, want 401 (not limited)", rec.Code)
	}
}

func TestRemote_PerIdentityBucketLimitsAdmittedRequestsWithADeterministicRetryAfter(t *testing.T) {
	rig := newRemoteRigBehindProxy(t)
	rig.registerFakeClient()
	token := rig.accessToken()
	// Each request comes from its own address, so only the identity's bucket can refuse.
	fromNewAddress := func(n int) *http.Response {
		return rig.do(http.MethodPost, wire.MCPPath, token, behindProxy("203.0.113."+strconv.Itoa(n))...).Result()
	}

	burst := int(writeRate.burst)
	for n := 1; n <= burst; n++ {
		if status := fromNewAddress(n).StatusCode; status != http.StatusOK {
			t.Fatalf("request %d: status %d, want 200 within the bucket", n, status)
		}
	}
	over := fromNewAddress(burst + 1)
	if over.StatusCode != http.StatusTooManyRequests || over.Header.Get("Retry-After") != "1" {
		t.Fatalf("status %d Retry-After %q, want 429 and 1 (one token per second)", over.StatusCode, over.Header.Get("Retry-After"))
	}
	if len(rig.reached) != burst {
		t.Errorf("the MCP handler ran %d times, want %d", len(rig.reached), burst)
	}

	rig.clock.Advance(time.Second)
	if status := fromNewAddress(burst + 2).StatusCode; status != http.StatusOK {
		t.Errorf("after one second: status %d, want 200", status)
	}
}
