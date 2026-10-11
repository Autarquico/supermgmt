package api

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func TestDevicePollingAtTheIdPIntervalIsNeverRateLimited(t *testing.T) {
	r := newRemote(t)

	for i := range 60 { // five minutes of polling every 5 s
		resp := r.request(http.MethodPost, wire.PathOIDCDevicePoll, "", `{"transaction_id":"t"}`)
		if resp.Status == http.StatusTooManyRequests {
			t.Fatalf("poll %d was rate limited", i+1)
		}
		r.clock.Advance(5 * time.Second)
	}
}

func TestPollsDoNotSpendTheLoginBucket(t *testing.T) {
	r := newRemote(t)
	for range 30 {
		r.request(http.MethodPost, wire.PathOIDCDevicePoll, "", `{"transaction_id":"t"}`)
	}

	resp := r.request(http.MethodPost, wire.PathOIDCStart, "", `{"redirect_uri":"http://127.0.0.1:1/callback","code_challenge":"c"}`)

	if resp.Status == http.StatusTooManyRequests {
		t.Fatal("polling exhausted the login bucket")
	}
}

func TestATrustedProxyMustForwardTheClientAddress(t *testing.T) {
	proxy, err := NewProxy([]string{"127.0.0.1"})
	must(t, err)
	r := newRemote(t, func(o *remoteOptions) { o.proxy = proxy })

	resp := r.request(http.MethodPost, wire.PathEnroll, "", `{"token":"smj_x"}`, headerForwardedProto, "https")

	if resp.Status != http.StatusBadRequest || decodeError(t, resp).Code != smerr.CodeInvalidArgument {
		t.Fatalf("status %d body %s, want 400 INVALID_ARGUMENT", resp.Status, resp.Body)
	}
}

func TestAUnixPeerMustForwardTheClientAddress(t *testing.T) {
	proxy, err := NewProxy([]string{"10.0.0.0/8"})
	must(t, err)
	unix := func(forwardedFor ...string) *http.Request {
		ctx := context.WithValue(context.Background(), http.LocalAddrContextKey, &net.UnixAddr{Name: "/run/sm.sock", Net: "unix"})
		req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/", nil)
		req.Header.Set(headerForwardedProto, "https")
		for _, v := range forwardedFor {
			req.Header.Add(headerForwardedFor, v)
		}
		return req
	}

	if _, err := proxy.clientOf(unix()); smerr.CodeOf(err) != smerr.CodeInvalidArgument {
		t.Errorf("no X-Forwarded-For: %v, want INVALID_ARGUMENT", err)
	}
	got, err := proxy.clientOf(unix("9.9.9.9"))
	if err != nil || got != netip.MustParseAddr("9.9.9.9") {
		t.Errorf("one address: %v, %v", got, err)
	}
}
