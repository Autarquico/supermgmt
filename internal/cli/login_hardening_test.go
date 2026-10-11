package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
)

func TestLoginDeviceFlowKeepsPollingThroughARateLimit(t *testing.T) {
	var polls []wire.DevicePollRequest
	b := newRemoteBox(t, routes{
		"POST " + wire.PathOIDCDevice: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.DeviceStart{TransactionID: "txn-1", UserCode: "AB", VerificationURI: "https://idp/d", IntervalSeconds: 2, ExpiresAt: later})
		},
		"POST " + wire.PathOIDCDevicePoll: func(w http.ResponseWriter, r *http.Request) {
			var req wire.DevicePollRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			polls = append(polls, req)
			if len(polls) == 1 {
				w.Header().Set("Retry-After", "30") // beyond what the client sits out itself
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			reply(w, 200, wire.DevicePoll{Status: wire.DeviceComplete, Session: &wire.LoginSession{Token: tokenTwo, ExpiresAt: later}})
		},
		"GET " + wire.PathMe: meRoute(tokenTwo),
	})
	b.useProfile()
	var waits []time.Duration
	deps := loginDeps{sleep: func(_ context.Context, d time.Duration) error { waits = append(waits, d); return nil }}

	r := b.runLogin(deps, "", "--device")

	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	if fmt.Sprint(waits) != "[2s 30s]" {
		t.Errorf("waits = %v, want the interval, then the Retry-After", waits)
	}
	if len(polls) != 2 || polls[0].TransactionID != polls[1].TransactionID {
		t.Errorf("polls = %+v, want the same transaction twice", polls)
	}
	if b.storedToken() != tokenTwo {
		t.Errorf("stored token = %q", b.storedToken())
	}
}

func TestLoginLoopbackIgnoresForgedRedirectsUntilTheRealOne(t *testing.T) {
	l := newLoginServer(t, tokenOne)
	deps := loginDeps{sleep: sleepContext, openBrowser: func(ctx context.Context, u string) error {
		for _, query := range []string{"code=x&state=x", "error=denied", "code=x", "error=denied&state=forged", "code=real&state=state-1"} {
			if err := l.browser(query)(ctx, u); err != nil {
				return err
			}
		}
		return nil
	}}

	r := l.b.runLogin(deps, "")

	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	if l.exchange.Code != "real" || l.exchange.State != "state-1" {
		t.Errorf("exchanged %+v, want only the redirect with the login's state", l.exchange)
	}
}

func TestLoginLoopbackForgedRedirectGetsABadRequestAndDoesNotEndTheWait(t *testing.T) {
	l := newLoginServer(t, tokenOne)
	var status int
	deps := loginDeps{sleep: sleepContext, callbackTimeout: 300 * time.Millisecond, openBrowser: func(ctx context.Context, _ string) error {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, l.start.RedirectURI+"?error=denied", http.NoBody)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		status = resp.StatusCode
		return resp.Body.Close()
	}}

	r := l.b.runLogin(deps, "")

	if status != http.StatusBadRequest {
		t.Errorf("forged redirect answered %d, want 400", status)
	}
	if r.code == 0 || !strings.Contains(r.stderr, "timed out") || strings.Contains(r.stderr, "denied") {
		t.Errorf("exit %d, stderr %q: a forged error must not be reported as the provider's refusal", r.code, r.stderr)
	}
}
