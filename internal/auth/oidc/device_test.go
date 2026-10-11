package oidc

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func approve(p *idp) { p.setDevice(func(d *deviceScript) { d.approved = true }) }

func asPending(t *testing.T, err error) Pending {
	t.Helper()
	var pending Pending
	if !errors.As(err, &pending) {
		t.Fatalf("error = %v, want Pending", err)
	}
	return pending
}

func TestDeviceStartHidesTheDeviceCodeAndSendsCredentialsInTheForm(t *testing.T) {
	clock := newClock()
	p := newIdP(t, clock)
	cl := newClient(t, p)

	txn, err := cl.DeviceStart(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if txn.UserCode != "ABCD-EFGH" || txn.VerificationURI != issuerURL+"/device" || !strings.HasSuffix(txn.VerificationURIComplete, "ABCD-EFGH") {
		t.Errorf("txn = %+v", txn)
	}
	if txn.Interval != 5*time.Second || !txn.ExpiresAt.Equal(clock.Now().Add(10*time.Minute)) {
		t.Errorf("interval %v, expires %v", txn.Interval, txn.ExpiresAt)
	}
	if len(txn.ID) < 20 || strings.Contains(txn.ID, "DEVICE") {
		t.Errorf("txn id %q must be random and unrelated to the device code", txn.ID)
	}
	form := p.lastDeviceRequest()
	if form.Get("client_id") != testClientID || form.Get("client_secret") != testSecret {
		t.Errorf("device request form = %v, want client credentials as fields", form)
	}
}

func TestDeviceStartDefaultsTheIntervalTo5Seconds(t *testing.T) {
	p := newIdP(t, newClock())
	p.setDevice(func(d *deviceScript) { d.interval = 0 })
	txn, err := newClient(t, p).DeviceStart(t.Context())
	if err != nil || txn.Interval != 5*time.Second {
		t.Fatalf("txn = %+v, %v", txn, err)
	}
}

func TestDeviceStartRefusals(t *testing.T) {
	t.Run("IdP without a device endpoint", func(t *testing.T) {
		p := newIdP(t, newClock())
		p.setDoc("device_authorization_endpoint", nil)
		_, err := newClient(t, p).DeviceStart(t.Context())
		var e *smerr.Error
		if !errors.As(err, &e) || e.Code != smerr.CodeCapabilityUnavailable {
			t.Fatalf("error = %v, want CAPABILITY_UNAVAILABLE", err)
		}
	})
	for _, uri := range []string{"http://10.0.0.5/device", "javascript:alert(1)", ""} {
		t.Run("verification uri "+uri, func(t *testing.T) {
			p := newIdP(t, newClock())
			p.setDevice(func(d *deviceScript) { d.verifyURI = uri })
			if _, err := newClient(t, p).DeviceStart(t.Context()); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	for name, uri := range map[string]string{
		"raw secret":       issuerURL + "/device?code=" + testSecret,
		"secret parameter": issuerURL + "/device?client_secret=anything",
		"secret in path":   issuerURL + "/device/" + testSecret,
	} {
		t.Run("verification uri with "+name, func(t *testing.T) {
			p := newIdP(t, newClock())
			p.setDevice(func(d *deviceScript) { d.verifyURI = uri })
			_, err := newClient(t, p).DeviceStart(t.Context())
			var e *smerr.Error
			if !errors.As(err, &e) || e.Code != smerr.CodeProviderError {
				t.Fatalf("error = %v, want PROVIDER_ERROR", err)
			}
			if strings.Contains(err.Error(), testSecret) {
				t.Errorf("error leaks the secret: %v", err)
			}
		})
	}
	t.Run("no expiry", func(t *testing.T) {
		p := newIdP(t, newClock())
		p.setDevice(func(d *deviceScript) { d.expiresIn = 0 })
		if _, err := newClient(t, p).DeviceStart(t.Context()); err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("IdP rejects the client", func(t *testing.T) {
		p := newIdP(t, newClock())
		cl := newClient(t, p, func(c *Config) { c.ClientSecret = "wrong" })
		_, err := cl.DeviceStart(t.Context())
		wantReason(t, err, smerr.ReasonOIDCInvalid)
	})
}

func TestDevicePollPendingThenSessionThenConflict(t *testing.T) {
	clock := newClock()
	p := newIdP(t, clock)
	cl := newClient(t, p)
	txn, _ := cl.DeviceStart(t.Context())

	clock.advance(txn.Interval)
	_, err := cl.DevicePoll(t.Context(), txn.ID)
	if pending := asPending(t, err); pending.SlowDown {
		t.Fatal("a poll on schedule must not be slowed down")
	}

	approve(p)
	clock.advance(txn.Interval)
	claims, err := cl.DevicePoll(t.Context(), txn.ID)
	if err != nil || claims.Email != "alice@example.com" {
		t.Fatalf("claims = %+v, %v", claims, err)
	}

	calls := p.hitCount("/token")
	for range 3 {
		clock.advance(time.Minute)
		_, err = cl.DevicePoll(t.Context(), txn.ID)
		var e *smerr.Error
		if !errors.As(err, &e) || e.Code != smerr.CodeConflict {
			t.Fatalf("replayed completion = %v, want CONFLICT", err)
		}
	}
	if p.hitCount("/token") != calls {
		t.Fatal("a completed transaction polled the IdP again, although the IdP would hand out tokens twice")
	}
}

func TestDevicePollTooSoonIsSlowDownWithoutAskingTheIdP(t *testing.T) {
	clock := newClock()
	p := newIdP(t, clock)
	cl := newClient(t, p)
	txn, _ := cl.DeviceStart(t.Context())

	_, err := cl.DevicePoll(t.Context(), txn.ID) // right after start: the first poll waits Interval
	if !asPending(t, err).SlowDown {
		t.Fatal("want slow_down")
	}
	clock.advance(5 * time.Second) // the interval is now 10 s
	_, err = cl.DevicePoll(t.Context(), txn.ID)
	if !asPending(t, err).SlowDown {
		t.Fatal("want slow_down: the penalty lasts")
	}
	if got := p.hitCount("/token"); got != 0 {
		t.Fatalf("IdP polled %d times for early client polls", got)
	}
	clock.advance(15 * time.Second) // interval is 15 s after two penalties
	_, err = cl.DevicePoll(t.Context(), txn.ID)
	if asPending(t, err).SlowDown {
		t.Fatal("a poll after the raised interval is on schedule")
	}
	if got := p.hitCount("/token"); got != 1 {
		t.Fatalf("IdP polled %d times, want 1 per accepted client poll", got)
	}
}

func TestIdPSlowDownRaisesTheInterval(t *testing.T) {
	clock := newClock()
	p := newIdP(t, clock)
	p.setDevice(func(d *deviceScript) { d.errorCode = "slow_down" })
	cl := newClient(t, p)
	txn, _ := cl.DeviceStart(t.Context())

	clock.advance(5 * time.Second)
	_, err := cl.DevicePoll(t.Context(), txn.ID)
	if !asPending(t, err).SlowDown {
		t.Fatal("want slow_down from the IdP passed on")
	}
	p.setDevice(func(d *deviceScript) { d.errorCode = "" })
	clock.advance(5 * time.Second) // 5 s < the raised 10 s
	_, err = cl.DevicePoll(t.Context(), txn.ID)
	if !asPending(t, err).SlowDown {
		t.Fatal("the IdP's slow_down must raise the interval by 5 s")
	}
}

func TestDeviceTransactionExpires(t *testing.T) {
	clock := newClock()
	p := newIdP(t, clock)
	cl := newClient(t, p)
	txn, _ := cl.DeviceStart(t.Context())

	clock.advance(10 * time.Minute)
	_, err := cl.DevicePoll(t.Context(), txn.ID)
	wantReason(t, err, smerr.ReasonOIDCInvalid)
	if got := p.hitCount("/token"); got != 0 {
		t.Fatalf("an expired transaction polled the IdP (%d)", got)
	}
}

func TestUnknownDeviceTransactionIsOIDCInvalid(t *testing.T) {
	cl := newClient(t, newIdP(t, newClock()))
	_, err := cl.DevicePoll(t.Context(), "nope")
	wantReason(t, err, smerr.ReasonOIDCInvalid)
}

func TestIdPEndingTheLoginEndsTheTransaction(t *testing.T) {
	for _, code := range []string{"expired_token", "access_denied", "invalid_grant"} {
		t.Run(code, func(t *testing.T) {
			clock := newClock()
			p := newIdP(t, clock)
			p.setDevice(func(d *deviceScript) { d.errorCode = code })
			cl := newClient(t, p)
			txn, _ := cl.DeviceStart(t.Context())

			clock.advance(txn.Interval)
			_, err := cl.DevicePoll(t.Context(), txn.ID)
			wantReason(t, err, smerr.ReasonOIDCInvalid)

			approve(p)
			clock.advance(txn.Interval)
			_, err = cl.DevicePoll(t.Context(), txn.ID)
			wantReason(t, err, smerr.ReasonOIDCInvalid) // gone, not resurrected
		})
	}
}

func TestConcurrentPollsOfOneApprovalYieldOneSession(t *testing.T) {
	clock := newClock()
	p := newIdP(t, clock)
	cl := newClient(t, p)
	txn, _ := cl.DeviceStart(t.Context())
	approve(p)
	clock.advance(txn.Interval)

	const pollers = 20
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		successes int
		conflicts int
	)
	for range pollers {
		wg.Go(func() {
			_, err := cl.DevicePoll(t.Context(), txn.ID)
			var e *smerr.Error
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				successes++
			case errors.As(err, &e) && e.Code == smerr.CodeConflict:
				conflicts++
			default:
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
	wg.Wait()
	if successes != 1 || conflicts != pollers-1 {
		t.Fatalf("successes = %d, conflicts = %d", successes, conflicts)
	}
	if got := p.hitCount("/token"); got != 1 {
		t.Fatalf("IdP polled %d times, want 1", got)
	}
}

func TestDeviceTokensAreVerifiedLikeAnyOther(t *testing.T) {
	clock := newClock()
	p := newIdP(t, clock)
	approve(p)
	p.setDevice(func(d *deviceScript) {
		d.deviceToken = func() string { return p.sign("RS256", "rsa1", p.with("", map[string]any{"aud": "other"})) }
	})
	cl := newClient(t, p)
	txn, _ := cl.DeviceStart(t.Context())

	clock.advance(txn.Interval)
	_, err := cl.DevicePoll(t.Context(), txn.ID)
	wantReason(t, err, smerr.ReasonOIDCInvalid)

	clock.advance(txn.Interval)
	_, err = cl.DevicePoll(t.Context(), txn.ID)
	wantReason(t, err, smerr.ReasonOIDCInvalid) // a transaction that produced a bad token is over
}

func TestDeviceFlowNeedsNoNonceButStillRefusesReplayedJTI(t *testing.T) {
	clock := newClock()
	p := newIdP(t, clock)
	approve(p)
	p.setDevice(func(d *deviceScript) {
		d.deviceToken = func() string { return p.sign("RS256", "rsa1", p.with("", map[string]any{"jti": "dev-1"})) }
	})
	cl := newClient(t, p)

	for i, wantReplay := range []bool{false, true} {
		txn, _ := cl.DeviceStart(t.Context())
		clock.advance(txn.Interval)
		_, err := cl.DevicePoll(t.Context(), txn.ID)
		if wantReplay {
			wantReason(t, err, smerr.ReasonOIDCReplay)
		} else if err != nil {
			t.Fatalf("login %d: %v", i, err)
		}
	}
}

func TestDeviceTransactionsAreBounded(t *testing.T) {
	p := newIdP(t, newClock())
	cl := newClient(t, p)
	first, _ := cl.DeviceStart(t.Context())
	for range registryLimit {
		if _, err := cl.DeviceStart(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	_, err := cl.DevicePoll(t.Context(), first.ID)
	wantReason(t, err, smerr.ReasonOIDCInvalid)
}
