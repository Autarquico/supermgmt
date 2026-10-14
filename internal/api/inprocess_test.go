package api

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/app"
)

// inProcessDo sends a request through the in-process transport of f.server
// as by.
func (f *m5Fixture) inProcessDo(by app.Caller, method, path, body string, headers ...string) (reply, error) {
	f.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, "http://in-process"+path, strings.NewReader(body))
	must(f.t, err)
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := (&http.Client{Transport: f.server.InProcess(by)}).Do(req)
	if err != nil {
		return reply{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	payload, err := io.ReadAll(resp.Body)
	must(f.t, err)
	return reply{Status: resp.StatusCode, Header: resp.Header, Body: payload}, nil
}

func TestInProcessRunsTheRequestAsTheGivenCaller(t *testing.T) {
	for name, opts := range map[string][]func(*m5Options){
		"socket server": nil,
		"HTTPS server":  {func(o *m5Options) { o.https = true }},
	} {
		t.Run(name, func(t *testing.T) {
			f := newM5Fixture(t, opts...)
			r, err := f.inProcessDo(f.mcp, http.MethodGet, wire.PathMe, "")
			must(t, err)
			if r.Status != http.StatusOK {
				t.Fatalf("status %d: %s", r.Status, r.Body)
			}
			if me := decodeData[wire.Me](t, r); me.IdentityID != f.mcp.ID {
				t.Errorf("caller = %s, want %s", me.IdentityID, f.mcp.ID)
			}
			if r.Header.Get(wire.HeaderCorrelationID) == "" {
				t.Error("the in-process answer lacks the correlation id: it did not go through the pipeline")
			}
		})
	}
}

func TestInProcessRefusesARequestThatCarriesAToken(t *testing.T) {
	f := newM5Fixture(t, func(o *m5Options) { o.https = true })
	if _, err := f.inProcessDo(f.mcp, http.MethodGet, wire.PathMe, "", wire.HeaderAuthorization, "Bearer "+m5AdminToken); err == nil {
		t.Error("a request with an Authorization header was served")
	}
	if seen := f.tokens.resolved(); len(seen) != 0 {
		t.Errorf("the resolver saw %v", seen)
	}
}

func TestInProcessNeedsACaller(t *testing.T) {
	f := newM5Fixture(t, func(o *m5Options) { o.https = true })
	if _, err := f.inProcessDo(app.Caller{}, http.MethodGet, wire.PathMe, ""); err == nil {
		t.Error("a request without a caller was served")
	}
}

func TestNoHeaderOfANetworkRequestChoosesTheCaller(t *testing.T) {
	f := newM5Fixture(t, func(o *m5Options) { o.https = true })
	r := f.do(http.MethodGet, wire.PathMe, "", "",
		"X-Caller", f.admin.ID.String(), "X-Forwarded-User", f.admin.ID.String(), "X-Identity", f.admin.ID.String())
	if r.Status != http.StatusUnauthorized {
		t.Errorf("status %d: %s, want 401", r.Status, r.Body)
	}
}

func TestInProcessChargesEachWriteOnceToTheCallersBucket(t *testing.T) {
	f := newM5Fixture(t, func(o *m5Options) { o.https = true })
	// An invalid body fails after admission, so only the bucket decides the first 429.
	write := func(by app.Caller) reply {
		r, err := f.inProcessDo(by, http.MethodPost, wire.PathPlans, `{}`, wire.HeaderIdempotencyKey, f.ids.NewID().String())
		must(t, err)
		return r
	}
	for i := 0; i < int(writeRate.burst); i++ {
		if r := write(f.mcp); r.Status == http.StatusTooManyRequests {
			t.Fatalf("write %d of %d was limited: a write is charged more than once", i+1, int(writeRate.burst))
		}
	}
	limited := write(f.mcp)
	if limited.Status != http.StatusTooManyRequests {
		t.Fatalf("write beyond the bucket: status %d, want 429", limited.Status)
	}
	if after, err := strconv.Atoi(limited.Header.Get("Retry-After")); err != nil || after < 1 {
		t.Errorf("Retry-After = %q", limited.Header.Get("Retry-After"))
	}
	if r := write(f.admin); r.Status == http.StatusTooManyRequests {
		t.Error("another identity shares the bucket")
	}
	if r, err := f.inProcessDo(f.mcp, http.MethodGet, wire.PathMe, ""); err != nil || r.Status != http.StatusOK {
		t.Errorf("a read while limited: %v status %d, want 200", err, r.Status)
	}
	f.clock.Advance(time.Second)
	if r := write(f.mcp); r.Status == http.StatusTooManyRequests {
		t.Error("still limited one refill interval later")
	}
	if r := write(f.mcp); r.Status != http.StatusTooManyRequests {
		t.Error("more than one token refilled per interval")
	}
}

func TestInProcessIssuingATokenRefusesAnIdempotencyKey(t *testing.T) {
	f := newM5Fixture(t, func(o *m5Options) { o.https = true })
	path := wire.Path(wire.PathMCPClientToken, f.ids.NewID().String())
	r, err := f.inProcessDo(f.admin, http.MethodPost, path, `{"expires_at":"2027-01-01T00:00:00Z"}`, wire.HeaderIdempotencyKey, "k")
	must(t, err)
	if r.Status != http.StatusBadRequest {
		t.Errorf("status %d: %s, want 400", r.Status, r.Body)
	}
}
