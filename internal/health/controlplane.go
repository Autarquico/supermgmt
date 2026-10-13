package health

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/autarquico/supermgmt/internal/netguard"
)

// maxDrainedBody bounds what is read (and discarded) from a response.
const maxDrainedBody = 64 << 10

// ControlPlane runs one control_plane-scope check from the daemon. hc must be
// a netguard client (health allowlist, http allowed, no redirects): every
// destination is vetted there. A malformed check is an error; any outcome of
// the request itself, including a refused destination, is an unhealthy Result
// whose Detail never contains a response body.
func ControlPlane(ctx context.Context, hc *http.Client, c Check) (Result, error) {
	if c.Scope != ScopeControlPlane {
		return Result{}, fmt.Errorf("health: scope %q is not %q", c.Scope, ScopeControlPlane)
	}
	u, err := controlPlaneURL(c)
	if err != nil {
		return Result{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return Result{}, fmt.Errorf("health: build request: %w", err)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return Result{Detail: requestFailure(err)}, nil
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxDrainedBody))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return Result{Status: resp.StatusCode, Detail: fmt.Sprintf("HTTP status %d", resp.StatusCode)}, nil
	}
	return Result{Healthy: true, Status: resp.StatusCode}, nil
}

func requestFailure(err error) string {
	switch {
	case errors.Is(err, netguard.ErrBlocked):
		return "destination refused by the outbound filter"
	case errors.Is(err, netguard.ErrRedirect):
		return "redirect refused"
	case errors.Is(err, context.DeadlineExceeded):
		return "timed out"
	}
	return "request failed"
}
