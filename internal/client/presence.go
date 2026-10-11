package client

import (
	"context"
	"io"
	"net/http"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
)

const (
	defaultPresenceRetry = 250 * time.Millisecond
	maxPresenceRetry     = 5 * time.Second
)

// HoldPresence keeps GET /presence open so the daemon counts this process as
// a connected client (ADR-0014 residency). It reconnects with exponential
// backoff, autostarting the daemon like any request, and returns only when
// ctx ends. Long-lived clients (the TUI, `sm jobs --watch`) run it in a
// goroutine.
func (c *Client) HoldPresence(ctx context.Context) error {
	retry := cmpOr(c.opts.PresenceRetry, defaultPresenceRetry)
	delay := retry
	for {
		if c.holdOnce(ctx) {
			delay = retry
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		delay = min(delay*2, maxPresenceRetry)
	}
}

// holdOnce blocks while the stream is open and reports whether it ever was.
func (c *Client) holdOnce(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+wire.PathPresence, http.NoBody)
	if err != nil {
		return false
	}
	c.authorize(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return true
}
