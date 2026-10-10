// Package domaintest provides deterministic test doubles for domain seams.
package domaintest

import (
	"sync"
	"time"
)

// FakeClock is a goroutine-safe domain.Clock under test control.
type FakeClock struct {
	mu  sync.Mutex
	now time.Time
}

// NewFakeClock starts the clock at start.
func NewFakeClock(start time.Time) *FakeClock { return &FakeClock{now: start} }

func (c *FakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *FakeClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

func (c *FakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}
