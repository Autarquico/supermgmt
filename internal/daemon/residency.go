package daemon

import (
	"context"
	"sync"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
)

// Residency decides when a local daemon may exit (spec §2.1.1, ADR-0014).
//
// The idle timer runs only while no long-lived client is attached (presence),
// no one-shot request is running (in flight) and no job is active. Any change
// restarts it; once it has run for the idle-exit duration the daemon should
// shut down. A resident daemon (daemon.resident) never expires.
type Residency struct {
	clock    domain.Clock
	idleExit time.Duration
	resident bool
	busy     func(context.Context) (bool, error)

	mu        sync.Mutex
	presence  int
	inFlight  int
	idleSince time.Time
}

// ResidencyConfig is what NewResidency needs. Busy reports active work
// (non-terminal jobs); when it fails the daemon is treated as busy, so the
// wrapper that logs the failure lives with the caller.
type ResidencyConfig struct {
	Clock    domain.Clock
	IdleExit time.Duration
	Resident bool
	Busy     func(context.Context) (bool, error)
}

// NewResidency starts the idle timer now.
func NewResidency(c ResidencyConfig) *Residency {
	r := &Residency{clock: c.Clock, idleExit: c.IdleExit, resident: c.Resident, busy: c.Busy}
	r.idleSince = c.Clock.Now()
	return r
}

// Present records a long-lived client; call the result when it goes.
func (r *Residency) Present() (leave func()) {
	return r.enter(&r.presence)
}

// Begin records a one-shot request in flight; call the result when it ends.
func (r *Residency) Begin() (end func()) {
	return r.enter(&r.inFlight)
}

func (r *Residency) enter(counter *int) func() {
	r.mu.Lock()
	*counter++
	r.idleSince = time.Time{}
	r.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			r.mu.Lock()
			defer r.mu.Unlock()
			*counter--
			r.restartTimerIfIdle()
		})
	}
}

// restartTimerIfIdle starts the idle timer at the moment the last client or
// request is gone. The caller holds mu.
func (r *Residency) restartTimerIfIdle() {
	if r.presence == 0 && r.inFlight == 0 {
		r.idleSince = r.clock.Now()
	}
}

// Expired reports whether the daemon has been idle for the idle-exit duration.
// It asks for active work, so a job that is queued, running, awaiting
// approval or interrupted keeps the daemon alive and restarts the timer.
func (r *Residency) Expired(ctx context.Context) bool {
	if r.resident || r.idleExit <= 0 {
		return false
	}
	r.mu.Lock()
	attached := r.presence > 0 || r.inFlight > 0
	r.mu.Unlock()
	if attached {
		return false
	}
	busy, err := r.busy(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil || busy {
		r.idleSince = r.clock.Now()
		return false
	}
	if r.idleSince.IsZero() {
		r.idleSince = r.clock.Now()
	}
	return r.clock.Now().Sub(r.idleSince) >= r.idleExit
}

// Watch polls Expired every interval and calls onIdle once when it holds. It
// returns when ctx ends or after onIdle.
func (r *Residency) Watch(ctx context.Context, interval time.Duration, onIdle func()) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if r.Expired(ctx) {
				onIdle()
				return
			}
		}
	}
}
