package app

import (
	"context"
	"sync"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/runtimes"
)

// statsFlights lets one `docker stats` sample of a node run at a time. It samples every container, takes a
// second, and callers who ask while it runs wait for that sample instead of starting another. Nothing is kept
// after the callers have their answer: no cache, no history. The zero value is ready.
type statsFlights struct {
	mu     sync.Mutex
	flying map[domain.ID]*statsFlight
}

type statsFlight struct {
	callers int // how many callers asked for this sample; for tests
	done    chan struct{}
	stats   []runtimes.ContainerStats
	at      time.Time
	err     error
}

// sample returns the sample of node, started by sample if none is running. at is when the sample was taken.
// A caller that gives up stops waiting; the sample goes on for the others.
func (f *statsFlights) sample(ctx context.Context, node domain.ID, clock domain.Clock,
	take func(context.Context) ([]runtimes.ContainerStats, error),
) ([]runtimes.ContainerStats, time.Time, error) {
	f.mu.Lock()
	flight, joined := f.flying[node]
	if !joined {
		if f.flying == nil {
			f.flying = map[domain.ID]*statsFlight{}
		}
		flight = &statsFlight{done: make(chan struct{})}
		f.flying[node] = flight
		go func() {
			flight.stats, flight.err = take(context.WithoutCancel(ctx))
			flight.at = clock.Now()
			f.mu.Lock()
			delete(f.flying, node)
			f.mu.Unlock()
			close(flight.done)
		}()
	}
	flight.callers++
	f.mu.Unlock()
	select {
	case <-flight.done:
		return flight.stats, flight.at, flight.err
	case <-ctx.Done():
		return nil, time.Time{}, ctx.Err()
	}
}

// callers is how many callers share the sample of node now in flight.
func (f *statsFlights) callers(node domain.ID) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	if flight := f.flying[node]; flight != nil {
		return flight.callers
	}
	return 0
}
