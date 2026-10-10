package app

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
)

const (
	defaultRefreshWorkers = 16
	defaultRefreshTick    = time.Second
	defaultProbeTimeout   = 90 * time.Second
)

// RefresherOptions tune the Refresher.
type RefresherOptions struct {
	Prober  *Prober
	Focus   *Focus         // nodes a client has open; nil means none
	Refresh config.Refresh // refresh.* intervals (spec §8.2)
	// Workers bounds the probes in flight; default 16.
	Workers int
	// Tick is how often due nodes are looked for; default 1s.
	Tick time.Duration
	// ProbeTimeout bounds one probe; default 90s.
	ProbeTimeout time.Duration
	// OnError receives probe failures other than the node being unreachable,
	// which is an observation, not an error.
	OnError func(node domain.ID, err error)
}

// Refresher keeps the observed state of every managed node fresh in the
// background, tiered by refresh.* (spec §12, §34), and is the reason request
// handlers never need to dial:
//
//   - every node is probed at refresh.metrics_interval (one session returns
//     reachability, metrics, addresses and capabilities, so that also covers
//     refresh.inventory_interval);
//   - nodes in focus are probed at refresh.focused_interval;
//   - runtimes and services are re-discovered at refresh.discovery_interval
//     (at refresh.inventory_interval for nodes in focus).
//
// The probes in flight are bounded, a node is never probed twice at once, and
// a hung node therefore occupies one slot until its probe times out.
type Refresher struct {
	core
	prober  *Prober
	focus   *Focus
	cfg2    config.Refresh
	workers chan struct{}
	tick    time.Duration
	timeout time.Duration
	onError func(domain.ID, error)

	mu       sync.Mutex
	last     map[domain.ID]refreshed
	inflight map[domain.ID]bool
	running  sync.WaitGroup
}

type refreshed struct{ status, full time.Time }

// NewRefresher validates cfg and the options.
func NewRefresher(cfg Config, o RefresherOptions) (*Refresher, error) {
	c, err := newCore(cfg)
	if err != nil {
		return nil, err
	}
	if o.Prober == nil {
		return nil, errors.New("app: prober is required")
	}
	r := &Refresher{
		core: c, prober: o.Prober, focus: o.Focus, cfg2: o.Refresh, tick: o.Tick, timeout: o.ProbeTimeout, onError: o.OnError,
		last: map[domain.ID]refreshed{}, inflight: map[domain.ID]bool{},
	}
	r.workers = make(chan struct{}, orDefaultInt(o.Workers, defaultRefreshWorkers))
	if r.tick <= 0 {
		r.tick = defaultRefreshTick
	}
	if r.timeout <= 0 {
		r.timeout = defaultProbeTimeout
	}
	if r.onError == nil {
		r.onError = func(domain.ID, error) {}
	}
	return r, nil
}

func orDefaultInt(n, fallback int) int {
	if n <= 0 {
		return fallback
	}
	return n
}

// Run schedules due probes every tick until ctx ends, then waits for the
// probes in flight (they are cancelled with ctx).
func (r *Refresher) Run(ctx context.Context) error {
	defer r.Wait()
	ticker := time.NewTicker(r.tick)
	defer ticker.Stop()
	for {
		if err := r.Pass(ctx); err != nil && ctx.Err() == nil {
			r.onError("", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// Wait blocks until every probe started so far has finished.
func (r *Refresher) Wait() { r.running.Wait() }

// Pass starts a probe for every managed node that is due and has a free slot,
// and returns without waiting for them.
func (r *Refresher) Pass(ctx context.Context) error {
	nodes, err := database.ListNodes(ctx, r.cfg.DB.Reader())
	if err != nil {
		return err
	}
	now := r.cfg.Clock.Now()
	for _, n := range nodes {
		if n.ManagementState == domain.ManagementRetired {
			continue
		}
		scope, due := r.due(n.ID, now)
		if due {
			r.start(ctx, n.ID, scope, now)
		}
	}
	return nil
}

// due decides whether the node needs a probe now and how deep it goes.
func (r *Refresher) due(id domain.ID, now time.Time) (ProbeScope, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.inflight[id] {
		return ProbeStatus, false
	}
	last := r.last[id]
	statusEvery, fullEvery := r.cfg2.MetricsInterval, r.cfg2.DiscoveryInterval
	if r.focus.Active(id) {
		statusEvery, fullEvery = r.cfg2.FocusedInterval, r.cfg2.InventoryInterval
	}
	fullDue := last.full.IsZero() || now.Sub(last.full) >= fullEvery
	statusDue := last.status.IsZero() || now.Sub(last.status) >= statusEvery
	switch {
	case fullDue:
		return ProbeFull, true
	case statusDue:
		return ProbeStatus, true
	}
	return ProbeStatus, false
}

// start runs a probe in the background if a slot is free; a node that finds
// none stays due and is picked up by the next pass.
func (r *Refresher) start(ctx context.Context, id domain.ID, scope ProbeScope, now time.Time) {
	select {
	case r.workers <- struct{}{}:
	default:
		return
	}
	r.mu.Lock()
	r.inflight[id] = true
	last := r.last[id]
	last.status = now
	if scope == ProbeFull {
		last.full = now
	}
	r.last[id] = last
	r.mu.Unlock()

	r.running.Go(func() {
		defer func() {
			<-r.workers
			r.mu.Lock()
			delete(r.inflight, id)
			r.mu.Unlock()
		}()
		probeCtx, cancel := context.WithTimeout(ctx, r.timeout)
		defer cancel()
		if err := r.prober.Probe(probeCtx, id, scope, nil); err != nil && ctx.Err() == nil && !connectivityFailure(err) {
			r.onError(id, err)
		}
	})
}
