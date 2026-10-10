package app

import (
	"context"
	"errors"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/jobs"
)

const (
	defaultSweepInterval   = time.Minute
	defaultObservationKeep = 24 * time.Hour
	eventSessionAbandoned  = "node.session.abandoned"
)

// SweeperOptions tune the Sweeper.
type SweeperOptions struct {
	Store    *jobs.Store
	Interval time.Duration // default 1m
	// ObservationRetention is how long superseded observations are kept;
	// default 24h. The newest of every (resource, kind) is always kept.
	ObservationRetention time.Duration
	OnError              func(error) // default: ignored
}

// Sweeper does the periodic housekeeping the daemon owes the database: it
// expires plans that waited too long for approval, drops idempotency records
// past their TTL, marks interactive sessions that never ended as abandoned and
// prunes old observations.
type Sweeper struct {
	core
	store     *jobs.Store
	interval  time.Duration
	retention time.Duration
	onError   func(error)
}

// NewSweeper validates cfg.
func NewSweeper(cfg Config, o SweeperOptions) (*Sweeper, error) {
	c, err := newCore(cfg)
	if err != nil {
		return nil, err
	}
	if o.Store == nil {
		return nil, errors.New("app: job store is required")
	}
	s := &Sweeper{core: c, store: o.Store, interval: o.Interval, retention: o.ObservationRetention, onError: o.OnError}
	if s.interval <= 0 {
		s.interval = defaultSweepInterval
	}
	if s.retention <= 0 {
		s.retention = defaultObservationKeep
	}
	if s.onError == nil {
		s.onError = func(error) {}
	}
	return s, nil
}

// Run sweeps once and then every interval until ctx ends.
func (s *Sweeper) Run(ctx context.Context) error {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		if err := s.Sweep(ctx); err != nil && ctx.Err() == nil {
			s.onError(err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// Sweep runs every housekeeping task once. A failing task does not stop the
// others; the errors are joined.
func (s *Sweeper) Sweep(ctx context.Context) error {
	return errors.Join(
		wrap("expire plans", s.expirePlans(ctx)),
		wrap("sweep idempotency records", s.sweepIdempotency(ctx)),
		wrap("abandon sessions", s.abandonSessions(ctx)),
		wrap("prune observations", s.pruneObservations(ctx)),
	)
}

func wrap(what string, err error) error {
	if err == nil {
		return nil
	}
	return errors.Join(errors.New(what), err)
}

func (s *Sweeper) expirePlans(ctx context.Context) error {
	_, err := s.store.ExpirePlans(ctx)
	return err
}

func (s *Sweeper) sweepIdempotency(ctx context.Context) error {
	return s.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		_, err := database.SweepIdempotencyRecords(ctx, tx, s.cfg.Clock.Now())
		return err
	})
}

// abandonSessions marks sessions issued more than sessionTTL ago and never
// ended as abandoned, and audits each (plan Q7).
func (s *Sweeper) abandonSessions(ctx context.Context) error {
	return s.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		now := s.cfg.Clock.Now()
		abandoned, err := database.AbandonStaleSessions(ctx, tx, now.Add(-sessionTTL), now)
		if err != nil {
			return err
		}
		for _, id := range abandoned {
			session, err := database.GetInteractiveSession(ctx, tx, id)
			if err != nil {
				return err
			}
			err = s.emit(ctx, tx, systemActor, eventSessionAbandoned, nodeRef(session.NodeID), domain.ResultSucceeded,
				map[string]any{"session_id": id.String(), "tool": string(session.Tool)})
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Sweeper) pruneObservations(ctx context.Context) error {
	return s.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		_, err := pruneObservations(ctx, tx, s.cfg.Clock.Now().Add(-s.retention))
		return err
	})
}

// Activity answers whether the daemon has work that must not be abandoned
// (ADR-0014): any job that is not succeeded, failed or cancelled keeps it alive.
type Activity struct {
	core
	store *jobs.Store
}

// NewActivity validates cfg.
func NewActivity(cfg Config, store *jobs.Store) (*Activity, error) {
	c, err := newCore(cfg)
	if err != nil {
		return nil, err
	}
	if store == nil {
		return nil, errors.New("app: job store is required")
	}
	return &Activity{core: c, store: store}, nil
}

// Busy reports whether any job is queued, running, awaiting approval or
// interrupted.
func (a *Activity) Busy(ctx context.Context) (bool, error) {
	var active []domain.JobState
	for _, state := range domain.AllJobStates() {
		if !state.Terminal() {
			active = append(active, state)
		}
	}
	found, err := a.store.List(ctx, a.cfg.DB.Reader(), jobs.ListFilter{States: active, Limit: 1})
	return len(found) > 0, err
}
