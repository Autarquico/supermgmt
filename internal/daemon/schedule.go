package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/backup"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
)

const (
	defaultScheduleCheck = 30 * time.Second
	defaultSweepEvery    = time.Hour
	// authGrace is how long an expired credential row stays, so that it reads
	// as expired rather than unknown to the person who held it.
	authGrace = 24 * time.Hour
	// stagedGrace keeps a freshly staged secret alive until its job exists.
	stagedGrace = time.Hour
)

// backupSchedule fires scheduled backups (spec §29.1). It is off while a
// restore hold is in force (ADR-0020) and resumes when the hold ends; a hold
// that cannot be read is treated as in force.
type backupSchedule struct {
	fire   func(context.Context) error
	held   func(context.Context) (bool, error)
	every  time.Duration
	report func(error)
}

// backupSchedule is nil when there is nothing to schedule: no schedule is
// configured, or a local daemon that is not resident (it would be gone before
// the schedule fired).
func (b *builder) backupSchedule() (*backupSchedule, error) {
	cfg := b.cfg
	if cfg.Backup.Schedule == "" || (cfg.Instance.Mode == config.ModeLocal && !cfg.Daemon.Resident) {
		return nil, nil
	}
	parsed, err := backup.ParseSchedule(cfg.Backup.Schedule)
	if err != nil {
		return nil, fmt.Errorf("backup.schedule: %w", err)
	}
	return &backupSchedule{
		fire:   app.NewBackupScheduler(b.backups, parsed, SystemIdentityID).Tick,
		held:   func(ctx context.Context) (bool, error) { return database.GetRestoreHold(ctx, b.db.Reader()) },
		every:  orDefault(b.o.ScheduleCheck, defaultScheduleCheck),
		report: func(err error) { b.o.Log.Error("scheduled backup", slog.Any("error", err)) },
	}, nil
}

func (s *backupSchedule) run(ctx context.Context) {
	ticker := time.NewTicker(s.every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.tick(ctx)
		}
	}
}

func (s *backupSchedule) tick(ctx context.Context) {
	held, err := s.held(ctx)
	if err != nil {
		s.report(fmt.Errorf("read the restore hold; skipping the schedule: %w", err))
		return
	}
	if held {
		return
	}
	if err := s.fire(ctx); err != nil {
		s.report(err)
	}
}

// authSweep deletes the sessions, tokens, codes and replay records that
// expired more than authGrace ago, and the staged secret versions no
// unfinished job needs any more.
type authSweep struct {
	db     *database.DB
	now    func() time.Time
	every  time.Duration
	report func(error)
}

func (b *builder) authSweep() *authSweep {
	return &authSweep{
		db: b.db, now: b.o.Clock.Now, every: orDefault(b.o.SweepEvery, defaultSweepEvery),
		report: func(err error) { b.o.Log.Error("auth sweep", slog.Any("error", err)) },
	}
}

func (s *authSweep) run(ctx context.Context) {
	s.once(ctx)
	ticker := time.NewTicker(s.every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.once(ctx)
		}
	}
}

func (s *authSweep) once(ctx context.Context) {
	s.sweep(ctx, "expired credentials", func(ctx context.Context, tx *database.Tx) error {
		_, err := database.SweepAuth(ctx, tx, s.now().Add(-authGrace))
		return err
	})
	s.sweep(ctx, "orphan staged secrets", func(ctx context.Context, tx *database.Tx) error {
		_, err := database.SweepOrphanStagedSecrets(ctx, tx, s.now().Add(-stagedGrace))
		return err
	})
}

func (s *authSweep) sweep(ctx context.Context, what string, fn func(context.Context, *database.Tx) error) {
	if err := s.db.WithWriteTx(ctx, fn); err != nil && ctx.Err() == nil {
		s.report(fmt.Errorf("sweep %s: %w", what, err))
	}
}

func orDefault(d, fallback time.Duration) time.Duration {
	if d <= 0 {
		return fallback
	}
	return d
}
