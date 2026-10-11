package app

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/backup"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
)

const (
	// JobBackupCreate is the type of the job that writes one archive.
	JobBackupCreate = "backup.create"

	actionBackupRead = "backup.read"

	eventBackupCreated = "backup.created"
	eventBackupPruned  = "backup.pruned"

	scheduledSource       = "scheduler"
	scheduleCheckInterval = 30 * time.Second
)

// systemCredential is the credential context of jobs the scheduler submits:
// the daemon acting for itself holds no token that could be revoked.
var systemCredential = domain.CredentialContext{Kind: domain.CredentialLocalSocket, ID: "system"}

// BackupOptions locate and describe the archives (spec §29.1).
type BackupOptions struct {
	Directory      string // backup.directory
	Retention      int    // backup.retention, at least 1
	KnownHostsPath string
	SMVersion      string
	Keys           backup.KeyReserver
}

// BackupService implements Backups: backup.create submits a job, backup.read
// lists the archives. The job itself is Handler.
type BackupService struct {
	core
	plans   *Plans
	queries *Queries
	store   *jobs.Store
	opts    BackupOptions
}

var _ Backups = (*BackupService)(nil)

// NewBackupService validates cfg and opts.
func NewBackupService(cfg Config, plans *Plans, queries *Queries, store *jobs.Store, opts BackupOptions) (*BackupService, error) {
	c, err := newCore(cfg)
	if err != nil {
		return nil, err
	}
	switch {
	case plans == nil || queries == nil || store == nil:
		return nil, errors.New("app: backups need plans, queries and the job store")
	case opts.Directory == "" || opts.Keys == nil:
		return nil, errors.New("app: backups need a directory and a key reserver")
	case opts.Retention < 1:
		return nil, fmt.Errorf("app: backup retention %d would delete every backup", opts.Retention)
	}
	return &BackupService{core: c, plans: plans, queries: queries, store: store, opts: opts}, nil
}

// Create submits a backup.create job for the caller (policy action
// backup.create). The archive is written when a worker claims the job.
func (b *BackupService) Create(ctx context.Context, by Caller) (Submission, error) {
	return commit(ctx, b.core, by, func(ctx context.Context, tx *database.Tx) (Submission, error) {
		actor, err := b.beginRequest(ctx, tx, by)
		if err != nil {
			return Submission{}, err
		}
		return b.submit(ctx, tx, by, actor)
	})
}

// SubmitScheduled submits a backup.create job as the system actor, which
// policy never evaluates and which never needs approval (spec §11.1). systemID
// is the daemon's identity row of actor type system.
func (b *BackupService) SubmitScheduled(ctx context.Context, systemID domain.ID) (Submission, error) {
	by := Caller{ID: systemID, Credential: systemCredential, Source: scheduledSource}
	return commit(ctx, b.core, by, func(ctx context.Context, tx *database.Tx) (Submission, error) {
		actor, err := loadActor(ctx, tx, systemID, systemCredential)
		if err != nil {
			return Submission{}, err
		}
		if actor.Type != domain.ActorSystem {
			return Submission{}, smerr.New(smerr.CodePolicyDenied, smerr.ReasonDefaultDeny, "only the system identity submits scheduled backups")
		}
		return b.submit(ctx, tx, by, actor)
	})
}

func (b *BackupService) submit(ctx context.Context, tx *database.Tx, by Caller, actor domain.Actor) (Submission, error) {
	instance, err := database.GetInstance(ctx, tx)
	if err != nil {
		return Submission{}, err
	}
	built, err := build(ctx, tx, JobBackupCreate, by.ID, domain.ResourceRef{Type: domain.ResourceInstance, ID: instance.ID}, map[string]any{})
	if err != nil {
		return Submission{}, err
	}
	res, err := b.evaluate(ctx, tx, actor, built)
	if err != nil {
		return Submission{}, err
	}
	return b.plans.planAndSubmit(ctx, tx, by, actor, built, res)
}

// List returns the committed archives, newest first (policy action backup.read).
func (b *BackupService) List(ctx context.Context, by Caller) ([]wire.Backup, error) {
	if _, err := b.queries.RequireRead(ctx, by, actionBackupRead, domain.ResourceRef{Type: domain.ResourceInstance}); err != nil {
		return nil, err
	}
	entries, err := backup.Archives{Dir: b.opts.Directory}.List()
	if err != nil {
		return nil, smerr.Wrap(err, smerr.CodeInternal, "", "a backup archive could not be read")
	}
	slices.Reverse(entries)
	out := make([]wire.Backup, len(entries))
	for i, e := range entries {
		out[i] = wire.Backup{
			Name: e.Name, SizeBytes: e.Size, CreatedAt: e.Manifest.CreatedAt,
			SchemaVersion: e.Manifest.SchemaVersion, SMVersion: e.Manifest.SMVersion, KEKIDs: nonNilIDs(e.Manifest.KEKIDs),
		}
	}
	return out, nil
}

func nonNilIDs(ids []domain.ID) []domain.ID {
	if ids == nil {
		return []domain.ID{}
	}
	return ids
}

// Handler is the executor of backup.create jobs. Register it under
// JobBackupCreate.
func (b *BackupService) Handler() jobs.Handler { return backupHandler{b} }

type backupHandler struct{ b *BackupService }

// Run writes one archive, audits it as the job's actor, then applies
// retention as the system actor. A retention failure is audited but does not
// fail a backup that is already committed.
func (h backupHandler) Run(ctx context.Context, lease jobs.Lease) error {
	b := h.b
	job, err := b.store.Get(ctx, b.cfg.DB.Reader(), lease.JobID)
	if err != nil {
		return err
	}
	instance, err := database.GetInstance(ctx, b.cfg.DB.Reader())
	if err != nil {
		return err
	}
	created, err := backup.Create(ctx, backup.CreateOptions{
		Dir: b.opts.Directory, Instance: instance.Name, KnownHostsPath: b.opts.KnownHostsPath, SMVersion: b.opts.SMVersion,
		Clock: b.cfg.Clock, Source: b.cfg.DB, Keys: b.opts.Keys,
	})
	if err != nil {
		return fmt.Errorf("create backup: %w", err)
	}
	submitter, err := loadActor(ctx, b.cfg.DB.Reader(), job.ActorID, credentialOf(job))
	if err != nil {
		return err
	}
	if err := b.audit(ctx, lease, submitter, instance.ID, eventBackupCreated, domain.ResultSucceeded, map[string]any{
		"name": created.Name, "size_bytes": created.Size, "schema_version": created.Manifest.SchemaVersion,
		"config_generation": created.Manifest.ConfigGeneration, "kek_ids": created.Manifest.KEKIDs,
	}); err != nil {
		return err
	}
	return b.prune(ctx, lease, instance.ID)
}

func (b *BackupService) prune(ctx context.Context, lease jobs.Lease, instance domain.ID) error {
	removed, err := backup.Prune(b.opts.Directory, b.opts.Retention)
	switch {
	case err != nil:
		return b.audit(ctx, lease, systemActor, instance, eventBackupPruned, domain.ResultFailed,
			map[string]any{"removed": removed, "code": string(smerr.CodeOf(err))})
	case len(removed) > 0:
		return b.audit(ctx, lease, systemActor, instance, eventBackupPruned, domain.ResultSucceeded,
			map[string]any{"removed": removed, "retention": b.opts.Retention})
	}
	return nil
}

// audit records an event in a write transaction fenced by the job's lease.
func (b *BackupService) audit(ctx context.Context, lease jobs.Lease, actor domain.Actor, instance domain.ID, event string, result domain.Result, data map[string]any) error {
	return b.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		if err := lease.Fence(ctx, tx); err != nil {
			return err
		}
		return b.emit(ctx, tx, actor, event, domain.ResourceRef{Type: domain.ResourceInstance, ID: instance}, result, data)
	})
}

// BackupScheduler submits scheduled backups (spec §29.1, backup.schedule). It
// remembers only when it last fired, in memory: a run the daemon was down for
// is skipped, not replayed.
type BackupScheduler struct {
	service  *BackupService
	schedule backup.Schedule
	systemID domain.ID
	last     time.Time
}

// NewBackupScheduler starts counting from now. Build it only when the
// schedule is set and the mode allows it (server mode, or local mode with
// daemon.resident) and no restore hold is in force.
func NewBackupScheduler(service *BackupService, schedule backup.Schedule, systemID domain.ID) *BackupScheduler {
	return &BackupScheduler{service: service, schedule: schedule, systemID: systemID, last: service.cfg.Clock.Now()}
}

// Tick submits a backup if the schedule fired since the last tick.
func (s *BackupScheduler) Tick(ctx context.Context) error {
	now := s.service.cfg.Clock.Now()
	next := s.schedule.Next(s.last)
	if next.IsZero() || next.After(now) {
		return nil
	}
	s.last = now
	if _, err := s.service.SubmitScheduled(ctx, s.systemID); err != nil {
		return fmt.Errorf("submit scheduled backup: %w", err)
	}
	return nil
}

// Run ticks until ctx ends, handing each failure to report.
func (s *BackupScheduler) Run(ctx context.Context, report func(error)) {
	ticker := time.NewTicker(scheduleCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.Tick(ctx); err != nil {
				report(err)
			}
		}
	}
}
