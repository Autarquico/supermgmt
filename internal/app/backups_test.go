package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/backup"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/secrets"
	"github.com/autarquico/supermgmt/internal/secrets/secretstest"
)

// allowAll lets any job claim: the production Revalidator and LockPlanner do
// not know instance targets yet (see the T5 report), and these tests are about
// what the backup service does once a worker holds the lease.
type allowAll struct{}

func (allowAll) Revalidate(context.Context, database.Querier, jobs.Job) error { return nil }
func (allowAll) PlanLocks(context.Context, database.Querier, jobs.Job) ([]domain.LockSpec, error) {
	return nil, nil
}

type backupFixture struct {
	*fixture
	svc    *BackupService
	store  *jobs.Store
	system domain.ID
	dir    string
}

func newBackupFixture(t *testing.T) *backupFixture {
	t.Helper()
	ctx := context.Background()
	f := newFixture(t)
	bf := &backupFixture{fixture: f, dir: filepath.Join(t.TempDir(), "backups")}

	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		bf.system = f.identity(ctx, tx, "system", domain.ActorSystem, "")
		inst := database.Instance{ID: f.ids.NewID(), Name: "lab", CreatedAt: f.clock.Now()}
		if err := database.CreateInstance(ctx, tx, inst); err != nil {
			return err
		}
		_, err := database.PutConfigSnapshot(ctx, tx, []byte("instance: lab\n"), nil, f.clock.Now())
		return err
	})
	keys, err := secrets.OpenFileKeys(ctx, filepath.Join(t.TempDir(), "keys"), secretstest.NewMemRepo(), f.ids)
	mustf(t, err, "OpenFileKeys")
	bf.store, err = jobs.NewStore(jobs.Config{DB: f.db, Clock: f.clock, IDs: f.ids, Revalidator: allowAll{}, LockPlanner: allowAll{}})
	mustf(t, err, "NewStore")
	plans, err := NewPlans(f.cfg, bf.store)
	mustf(t, err, "NewPlans")
	queries, err := NewQueries(f.cfg, bf.store, config.ModeLocal)
	mustf(t, err, "NewQueries")
	bf.svc, err = NewBackupService(f.cfg, plans, queries, bf.store, BackupOptions{
		Directory: bf.dir, Retention: 2, KnownHostsPath: filepath.Join(t.TempDir(), "known_hosts"), SMVersion: "9.9.9", Keys: keys,
	})
	mustf(t, err, "NewBackupService")
	return bf
}

func (bf *backupFixture) submitAsAdmin() Submission {
	bf.t.Helper()
	s, err := bf.svc.Create(context.Background(), bf.caller(bf.admin))
	mustf(bf.t, err, "Create")
	return s
}

// runNext claims the next job and runs it through the backup handler.
func (bf *backupFixture) runNext() error {
	bf.t.Helper()
	claimed, ok, err := bf.store.Claim(context.Background(), "worker-1")
	mustf(bf.t, err, "Claim")
	if !ok {
		bf.t.Fatal("no job to claim")
	}
	return bf.svc.Handler().Run(context.Background(), claimed.Lease)
}

func (bf *backupFixture) jobsOfType() []jobs.Job {
	bf.t.Helper()
	all, err := bf.store.List(context.Background(), bf.db.Reader(), jobs.ListFilter{})
	mustf(bf.t, err, "List jobs")
	return all
}

func TestAdminCreatesAQueuedBackupJobOnTheInstance(t *testing.T) {
	bf := newBackupFixture(t)

	s := bf.submitAsAdmin()

	if s.Job.Type != JobBackupCreate || s.Job.State != domain.JobQueued || s.Job.Resource.Type != domain.ResourceInstance || s.Job.ActorID != bf.admin {
		t.Errorf("job = %+v", s.Job)
	}
	if s.Policy.ApprovalRequired {
		t.Error("backup.create needed approval for an admin")
	}
	if got := bf.events("plan.create", "plan.submit"); len(got) != 2 {
		t.Errorf("plan events = %d, want 2", len(got))
	}
}

func TestPolicyDecidesWhoMayCreateABackup(t *testing.T) {
	bf := newBackupFixture(t)

	_, err := bf.svc.Create(context.Background(), bf.caller(bf.alice)) // operator

	wantError(t, err, smerr.CodePolicyDenied, smerr.ReasonDefaultDeny)
	if len(bf.jobsOfType()) != 0 {
		t.Error("a denied request enqueued a job")
	}
	if denied := bf.events("policy.deny"); len(denied) != 1 || denied[0].Data["action"] != "backup.create" {
		t.Errorf("denial events = %+v", denied)
	}
}

func TestARevokedCredentialCannotCreateABackup(t *testing.T) {
	bf := newBackupFixture(t)
	by := bf.caller(bf.admin)
	bf.creds.set(by.Credential.ID, CredentialRevoked)

	_, err := bf.svc.Create(context.Background(), by)

	wantError(t, err, smerr.CodeUnauthenticated, smerr.ReasonCredentialRevoked)
}

func TestTheBackupJobWritesAnArchiveAndAuditsIt(t *testing.T) {
	bf := newBackupFixture(t)
	bf.submitAsAdmin()

	mustf(t, bf.runNext(), "run")

	entries, err := backup.Archives{Dir: bf.dir}.List()
	mustf(t, err, "List archives")
	if len(entries) != 1 || entries[0].Manifest.SMVersion != "9.9.9" || entries[0].Manifest.ConfigGeneration != 1 {
		t.Fatalf("archives = %+v", entries)
	}
	created := bf.events("backup.created")
	if len(created) != 1 || created[0].ActorID != bf.admin || created[0].Data["name"] != entries[0].Name {
		t.Errorf("backup.created events = %+v", created)
	}
}

func TestRetentionPrunesTheOldestAsTheSystemActor(t *testing.T) {
	bf := newBackupFixture(t)
	var names []string
	for range 3 {
		bf.clock.Advance(time.Hour)
		bf.submitAsAdmin()
		mustf(t, bf.runNext(), "run")
	}

	list, err := bf.svc.List(context.Background(), bf.caller(bf.admin))
	mustf(t, err, "List")
	for _, b := range list {
		names = append(names, b.Name)
	}

	if len(list) != 2 || !list[0].CreatedAt.After(list[1].CreatedAt) {
		t.Fatalf("List = %v, want the 2 newest, newest first", names)
	}
	pruned := bf.events("backup.pruned")
	if len(pruned) != 1 || pruned[0].ActorType != domain.ActorSystem {
		t.Errorf("backup.pruned events = %+v", pruned)
	}
}

func TestAFailingBackupFailsTheJobAndLeavesNoArchive(t *testing.T) {
	bf := newBackupFixture(t)
	bf.submitAsAdmin()
	bf.inTx(func(ctx context.Context, tx *database.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM settings WHERE key = ?`, database.SettingConfigSnapshot)
		return err
	})

	err := bf.runNext()

	wantError(t, err, smerr.CodeConflict, "")
	if entries, _ := os.ReadDir(bf.dir); len(entries) != 0 {
		t.Errorf("backup directory = %v", entries)
	}
	if len(bf.events("backup.created")) != 0 {
		t.Error("a failed backup was audited as created")
	}
}

func TestListRequiresBackupRead(t *testing.T) {
	bf := newBackupFixture(t)

	_, err := bf.svc.List(context.Background(), bf.caller(bf.dave)) // no roles

	wantError(t, err, smerr.CodePolicyDenied, smerr.ReasonDefaultDeny)
	if list, err := bf.svc.List(context.Background(), bf.caller(bf.alice)); err != nil || list == nil || len(list) != 0 {
		t.Errorf("operator List = %v, %v; want an empty, non-nil list", list, err)
	}
}

func TestScheduledBackupIsSubmittedByTheSystemActorWithoutApproval(t *testing.T) {
	bf := newBackupFixture(t)

	s, err := bf.svc.SubmitScheduled(context.Background(), bf.system)

	mustf(t, err, "SubmitScheduled")
	if s.Job.ActorID != bf.system || s.Job.State != domain.JobQueued || s.Policy.ApprovalRequired {
		t.Errorf("job = %+v, policy = %+v", s.Job, s.Policy)
	}
	mustf(t, bf.runNext(), "run")
	if created := bf.events("backup.created"); len(created) != 1 || created[0].ActorType != domain.ActorSystem {
		t.Errorf("backup.created events = %+v", created)
	}
}

func TestOnlyTheSystemIdentitySubmitsScheduledBackups(t *testing.T) {
	bf := newBackupFixture(t)

	_, err := bf.svc.SubmitScheduled(context.Background(), bf.admin)

	wantError(t, err, smerr.CodePolicyDenied, smerr.ReasonDefaultDeny)
	if len(bf.jobsOfType()) != 0 {
		t.Error("a human identity submitted a scheduled backup")
	}
}

func TestSchedulerFiresOncePerScheduledMinute(t *testing.T) {
	bf := newBackupFixture(t)
	schedule, err := backup.ParseSchedule("0 3 * * *")
	mustf(t, err, "ParseSchedule")
	sched := NewBackupScheduler(bf.svc, schedule, bf.system) // created at 12:00
	tick := func(to time.Time) {
		bf.t.Helper()
		bf.clock.Set(to)
		mustf(bf.t, sched.Tick(context.Background()), "Tick")
	}

	tick(epoch.Add(time.Hour)) // 13:00, nothing due
	if n := len(bf.jobsOfType()); n != 0 {
		t.Fatalf("jobs before 03:00 = %d", n)
	}
	tick(time.Date(2026, 10, 11, 3, 0, 30, 0, time.UTC))
	tick(time.Date(2026, 10, 11, 3, 1, 0, 0, time.UTC)) // same occurrence
	if n := len(bf.jobsOfType()); n != 1 {
		t.Fatalf("jobs after the first 03:00 = %d, want 1", n)
	}
	tick(time.Date(2026, 10, 12, 3, 0, 0, 0, time.UTC))
	if n := len(bf.jobsOfType()); n != 2 {
		t.Errorf("jobs after the second 03:00 = %d, want 2", n)
	}
}

func TestSchedulerSkipsRunsMissedWhileDown(t *testing.T) {
	bf := newBackupFixture(t)
	schedule, _ := backup.ParseSchedule("0 3 * * *")
	sched := NewBackupScheduler(bf.svc, schedule, bf.system)
	bf.clock.Set(epoch.Add(5 * 24 * time.Hour)) // five 03:00s passed before the first tick

	mustf(t, sched.Tick(context.Background()), "Tick")

	if n := len(bf.jobsOfType()); n != 1 {
		t.Errorf("jobs = %d, want one catch-up job, not five", n)
	}
}

func TestBackupServiceRejectsUnsafeOptions(t *testing.T) {
	bf := newBackupFixture(t)
	plans, _ := NewPlans(bf.cfg, bf.store)
	queries, _ := NewQueries(bf.cfg, bf.store, config.ModeLocal)
	ok := bf.svc.opts

	for name, edit := range map[string]func(*BackupOptions){
		"zero retention": func(o *BackupOptions) { o.Retention = 0 },
		"no directory":   func(o *BackupOptions) { o.Directory = "" },
		"no reserver":    func(o *BackupOptions) { o.Keys = nil },
	} {
		o := ok
		edit(&o)
		if _, err := NewBackupService(bf.cfg, plans, queries, bf.store, o); err == nil {
			t.Errorf("%s: NewBackupService succeeded", name)
		}
	}
}
