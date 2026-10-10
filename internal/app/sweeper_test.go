package app

import (
	"context"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func (f *fixture) sweeper(t *testing.T) *Sweeper {
	t.Helper()
	s, err := NewSweeper(f.cfg, SweeperOptions{Store: f.store})
	mustf(t, err, "NewSweeper")
	return s
}

func TestSweepFailsJobsWhosePlanExpiredWhileWaitingForApproval(t *testing.T) {
	f := newFixture(t)
	sub, _ := f.submitReboot()
	f.clock.Advance(defaultPlanTTL + time.Minute)

	mustf(t, f.sweeper(t).Sweep(context.Background()), "Sweep")

	job := f.job(sub.Job.ID)
	if job.State != domain.JobFailed || job.Error == nil || job.Error.Reason != smerr.ReasonPlanExpired {
		t.Errorf("job = %s %+v, want failed with PLAN_EXPIRED", job.State, job.Error)
	}
}

func TestSweepDropsExpiredIdempotencyRecordsOnly(t *testing.T) {
	f := newFixture(t)
	old, _ := f.keyed(f.alice, "old", "h1")
	_, err := f.plans.Create(context.Background(), old, f.reboot())
	mustf(t, err, "Create")
	f.clock.Advance(idempotencyTTL - time.Hour)
	young, _ := f.keyed(f.alice, "young", "h2")
	_, err = f.plans.Create(context.Background(), young, f.reboot())
	mustf(t, err, "Create")
	f.clock.Advance(2 * time.Hour) // "old" is now past its TTL, "young" is not

	mustf(t, f.sweeper(t).Sweep(context.Background()), "Sweep")

	reader := f.db.Reader()
	if _, err := database.GetIdempotencyRecord(context.Background(), reader, f.alice, "old"); smerr.CodeOf(err) != smerr.CodeNotFound {
		t.Errorf("expired record: %v", err)
	}
	if _, err := database.GetIdempotencyRecord(context.Background(), reader, f.alice, "young"); err != nil {
		t.Errorf("live record: %v", err)
	}
}

func (f *fixture) observe(kind string, at time.Time) {
	f.t.Helper()
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		return database.RecordObservation(ctx, tx, database.Observation{
			ID: f.ids.NewID(), ResourceType: domain.ResourceNode, ResourceID: f.node.ID, Kind: kind, Value: map[string]any{"at": at.String()}, ObservedAt: at,
		})
	})
}

func (f *fixture) observationCount(kind string) int {
	f.t.Helper()
	var n int
	err := f.db.Reader().QueryRowContext(context.Background(), `SELECT COUNT(*) FROM observations WHERE kind = ?`, kind).Scan(&n)
	mustf(f.t, err, "count observations")
	return n
}

func TestSweepPrunesOldObservationsButAlwaysKeepsTheLatestOfEachKind(t *testing.T) {
	f := newFixture(t)
	now := f.clock.Now()
	f.observe("metrics", now.Add(-72*time.Hour))
	f.observe("metrics", now.Add(-48*time.Hour))
	f.observe("metrics", now.Add(-time.Hour))
	f.observe("system", now.Add(-96*time.Hour)) // old, but the only one of its kind

	mustf(t, f.sweeper(t).Sweep(context.Background()), "Sweep")

	if f.observationCount("metrics") != 1 || f.observationCount("system") != 1 {
		t.Errorf("metrics %d, system %d; want only the newest of each kept", f.observationCount("metrics"), f.observationCount("system"))
	}
	latest, err := database.LatestObservation(context.Background(), f.db.Reader(), domain.ResourceRef{Type: domain.ResourceNode, ID: f.node.ID}, "metrics")
	if err != nil || !latest.ObservedAt.Equal(now.Add(-time.Hour)) {
		t.Errorf("latest = %+v, %v", latest, err)
	}
}

func TestSweepKeepsRecentObservations(t *testing.T) {
	f := newFixture(t)
	now := f.clock.Now()
	f.observe("metrics", now.Add(-3*time.Hour))
	f.observe("metrics", now.Add(-2*time.Hour))
	f.observe("metrics", now.Add(-time.Hour))

	mustf(t, f.sweeper(t).Sweep(context.Background()), "Sweep")

	if f.observationCount("metrics") != 3 {
		t.Errorf("%d observations left; those inside the retention window stay", f.observationCount("metrics"))
	}
}

func TestRunSweepsRightAwayAndStopsWithItsContext(t *testing.T) {
	f := newFixture(t)
	sub, _ := f.submitReboot()
	f.clock.Advance(defaultPlanTTL + time.Minute)
	s, err := NewSweeper(f.cfg, SweeperOptions{Store: f.store, Interval: time.Hour})
	mustf(t, err, "NewSweeper")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	eventually(t, "the first sweep", func() bool { return f.job(sub.Job.ID).State == domain.JobFailed })
	cancel()

	if err := <-done; err != nil {
		t.Errorf("Run: %v", err)
	}
}

func TestBusyIsTrueWhileAnyJobIsNotTerminal(t *testing.T) {
	f := newFixture(t)
	activity, err := NewActivity(f.cfg, f.store)
	mustf(t, err, "NewActivity")
	busy := func() bool {
		t.Helper()
		b, err := activity.Busy(context.Background())
		mustf(t, err, "Busy")
		return b
	}
	if busy() {
		t.Fatal("an empty daemon is not busy")
	}

	sub, _ := f.submitReboot()
	if !busy() {
		t.Error("a job awaiting approval keeps the daemon alive")
	}
	f.approveToQuorum(sub.Job)
	if !busy() {
		t.Error("a queued job keeps the daemon alive")
	}
	claimed, _ := f.claim()
	if !busy() {
		t.Error("a running job keeps the daemon alive")
	}
	mustf(t, f.store.Succeed(context.Background(), claimed.Lease), "Succeed")
	if busy() {
		t.Error("only finished jobs: the daemon may idle out")
	}
}

func TestAnInterruptedJobKeepsTheDaemonAlive(t *testing.T) {
	f := newFixture(t)
	activity, _ := NewActivity(f.cfg, f.store)
	f.interrupted()

	busy, err := activity.Busy(context.Background())

	if err != nil || !busy {
		t.Errorf("Busy = %v, %v; an interrupted job awaits the reconciler or a human", busy, err)
	}
}
