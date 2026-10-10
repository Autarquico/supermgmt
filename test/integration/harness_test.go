// Package integration wires the real M0 packages together (SQLite, policy,
// app services, job store and engine) and exercises them from the outside.
package integration

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
)

var epoch = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

const leaseTTL = 30 * time.Second

// activeCredentials reports every credential active.
type activeCredentials struct{}

func (activeCredentials) Status(context.Context, domain.CredentialContext) (app.CredentialState, error) {
	return app.CredentialActive, nil
}

// world is a migrated database with the default policy, the real app services
// and job store, a production node (two approvals to reboot) and a development
// node (no approval), plus three operators: alice, bob and carol.
type world struct {
	t     *testing.T
	db    *database.DB
	clock *domaintest.FakeClock
	ids   *domaintest.SequentialIDs
	store *jobs.Store
	plans *app.Plans
	appr  *app.Approvals

	prodEnv, devEnv   domain.Environment
	prodNode, devNode domain.Node
	alice, bob, carol domain.ID
}

func newWorld(t *testing.T) *world {
	t.Helper()
	ctx := context.Background()
	clock := domaintest.NewFakeClock(epoch)
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "sm.db"), database.Options{Clock: clock})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	pol, err := policy.Default()
	if err != nil {
		t.Fatalf("default policy: %v", err)
	}
	w := &world{t: t, db: db, clock: clock, ids: domaintest.NewSequentialIDs()}
	w.seed()

	cfg := app.Config{DB: db, Clock: clock, IDs: w.ids, Policy: pol, Credentials: activeCredentials{}}
	reval, err := app.NewRevalidator(cfg)
	if err != nil {
		t.Fatalf("NewRevalidator: %v", err)
	}
	w.store, err = jobs.NewStore(jobs.Config{
		DB: db, Clock: clock, IDs: w.ids, Revalidator: reval, LockPlanner: app.LockPlanner{}, LeaseTTL: leaseTTL,
	})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if w.plans, err = app.NewPlans(cfg, w.store); err != nil {
		t.Fatalf("NewPlans: %v", err)
	}
	if w.appr, err = app.NewApprovals(cfg, w.store); err != nil {
		t.Fatalf("NewApprovals: %v", err)
	}
	return w
}

func (w *world) seed() {
	w.t.Helper()
	w.inTx(func(ctx context.Context, tx *database.Tx) error {
		now := w.clock.Now()
		provider, err := database.CreateProvider(ctx, tx, domain.Provider{
			ID: w.ids.NewID(), Type: "ssh", Name: "ssh-hosts", Origin: domain.ProviderStatic, CreatedAt: now, UpdatedAt: now,
		})
		if err != nil {
			return err
		}
		w.prodEnv, err = database.CreateEnvironment(ctx, tx, domain.Environment{
			ID: w.ids.NewID(), Name: "prod", RiskLevel: domain.EnvironmentProduction, ApprovalsRequired: 2,
		})
		if err != nil {
			return err
		}
		w.devEnv, err = database.CreateEnvironment(ctx, tx, domain.Environment{
			ID: w.ids.NewID(), Name: "dev", RiskLevel: domain.EnvironmentDevelopment,
		})
		if err != nil {
			return err
		}
		if w.prodNode, err = w.node(ctx, tx, provider.ID, w.prodEnv.ID, "web-1"); err != nil {
			return err
		}
		if w.devNode, err = w.node(ctx, tx, provider.ID, w.devEnv.ID, "dev-1"); err != nil {
			return err
		}
		operator, err := database.GetRoleByName(ctx, tx, "operator")
		if err != nil {
			return err
		}
		for _, who := range []struct {
			id      *domain.ID
			subject string
		}{{&w.alice, "alice"}, {&w.bob, "bob"}, {&w.carol, "carol"}} {
			*who.id = w.ids.NewID()
			err := database.CreateIdentity(ctx, tx, database.Identity{
				ID: *who.id, ActorType: domain.ActorHuman, Subject: who.subject, CreatedAt: now,
			})
			if err != nil {
				return err
			}
			err = database.CreateRoleBinding(ctx, tx, database.RoleBinding{
				ID: w.ids.NewID(), IdentityID: *who.id, RoleID: operator.ID, CreatedAt: now,
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func (w *world) node(ctx context.Context, tx *database.Tx, provider, env domain.ID, name string) (domain.Node, error) {
	now := w.clock.Now()
	node, err := database.CreateNode(ctx, tx, domain.Node{
		ID: w.ids.NewID(), ProviderID: provider, NativeID: name, Name: name, Kind: "ssh",
		EnvironmentID: &env, ManagementState: domain.ManagementManaged, Reachability: domain.ReachabilityUnknown,
		Tags: []string{"web"}, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		return domain.Node{}, err
	}
	for _, capability := range []string{"node.reboot", "node.read"} {
		err = database.SetNodeCapability(ctx, tx, node.ID, database.NodeCapability{Capability: capability, Available: true, CheckedAt: now})
		if err != nil {
			return domain.Node{}, err
		}
	}
	return node, nil
}

func (w *world) inTx(fn func(ctx context.Context, tx *database.Tx) error) {
	w.t.Helper()
	if err := w.db.WithWriteTx(context.Background(), fn); err != nil {
		w.t.Fatalf("write tx: %v", err)
	}
}

func (w *world) caller(id domain.ID) app.Caller {
	return app.Caller{ID: id, Credential: domain.CredentialContext{
		Kind: domain.CredentialAPIToken, ID: "token-" + id.String(), Scopes: []string{},
	}}
}

// submit plans and submits action on node as alice.
func (w *world) submit(action string, node domain.Node) jobs.Job {
	w.t.Helper()
	ctx := context.Background()
	target := domain.ResourceRef{Type: domain.ResourceNode, ID: node.ID}
	created, err := w.plans.Create(ctx, w.caller(w.alice), app.PlanRequest{Action: action, Target: target})
	if err != nil {
		w.t.Fatalf("Create: %v", err)
	}
	sub, err := w.plans.Submit(ctx, w.caller(w.alice), created.Record.ID, created.Record.PlanHash)
	if err != nil {
		w.t.Fatalf("Submit: %v", err)
	}
	return sub.Job
}

// submitReboot submits a node.reboot, which every environment gates behind approval.
func (w *world) submitReboot(node domain.Node) jobs.Job { return w.submit("node.reboot", node) }

// approveToQuorum has bob and then carol approve the job until it is queued.
func (w *world) approveToQuorum(job jobs.Job) jobs.Job {
	w.t.Helper()
	for _, approver := range []domain.ID{w.bob, w.carol} {
		if job.State == domain.JobQueued {
			break
		}
		var err error
		job, err = w.appr.Approve(context.Background(), w.caller(approver),
			app.DecisionRequest{JobID: job.ID, PlanHash: job.PlanHash, Reason: "ok"})
		if err != nil {
			w.t.Fatalf("approve: %v", err)
		}
	}
	return job
}

func (w *world) job(id domain.ID) jobs.Job {
	w.t.Helper()
	job, err := w.store.Get(context.Background(), w.db.Reader(), id)
	if err != nil {
		w.t.Fatalf("Get job: %v", err)
	}
	return job
}

// events returns every audit event recorded so far, oldest first.
func (w *world) events() []domain.Event {
	w.t.Helper()
	events, err := database.ListEvents(context.Background(), w.db.Reader(), 0, 10_000)
	if err != nil {
		w.t.Fatalf("ListEvents: %v", err)
	}
	return events
}

// jobActions lists the audit actions recorded for a job, oldest first.
func (w *world) jobActions(id domain.ID) []string {
	w.t.Helper()
	var out []string
	for _, e := range w.events() {
		if e.ResourceType == domain.ResourceJob && e.ResourceID == id {
			out = append(out, e.Action)
		}
	}
	return out
}

func (w *world) lockCount(ctx context.Context) int {
	w.t.Helper()
	var n int
	if err := w.db.Reader().QueryRowContext(ctx, `SELECT COUNT(*) FROM resource_locks`).Scan(&n); err != nil {
		w.t.Fatalf("count locks: %v", err)
	}
	return n
}

// bumpSpecRevision edits the node's configured tags, which bumps spec_revision.
func (w *world) bumpSpecRevision(node domain.ID) {
	w.t.Helper()
	w.inTx(func(ctx context.Context, tx *database.Tx) error {
		n, err := database.GetNode(ctx, tx, node)
		if err != nil {
			return err
		}
		n.Tags = append(n.Tags, "edited")
		n.UpdatedAt = w.clock.Now()
		_, err = database.UpdateNodeSpec(ctx, tx, n, n.SpecRevision)
		return err
	})
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for range 2000 {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
