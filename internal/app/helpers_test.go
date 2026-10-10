package app

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
)

var epoch = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

// fakeCredentials reports every credential active unless told otherwise.
type fakeCredentials struct {
	mu     sync.Mutex
	states map[string]CredentialState
}

func (f *fakeCredentials) Status(_ context.Context, cred domain.CredentialContext) (CredentialState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if state, ok := f.states[cred.ID]; ok {
		return state, nil
	}
	return CredentialActive, nil
}

func (f *fakeCredentials) set(id string, state CredentialState) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.states[id] = state
}

// fixture is a migrated database with a production node that needs two
// approvals to reboot, three operators and one identity without roles.
type fixture struct {
	t        *testing.T
	db       *database.DB
	clock    *domaintest.FakeClock
	ids      *domaintest.SequentialIDs
	creds    *fakeCredentials
	cfg      Config
	store    *jobs.Store
	plans    *Plans
	appr     *Approvals
	env      domain.Environment
	provider domain.Provider
	node     domain.Node
	alice    domain.ID // operator, requester
	bob      domain.ID // operator
	carol    domain.ID // operator
	dave     domain.ID // no roles
	service  domain.Service
}

func newFixture(t *testing.T, tweak ...func(*Config)) *fixture {
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
		t.Fatalf("Default policy: %v", err)
	}
	f := &fixture{
		t: t, db: db, clock: clock, ids: domaintest.NewSequentialIDs(),
		creds: &fakeCredentials{states: map[string]CredentialState{}},
	}
	f.cfg = Config{DB: db, Clock: clock, IDs: f.ids, Policy: pol, Credentials: f.creds}
	for _, fn := range tweak {
		fn(&f.cfg)
	}
	f.seed()

	reval, err := NewRevalidator(f.cfg)
	if err != nil {
		t.Fatalf("NewRevalidator: %v", err)
	}
	f.store, err = jobs.NewStore(jobs.Config{
		DB: db, Clock: clock, IDs: f.ids, Revalidator: reval, LockPlanner: LockPlanner{},
	})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if f.plans, err = NewPlans(f.cfg, f.store); err != nil {
		t.Fatalf("NewPlans: %v", err)
	}
	if f.appr, err = NewApprovals(f.cfg, f.store); err != nil {
		t.Fatalf("NewApprovals: %v", err)
	}
	return f
}

func (f *fixture) seed() {
	f.t.Helper()
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		now := f.clock.Now()
		var err error
		f.provider, err = database.CreateProvider(ctx, tx, domain.Provider{
			ID: f.ids.NewID(), Type: "ssh", Name: "ssh-hosts", Origin: domain.ProviderStatic, CreatedAt: now, UpdatedAt: now,
		})
		if err != nil {
			return err
		}
		f.env, err = database.CreateEnvironment(ctx, tx, domain.Environment{
			ID: f.ids.NewID(), Name: "prod", RiskLevel: domain.EnvironmentProduction, ApprovalsRequired: 2,
		})
		if err != nil {
			return err
		}
		f.node, err = database.CreateNode(ctx, tx, domain.Node{
			ID: f.ids.NewID(), ProviderID: f.provider.ID, NativeID: "web-1", Name: "web-1", Kind: "ssh",
			EnvironmentID: &f.env.ID, ManagementState: domain.ManagementManaged, Reachability: domain.ReachabilityUnknown,
			Tags: []string{"web"}, CreatedAt: now, UpdatedAt: now,
		})
		if err != nil {
			return err
		}
		for _, capability := range []string{"node.reboot", "service.restart", "service.read", "node.read"} {
			err = database.SetNodeCapability(ctx, tx, f.node.ID, database.NodeCapability{
				Capability: capability, Available: true, CheckedAt: now,
			})
			if err != nil {
				return err
			}
		}
		runtime := domain.Runtime{ID: f.ids.NewID(), NodeID: f.node.ID, Type: "systemd", NativeID: "systemd"}
		if err := database.CreateRuntime(ctx, tx, runtime); err != nil {
			return err
		}
		f.service, err = database.CreateService(ctx, tx, domain.Service{
			ID: f.ids.NewID(), RuntimeID: runtime.ID, NodeID: f.node.ID, NativeID: "nginx.service", Name: "nginx", Kind: "unit",
		})
		if err != nil {
			return err
		}
		operator := f.role(ctx, tx, "operator")
		f.alice = f.identity(ctx, tx, "alice", domain.ActorHuman, operator)
		f.bob = f.identity(ctx, tx, "bob", domain.ActorHuman, operator)
		f.carol = f.identity(ctx, tx, "carol", domain.ActorHuman, operator)
		f.dave = f.identity(ctx, tx, "dave", domain.ActorHuman, "")
		return nil
	})
}

// role returns a built-in role seeded by the initial migration.
func (f *fixture) role(ctx context.Context, tx *database.Tx, name string) domain.ID {
	role, err := database.GetRoleByName(ctx, tx, name)
	if err != nil {
		f.t.Fatalf("GetRoleByName(%s): %v", name, err)
	}
	return role.ID
}

func (f *fixture) identity(ctx context.Context, tx *database.Tx, subject string, typ domain.ActorType, role domain.ID) domain.ID {
	id := f.ids.NewID()
	err := database.CreateIdentity(ctx, tx, database.Identity{
		ID: id, ActorType: typ, Subject: subject, CreatedAt: f.clock.Now(),
	})
	if err != nil {
		f.t.Fatalf("CreateIdentity: %v", err)
	}
	if role != "" {
		err = database.CreateRoleBinding(ctx, tx, database.RoleBinding{
			ID: f.ids.NewID(), IdentityID: id, RoleID: role, CreatedAt: f.clock.Now(),
		})
		if err != nil {
			f.t.Fatalf("CreateRoleBinding: %v", err)
		}
	}
	return id
}

func (f *fixture) inTx(fn func(ctx context.Context, tx *database.Tx) error) {
	f.t.Helper()
	if err := f.db.WithWriteTx(context.Background(), fn); err != nil {
		f.t.Fatalf("write tx: %v", err)
	}
}

// caller is an identity presenting its own API token.
func (f *fixture) caller(id domain.ID) Caller {
	return Caller{ID: id, Credential: domain.CredentialContext{
		Kind: domain.CredentialAPIToken, ID: "token-" + id.String(), Scopes: []string{},
	}}
}

func (f *fixture) reboot() PlanRequest {
	return PlanRequest{Action: "node.reboot", Target: domain.ResourceRef{Type: domain.ResourceNode, ID: f.node.ID}}
}

// submitReboot plans and submits a production node reboot as alice.
func (f *fixture) submitReboot() (Submission, CreatedPlan) {
	f.t.Helper()
	created, err := f.plans.Create(context.Background(), f.caller(f.alice), f.reboot())
	if err != nil {
		f.t.Fatalf("Create: %v", err)
	}
	sub, err := f.plans.Submit(context.Background(), f.caller(f.alice), created.Record.ID, created.Record.PlanHash)
	if err != nil {
		f.t.Fatalf("Submit: %v", err)
	}
	return sub, created
}

func (f *fixture) approve(approver domain.ID, job jobs.Job) (jobs.Job, error) {
	return f.appr.Approve(context.Background(), f.caller(approver),
		DecisionRequest{JobID: job.ID, PlanHash: job.PlanHash, Reason: "ok"})
}

// approveToQuorum has bob and carol approve the job.
func (f *fixture) approveToQuorum(job jobs.Job) jobs.Job {
	f.t.Helper()
	for _, approver := range []domain.ID{f.bob, f.carol} {
		var err error
		if job, err = f.approve(approver, job); err != nil {
			f.t.Fatalf("approve: %v", err)
		}
	}
	return job
}

func (f *fixture) job(id domain.ID) jobs.Job {
	f.t.Helper()
	job, err := f.store.Get(context.Background(), f.db.Reader(), id)
	if err != nil {
		f.t.Fatalf("Get job: %v", err)
	}
	return job
}

// events returns every audit event whose action is one of actions (all when none given).
func (f *fixture) events(actions ...string) []domain.Event {
	f.t.Helper()
	all, err := database.ListEvents(context.Background(), f.db.Reader(), 0, 10000)
	if err != nil {
		f.t.Fatalf("ListEvents: %v", err)
	}
	if len(actions) == 0 {
		return all
	}
	var out []domain.Event
	for _, e := range all {
		for _, a := range actions {
			if e.Action == a {
				out = append(out, e)
			}
		}
	}
	return out
}

func (f *fixture) claim() (jobs.Claimed, bool) {
	f.t.Helper()
	claimed, ok, err := f.store.Claim(context.Background(), "worker-1")
	if err != nil {
		f.t.Fatalf("Claim: %v", err)
	}
	return claimed, ok
}

// bumpNodeRevision edits the node's configured tags, which bumps spec_revision.
func (f *fixture) bumpNodeRevision() {
	f.t.Helper()
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		node, err := database.GetNode(ctx, tx, f.node.ID)
		if err != nil {
			return err
		}
		node.Tags = append(node.Tags, "edited")
		node.UpdatedAt = f.clock.Now()
		_, err = database.UpdateNodeSpec(ctx, tx, node, node.SpecRevision)
		return err
	})
}

// wantError fails unless err is a typed error with the given code and reason.
func wantError(t *testing.T, err error, code smerr.Code, reason smerr.Reason) {
	t.Helper()
	var typed *smerr.Error
	if err == nil {
		t.Fatalf("got nil error, want %s/%s", code, reason)
	}
	if !errors.As(err, &typed) || typed.Code != code || typed.Reason != reason {
		t.Fatalf("got %v, want %s/%s", err, code, reason)
	}
}
