package integration

import (
	"context"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/auth"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
)

// Approval and credentials of an MCP client's jobs, on the real job store, app
// services, policy and credential store (spec §11.1, §11.4, §24). The only
// fake is the executor of node.reboot, which counts its runs.

// mcpWorldGrant lets every mcp identity plan and submit reboots; the floors
// (approval for operational risk, no approving) must hold regardless.
const mcpWorldGrant = `
  - name: world-mcp-reboot
    subjects: ["type:mcp"]
    allow: ["node.reboot"]
`

// mcpWorldGovernanceGrant additionally grants the governance actions to every
// mcp identity: the never-approve floor must hold against an explicit grant.
const mcpWorldGovernanceGrant = mcpWorldGrant + `
  - name: world-mcp-governance
    subjects: ["type:mcp"]
    allow: ["approval.grant", "approval.reject", "job.resolve"]
`

// mcpWorld is a world whose credentials are the real ones and whose policy
// grants an mcp identity what its grant says. Operators alice, bob and carol
// reach it over the local socket, so only the MCP client's credential varies.
type mcpWorld struct {
	*world
	cfg app.Config
	gov *app.Governance
}

func newMCPWorld(t *testing.T, grant string) *mcpWorld {
	t.Helper()
	ctx := context.Background()
	clock := domaintest.NewFakeClock(epoch)
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "sm.db"), database.Options{Clock: clock})
	mcpRigMust(t, err)
	t.Cleanup(func() { _ = db.Close() })
	mcpRigMust(t, db.Migrate(ctx))
	pol, err := policy.Parse(append(policy.DefaultYAML(), []byte(grant)...))
	mcpRigMust(t, err)

	w := &world{t: t, db: db, clock: clock, ids: domaintest.NewSequentialIDs()}
	w.seed()
	cfg := app.Config{
		DB: db, Clock: clock, IDs: w.ids, Policy: pol, MCPWritesEnabled: true,
		Credentials: auth.CredentialStatus{DB: db, Clock: clock},
	}
	reval, err := app.NewRevalidator(cfg)
	mcpRigMust(t, err)
	w.store, err = jobs.NewStore(jobs.Config{DB: db, Clock: clock, IDs: w.ids, Revalidator: reval, LockPlanner: app.LockPlanner{}, LeaseTTL: leaseTTL})
	mcpRigMust(t, err)
	w.plans, err = app.NewPlans(cfg, w.store)
	mcpRigMust(t, err)
	w.appr, err = app.NewApprovals(cfg, w.store)
	mcpRigMust(t, err)
	gov, err := app.NewGovernance(cfg, w.store)
	mcpRigMust(t, err)
	return &mcpWorld{world: w, cfg: cfg, gov: gov}
}

// operator is a human on the local socket, whose credential is always active.
func (m *mcpWorld) operator(id domain.ID) app.Caller {
	return app.Caller{ID: id, Credential: domain.CredentialContext{Kind: domain.CredentialLocalSocket}}
}

// localClient registers an mcp identity with an issued local token that lives
// for lifetime, and returns the caller that token authenticates.
func (m *mcpWorld) localClient(lifetime time.Duration) (app.Caller, domain.ID) {
	m.t.Helper()
	var caller app.Caller
	var client domain.ID
	m.inTx(func(ctx context.Context, tx *database.Tx) error {
		now := m.clock.Now()
		identity := m.ids.NewID()
		client = m.ids.NewID()
		err := database.CreateIdentity(ctx, tx, database.Identity{
			ID: identity, ActorType: domain.ActorMCP, Issuer: "supermgmt:mcp-local", Subject: client.String(), CreatedAt: now,
		})
		if err != nil {
			return err
		}
		err = database.CreateMCPClient(ctx, tx, database.MCPClient{
			ID: client, IdentityID: identity, Name: "local-" + client.String(), Origin: database.MCPOriginLocal,
			State: database.MCPClientPendingToken, RequestedBy: m.alice, ApprovedAt: now, CreatedAt: now, UpdatedAt: now,
		})
		if err != nil {
			return err
		}
		if _, err = database.IssueMCPToken(ctx, tx, client, "hash-"+client.String(), now, now.Add(lifetime)); err != nil {
			return err
		}
		caller = app.Caller{ID: identity, Credential: domain.CredentialContext{Kind: domain.CredentialMCPToken, ID: client.String(), Scopes: []string{}}}
		return nil
	})
	return caller, client
}

// remoteClient registers an mcp identity of the OAuth triple with one access
// token that lives for lifetime, and returns the caller that token authenticates.
func (m *mcpWorld) remoteClient(lifetime time.Duration) (app.Caller, domain.ID) {
	m.t.Helper()
	var caller app.Caller
	var client domain.ID
	m.inTx(func(ctx context.Context, tx *database.Tx) error {
		now := m.clock.Now()
		identity := m.ids.NewID()
		client = m.ids.NewID()
		err := database.CreateIdentity(ctx, tx, database.Identity{
			ID: identity, ActorType: domain.ActorMCP, Issuer: "https://as.test", Subject: "assistant", ClientID: "assistant-app", CreatedAt: now,
		})
		if err != nil {
			return err
		}
		err = database.CreateMCPClient(ctx, tx, database.MCPClient{
			ID: client, IdentityID: identity, Name: "remote-" + client.String(), Origin: database.MCPOriginRemote,
			State: database.MCPClientActive, RequestedBy: m.alice, ApprovedAt: now, CreatedAt: now, UpdatedAt: now,
		})
		if err != nil {
			return err
		}
		token, err := database.RecordOAuthAccessToken(ctx, tx, database.OAuthAccessToken{
			ID: m.ids.NewID(), MCPClientID: client, TokenHash: "oauth-" + client.String(), Issuer: "https://as.test",
			IssuedAt: now, ExpiresAt: now.Add(lifetime), FirstSeenAt: now,
		})
		if err != nil {
			return err
		}
		caller = app.Caller{ID: identity, Credential: domain.CredentialContext{Kind: domain.CredentialOAuthAccessToken, ID: token.ID.String(), Scopes: []string{}}}
		return nil
	})
	return caller, client
}

// reboot has the mcp caller plan and submit a node.reboot.
func (m *mcpWorld) reboot(by app.Caller, node domain.Node) jobs.Job {
	m.t.Helper()
	ctx := context.Background()
	created, err := m.plans.Create(ctx, by, app.PlanRequest{Action: "node.reboot", Target: domain.ResourceRef{Type: domain.ResourceNode, ID: node.ID}})
	mcpRigMust(m.t, err)
	submitted, err := m.plans.Submit(ctx, by, created.Record.ID, created.Record.PlanHash)
	mcpRigMust(m.t, err)
	return submitted.Job
}

// approveToQueued has bob and then carol approve the exact hash of job.
func (m *mcpWorld) approveToQueued(job jobs.Job) jobs.Job {
	m.t.Helper()
	for _, approver := range []domain.ID{m.bob, m.carol} {
		if job.State == domain.JobQueued {
			break
		}
		var err error
		job, err = m.appr.Approve(context.Background(), m.operator(approver), app.DecisionRequest{JobID: job.ID, PlanHash: job.PlanHash, Reason: "ok"})
		mcpRigMust(m.t, err)
	}
	if job.State != domain.JobQueued {
		m.t.Fatalf("job state = %s after the approvals, want queued", job.State)
	}
	return job
}

func (m *mcpWorld) approvalCount(job domain.ID) int {
	m.t.Helper()
	var n int
	mcpRigMust(m.t, m.db.Reader().QueryRowContext(context.Background(), `SELECT COUNT(*) FROM job_approvals WHERE job_id = ?`, job).Scan(&n))
	return n
}

// wantFailedAtClaim claims and requires that the job was failed with reason
// instead of being handed to a worker.
func (m *mcpWorld) wantFailedAtClaim(job domain.ID, reason smerr.Reason) {
	m.t.Helper()
	_, claimed, err := m.store.Claim(context.Background(), "worker-1")
	if err != nil || claimed {
		m.t.Fatalf("Claim = claimed %v, err %v; want the job failed instead of handed out", claimed, err)
	}
	got := m.job(job)
	if got.State != domain.JobFailed || got.Error == nil || got.Error.Reason != reason {
		m.t.Fatalf("job = %s %+v, want failed with %s", got.State, got.Error, reason)
	}
}

// ---- the approval floor ----------------------------------------------------

func TestAProductionRebootAskedForByAnMCPClientRunsOnlyOnceTheExactHashIsApproved(t *testing.T) {
	m := newMCPWorld(t, mcpWorldGrant)
	caller, _ := m.localClient(24 * time.Hour)
	var runs atomic.Int64
	runEngine(t, m.world, map[string]jobs.Handler{"node.reboot": handlerFunc(func(context.Context, jobs.Lease) error {
		runs.Add(1)
		return nil
	})})

	job := m.reboot(caller, m.prodNode)

	if job.State != domain.JobAwaitingApproval {
		t.Fatalf("job = %s, want awaiting_approval: an mcp identity's production write needs approval", job.State)
	}
	time.Sleep(100 * time.Millisecond)
	if got := runs.Load(); got != 0 {
		t.Fatalf("the executor ran %d times before any approval", got)
	}
	wrongHash := app.DecisionRequest{JobID: job.ID, PlanHash: strings.Repeat("0", len(job.PlanHash)), Reason: "ok"}
	if _, err := m.appr.Approve(context.Background(), m.operator(m.bob), wrongHash); mcpSecReasonOf(err) != smerr.ReasonPlanStale {
		t.Fatalf("approving a different hash = %v, want PLAN_STALE", err)
	}
	if got := m.approvalCount(job.ID); got != 0 {
		t.Fatalf("%d approvals were recorded for the wrong hash", got)
	}

	m.approveToQueued(job)

	eventually(t, "the approved job to run once", func() bool { return m.job(job.ID).State == domain.JobSucceeded })
	if got := runs.Load(); got != 1 {
		t.Errorf("the executor ran %d times, want exactly 1", got)
	}
}

func TestAnMCPClientCanNeverApproveOrRejectEvenWhenGrantedTheGovernanceActions(t *testing.T) {
	m := newMCPWorld(t, mcpWorldGovernanceGrant)
	caller, _ := m.localClient(24 * time.Hour)
	job := m.reboot(m.operator(m.alice), m.prodNode)
	request := app.DecisionRequest{JobID: job.ID, PlanHash: job.PlanHash, Reason: "looks fine"}

	_, approveErr := m.appr.Approve(context.Background(), caller, request)
	_, rejectErr := m.appr.Reject(context.Background(), caller, request)

	for name, err := range map[string]error{"approve": approveErr, "reject": rejectErr} {
		if smerr.CodeOf(err) != smerr.CodePolicyDenied {
			t.Errorf("%s = %v, want POLICY_DENIED", name, err)
		}
	}
	if got := m.approvalCount(job.ID); got != 0 {
		t.Errorf("%d decisions were recorded by an mcp identity", got)
	}
	if state := m.job(job.ID).State; state != domain.JobAwaitingApproval {
		t.Errorf("job = %s, want it still awaiting approval", state)
	}
}

func TestAnMCPClientWithoutAGrantCannotResolveAJob(t *testing.T) {
	m := newMCPWorld(t, mcpWorldGrant)
	caller, _ := m.localClient(24 * time.Hour)
	job := m.reboot(m.operator(m.alice), m.devNode)

	_, err := m.gov.Resolve(context.Background(), caller, app.ResolveRequest{JobID: job.ID, PlanHash: job.PlanHash, Outcome: jobs.ResolveFailed, Note: "by hand"})

	if smerr.CodeOf(err) != smerr.CodePolicyDenied {
		t.Errorf("resolve = %v, want POLICY_DENIED", err)
	}
}

// ---- claim-time revalidation ---------------------------------------------------

func TestInputsChangedAfterAnMCPJobWasApprovedFailTheClaimAsStale(t *testing.T) {
	m := newMCPWorld(t, mcpWorldGrant)
	caller, _ := m.localClient(24 * time.Hour)
	job := m.approveToQueued(m.reboot(caller, m.prodNode))

	m.bumpSpecRevision(m.prodNode.ID)

	m.wantFailedAtClaim(job.ID, smerr.ReasonPlanStale)
}

func TestACredentialThatIsGoneByClaimTimeFailsTheQueuedMCPJob(t *testing.T) {
	cases := []struct {
		name   string
		client func(m *mcpWorld) (app.Caller, domain.ID)
		change func(m *mcpWorld, client domain.ID)
		want   smerr.Reason
	}{
		{
			"a local token whose client was deleted", func(m *mcpWorld) (app.Caller, domain.ID) { return m.localClient(24 * time.Hour) },
			deleteMCPClientOf, smerr.ReasonCredentialRevoked,
		},
		{
			"a local token that expired", func(m *mcpWorld) (app.Caller, domain.ID) { return m.localClient(time.Hour) },
			func(m *mcpWorld, _ domain.ID) { m.clock.Advance(2 * time.Hour) }, smerr.ReasonCredentialExpired,
		},
		{
			"an OAuth access token whose client was deleted", func(m *mcpWorld) (app.Caller, domain.ID) { return m.remoteClient(24 * time.Hour) },
			deleteMCPClientOf, smerr.ReasonCredentialRevoked,
		},
		{
			"an OAuth access token that expired", func(m *mcpWorld) (app.Caller, domain.ID) { return m.remoteClient(time.Hour) },
			func(m *mcpWorld, _ domain.ID) { m.clock.Advance(2 * time.Hour) }, smerr.ReasonCredentialExpired,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newMCPWorld(t, mcpWorldGrant)
			caller, client := tc.client(m)
			job := m.approveToQueued(m.reboot(caller, m.devNode))

			tc.change(m, client)

			m.wantFailedAtClaim(job.ID, tc.want)
		})
	}
}

// deleteMCPClientOf deletes the client the way the delete action does at the
// database: the client row, and with it every OAuth token row.
func deleteMCPClientOf(m *mcpWorld, client domain.ID) {
	m.t.Helper()
	m.inTx(func(ctx context.Context, tx *database.Tx) error {
		if _, err := database.DeleteMCPClient(ctx, tx, client, m.clock.Now()); err != nil {
			return err
		}
		_, err := database.RevokeOAuthTokensOfClient(ctx, tx, client, m.clock.Now())
		return err
	})
}
