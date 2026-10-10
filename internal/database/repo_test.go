package database

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// fixture runs repository calls inside one rolled-back-on-failure write transaction.
type fixture struct {
	t   *testing.T
	db  *DB
	ids *domaintest.SequentialIDs
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	return &fixture{t: t, db: migratedTest(t), ids: domaintest.NewSequentialIDs()}
}

func (f *fixture) tx(fn func(ctx context.Context, q Querier)) {
	f.t.Helper()
	if err := f.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *Tx) error {
		fn(ctx, tx)
		return nil
	}); err != nil {
		f.t.Fatalf("transaction: %v", err)
	}
}

// must unwraps a repository result; a failure panics, which the test runner
// reports with the offending line.
func must[T any](v T, err error) T {
	if err != nil {
		panic(fmt.Sprintf("unexpected error: %v", err))
	}
	return v
}

func noErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func wantError(t *testing.T, err error, code smerr.Code, reason smerr.Reason) {
	t.Helper()
	if err == nil {
		t.Fatalf("got nil error, want %s/%s", code, reason)
	}
	if !errors.Is(err, smerr.New(code, reason, "")) {
		t.Fatalf("got %v, want %s/%s", err, code, reason)
	}
}

func (f *fixture) identity(ctx context.Context, q Querier, actor domain.ActorType, subject string) Identity {
	f.t.Helper()
	i := Identity{ID: f.ids.NewID(), ActorType: actor, Subject: subject, DisplayName: subject, CreatedAt: testEpoch}
	noErr(f.t, CreateIdentity(ctx, q, i))
	return i
}

func (f *fixture) provider(ctx context.Context, q Querier, name string) domain.Provider {
	f.t.Helper()
	return must(CreateProvider(ctx, q, domain.Provider{
		ID: f.ids.NewID(), Type: "ssh", Name: name, Origin: domain.ProviderStatic,
		Config: map[string]any{"k": "v"}, CreatedAt: testEpoch, UpdatedAt: testEpoch,
	}))
}

func (f *fixture) node(ctx context.Context, q Querier, p domain.Provider, name string, tags ...string) domain.Node {
	f.t.Helper()
	return must(CreateNode(ctx, q, domain.Node{
		ID: f.ids.NewID(), ProviderID: p.ID, NativeID: name, Name: name, Kind: "host",
		ManagementState: domain.ManagementManaged, Reachability: domain.ReachabilityUnknown,
		Endpoint: domain.NodeEndpoint{Host: "10.0.0.1", Port: 22, User: "sm", HostPublicKey: "ssh-ed25519 AAAA"},
		Tags:     tags, CreatedAt: testEpoch, UpdatedAt: testEpoch,
	}))
}

// ---- identities and roles --------------------------------------------------

func TestIdentitiesAndRoleBindings(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		alice := f.identity(ctx, q, domain.ActorHuman, "alice")
		got := must(GetIdentity(ctx, q, alice.ID))
		if got.Subject != "alice" || got.ActorType != domain.ActorHuman || !got.CreatedAt.Equal(testEpoch) || got.DisabledAt != nil {
			t.Fatalf("round trip: %+v", got)
		}

		_, err := GetIdentity(ctx, q, f.ids.NewID())
		wantError(t, err, smerr.CodeNotFound, "")

		dup := Identity{ID: f.ids.NewID(), ActorType: domain.ActorHuman, Subject: "alice", CreatedAt: testEpoch}
		wantError(t, CreateIdentity(ctx, q, dup), smerr.CodeConflict, "")

		admin := must(GetRoleByName(ctx, q, "admin"))
		viewer := must(GetRoleByName(ctx, q, "viewer"))
		for _, r := range []Role{viewer, admin} {
			noErr(t, CreateRoleBinding(ctx, q, RoleBinding{ID: f.ids.NewID(), IdentityID: alice.ID, RoleID: r.ID, CreatedAt: testEpoch}))
		}
		again := RoleBinding{ID: f.ids.NewID(), IdentityID: alice.ID, RoleID: admin.ID, CreatedAt: testEpoch}
		wantError(t, CreateRoleBinding(ctx, q, again), smerr.CodeConflict, "")

		roles := must(ListRolesForIdentity(ctx, q, alice.ID))
		if len(roles) != 2 || roles[0].Name != "admin" || roles[1].Name != "viewer" {
			t.Fatalf("roles = %+v, want admin, viewer", roles)
		}
		bob := f.identity(ctx, q, domain.ActorHuman, "bob")
		if roles := must(ListRolesForIdentity(ctx, q, bob.ID)); len(roles) != 0 {
			t.Fatalf("bob roles = %+v, want none", roles)
		}
	})
}

func TestCreateRole(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		noErr(t, CreateRole(ctx, q, Role{ID: f.ids.NewID(), Name: "auditor", Description: "reads events"}))
		if r := must(GetRoleByName(ctx, q, "auditor")); r.Description != "reads events" {
			t.Fatalf("role = %+v", r)
		}
		wantError(t, CreateRole(ctx, q, Role{ID: f.ids.NewID(), Name: "admin"}), smerr.CodeConflict, "")
		_, err := GetRoleByName(ctx, q, "nobody")
		wantError(t, err, smerr.CodeNotFound, "")
	})
}

// ---- inventory -------------------------------------------------------------

func TestInventoryRoundTrips(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		env := must(CreateEnvironment(ctx, q, domain.Environment{
			ID: f.ids.NewID(), Name: "prod", RiskLevel: domain.EnvironmentProduction,
			RequireProvenance: true, ApprovalsRequired: 2,
		}))
		if env.SpecRevision != 1 {
			t.Fatalf("new environment revision = %d, want 1", env.SpecRevision)
		}
		gotEnv := must(GetEnvironment(ctx, q, env.ID))
		if gotEnv != env {
			t.Fatalf("environment = %+v, want %+v", gotEnv, env)
		}
		if envs := must(ListEnvironments(ctx, q)); len(envs) != 1 {
			t.Fatalf("environments = %d", len(envs))
		}

		p := f.provider(ctx, q, "static-ssh")
		gotP := must(GetProvider(ctx, q, p.ID))
		if gotP.Config["k"] != "v" || gotP.SpecRevision != 1 || gotP.LastSyncAt != nil || !gotP.CreatedAt.Equal(testEpoch) {
			t.Fatalf("provider = %+v", gotP)
		}
		_, err := CreateProvider(ctx, q, domain.Provider{
			ID: f.ids.NewID(), Type: "ssh", Name: "static-ssh",
			Origin: domain.ProviderStatic, CreatedAt: testEpoch, UpdatedAt: testEpoch,
		})
		wantError(t, err, smerr.CodeConflict, "")

		n := f.node(ctx, q, p, "web-1", "zeta", "alpha", "alpha")
		if !slices.Equal(n.Tags, []string{"alpha", "zeta"}) {
			t.Fatalf("tags = %v, want sorted and deduplicated", n.Tags)
		}
		if n.Endpoint.Host != "10.0.0.1" || n.Endpoint.HostPublicKey != "ssh-ed25519 AAAA" || n.EnvironmentID != nil {
			t.Fatalf("node = %+v", n)
		}
		dup := domain.Node{
			ID: f.ids.NewID(), ProviderID: p.ID, NativeID: "web-1", Name: "other", Kind: "host",
			ManagementState: domain.ManagementManaged, Reachability: domain.ReachabilityUnknown,
			CreatedAt: testEpoch, UpdatedAt: testEpoch,
		}
		_, err = CreateNode(ctx, q, dup)
		wantError(t, err, smerr.CodeConflict, "")

		f.node(ctx, q, p, "db-1", "alpha")
		nodes := must(ListNodes(ctx, q))
		if len(nodes) != 2 || nodes[0].Name != "db-1" || !slices.Equal(nodes[0].Tags, []string{"alpha"}) ||
			!slices.Equal(nodes[1].Tags, []string{"alpha", "zeta"}) {
			t.Fatalf("nodes = %+v", nodes)
		}
		_, err = GetNode(ctx, q, f.ids.NewID())
		wantError(t, err, smerr.CodeNotFound, "")

		rt := domain.Runtime{
			ID: f.ids.NewID(), NodeID: n.ID, Type: "docker", NativeID: "local", Version: "27",
			Metadata: map[string]any{"a": "b"},
		}
		noErr(t, CreateRuntime(ctx, q, rt))
		if got := must(GetRuntime(ctx, q, rt.ID)); got.Version != "27" || got.Metadata["a"] != "b" {
			t.Fatalf("runtime = %+v", got)
		}
		if rts := must(ListRuntimes(ctx, q, n.ID)); len(rts) != 1 {
			t.Fatalf("runtimes = %d", len(rts))
		}

		svc := must(CreateService(ctx, q, domain.Service{
			ID: f.ids.NewID(), RuntimeID: rt.ID, NodeID: n.ID,
			NativeID: "c1", Name: "web", Kind: "container", Status: "running", Health: "healthy",
		}))
		if svc.SpecRevision != 1 {
			t.Fatalf("service revision = %d", svc.SpecRevision)
		}
		if got := must(GetService(ctx, q, svc.ID)); got.Health != "healthy" || got.Name != "web" {
			t.Fatalf("service = %+v", got)
		}
		if svcs := must(ListServices(ctx, q, n.ID)); len(svcs) != 1 {
			t.Fatalf("services = %d", len(svcs))
		}
		_, err = GetService(ctx, q, f.ids.NewID())
		wantError(t, err, smerr.CodeNotFound, "")
	})
}

// ---- spec_revision guard ---------------------------------------------------

func TestUpdateNodeSpecBumpsRevisionAndReplacesTags(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		n := f.node(ctx, q, f.provider(ctx, q, "p"), "web-1", "old")
		edited := n
		edited.Name, edited.Tags = "web-renamed", []string{"new", "tags"}
		edited.Endpoint.Host = "10.0.0.9"
		edited.UpdatedAt = testEpoch.Add(time.Minute)

		got := must(UpdateNodeSpec(ctx, q, edited, n.SpecRevision))
		if got.SpecRevision != n.SpecRevision+1 {
			t.Fatalf("revision = %d, want %d", got.SpecRevision, n.SpecRevision+1)
		}
		if got.Name != "web-renamed" || got.Endpoint.Host != "10.0.0.9" || !slices.Equal(got.Tags, []string{"new", "tags"}) {
			t.Fatalf("node = %+v", got)
		}
		if !got.UpdatedAt.Equal(testEpoch.Add(time.Minute)) {
			t.Fatalf("updated_at = %v", got.UpdatedAt)
		}
	})
}

func TestUpdateNodeSpecRejectsStaleRevision(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		n := f.node(ctx, q, f.provider(ctx, q, "p"), "web-1", "keep")
		first := n
		first.Name = "first"
		must(UpdateNodeSpec(ctx, q, first, n.SpecRevision))

		second := n
		second.Name, second.Tags = "second", []string{"lost"}
		_, err := UpdateNodeSpec(ctx, q, second, n.SpecRevision) // still holds the old revision
		wantError(t, err, smerr.CodeConflict, "")

		var typed *smerr.Error
		if !errors.As(err, &typed) || typed.Details["current_spec_revision"] != int64(2) {
			t.Fatalf("error details = %+v", typed)
		}
		stored := must(GetNode(ctx, q, n.ID))
		if stored.Name != "first" || !slices.Equal(stored.Tags, []string{"keep"}) || stored.SpecRevision != 2 {
			t.Fatalf("stale write leaked: %+v", stored)
		}

		missing := n
		missing.ID = f.ids.NewID()
		_, err = UpdateNodeSpec(ctx, q, missing, 1)
		wantError(t, err, smerr.CodeNotFound, "")
	})
}

func TestObservationWritersNeverBumpSpecRevision(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		n := f.node(ctx, q, f.provider(ctx, q, "p"), "web-1", "t")
		seen := testEpoch.Add(time.Hour)

		noErr(t, SetNodeReachability(ctx, q, n.ID, domain.ReachabilityReachable))
		noErr(t, TouchLastSeen(ctx, q, n.ID, seen))
		noErr(t, SetNodeCapability(ctx, q, n.ID, NodeCapability{Capability: "node.ssh", Available: true, CheckedAt: seen}))
		noErr(t, SetNodeCapability(ctx, q, n.ID, NodeCapability{
			Capability: "node.ssh", Available: false,
			Metadata: map[string]any{"why": "down"}, CheckedAt: seen,
		}))
		noErr(t, RecordObservation(ctx, q, Observation{
			ID: f.ids.NewID(), ResourceType: domain.ResourceNode,
			ResourceID: n.ID, Kind: "metrics", Value: map[string]any{"cpu": 3}, ObservedAt: seen,
		}))

		got := must(GetNode(ctx, q, n.ID))
		if got.SpecRevision != n.SpecRevision {
			t.Fatalf("observations changed spec_revision: %d -> %d", n.SpecRevision, got.SpecRevision)
		}
		if got.Reachability != domain.ReachabilityReachable || got.LastSeenAt == nil || !got.LastSeenAt.Equal(seen) {
			t.Fatalf("observation not stored: %+v", got)
		}
		caps := must(ListNodeCapabilities(ctx, q, n.ID))
		if len(caps) != 1 || caps[0].Available || caps[0].Metadata["why"] != "down" {
			t.Fatalf("capabilities = %+v, want one upserted entry", caps)
		}
		var observations int
		noErr(t, q.QueryRowContext(ctx, `SELECT count(*) FROM observations`).Scan(&observations))
		if observations != 1 {
			t.Fatalf("observations = %d", observations)
		}
		wantError(t, SetNodeReachability(ctx, q, f.ids.NewID(), domain.ReachabilityReachable), smerr.CodeNotFound, "")
	})
}

// ---- events ----------------------------------------------------------------

func event(id domain.ID, action string) domain.Event {
	return domain.Event{
		EventID: id, Timestamp: testEpoch, ActorType: domain.ActorSystem, ActorID: id, Source: "test",
		Action: action, ResourceType: domain.ResourceNode, ResourceID: id,
		Severity: domain.SeverityInfo, Result: domain.ResultSucceeded, Data: map[string]any{"n": "1"},
	}
}

func TestEventsGetMonotonicSeqAndPage(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		w := EventsIn(q)
		var seqs []int64
		for _, action := range []string{"a", "b", "c"} {
			stored := must(w.AppendEvent(ctx, event(f.ids.NewID(), action)))
			seqs = append(seqs, stored.Seq)
		}
		if seqs[0] <= 0 || seqs[0] >= seqs[1] || seqs[1] >= seqs[2] {
			t.Fatalf("seqs = %v, want strictly increasing", seqs)
		}
		page := must(ListEvents(ctx, q, seqs[0], 1))
		if len(page) != 1 || page[0].Action != "b" || page[0].Seq != seqs[1] || page[0].Data["n"] != "1" {
			t.Fatalf("page = %+v", page)
		}
		rest := must(ListEvents(ctx, q, seqs[1], 10))
		if len(rest) != 1 || rest[0].Action != "c" {
			t.Fatalf("rest = %+v", rest)
		}
		_, err := ListEvents(ctx, q, 0, 0)
		wantError(t, err, smerr.CodeInvalidArgument, "")

		dup := event(page[0].EventID, "again")
		_, err = w.AppendEvent(ctx, dup)
		wantError(t, err, smerr.CodeConflict, "")
	})
}

func TestEventRollsBackWithItsTransaction(t *testing.T) {
	f := newFixture(t)
	boom := errors.New("boom")
	err := f.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *Tx) error {
		must(EventsIn(tx).AppendEvent(ctx, event(f.ids.NewID(), "doomed")))
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if got := must(ListEvents(context.Background(), f.db.Reader(), 0, 10)); len(got) != 0 {
		t.Fatalf("event survived rollback: %+v", got)
	}
}

// ---- plans -----------------------------------------------------------------

func (f *fixture) job(ctx context.Context, q Querier, actor domain.ID) domain.ID {
	f.t.Helper()
	row := baselines()["jobs"]
	id := f.ids.NewID()
	row = override(row, "id", id.String())
	row = override(row, "actor_id", actor.String())
	row = override(row, "resource_id", id.String())
	noErr(f.t, insertRow(ctx, q.(*Tx), "jobs", row))
	return id
}

func (f *fixture) plan(ctx context.Context, q Querier, actor domain.ID) PlanRecord {
	f.t.Helper()
	p := PlanRecord{
		ID: f.ids.NewID(), Action: "node.reboot", ActorID: actor,
		Credential:  domain.CredentialContext{Kind: domain.CredentialSession, ID: "sess-1", Scopes: []string{"node.reboot"}},
		PlanJSON:    []byte(`{"version":3}`),
		PlanHash:    "sha256:abcd",
		FinalizedAt: testEpoch, CreatedAt: testEpoch, ExpiresAt: testEpoch.Add(24 * time.Hour),
	}
	noErr(f.t, InsertPlan(ctx, q, p))
	return p
}

func TestPlanRoundTripKeepsBytesExactly(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		actor := f.identity(ctx, q, domain.ActorHuman, "alice")
		p := f.plan(ctx, q, actor.ID)
		got := must(GetPlan(ctx, q, p.ID))
		if string(got.PlanJSON) != `{"version":3}` || got.PlanHash != p.PlanHash || got.SubmittedJobID != nil {
			t.Fatalf("plan = %+v", got)
		}
		if got.Credential.Kind != domain.CredentialSession || !slices.Equal(got.Credential.Scopes, []string{"node.reboot"}) ||
			!got.ExpiresAt.Equal(p.ExpiresAt) {
			t.Fatalf("credential/expiry lost: %+v", got)
		}
		_, err := GetPlan(ctx, q, f.ids.NewID())
		wantError(t, err, smerr.CodeNotFound, "")
	})
}

func TestMarkSubmittedAllowsExactlyOneJobPerPlan(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		actor := f.identity(ctx, q, domain.ActorHuman, "alice")
		p, other := f.plan(ctx, q, actor.ID), f.plan(ctx, q, actor.ID)
		job, job2 := f.job(ctx, q, actor.ID), f.job(ctx, q, actor.ID)

		noErr(t, MarkSubmitted(ctx, q, p.ID, job))
		if got := must(GetPlan(ctx, q, p.ID)); got.SubmittedJobID == nil || *got.SubmittedJobID != job {
			t.Fatalf("submitted job = %v", got.SubmittedJobID)
		}
		wantError(t, MarkSubmitted(ctx, q, p.ID, job2), smerr.CodeConflict, smerr.ReasonAlreadySubmitted)
		wantError(t, MarkSubmitted(ctx, q, p.ID, job), smerr.CodeConflict, smerr.ReasonAlreadySubmitted)
		// One job cannot serve two plans either (UNIQUE(submitted_job_id)).
		wantError(t, MarkSubmitted(ctx, q, other.ID, job), smerr.CodeConflict, smerr.ReasonAlreadySubmitted)
		wantError(t, MarkSubmitted(ctx, q, f.ids.NewID(), job2), smerr.CodeNotFound, "")
	})
}

// ---- approvals -------------------------------------------------------------

func approval(f *fixture, job, approver domain.ID, d domain.ApprovalDecision, expires time.Time) Approval {
	return Approval{
		ID: f.ids.NewID(), JobID: job, PlanHash: "sha256:abcd", ApproverID: approver,
		Decision: d, Reason: "because", ExpiresAt: expires,
	}
}

func TestApprovalIsUniquePerApproverUntilItExpires(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		requester := f.identity(ctx, q, domain.ActorHuman, "req")
		carol := f.identity(ctx, q, domain.ActorHuman, "carol")
		dave := f.identity(ctx, q, domain.ActorHuman, "dave")
		job := f.job(ctx, q, requester.ID)
		ttl := time.Hour

		first := must(RecordDecision(ctx, q, approval(f, job, carol.ID, domain.DecisionApprove, testEpoch.Add(ttl)), testEpoch))
		if !first.CreatedAt.Equal(testEpoch) || first.RenewedAt != nil {
			t.Fatalf("first = %+v", first)
		}
		must(RecordDecision(ctx, q, approval(f, job, dave.ID, domain.DecisionApprove, testEpoch.Add(ttl)), testEpoch))

		// Still valid one second before expiry: a second decision is refused.
		_, err := RecordDecision(ctx, q, approval(f, job, carol.ID, domain.DecisionApprove, testEpoch.Add(2*ttl)),
			testEpoch.Add(ttl-time.Second))
		wantError(t, err, smerr.CodeConflict, smerr.ReasonAlreadyDecided)

		// At the expiry instant the approval no longer counts and may be renewed in place.
		renewAt := testEpoch.Add(ttl)
		renewed := must(RecordDecision(ctx, q, approval(f, job, carol.ID, domain.DecisionApprove, renewAt.Add(ttl)), renewAt))
		if renewed.ID != first.ID || renewed.RenewedAt == nil || !renewed.RenewedAt.Equal(renewAt) ||
			!renewed.ExpiresAt.Equal(renewAt.Add(ttl)) || !renewed.CreatedAt.Equal(testEpoch) {
			t.Fatalf("renewed = %+v, first = %+v", renewed, first)
		}

		all := must(ListDecisions(ctx, q, job, "sha256:abcd"))
		if len(all) != 2 || all[0].ID != first.ID || all[0].RenewedAt == nil || all[1].RenewedAt != nil {
			t.Fatalf("decisions = %+v", all)
		}
		if other := must(ListDecisions(ctx, q, job, "sha256:other")); len(other) != 0 {
			t.Fatalf("approvals leaked across plan hashes: %+v", other)
		}
	})
}

func TestRejectionIsFinal(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		requester := f.identity(ctx, q, domain.ActorHuman, "req")
		erin := f.identity(ctx, q, domain.ActorHuman, "erin")
		job := f.job(ctx, q, requester.ID)

		must(RecordDecision(ctx, q, approval(f, job, erin.ID, domain.DecisionReject, testEpoch.Add(time.Hour)), testEpoch))
		later := testEpoch.Add(48 * time.Hour) // long after expiry
		for _, d := range []domain.ApprovalDecision{domain.DecisionApprove, domain.DecisionReject} {
			_, err := RecordDecision(ctx, q, approval(f, job, erin.ID, d, later.Add(time.Hour)), later)
			wantError(t, err, smerr.CodeConflict, smerr.ReasonAlreadyDecided)
		}
		if got := must(ListDecisions(ctx, q, job, "sha256:abcd")); len(got) != 1 || got[0].Decision != domain.DecisionReject {
			t.Fatalf("decisions = %+v", got)
		}
	})
}

// Pinned conservative reading of §11.4: an approver whose approval has expired
// may answer with a rejection; the row becomes a (final) rejection.
func TestExpiredApprovalCanBeAnsweredWithRejection(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		requester := f.identity(ctx, q, domain.ActorHuman, "req")
		fay := f.identity(ctx, q, domain.ActorHuman, "fay")
		job := f.job(ctx, q, requester.ID)
		must(RecordDecision(ctx, q, approval(f, job, fay.ID, domain.DecisionApprove, testEpoch.Add(time.Hour)), testEpoch))

		at := testEpoch.Add(2 * time.Hour)
		got := must(RecordDecision(ctx, q, approval(f, job, fay.ID, domain.DecisionReject, at.Add(time.Hour)), at))
		if got.Decision != domain.DecisionReject || got.RenewedAt == nil {
			t.Fatalf("got = %+v", got)
		}
		_, err := RecordDecision(ctx, q, approval(f, job, fay.ID, domain.DecisionApprove, at.Add(time.Hour)), at.Add(time.Hour*3))
		wantError(t, err, smerr.CodeConflict, smerr.ReasonAlreadyDecided)
	})
}
