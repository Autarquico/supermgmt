package app

import (
	"context"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func (f *fixture) queries(t *testing.T) *Queries {
	t.Helper()
	q, err := NewQueries(f.cfg, f.store, config.ModeLocal)
	mustf(t, err, "NewQueries")
	return q
}

func TestMeDescribesTheCaller(t *testing.T) {
	f := newFixture(t)

	me, err := f.queries(t).Me(context.Background(), f.caller(f.alice))
	if err != nil {
		t.Fatalf("Me: %v", err)
	}
	if me.IdentityID != f.alice || me.ActorType != domain.ActorHuman || me.DisplayName != "alice" ||
		me.Credential != domain.CredentialAPIToken || len(me.Roles) != 1 || me.Roles[0] != "operator" || me.InstanceMode != "local" {
		t.Errorf("me = %+v", me)
	}
}

func TestMeRefusesARevokedCredential(t *testing.T) {
	f := newFixture(t)
	by := f.caller(f.alice)
	f.creds.set(by.Credential.ID, CredentialRevoked)

	_, err := f.queries(t).Me(context.Background(), by)

	wantError(t, err, smerr.CodeUnauthenticated, smerr.ReasonCredentialRevoked)
}

func TestJobsListNewestFirstAndFilterByState(t *testing.T) {
	f := newFixture(t)
	f.submitReboot()
	q := f.queries(t)

	all, err := q.Jobs(context.Background(), f.caller(f.alice), wire.JobQuery{})
	waiting, _ := q.Jobs(context.Background(), f.caller(f.alice), wire.JobQuery{States: []domain.JobState{domain.JobAwaitingApproval}})
	running, _ := q.Jobs(context.Background(), f.caller(f.alice), wire.JobQuery{States: []domain.JobState{domain.JobRunning}})

	if err != nil || len(all.Items) != 1 || len(waiting.Items) != 1 || len(running.Items) != 0 {
		t.Errorf("all %d waiting %d running %d, %v", len(all.Items), len(waiting.Items), len(running.Items), err)
	}
	if job := all.Items[0]; job.Type != "node.reboot" || job.State != domain.JobAwaitingApproval || job.Resource.ID != f.node.ID || job.PlanHash == "" {
		t.Errorf("job = %+v", job)
	}
}

func TestReadsAreDeniedAndAuditedWithoutThePermission(t *testing.T) {
	f := newFixture(t)
	q := f.queries(t)
	ctx, by := context.Background(), f.caller(f.dave)

	_, jobsErr := q.Jobs(ctx, by, wire.JobQuery{})
	_, approvalsErr := q.Approvals(ctx, by, wire.PageQuery{})
	_, eventsErr := q.Events(ctx, by, wire.EventQuery{})

	for name, err := range map[string]error{"jobs": jobsErr, "approvals": approvalsErr, "events": eventsErr} {
		if smerr.CodeOf(err) != smerr.CodePolicyDenied {
			t.Errorf("%s: %v, want POLICY_DENIED", name, err)
		}
	}
	if got := len(f.events("policy.deny")); got != 3 {
		t.Errorf("%d denial events, want 3", got)
	}
}

func TestJobDetailShowsTheIntentsWithPreStateAndEvidenceSlots(t *testing.T) {
	f := newFixture(t)
	job := f.interrupted()

	detail, err := f.queries(t).Job(context.Background(), f.caller(f.alice), job.ID)

	if err != nil || detail.Job.State != domain.JobInterrupted || len(detail.Intents) != 1 {
		t.Fatalf("Job = %+v, %v", detail, err)
	}
	if in := detail.Intents[0]; in.Operation != "node.reboot" || in.Target != "node:"+f.node.ID.String() || in.DispatchedAt == nil {
		t.Errorf("intent = %+v", in)
	}
	if _, err := f.queries(t).Job(context.Background(), f.caller(f.alice), "00000000-0000-7000-8000-00000000ffff"); smerr.CodeOf(err) != smerr.CodeNotFound {
		t.Errorf("missing job: %v", err)
	}
}

func TestApprovalsShowWhatAnApproverMustSee(t *testing.T) {
	f := newFixture(t)
	sub, created := f.submitReboot()
	q := f.queries(t)

	before, err := q.Approvals(context.Background(), f.caller(f.bob), wire.PageQuery{})
	if err != nil || len(before.Items) != 1 {
		t.Fatalf("Approvals = %d, %v", len(before.Items), err)
	}
	if _, err := f.approve(f.bob, sub.Job); err != nil {
		t.Fatalf("approve: %v", err)
	}
	after, _ := q.Approvals(context.Background(), f.caller(f.bob), wire.PageQuery{})

	view := before.Items[0]
	if view.Quorum != 2 || view.Approvals != 0 || len(view.Environments) != 1 || view.Environments[0] != "prod" ||
		string(view.Plan) != string(created.Record.PlanJSON) || !view.ExpiresAt.Equal(created.Record.ExpiresAt) {
		t.Errorf("approval = %+v", view)
	}
	if after.Items[0].Approvals != 1 {
		t.Errorf("approvals after bob = %d, want 1", after.Items[0].Approvals)
	}
}

func TestApprovalsOmitJobsThatAreNoLongerWaiting(t *testing.T) {
	f := newFixture(t)
	sub, _ := f.submitReboot()
	f.approveToQuorum(sub.Job)

	page, err := f.queries(t).Approvals(context.Background(), f.caller(f.bob), wire.PageQuery{})

	if err != nil || len(page.Items) != 0 {
		t.Errorf("Approvals = %d, %v", len(page.Items), err)
	}
}

func TestEventsPageByCursorAndFilterByResource(t *testing.T) {
	f := newFixture(t)
	f.submitReboot()
	q := f.queries(t)
	ctx, by := context.Background(), f.caller(f.alice)

	first, err := q.Events(ctx, by, wire.EventQuery{PageQuery: wire.PageQuery{Limit: 2}})
	if err != nil || len(first.Items) != 2 || first.NextCursor == "" {
		t.Fatalf("first page = %d, cursor %q, %v", len(first.Items), first.NextCursor, err)
	}
	second, err := q.Events(ctx, by, wire.EventQuery{PageQuery: wire.PageQuery{Limit: 2, Cursor: first.NextCursor}})
	if err != nil || len(second.Items) == 0 || second.Items[0].Seq <= first.Items[1].Seq {
		t.Fatalf("second page = %+v, %v", second.Items, err)
	}
	onlyJobs, _ := q.Events(ctx, by, wire.EventQuery{ResourceType: domain.ResourceJob})
	for _, e := range onlyJobs.Items {
		if e.Resource.Type != domain.ResourceJob {
			t.Errorf("event %s is a %s event", e.Action, e.Resource.Type)
		}
	}
	if len(onlyJobs.Items) == 0 {
		t.Error("the job events are missing")
	}
	later, _ := q.Events(ctx, by, wire.EventQuery{AfterSeq: first.Items[1].Seq})
	if len(later.Items) == 0 || later.Items[0].Seq != first.Items[1].Seq+1 {
		t.Errorf("after_seq returned %+v", later.Items)
	}
	if _, err := q.Events(ctx, by, wire.EventQuery{PageQuery: wire.PageQuery{Cursor: "x"}}); smerr.CodeOf(err) != smerr.CodeInvalidArgument {
		t.Errorf("bad cursor: %v", err)
	}
}
