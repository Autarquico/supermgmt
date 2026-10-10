package app

import (
	"context"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/plan"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/policy"
)

func TestCreateRecordsThePlanWithCurrentRevisionsAndExpiry(t *testing.T) {
	f := newFixture(t)

	created, err := f.plans.Create(context.Background(), f.caller(f.alice), f.reboot())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if got := created.Plan.Targets[0]; got.Type != "node" || got.ID != f.node.ID.String() || *got.SpecRevision != f.node.SpecRevision {
		t.Errorf("target = %+v, want node %s at revision %d", got, f.node.ID, f.node.SpecRevision)
	}
	if hash, _ := plan.Hash(created.Plan); hash != created.Record.PlanHash {
		t.Errorf("stored hash %s differs from the plan's hash %s", created.Record.PlanHash, hash)
	}
	if want := epoch.Add(24 * time.Hour); !created.Record.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt = %v, want %v", created.Record.ExpiresAt, want)
	}
	if created.Plan.Risk != domain.RiskHigh || created.Plan.Actor != "identity/"+f.alice.String() {
		t.Errorf("risk %s actor %s", created.Plan.Risk, created.Plan.Actor)
	}
	wantInputs := map[string]int64{"environment": f.env.SpecRevision}
	for _, in := range created.Plan.Inputs {
		if rev, ok := wantInputs[in.Type]; ok && *in.SpecRevision != rev {
			t.Errorf("input %s revision = %d, want %d", in.Type, *in.SpecRevision, rev)
		}
	}
	if len(f.events("plan.create")) != 1 {
		t.Errorf("want one plan.create event, got %d", len(f.events("plan.create")))
	}
}

func TestCreateReportsPolicyIncludingTheQuorumTheEnvironmentDemands(t *testing.T) {
	f := newFixture(t)

	created, err := f.plans.Create(context.Background(), f.caller(f.alice), f.reboot())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if p := created.Policy; p.Decision != policy.DecisionAllow || !p.ApprovalRequired || p.Quorum != 2 {
		t.Errorf("policy = %+v, want allow with approval and quorum 2", p)
	}
}

func TestCreateWorksForServiceTargetsAndPinsTheirNode(t *testing.T) {
	f := newFixture(t)

	created, err := f.plans.Create(context.Background(), f.caller(f.alice), PlanRequest{
		Action: "service.restart", Target: domain.ResourceRef{Type: domain.ResourceService, ID: f.service.ID},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	var pinsNode bool
	for _, in := range created.Plan.Inputs {
		pinsNode = pinsNode || (in.Type == "node" && in.ID == f.node.ID.String())
	}
	if !pinsNode {
		t.Errorf("service plan inputs %+v do not pin the node", created.Plan.Inputs)
	}
}

func TestCreateRefusesWhatCannotBePlanned(t *testing.T) {
	f := newFixture(t)
	node := domain.ResourceRef{Type: domain.ResourceNode, ID: f.node.ID}
	tests := []struct {
		name   string
		req    PlanRequest
		code   smerr.Code
		reason smerr.Reason
	}{
		{"unknown action", PlanRequest{Action: "node.explode", Target: node}, smerr.CodeInvalidArgument, smerr.ReasonUnknownAction},
		{"action that is not a job", PlanRequest{Action: "node.read", Target: node}, smerr.CodeInvalidArgument, ""},
		{"target of the wrong type for the action", PlanRequest{
			Action: "node.reboot", Target: domain.ResourceRef{Type: domain.ResourceService, ID: f.service.ID},
		}, smerr.CodeInvalidArgument, ""},
		{"parameter outside the action's schema", PlanRequest{
			Action: "node.reboot", Target: node, Parameters: map[string]any{"force": "yes"},
		}, smerr.CodeInvalidArgument, ""},
		{"target that does not exist", PlanRequest{
			Action: "node.reboot", Target: domain.ResourceRef{Type: domain.ResourceNode, ID: f.ids.NewID()},
		}, smerr.CodeNotFound, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := f.plans.Create(context.Background(), f.caller(f.alice), tt.req)
			wantError(t, err, tt.code, tt.reason)
		})
	}
}

func TestCreateWithoutPlanPermissionIsDeniedAndAudited(t *testing.T) {
	f := newFixture(t)

	_, err := f.plans.Create(context.Background(), f.caller(f.dave), f.reboot())

	wantError(t, err, smerr.CodePolicyDenied, smerr.ReasonDefaultDeny)
	if got := f.events("policy.deny"); len(got) != 1 || got[0].ActorID != f.dave || got[0].Result != domain.ResultDenied {
		t.Errorf("want one denied policy.deny event by dave, got %+v", got)
	}
	if got := f.events("plan.create"); len(got) != 0 {
		t.Errorf("a denied request must not create a plan, got %d plan.create events", len(got))
	}
}

func TestCreateWithRevokedCredentialFails(t *testing.T) {
	f := newFixture(t)
	f.creds.set("token-"+f.alice.String(), CredentialRevoked)

	_, err := f.plans.Create(context.Background(), f.caller(f.alice), f.reboot())

	wantError(t, err, smerr.CodeUnauthenticated, smerr.ReasonCredentialRevoked)
}

func TestCreateReportsMissingCapabilityAndSubmitRefusesIt(t *testing.T) {
	f := newFixture(t)
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		return database.SetNodeCapability(ctx, tx, f.node.ID, database.NodeCapability{
			Capability: "node.reboot", Available: false, CheckedAt: f.clock.Now(),
		})
	})

	created, err := f.plans.Create(context.Background(), f.caller(f.alice), f.reboot())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.Policy.Decision != policy.DecisionCapabilityUnavailable {
		t.Fatalf("decision = %s, want capability_unavailable", created.Policy.Decision)
	}
	if len(f.events("policy.capability_unavailable")) != 1 {
		t.Errorf("capability gap not audited at plan creation")
	}

	_, err = f.plans.Submit(context.Background(), f.caller(f.alice), created.Record.ID, created.Record.PlanHash)
	wantError(t, err, smerr.CodeCapabilityUnavailable, "")
}

func TestSubmitOfAProductionRebootAwaitsApprovalAndBindsPlanAndJob(t *testing.T) {
	f := newFixture(t)

	sub, created := f.submitReboot()

	job := sub.Job
	if job.State != domain.JobAwaitingApproval || job.Type != "node.reboot" || job.Risk != domain.RiskHigh {
		t.Errorf("job = %s %s %s", job.Type, job.State, job.Risk)
	}
	if job.PlanID == nil || *job.PlanID != created.Record.ID || job.PlanHash != created.Record.PlanHash {
		t.Errorf("job is not bound to the plan: %v %s", job.PlanID, job.PlanHash)
	}
	if job.RetryClass != domain.RetryNonRetryable || job.MaxAttempts != 1 {
		t.Errorf("retry %s attempts %d come from the catalog", job.RetryClass, job.MaxAttempts)
	}
	stored, err := database.GetPlan(context.Background(), f.db.Reader(), created.Record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.SubmittedJobID == nil || *stored.SubmittedJobID != job.ID {
		t.Errorf("plan.submitted_job_id = %v, want %s", stored.SubmittedJobID, job.ID)
	}
	if len(f.events("plan.submit")) != 1 || len(f.events("job.awaiting_approval")) != 1 {
		t.Errorf("want one plan.submit and one job.awaiting_approval event")
	}
}

func TestSubmitWithoutApprovalRequirementQueuesTheJob(t *testing.T) {
	f := newFixture(t)
	created, err := f.plans.Create(context.Background(), f.caller(f.alice), PlanRequest{
		Action: "node.probe", Target: domain.ResourceRef{Type: domain.ResourceNode, ID: f.node.ID},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	sub, err := f.plans.Submit(context.Background(), f.caller(f.alice), created.Record.ID, created.Record.PlanHash)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	if sub.Job.State != domain.JobQueued {
		t.Errorf("state = %s, want queued", sub.Job.State)
	}
}

func TestSubmitStoresTheSubmittingCredentialOnTheJob(t *testing.T) {
	f := newFixture(t)
	created, err := f.plans.Create(context.Background(), f.caller(f.alice), f.reboot())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	submitting := Caller{ID: f.alice, Credential: domain.CredentialContext{
		Kind: domain.CredentialSession, ID: "session-9", Scopes: []string{"node.*"},
	}}

	sub, err := f.plans.Submit(context.Background(), submitting, created.Record.ID, created.Record.PlanHash)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	if j := sub.Job; j.CredentialKind != domain.CredentialSession || j.CredentialID != "session-9" || len(j.Scopes) != 1 {
		t.Errorf("job credential = %s %s %v", j.CredentialKind, j.CredentialID, j.Scopes)
	}
}

func TestSubmitRefusals(t *testing.T) {
	tests := []struct {
		name    string
		arrange func(f *fixture, created CreatedPlan) (Caller, string)
		code    smerr.Code
		reason  smerr.Reason
	}{
		{"someone other than the plan's actor", func(f *fixture, c CreatedPlan) (Caller, string) {
			return f.caller(f.bob), c.Record.PlanHash
		}, smerr.CodePolicyDenied, smerr.ReasonNotPlanActor},
		{"hash that is not the plan's", func(f *fixture, c CreatedPlan) (Caller, string) {
			return f.caller(f.alice), "sha256:00"
		}, smerr.CodeConflict, smerr.ReasonPlanStale},
		{"expired plan", func(f *fixture, c CreatedPlan) (Caller, string) {
			f.clock.Advance(24 * time.Hour)
			return f.caller(f.alice), c.Record.PlanHash
		}, smerr.CodeConflict, smerr.ReasonPlanExpired},
		{"input changed since planning", func(f *fixture, c CreatedPlan) (Caller, string) {
			f.bumpNodeRevision()
			return f.caller(f.alice), c.Record.PlanHash
		}, smerr.CodeConflict, smerr.ReasonPlanStale},
		{"revoked credential", func(f *fixture, c CreatedPlan) (Caller, string) {
			f.creds.set("token-"+f.alice.String(), CredentialRevoked)
			return f.caller(f.alice), c.Record.PlanHash
		}, smerr.CodeUnauthenticated, smerr.ReasonCredentialRevoked},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			created, err := f.plans.Create(context.Background(), f.caller(f.alice), f.reboot())
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			by, hash := tt.arrange(f, created)

			_, err = f.plans.Submit(context.Background(), by, created.Record.ID, hash)

			wantError(t, err, tt.code, tt.reason)
			stored, _ := database.GetPlan(context.Background(), f.db.Reader(), created.Record.ID)
			if stored.SubmittedJobID != nil {
				t.Errorf("a refused submit left the plan bound to job %s", *stored.SubmittedJobID)
			}
		})
	}
}

func TestSubmitTwiceIsAlreadySubmittedAndCreatesNoSecondJob(t *testing.T) {
	f := newFixture(t)
	_, created := f.submitReboot()

	_, err := f.plans.Submit(context.Background(), f.caller(f.alice), created.Record.ID, created.Record.PlanHash)

	wantError(t, err, smerr.CodeConflict, smerr.ReasonAlreadySubmitted)
	if n := len(f.events("job.awaiting_approval")); n != 1 {
		t.Errorf("want exactly one job created, got %d", n)
	}
}

func TestSubmitReevaluatesPolicyAndDenialIsAudited(t *testing.T) {
	f := newFixture(t)
	created, err := f.plans.Create(context.Background(), f.caller(f.alice), f.reboot())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM role_bindings WHERE identity_id = ?`, f.alice)
		return err
	})

	_, err = f.plans.Submit(context.Background(), f.caller(f.alice), created.Record.ID, created.Record.PlanHash)

	wantError(t, err, smerr.CodePolicyDenied, smerr.ReasonDefaultDeny)
	if len(f.events("policy.deny")) != 1 {
		t.Errorf("denial at submit not audited")
	}
	if n := len(f.events("job.awaiting_approval", "job.queued")); n != 0 {
		t.Errorf("a denied submit created a job")
	}
}
