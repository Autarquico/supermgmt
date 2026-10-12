package database

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// deploymentWorld holds the parent rows every deployment needs.
type deploymentWorld struct {
	f      *fixture
	target domain.ID
}

func newDeploymentWorld(t *testing.T) *deploymentWorld {
	t.Helper()
	f := newFixture(t)
	w := &deploymentWorld{f: f, target: "target-1"}
	f.tx(func(ctx context.Context, q Querier) {
		for _, stmt := range []string{
			`INSERT INTO identities (id, actor_type, created_at) VALUES ('id-1', 'human', 1)`,
			`INSERT INTO providers (id, type, name, origin, created_at, updated_at) VALUES ('prov-1', 'ssh', 'ssh', 'static', 1, 1)`,
			`INSERT INTO nodes (id, provider_id, native_id, name, kind, management_state, reachability, created_at, updated_at)
				VALUES ('node-1', 'prov-1', 'n', 'n', 'host', 'managed', 'unknown', 1, 1)`,
			`INSERT INTO environments (id, name, risk_level) VALUES ('env-1', 'prod', 'production')`,
			`INSERT INTO apps (id, name, deployed_service, image_policy_json, compose_source, created_at, updated_at)
				VALUES ('app-1', 'web', 'web', '{}', 'control-plane', 1, 1)`,
			`INSERT INTO app_targets (id, app_id, environment_id, node_id, compose_project, deployment_policy_json, created_at, updated_at)
				VALUES ('target-1', 'app-1', 'env-1', 'node-1', 'web-prod', '{}', 1, 1)`,
		} {
			if _, err := q.ExecContext(ctx, stmt); err != nil {
				t.Fatalf("seed parents: %v", err)
			}
		}
	})
	return w
}

func (w *deploymentWorld) deployment(id string, at time.Time) Deployment {
	return Deployment{
		ID: domain.ID(id), Kind: deployments.KindDeploy, AppID: "app-1", AppTargetID: w.target,
		EnvironmentID: "env-1", NodeID: "node-1", State: deployments.StateCreated, RequestedBy: "id-1",
		CommitSha: "abc", RequestedRaw: json.RawMessage(`{"images":[]}`),
		Credential: domain.CredentialContext{Kind: domain.CredentialSession, ID: "sess", Scopes: []string{"deployment.create"}},
		CreatedAt:  at, UpdatedAt: at,
	}
}

func (w *deploymentWorld) insert(id string, at time.Time) Deployment {
	d := w.deployment(id, at)
	w.f.tx(func(ctx context.Context, q Querier) { noErr(w.f.t, InsertDeployment(ctx, q, d)) })
	return d
}

// walk moves a deployment through states, failing the test on a rejected step.
func (w *deploymentWorld) walk(id domain.ID, at time.Time, states ...deployments.State) {
	w.f.tx(func(ctx context.Context, q Querier) {
		for _, s := range states {
			noErr(w.f.t, TransitionDeployment(ctx, q, id, s, StateFailure{}, at))
		}
	})
}

func (w *deploymentWorld) get(id domain.ID) Deployment {
	var d Deployment
	w.f.tx(func(ctx context.Context, q Querier) { d = must(GetDeployment(ctx, q, id)) })
	return d
}

func TestDeploymentRoundTripsItsProvisionalInputs(t *testing.T) {
	w := newDeploymentWorld(t)
	expires := testEpoch.Add(time.Hour)
	d := w.deployment("dep-1", testEpoch)
	d.Credential.ExpiresAt = &expires
	d.CIDeadlineAt = &expires
	d.NextCICheck = &testEpoch
	w.f.tx(func(ctx context.Context, q Querier) { noErr(t, InsertDeployment(ctx, q, d)) })

	got := w.get("dep-1")
	if got.State != deployments.StateCreated || got.Strategy != "docker-compose" || got.CommitSha != "abc" {
		t.Fatalf("deployment = %+v", got)
	}
	if got.Credential.Kind != domain.CredentialSession || !slices.Equal(got.Credential.Scopes, []string{"deployment.create"}) ||
		got.Credential.ExpiresAt == nil || !got.Credential.ExpiresAt.Equal(expires) {
		t.Fatalf("credential context = %+v", got.Credential)
	}
	if got.JobID != nil || got.PlanID != nil || got.PlanHash != "" || got.Recovery != nil || got.KnownGood || got.MutationStarted {
		t.Fatalf("a provisional deployment carries finalization state: %+v", got)
	}
	if got.CIDeadlineAt == nil || got.NextCICheck == nil || got.FinishedAt != nil {
		t.Fatalf("timestamps = %+v", got)
	}
}

func TestDeploymentMissingAndDuplicate(t *testing.T) {
	w := newDeploymentWorld(t)
	w.insert("dep-1", testEpoch)
	w.f.tx(func(ctx context.Context, q Querier) {
		_, err := GetDeployment(ctx, q, "nope")
		wantError(t, err, smerr.CodeNotFound, "")
		wantError(t, InsertDeployment(ctx, q, w.deployment("dep-1", testEpoch)), smerr.CodeConflict, "")
		wantError(t, TransitionDeployment(ctx, q, "nope", deployments.StateFailed, StateFailure{}, testEpoch), smerr.CodeNotFound, "")
	})
}

func TestTransitionFollowsTheStateMachineAndRecordsMutation(t *testing.T) {
	w := newDeploymentWorld(t)
	w.insert("dep-1", testEpoch)
	w.walk("dep-1", testEpoch, deployments.StateQueued, deployments.StatePreparing, deployments.StateStaging)
	if w.get("dep-1").MutationStarted {
		t.Fatal("staging marked the mutation as started")
	}
	w.walk("dep-1", testEpoch, deployments.StateDeploying)
	if !w.get("dep-1").MutationStarted {
		t.Fatal("deploying did not mark the mutation as started")
	}
	w.walk("dep-1", testEpoch, deployments.StateInterrupted)
	if got := w.get("dep-1"); !got.MutationStarted || got.FinishedAt != nil {
		t.Fatalf("interrupted lost the mutation flag or finished: %+v", got)
	}

	w.f.tx(func(ctx context.Context, q Querier) {
		wantError(t, TransitionDeployment(ctx, q, "dep-1", deployments.StateCreated, StateFailure{}, testEpoch),
			smerr.CodeConflict, smerr.ReasonInvalidTransition)
	})
}

func TestTransitionToATerminalStateStampsFinishAndFailure(t *testing.T) {
	w := newDeploymentWorld(t)
	w.insert("dep-1", testEpoch)
	finish := testEpoch.Add(time.Minute)
	failure := StateFailure{Code: "PREFLIGHT_FAILED", Reason: "PREFLIGHT_FAILED", Cause: "IMAGE_SIZE_UNKNOWN"}
	w.f.tx(func(ctx context.Context, q Querier) {
		noErr(t, TransitionDeployment(ctx, q, "dep-1", deployments.StateFailed, failure, finish))
		wantError(t, TransitionDeployment(ctx, q, "dep-1", deployments.StateQueued, StateFailure{}, finish),
			smerr.CodeConflict, smerr.ReasonInvalidTransition)
	})
	got := w.get("dep-1")
	if got.State != deployments.StateFailed || got.Failure != failure || got.FinishedAt == nil || !got.FinishedAt.Equal(finish) {
		t.Fatalf("failed deployment = %+v", got)
	}
}

func TestACauseNeedsAReason(t *testing.T) {
	w := newDeploymentWorld(t)
	w.insert("dep-1", testEpoch)
	w.f.tx(func(ctx context.Context, q Querier) {
		err := TransitionDeployment(ctx, q, "dep-1", deployments.StateFailed, StateFailure{Cause: "STATEFUL"}, testEpoch)
		if err == nil {
			t.Fatal("a cause without a reason was stored")
		}
	})
}

func TestBindDeploymentPlanBindsOnceAndJobsAreNotShared(t *testing.T) {
	w := newDeploymentWorld(t)
	w.insert("dep-1", testEpoch)
	w.insert("dep-2", testEpoch)
	w.f.tx(func(ctx context.Context, q Querier) {
		for _, stmt := range []string{
			`INSERT INTO jobs (id, type, resource_type, resource_id, actor_id, credential_kind, state, risk, retry_class, scheduled_at, created_at)
				VALUES ('job-1', 'deployment.create', 'deployment', 'dep-1', 'id-1', 'session', 'queued', 'high', 'resumable', 1, 1)`,
		} {
			if _, err := q.ExecContext(ctx, stmt); err != nil {
				t.Fatal(err)
			}
		}
		for _, id := range []domain.ID{"plan-1", "plan-2"} {
			noErr(t, InsertPlan(ctx, q, PlanRecord{
				ID: id, Action: "deployment.create", ActorID: "id-1", PlanJSON: []byte("{}"), PlanHash: "sha256:" + string(id),
				Credential:  domain.CredentialContext{Kind: domain.CredentialSession},
				FinalizedAt: testEpoch, CreatedAt: testEpoch, ExpiresAt: testEpoch.Add(time.Hour),
			}))
		}
		noErr(t, BindDeploymentPlan(ctx, q, "dep-1", "plan-1", "job-1", "sha256:plan-1", "sha256:compose", testEpoch))
		wantError(t, BindDeploymentPlan(ctx, q, "dep-1", "plan-2", "job-1", "sha256:plan-2", "sha256:c", testEpoch), smerr.CodeConflict, "")
		wantError(t, BindDeploymentPlan(ctx, q, "dep-2", "plan-2", "job-1", "sha256:plan-2", "sha256:c", testEpoch), smerr.CodeConflict, "")
		wantError(t, BindDeploymentPlan(ctx, q, "nope", "plan-2", "job-1", "sha256:plan-2", "sha256:c", testEpoch), smerr.CodeNotFound, "")

		byJob := must(GetDeploymentByJob(ctx, q, "job-1"))
		if byJob.ID != "dep-1" || byJob.PlanHash != "sha256:plan-1" || byJob.ComposeHash != "sha256:compose" ||
			byJob.PlanID == nil || *byJob.PlanID != "plan-1" {
			t.Fatalf("bound deployment = %+v", byJob)
		}
		_, err := GetDeploymentByJob(ctx, q, "job-9")
		wantError(t, err, smerr.CodeNotFound, "")
	})
}

func TestRecoveryRecordIsWrittenAndReadWhole(t *testing.T) {
	w := newDeploymentWorld(t)
	w.insert("dep-1", testEpoch)
	w.insert("dep-old", testEpoch.Add(-time.Hour))
	target := domain.ID("dep-old")
	w.f.tx(func(ctx context.Context, q Querier) {
		got, err := GetDeploymentRecovery(ctx, q, "dep-1")
		noErr(t, err)
		if got != nil {
			t.Fatalf("recovery before any verdict = %+v", got)
		}

		forward := deployments.Recovery{Mode: deployments.RecoveryForward, ResumeStep: "pull", Reason: "complete"}
		noErr(t, SetDeploymentRecovery(ctx, q, "dep-1", forward, testEpoch))
		if got := must(GetDeploymentRecovery(ctx, q, "dep-1")); *got != forward {
			t.Fatalf("forward record = %+v", got)
		}

		safety := deployments.Recovery{Mode: deployments.RecoverySafetyRecovery, ResumeStep: "restore-pull", Reason: "REVOKED", Target: &target}
		noErr(t, SetDeploymentRecovery(ctx, q, "dep-1", safety, testEpoch))
		got = must(GetDeploymentRecovery(ctx, q, "dep-1"))
		if got.Mode != safety.Mode || got.ResumeStep != safety.ResumeStep || got.Reason != safety.Reason ||
			got.Target == nil || *got.Target != target {
			t.Fatalf("safety record = %+v", got)
		}

		_, err = GetDeploymentRecovery(ctx, q, "nope")
		wantError(t, err, smerr.CodeNotFound, "")
		wantError(t, SetDeploymentRecovery(ctx, q, "nope", forward, testEpoch), smerr.CodeNotFound, "")
	})
}

func TestRecoveryRecordRejectsInconsistentModes(t *testing.T) {
	w := newDeploymentWorld(t)
	w.insert("dep-1", testEpoch)
	target := domain.ID("dep-1")
	for name, r := range map[string]deployments.Recovery{
		"safety recovery without a target": {Mode: deployments.RecoverySafetyRecovery},
		"forward with a target":            {Mode: deployments.RecoveryForward, Target: &target},
		"unknown mode":                     {Mode: "sideways"},
	} {
		t.Run(name, func(t *testing.T) {
			w.f.tx(func(ctx context.Context, q Querier) {
				wantError(t, SetDeploymentRecovery(ctx, q, "dep-1", r, testEpoch), smerr.CodeInvalidArgument, "")
			})
			if w.get("dep-1").Recovery != nil {
				t.Fatal("a rejected record was stored")
			}
		})
	}
}

func TestKnownGoodNeedsASucceededDeploymentAndIsQueriedNewestFirst(t *testing.T) {
	w := newDeploymentWorld(t)
	var ids []domain.ID
	for i, name := range []string{"dep-1", "dep-2", "dep-3", "dep-4"} {
		at := testEpoch.Add(time.Duration(i) * time.Hour)
		w.insert(name, at)
		ids = append(ids, domain.ID(name))
	}
	for _, id := range ids[:3] { // dep-4 stays created
		w.walk(id, testEpoch, deployments.StateQueued, deployments.StatePreparing, deployments.StateStaging,
			deployments.StateDeploying, deployments.StateVerifying)
	}
	for i, id := range ids[:2] { // dep-1, dep-2 succeed; dep-3 is still verifying
		w.f.tx(func(ctx context.Context, q Querier) {
			noErr(t, TransitionDeployment(ctx, q, id, deployments.StateSucceeded, StateFailure{}, testEpoch.Add(time.Duration(i)*time.Minute)))
		})
	}

	w.f.tx(func(ctx context.Context, q Querier) {
		_, err := NewestKnownGood(ctx, q, w.target, nil)
		wantError(t, err, smerr.CodeNotFound, "")

		wantError(t, MarkDeploymentKnownGood(ctx, q, "dep-3", testEpoch), smerr.CodeConflict, smerr.ReasonInvalidTransition)
		wantError(t, MarkDeploymentKnownGood(ctx, q, "nope", testEpoch), smerr.CodeNotFound, "")
		noErr(t, MarkDeploymentKnownGood(ctx, q, "dep-1", testEpoch))
		noErr(t, MarkDeploymentKnownGood(ctx, q, "dep-2", testEpoch))

		if got := must(NewestKnownGood(ctx, q, w.target, nil)); got.ID != "dep-2" || !got.KnownGood {
			t.Fatalf("newest known good = %+v, want dep-2", got)
		}
		before := domain.ID("dep-2")
		if got := must(NewestKnownGood(ctx, q, w.target, &before)); got.ID != "dep-1" {
			t.Fatalf("known good before dep-2 = %s, want dep-1", got.ID)
		}
		before = "dep-3" // not itself known good: the newest older one answers
		if got := must(NewestKnownGood(ctx, q, w.target, &before)); got.ID != "dep-2" {
			t.Fatalf("known good before dep-3 = %s, want dep-2", got.ID)
		}
		first := domain.ID("dep-1")
		_, err = NewestKnownGood(ctx, q, w.target, &first)
		wantError(t, err, smerr.CodeNotFound, "")
		_, err = NewestKnownGood(ctx, q, "other-target", nil)
		wantError(t, err, smerr.CodeNotFound, "")
	})
}

func TestListDeploymentsFiltersAndOrdersNewestFirst(t *testing.T) {
	w := newDeploymentWorld(t)
	w.insert("dep-1", testEpoch)
	w.insert("dep-2", testEpoch.Add(time.Minute))
	w.insert("dep-3", testEpoch.Add(2*time.Minute))
	w.walk("dep-2", testEpoch, deployments.StateQueued)

	ids := func(f DeploymentFilter, limit int) []domain.ID {
		var out []domain.ID
		w.f.tx(func(ctx context.Context, q Querier) {
			for _, d := range must(ListDeployments(ctx, q, f, limit)) {
				out = append(out, d.ID)
			}
		})
		return out
	}
	if got := ids(DeploymentFilter{}, 10); !slices.Equal(got, []domain.ID{"dep-3", "dep-2", "dep-1"}) {
		t.Fatalf("all = %v", got)
	}
	if got := ids(DeploymentFilter{AppTargetID: w.target, State: deployments.StateQueued}, 10); !slices.Equal(got, []domain.ID{"dep-2"}) {
		t.Fatalf("queued on target = %v", got)
	}
	if got := ids(DeploymentFilter{}, 2); len(got) != 2 {
		t.Fatalf("limit ignored: %v", got)
	}
	if got := ids(DeploymentFilter{AppID: "other"}, 10); len(got) != 0 {
		t.Fatalf("filter by another app = %v", got)
	}
}

func TestDueCIChecksListOnlyWaitingDeploymentsThatAreDue(t *testing.T) {
	w := newDeploymentWorld(t)
	for _, c := range []struct {
		id   string
		next time.Duration
	}{{"dep-late", 10 * time.Minute}, {"dep-due-2", 2 * time.Minute}, {"dep-due-1", time.Minute}, {"dep-not-waiting", time.Minute}} {
		d := w.deployment(c.id, testEpoch)
		next := testEpoch.Add(c.next)
		d.NextCICheck = &next
		w.f.tx(func(ctx context.Context, q Querier) { noErr(t, InsertDeployment(ctx, q, d)) })
		if c.id != "dep-not-waiting" {
			w.walk(domain.ID(c.id), testEpoch, deployments.StateWaitingCI)
		}
	}
	w.f.tx(func(ctx context.Context, q Querier) {
		var got []domain.ID
		for _, d := range must(ListDueCIChecks(ctx, q, testEpoch.Add(5*time.Minute), 10)) {
			got = append(got, d.ID)
		}
		if !slices.Equal(got, []domain.ID{"dep-due-1", "dep-due-2"}) {
			t.Fatalf("due = %v", got)
		}
		noErr(t, ScheduleCICheck(ctx, q, "dep-late", testEpoch, testEpoch))
		if n := len(must(ListDueCIChecks(ctx, q, testEpoch.Add(5*time.Minute), 10))); n != 3 {
			t.Fatalf("due after rescheduling = %d, want 3", n)
		}
		wantError(t, ScheduleCICheck(ctx, q, "nope", testEpoch, testEpoch), smerr.CodeNotFound, "")
	})
}

func TestDeploymentStepsKeepEveryAttemptInOrder(t *testing.T) {
	w := newDeploymentWorld(t)
	w.insert("dep-1", testEpoch)
	w.f.tx(func(ctx context.Context, q Querier) {
		step := func(id string, ordinal int, name string, attempt int) DeploymentStep {
			return DeploymentStep{ID: domain.ID(id), DeploymentID: "dep-1", Ordinal: ordinal, Name: name, State: StepPending, Attempt: attempt}
		}
		noErr(t, InsertDeploymentStep(ctx, q, step("s-pull-1", 4, "pull", 0)))
		noErr(t, InsertDeploymentStep(ctx, q, step("s-pre", 1, "preflight", 1)))
		noErr(t, InsertDeploymentStep(ctx, q, step("s-pull-2", 4, "pull", 2)))
		wantError(t, InsertDeploymentStep(ctx, q, step("s-dup", 4, "pull", 1)), smerr.CodeConflict, "")

		started, finished := testEpoch, testEpoch.Add(time.Second)
		noErr(t, UpdateDeploymentStep(ctx, q, DeploymentStep{
			ID: "s-pre", State: StepSucceeded, StartedAt: &started, FinishedAt: &finished, OutputRef: "/srv/backup.sql",
		}))
		noErr(t, UpdateDeploymentStep(ctx, q, DeploymentStep{
			ID: "s-pull-1", State: StepFailed, StartedAt: &started, ErrorJSON: json.RawMessage(`{"code":"STAGING_FAILED"}`),
		}))
		wantError(t, UpdateDeploymentStep(ctx, q, DeploymentStep{ID: "nope", State: StepRunning}), smerr.CodeNotFound, "")

		got := must(ListDeploymentSteps(ctx, q, "dep-1"))
		var order []domain.ID
		for _, s := range got {
			order = append(order, s.ID)
		}
		if !slices.Equal(order, []domain.ID{"s-pre", "s-pull-1", "s-pull-2"}) {
			t.Fatalf("order = %v", order)
		}
		if p := got[0]; p.State != StepSucceeded || p.OutputRef != "/srv/backup.sql" || p.FinishedAt == nil || !p.FinishedAt.Equal(finished) || p.ErrorJSON != nil {
			t.Fatalf("preflight step = %+v", p)
		}
		if p := got[1]; p.State != StepFailed || p.Attempt != 1 || string(p.ErrorJSON) != `{"code":"STAGING_FAILED"}` || p.OutputRef != "" {
			t.Fatalf("first pull attempt = %+v", p)
		}
		if other := must(ListDeploymentSteps(ctx, q, "dep-other")); len(other) != 0 {
			t.Fatalf("steps of another deployment = %v", other)
		}
	})
}

func TestReplaceHealthChecksSwapsTheWholeSet(t *testing.T) {
	w := newDeploymentWorld(t)
	check := func(id, typ, scope string, enabled bool, at time.Time) HealthCheck {
		return HealthCheck{ID: domain.ID(id), Type: typ, Scope: scope, Config: json.RawMessage(`{"port":8080}`), Enabled: enabled, CreatedAt: at}
	}
	w.f.tx(func(ctx context.Context, q Querier) {
		noErr(t, ReplaceHealthChecks(ctx, q, w.target, []HealthCheck{
			check("hc-1", "http", "node", true, testEpoch),
			check("hc-2", "tcp", "node", false, testEpoch.Add(time.Second)),
		}))
		all := must(ListHealthChecks(ctx, q, w.target, false))
		if len(all) != 2 || all[0].ID != "hc-1" || all[0].ResourceType != ResourceAppTarget || all[0].SpecRevision != 1 ||
			string(all[0].Config) != `{"port":8080}` {
			t.Fatalf("checks = %+v", all)
		}
		if enabled := must(ListHealthChecks(ctx, q, w.target, true)); len(enabled) != 1 || enabled[0].ID != "hc-1" {
			t.Fatalf("enabled checks = %+v", enabled)
		}

		noErr(t, ReplaceHealthChecks(ctx, q, w.target, []HealthCheck{check("hc-3", "docker-health", "node", true, testEpoch)}))
		if all := must(ListHealthChecks(ctx, q, w.target, false)); len(all) != 1 || all[0].ID != "hc-3" {
			t.Fatalf("checks after replace = %+v", all)
		}
		noErr(t, ReplaceHealthChecks(ctx, q, w.target, nil))
		if all := must(ListHealthChecks(ctx, q, w.target, false)); len(all) != 0 {
			t.Fatalf("checks after clearing = %+v", all)
		}
	})
}

func TestReplaceHealthChecksRefusesAnUnknownType(t *testing.T) {
	w := newDeploymentWorld(t)
	w.f.tx(func(ctx context.Context, q Querier) {
		err := ReplaceHealthChecks(ctx, q, w.target, []HealthCheck{{ID: "hc-1", Type: "command-template", Scope: "node", Config: json.RawMessage(`{}`), CreatedAt: testEpoch}})
		if err == nil {
			t.Fatal("a health check type outside the M4 set was stored")
		}
	})
}
