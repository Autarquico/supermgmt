package app

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
)

const (
	depCommit      = "0123456789abcdef0123456789abcdef01234567"
	depOtherCommit = "fedcba9876543210fedcba9876543210fedcba98"
	depWorkflowRef = "acme/web/" + automationDeployWorkflow + "@refs/heads/main"
)

var depWebDigest = "sha256:" + strings.Repeat("a", 64)

// depCanceller records the job cancels a deployment delegates.
type depCanceller struct {
	calls []depCancelCall
}

type depCancelCall struct {
	job      domain.ID
	planHash string
}

func (c *depCanceller) Cancel(_ context.Context, _ Caller, job domain.ID, planHash string) (jobs.Job, error) {
	c.calls = append(c.calls, depCancelCall{job: job, planHash: planHash})
	return jobs.Job{ID: job}, nil
}

// depFixture is an app with a target in dev, a deployer and a Deployments
// service whose job cancels are recorded.
type depFixture struct {
	*appsFixture
	deployments *Deployments
	canceller   *depCanceller
	deployer    domain.ID
	app         AppView
	target      AppTargetView
}

func newDepFixture(t *testing.T, gated bool) *depFixture {
	t.Helper()
	af := newAppsFixture(t)
	governance, err := NewGovernance(af.cfg, af.store)
	mustf(t, err, "NewGovernance")
	service, err := NewDeployments(af.cfg, governance, CIPolling{Initial: 10 * time.Second, Max: time.Minute, Timeout: time.Hour})
	mustf(t, err, "NewDeployments")
	f := &depFixture{appsFixture: af, deployments: service, canceller: &depCanceller{}}
	f.deployments.canceller = f.canceller
	if gated {
		f.app = af.createApp(withAutomation(af))
	} else {
		f.app = af.createApp()
	}
	f.target = af.mustTarget(f.app, "dev")
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		f.deployer = f.identity(ctx, tx, "dana", domain.ActorHuman, f.role(ctx, tx, "deployer"))
		return database.SetNodeCapability(ctx, tx, f.node.ID, database.NodeCapability{
			Capability: capabilityComposeDeploy, Available: true, CheckedAt: f.clock.Now(),
		})
	})
	return f
}

func (f *depFixture) request(mutate ...func(*CreateDeployment)) CreateDeployment {
	r := CreateDeployment{
		AppTargetID: f.target.ID, CommitSHA: depCommit,
		Images: []RequestedImage{{Service: "web", Digest: depWebDigest}},
	}
	for _, m := range mutate {
		m(&r)
	}
	return r
}

func (f *depFixture) create(mutate ...func(*CreateDeployment)) DeploymentView {
	f.t.Helper()
	view, err := f.deployments.Create(context.Background(), f.caller(f.deployer), f.request(mutate...))
	mustf(f.t, err, "Create")
	return view
}

func (f *depFixture) row(id domain.ID) database.Deployment {
	f.t.Helper()
	row, err := database.GetDeployment(context.Background(), f.db.Reader(), id)
	mustf(f.t, err, "GetDeployment")
	return row
}

func (f *depFixture) count() int {
	f.t.Helper()
	rows, err := database.ListDeployments(context.Background(), f.db.Reader(), database.DeploymentFilter{}, 100)
	mustf(f.t, err, "ListDeployments")
	return len(rows)
}

// oidcCaller is the app's automation identity presenting a verified Actions
// token whose stored claims are the defaults below, changed by mutate.
func (f *depFixture) oidcCaller(jti string, mutate ...func(*string)) Caller {
	f.t.Helper()
	claims := `{"repository_id":4242,"workflow_ref":"` + depWorkflowRef + `","sha":"` + depCommit +
		`","ref":"refs/heads/main","event_name":"push","run_id":9,"run_attempt":1}`
	for _, m := range mutate {
		m(&claims)
	}
	identity := *f.app.AutomationIdentityID
	id := database.GithubOIDCCredentialID("https://token.actions.githubusercontent.com", jti)
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		err := database.InsertGithubOIDCCredential(ctx, tx, database.GithubOIDCCredential{
			ID: id, IdentityID: identity, RepositoryID: 4242, ClaimsJSON: []byte(claims),
			IssuedAt: f.clock.Now(), ExpiresAt: f.clock.Now().Add(10 * time.Minute), CreatedAt: f.clock.Now(),
		})
		if err != nil {
			return err
		}
		return database.CreateRoleBinding(ctx, tx, database.RoleBinding{
			ID: f.ids.NewID(), IdentityID: identity, RoleID: f.role(ctx, tx, "deployer"), CreatedAt: f.clock.Now(),
		})
	})
	expires := f.clock.Now().Add(10 * time.Minute)
	return Caller{ID: identity, Credential: domain.CredentialContext{
		Kind: domain.CredentialGitHubOIDC, ID: id, Scopes: []string{"deployment.create", "deployment.read"}, ExpiresAt: &expires,
	}}
}

// ---- Create ---------------------------------------------------------------------------------

func TestDeploymentsCreate_WaitsForCIWithOnlyTheProvisionalInputs(t *testing.T) {
	f := newDepFixture(t, true)
	cred := f.caller(f.deployer).Credential

	view := f.create(func(r *CreateDeployment) {
		r.Images = []RequestedImage{{Service: "worker", Digest: "sha256:" + strings.Repeat("b", 64)}, {Service: "web", Digest: depWebDigest}}
	})

	if view.State != string(deployments.StateWaitingCI) || view.Kind != deployments.KindDeploy {
		t.Fatalf("state %q kind %q, want waiting_ci deploy", view.State, view.Kind)
	}
	if view.PlanHash != nil || view.PlanID != nil || view.JobID != nil || view.ComposeHash != nil {
		t.Errorf("a provisional deployment has no plan, job or compose hash: %+v", view)
	}
	if view.CommitSHA != depCommit || view.AppID != f.app.ID || view.NodeID != f.node.ID || view.RequestedBy != f.deployer {
		t.Errorf("view = %+v", view)
	}
	if len(view.Images) != 2 || view.Images[0].Service != "web" || view.Images[1].Service != "worker" {
		t.Errorf("images = %+v, want them sorted by service", view.Images)
	}
	row := f.row(view.ID)
	now := f.clock.Now()
	if row.CIDeadlineAt == nil || !row.CIDeadlineAt.Equal(now.Add(time.Hour)) || row.NextCICheck == nil || !row.NextCICheck.Equal(now) {
		t.Errorf("deadline %v, next check %v; want now+ci_timeout and now", row.CIDeadlineAt, row.NextCICheck)
	}
	if row.Credential.Kind != cred.Kind || row.Credential.ID != cred.ID {
		t.Errorf("credential context = %+v, want %+v", row.Credential, cred)
	}
	created := f.events(eventDeploymentCreated)
	if len(created) != 1 || created[0].ResourceID != view.ID || created[0].CorrelationID != view.ID.String() {
		t.Errorf("events = %+v, want one deployment.created correlated to the deployment", created)
	}
}

func TestDeploymentsCreate_WithoutACIGateStaysCreated(t *testing.T) {
	f := newDepFixture(t, false)

	view := f.create()

	row := f.row(view.ID)
	if view.State != string(deployments.StateCreated) || row.CIDeadlineAt != nil || row.NextCICheck != nil {
		t.Errorf("state %q deadline %v next %v; want created without CI scheduling", view.State, row.CIDeadlineAt, row.NextCICheck)
	}
}

func TestDeploymentsCreate_RejectsMalformedRequests(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*CreateDeployment)
	}{
		{"no target", func(r *CreateDeployment) { r.AppTargetID = "" }},
		{"short commit", func(r *CreateDeployment) { r.CommitSHA = depCommit[:12] }},
		{"upper-case commit", func(r *CreateDeployment) { r.CommitSHA = strings.ToUpper(depCommit) }},
		{"no images", func(r *CreateDeployment) { r.Images = nil }},
		{"tag instead of digest", func(r *CreateDeployment) { r.Images[0].Digest = "latest" }},
		{"short digest", func(r *CreateDeployment) { r.Images[0].Digest = "sha256:abc" }},
		{"sha512 digest", func(r *CreateDeployment) { r.Images[0].Digest = "sha512:" + strings.Repeat("a", 128) }},
		{"service with a slash", func(r *CreateDeployment) { r.Images[0].Service = "../web" }},
		{"service named twice", func(r *CreateDeployment) {
			r.Images = append(r.Images, RequestedImage{Service: "web", Digest: "sha256:" + strings.Repeat("c", 64)})
		}},
		{"deployed service missing", func(r *CreateDeployment) { r.Images[0].Service = "worker" }},
		{"too many images", func(r *CreateDeployment) {
			r.Images = nil
			for i := range maxRequestedImages + 1 {
				r.Images = append(r.Images, RequestedImage{Service: "s" + strings.Repeat("x", i%50) + string(rune('a'+i%26)), Digest: depWebDigest})
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newDepFixture(t, true)

			_, err := f.deployments.Create(context.Background(), f.caller(f.deployer), f.request(tc.mutate))

			wantAppsCode(t, err, smerr.CodeInvalidArgument)
			if f.count() != 0 {
				t.Errorf("a rejected request left %d deployments", f.count())
			}
		})
	}
}

func TestDeploymentsCreate_UnknownTargetIsNotFound(t *testing.T) {
	f := newDepFixture(t, true)

	_, err := f.deployments.Create(context.Background(), f.caller(f.deployer), f.request(func(r *CreateDeployment) { r.AppTargetID = "nope" }))

	wantAppsCode(t, err, smerr.CodeNotFound)
}

func TestDeploymentsCreate_PolicyDecidesWhoMayDeploy(t *testing.T) {
	f := newDepFixture(t, true)

	_, err := f.deployments.Create(context.Background(), f.caller(f.alice), f.request())

	wantAppsCode(t, err, smerr.CodePolicyDenied)
	if f.count() != 0 {
		t.Errorf("a denied request left %d deployments", f.count())
	}
	if denied := f.events("policy.deny"); len(denied) != 1 {
		t.Errorf("policy events = %+v, want the refusal audited", denied)
	}
}

func TestDeploymentsCreate_NeedsTheComposeDeployCapability(t *testing.T) {
	f := newDepFixture(t, true)
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		return database.SetNodeCapability(ctx, tx, f.node.ID, database.NodeCapability{
			Capability: capabilityComposeDeploy, Available: false, CheckedAt: f.clock.Now(),
		})
	})

	_, err := f.deployments.Create(context.Background(), f.caller(f.deployer), f.request())

	wantAppsCode(t, err, smerr.CodeCapabilityUnavailable)
}

func TestDeploymentsCreate_RefusesARevokedCredential(t *testing.T) {
	f := newDepFixture(t, true)
	caller := f.caller(f.deployer)
	f.creds.set(caller.Credential.ID, CredentialRevoked)

	_, err := f.deployments.Create(context.Background(), caller, f.request())

	wantError(t, err, smerr.CodeUnauthenticated, smerr.ReasonCredentialRevoked)
}

// ---- GitHub Actions entitlement ---------------------------------------------------------------

func TestDeploymentsCreate_AnActionsTokenDeploysTheCommitItWasIssuedFor(t *testing.T) {
	f := newDepFixture(t, true)
	caller := f.oidcCaller("jti-1")

	view, err := f.deployments.Create(context.Background(), caller, f.request())

	mustf(t, err, "Create")
	row := f.row(view.ID)
	if row.Credential.Kind != domain.CredentialGitHubOIDC || row.Credential.ID != caller.Credential.ID || row.RequestedBy != caller.ID {
		t.Errorf("credential context = %+v requested by %s, want the token's", row.Credential, row.RequestedBy)
	}
	if len(row.Credential.Scopes) != 2 || row.Credential.ExpiresAt == nil {
		t.Errorf("scopes %v expiry %v, want the token's implicit scopes and expiry", row.Credential.Scopes, row.Credential.ExpiresAt)
	}
}

func TestDeploymentsCreate_AnActionsTokenCannotDeployWhatItWasNotIssuedFor(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*string)
	}{
		{"another commit", func(c *string) { *c = strings.Replace(*c, depCommit, depOtherCommit, 1) }},
		{"another branch", func(c *string) { *c = strings.ReplaceAll(*c, "refs/heads/main", "refs/heads/dev") }},
		{"a pull request event", func(c *string) { *c = strings.Replace(*c, `"push"`, `"pull_request"`, 1) }},
		{"another repository", func(c *string) { *c = strings.Replace(*c, `"repository_id":4242`, `"repository_id":1`, 1) }},
		{"another workflow", func(c *string) { *c = strings.Replace(*c, "deploy.yml", "other.yml", 1) }},
		{"a reusable workflow the policy does not name", func(c *string) {
			*c = strings.Replace(*c, `"run_id"`, `"job_workflow_ref":"acme/shared/.github/workflows/d.yml@main","run_id"`, 1)
		}},
		{"no run", func(c *string) { *c = strings.Replace(*c, `"run_id":9`, `"run_id":0`, 1) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newDepFixture(t, true)
			caller := f.oidcCaller("jti-1", tc.mutate)

			_, err := f.deployments.Create(context.Background(), caller, f.request())

			wantAppsCode(t, err, smerr.CodePolicyDenied)
			if f.count() != 0 {
				t.Errorf("a refused token left %d deployments", f.count())
			}
		})
	}
}

func TestDeploymentsCreate_AnActionsTokenOfAnotherAppIsRefused(t *testing.T) {
	f := newDepFixture(t, true)
	other := f.createApp(withAutomation(f.appsFixture), func(r *wire.CreateAppRequest) {
		r.Name = "web2"
		r.CIPolicy.DeployWorkflow = ".github/workflows/deploy2.yml"
	})
	f.app = other
	caller := f.oidcCaller("jti-1")
	f.app = AppView{}

	_, err := f.deployments.Create(context.Background(), caller, f.request())

	wantAppsCode(t, err, smerr.CodePolicyDenied)
}

func TestDeploymentsCreate_ARevokedOrExpiredActionsTokenIsRefused(t *testing.T) {
	for _, state := range []CredentialState{CredentialRevoked, CredentialExpired} {
		t.Run(string(state), func(t *testing.T) {
			f := newDepFixture(t, true)
			caller := f.oidcCaller("jti-1")
			f.creds.set(caller.Credential.ID, state)

			_, err := f.deployments.Create(context.Background(), caller, f.request())

			wantAppsCode(t, err, smerr.CodeUnauthenticated)
		})
	}
}

// ---- Cancel ---------------------------------------------------------------------------------

func TestDeploymentsCancel_EndsAProvisionalDeploymentItself(t *testing.T) {
	for _, gated := range []bool{true, false} {
		t.Run(map[bool]string{true: "waiting_ci", false: "created"}[gated], func(t *testing.T) {
			f := newDepFixture(t, gated)
			created := f.create()

			view, err := f.deployments.Cancel(context.Background(), f.caller(f.deployer), created.ID)

			mustf(t, err, "Cancel")
			if view.State != string(deployments.StateCancelled) || view.FinishedAt == nil {
				t.Errorf("state %q finished %v, want cancelled and finished", view.State, view.FinishedAt)
			}
			if len(f.canceller.calls) != 0 {
				t.Errorf("no job exists, yet %d job cancels were requested", len(f.canceller.calls))
			}
			if events := f.events(eventDeploymentCancelled); len(events) != 1 || events[0].CorrelationID != created.ID.String() {
				t.Errorf("events = %+v, want one correlated deployment.cancelled", events)
			}
		})
	}
}

func TestDeploymentsCancel_ARepeatedCancelIsAConflict(t *testing.T) {
	f := newDepFixture(t, true)
	created := f.create()
	_, err := f.deployments.Cancel(context.Background(), f.caller(f.deployer), created.ID)
	mustf(t, err, "first Cancel")

	_, err = f.deployments.Cancel(context.Background(), f.caller(f.deployer), created.ID)

	wantError(t, err, smerr.CodeConflict, smerr.ReasonInvalidTransition)
}

func TestDeploymentsCancel_NeedsJobCancelPolicy(t *testing.T) {
	f := newDepFixture(t, true)
	created := f.create()

	_, err := f.deployments.Cancel(context.Background(), f.caller(f.dave), created.ID)

	wantAppsCode(t, err, smerr.CodePolicyDenied)
	if got := f.row(created.ID).State; got != deployments.StateWaitingCI {
		t.Errorf("state = %s, want waiting_ci: a refused cancel changes nothing", got)
	}
}

func TestDeploymentsCancel_UnknownDeploymentIsNotFound(t *testing.T) {
	f := newDepFixture(t, true)

	_, err := f.deployments.Cancel(context.Background(), f.caller(f.deployer), "nope")

	wantAppsCode(t, err, smerr.CodeNotFound)
}

func TestDeploymentsCancel_DelegatesToTheJobOnceOneExists(t *testing.T) {
	f := newDepFixture(t, true)
	created := f.create()
	sub, _ := f.submitReboot()
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		return database.BindDeploymentPlan(ctx, tx, created.ID, *sub.Job.PlanID, sub.Job.ID, sub.Job.PlanHash, "sha256:"+strings.Repeat("d", 64), f.clock.Now())
	})

	view, err := f.deployments.Cancel(context.Background(), f.caller(f.deployer), created.ID)

	mustf(t, err, "Cancel")
	if len(f.canceller.calls) != 1 || f.canceller.calls[0].job != sub.Job.ID || f.canceller.calls[0].planHash != sub.Job.PlanHash {
		t.Fatalf("job cancels = %+v, want the deployment's job with its plan hash", f.canceller.calls)
	}
	if view.JobID == nil || *view.JobID != sub.Job.ID || view.PlanHash == nil || *view.PlanHash != sub.Job.PlanHash {
		t.Errorf("view = %+v, want it to show the bound job and plan hash", view)
	}
}

// ---- Get and List ----------------------------------------------------------------------------

func TestDeploymentsGet_ShowsStepsAndFailure(t *testing.T) {
	f := newDepFixture(t, true)
	created := f.create()
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		started := f.clock.Now()
		err := database.InsertDeploymentStep(ctx, tx, database.DeploymentStep{
			ID: f.ids.NewID(), DeploymentID: created.ID, Ordinal: 1, Name: deployments.StepPreflight,
			State: database.StepFailed, StartedAt: &started,
			ErrorJSON: []byte(`{"code":"DEPLOYMENT_FAILED","reason":"PREFLIGHT_FAILED","cause":"IMAGE_SIZE_UNKNOWN","message":"no size"}`),
		})
		if err != nil {
			return err
		}
		return database.TransitionDeployment(ctx, tx, created.ID, deployments.StateFailed,
			database.StateFailure{Code: "DEPLOYMENT_FAILED", Reason: "PREFLIGHT_FAILED", Cause: "IMAGE_SIZE_UNKNOWN"}, f.clock.Now())
	})

	view, err := f.deployments.Get(context.Background(), f.caller(f.alice), created.ID)

	mustf(t, err, "Get")
	if view.State != "failed" || view.StateCode != smerr.CodeDeploymentFailed || view.StateReason != smerr.ReasonPreflightFailed {
		t.Errorf("state %q code %q reason %q", view.State, view.StateCode, view.StateReason)
	}
	if len(view.Steps) != 1 || view.Steps[0].Name != deployments.StepPreflight || view.Steps[0].Error == nil || view.Steps[0].Error.Cause != "IMAGE_SIZE_UNKNOWN" {
		t.Errorf("steps = %+v", view.Steps)
	}
}

func TestDeploymentsGet_RefusesAnIdentityWithoutRead(t *testing.T) {
	f := newDepFixture(t, true)
	created := f.create()

	_, err := f.deployments.Get(context.Background(), f.caller(f.dave), created.ID)

	wantAppsCode(t, err, smerr.CodePolicyDenied)
}

func TestDeploymentsList_ReturnsTheReadableOnesNewestFirstInPages(t *testing.T) {
	f := newDepFixture(t, true)
	first := f.create()
	f.clock.Advance(time.Minute)
	second := f.create(func(r *CreateDeployment) { r.CommitSHA = depOtherCommit })

	page, err := f.deployments.List(context.Background(), f.caller(f.alice), database.DeploymentFilter{}, wire.PageQuery{Limit: 1})
	mustf(t, err, "List")
	if len(page.Items) != 1 || page.Items[0].ID != second.ID || page.NextCursor == "" {
		t.Fatalf("first page = %+v, want only the newest and a cursor", page)
	}
	rest, err := f.deployments.List(context.Background(), f.caller(f.alice), database.DeploymentFilter{}, wire.PageQuery{Limit: 1, Cursor: page.NextCursor})
	mustf(t, err, "List page 2")
	if len(rest.Items) != 1 || rest.Items[0].ID != first.ID || rest.NextCursor != "" {
		t.Errorf("second page = %+v, want the older one and no cursor", rest)
	}
	none, err := f.deployments.List(context.Background(), f.caller(f.dave), database.DeploymentFilter{}, wire.PageQuery{})
	mustf(t, err, "List as dave")
	if len(none.Items) != 0 {
		t.Errorf("an identity without read saw %d deployments", len(none.Items))
	}
}
