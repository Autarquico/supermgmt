package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/plan"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/policy"
	"github.com/autarquico/supermgmt/internal/providers/github"
)

const (
	appsWebCompose = `
services:
  web:
    image: ghcr.io/acme/web:placeholder
    environment:
      DATABASE_URL: ${secret:db}
    ports:
      - {target: 8080, published: 8080, host_ip: 127.0.0.1}
`
	appsRedisPinned  = "docker.io/library/redis@sha256:3333333333333333333333333333333333333333333333333333333333333333"
	appsWithSidecars = `
services:
  web:
    image: ghcr.io/acme/web:placeholder
    ports:
      - {target: 8080, published: 8080, host_ip: 127.0.0.1}
  redis:
    image: ` + appsRedisPinned + `
`
	appsPrivilegedCompose = `
services:
  web:
    image: ghcr.io/acme/web:placeholder
    privileged: true
`
	appsLANCompose = `
services:
  web:
    image: ghcr.io/acme/web:placeholder
    ports:
      - {target: 8080, published: 8080, host_ip: 192.168.1.5}
`
	appsTagSidecarCompose = `
services:
  web:
    image: ghcr.io/acme/web:placeholder
  redis:
    image: docker.io/library/redis:7
`
)

// appsGitHub answers repository lookups from a table and counts every use.
type appsGitHub struct {
	mu       sync.Mutex
	repos    map[int64]github.Repo
	calls    int
	pages    []github.Page
	listFail error
}

func (g *appsGitHub) For(context.Context, domain.ID) (github.Client, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.calls++
	return appsGitHubClient{Client: nil, g: g}, nil
}

func (g *appsGitHub) used() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.calls
}

type appsGitHubClient struct {
	github.Client
	g *appsGitHub
}

func (c appsGitHubClient) Repository(_ context.Context, id int64) (github.Repo, error) {
	repo, ok := c.g.repos[id]
	if !ok {
		return github.Repo{}, &github.APIError{Status: http.StatusNotFound, Message: "Not Found"}
	}
	return repo, nil
}

// appsFixture is the base fixture plus an Apps service whose plan builder
// stands in for the one T9b adds; gated makes its plans target a production
// environment, so policy asks for approval.
type appsFixture struct {
	*fixture
	apps     *Apps
	gh       *appsGitHub
	ghHost   domain.Provider
	dev      domain.Environment
	staging  domain.Environment
	gated    bool
	retired  domain.Node
	repoMain github.Repo
}

func newAppsFixture(t *testing.T) *appsFixture {
	t.Helper()
	f := newFixture(t)
	af := &appsFixture{
		fixture:  f,
		repoMain: github.Repo{ID: 4242, OwnerID: 77, Owner: "acme", Name: "web", URL: "https://github.com/acme/web", DefaultBranch: "main"},
	}
	af.gh = &appsGitHub{repos: map[int64]github.Repo{af.repoMain.ID: af.repoMain}}
	apps, err := NewApps(f.cfg, f.store, af.gh)
	mustf(t, err, "NewApps")
	apps.build = af.planFor
	af.apps = apps
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		now := f.clock.Now()
		var err error
		af.ghHost, err = database.CreateProvider(ctx, tx, domain.Provider{
			ID: f.ids.NewID(), Type: github.ProviderType, Name: "github", Origin: domain.ProviderAPI,
			Endpoint: "https://api.github.com", CredentialRef: "secret://providers/github/token", CreatedAt: now, UpdatedAt: now,
		})
		if err != nil {
			return err
		}
		af.dev, err = database.CreateEnvironment(ctx, tx, domain.Environment{ID: f.ids.NewID(), Name: "dev", RiskLevel: domain.EnvironmentDevelopment})
		if err != nil {
			return err
		}
		af.staging, err = database.CreateEnvironment(ctx, tx, domain.Environment{ID: f.ids.NewID(), Name: "staging", RiskLevel: domain.EnvironmentStaging})
		if err != nil {
			return err
		}
		af.retired, err = database.CreateNode(ctx, tx, domain.Node{
			ID: f.ids.NewID(), ProviderID: f.provider.ID, NativeID: "old-1", Name: "old-1", Kind: "ssh",
			ManagementState: domain.ManagementRetired, Reachability: domain.ReachabilityUnknown,
			Endpoint:  domain.NodeEndpoint{Host: "10.0.0.9", Port: 22, User: "supermgmt", AdminUser: "admin", HostPublicKey: testHostKey},
			CreatedAt: now, UpdatedAt: now,
		})
		return err
	})
	return af
}

// planFor is the stand-in for build: the plan of a direct action, gated or not.
func (a *appsFixture) planFor(_ context.Context, _ database.Querier, action string, actorID domain.ID, ref domain.ResourceRef, params map[string]any) (built, error) {
	spec, ok := policy.Lookup(action)
	if !ok {
		return built{}, errors.New("unknown action " + action)
	}
	spec.Retry, spec.MaxAttempts = retryOfDirect(action)
	attrs := policy.Attributes{}
	if a.gated {
		attrs = policy.Attributes{Environment: a.env.Name, EnvironmentRisk: a.env.RiskLevel, ApprovalsRequired: a.env.ApprovalsRequired}
	}
	return built{
		spec:   spec,
		target: policy.Target{Ref: ref, Attrs: attrs},
		plan: plan.Plan{
			Version: plan.Version, Action: action, Actor: "identity/" + actorID.String(),
			Targets:    []plan.Target{{Type: string(ref.Type), ID: ref.ID.String()}},
			Parameters: params, Risk: spec.Risk,
		},
	}, nil
}

func (a *appsFixture) createRequest(mutate ...func(*wire.CreateAppRequest)) wire.CreateAppRequest {
	r := wire.CreateAppRequest{
		Name: "web", DeployedService: "web", ImagePolicy: wire.ImagePolicy{Deployed: "ghcr.io/acme/web"},
		ComposeContent: appsWebCompose, SecretRefs: map[string]string{"db": "secret://apps/web/database_url"},
	}
	for _, m := range mutate {
		m(&r)
	}
	return r
}

func (a *appsFixture) createApp(mutate ...func(*wire.CreateAppRequest)) AppView {
	a.t.Helper()
	res, err := a.apps.Create(context.Background(), a.caller(a.admin), a.createRequest(mutate...))
	mustf(a.t, err, "Create")
	if res.Applied == nil {
		a.t.Fatalf("Create did not apply: %+v", res)
	}
	return *res.Applied
}

func (a *appsFixture) createTarget(app AppView, env string, node domain.ID, mutate ...func(*wire.DeploymentPolicy)) (DirectResult[AppTargetView], error) {
	policy := wire.DeploymentPolicy{Rollback: rollbackAutomatic}
	for _, m := range mutate {
		m(&policy)
	}
	return a.apps.CreateTarget(context.Background(), a.caller(a.admin), app.ID,
		wire.CreateAppTargetRequest{Environment: env, NodeID: node, DeploymentPolicy: policy})
}

func (a *appsFixture) mustTarget(app AppView, env string, mutate ...func(*wire.DeploymentPolicy)) AppTargetView {
	a.t.Helper()
	res, err := a.createTarget(app, env, a.node.ID, mutate...)
	mustf(a.t, err, "CreateTarget")
	if res.Applied == nil {
		a.t.Fatalf("CreateTarget did not apply: %+v", res)
	}
	return *res.Applied
}

func appsReasonOf(err error) smerr.Reason {
	var typed *smerr.Error
	if errors.As(err, &typed) {
		return typed.Reason
	}
	return ""
}

func wantAppsCode(t *testing.T, err error, want smerr.Code) {
	t.Helper()
	if smerr.CodeOf(err) != want {
		t.Fatalf("error = %v, want code %s", err, want)
	}
}

func appsSHA256(text string) string {
	sum := sha256.Sum256([]byte(text))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ---- Create ---------------------------------------------------------------------------

func TestAppsCreate_StoresTheConfigurationAndOnlyTheSourceHash(t *testing.T) {
	f := newAppsFixture(t)

	app := f.createApp()

	if app.ComposeSource != composeSourceControlPlane || app.ManifestPath != ".supermgmt.yaml" {
		t.Errorf("defaults: source %q, manifest %q", app.ComposeSource, app.ManifestPath)
	}
	if app.ComposeSourceHash != appsSHA256(appsWebCompose) {
		t.Errorf("compose_source_hash = %s, want the SHA-256 of the control-plane text", app.ComposeSourceHash)
	}
	if app.SpecRevision != 1 || len(app.Targets) != 0 || app.Repository != nil || app.AutomationIdentityID != nil {
		t.Errorf("app = %+v", app)
	}
	if app.ImagePolicy.Sidecars == nil || app.Variables == nil || app.SecretRefs["db"] != "secret://apps/web/database_url" {
		t.Errorf("maps must be present and kept: %+v", app)
	}
	if events := f.events(appWriteAction); len(events) != 1 || events[0].Data["operation"] != "create" {
		t.Errorf("events = %+v, want one app.write create event", events)
	}
}

func TestAppsCreate_RejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(*wire.CreateAppRequest)
		wantReason smerr.Reason
	}{
		{"upper-case name", func(r *wire.CreateAppRequest) { r.Name = "Web" }, ""},
		{"name that cannot form a project", func(r *wire.CreateAppRequest) { r.Name = "web_app" }, ""},
		{"missing deployed service", func(r *wire.CreateAppRequest) { r.DeployedService = "" }, ""},
		{"deployed image with a tag", func(r *wire.CreateAppRequest) { r.ImagePolicy.Deployed = "ghcr.io/acme/web:1.2" }, ""},
		{"deployed image with a digest", func(r *wire.CreateAppRequest) {
			r.ImagePolicy.Deployed = "ghcr.io/acme/web@sha256:" + strings.Repeat("a", 64)
		}, ""},
		{"registry port is not a tag", func(r *wire.CreateAppRequest) { r.ImagePolicy.Deployed = "localhost:5000" }, ""},
		{"sidecar named like the deployed service", func(r *wire.CreateAppRequest) {
			r.ImagePolicy.Sidecars = map[string]string{"web": "docker.io/library/redis"}
		}, ""},
		{"pinned entry without digest", func(r *wire.CreateAppRequest) { r.ImagePolicy.Pinned = []string{"docker.io/library/redis:7"} }, ""},
		{"manifest path escapes the repository", func(r *wire.CreateAppRequest) { r.ManifestPath = "../outside.yaml" }, ""},
		{"absolute manifest path", func(r *wire.CreateAppRequest) { r.ManifestPath = "/etc/passwd" }, ""},
		{"unknown compose source", func(r *wire.CreateAppRequest) { r.ComposeSource = "somewhere" }, ""},
		{"control-plane source without content", func(r *wire.CreateAppRequest) { r.ComposeContent = "" }, ""},
		{"repository source without a repository", func(r *wire.CreateAppRequest) {
			r.ComposeSource, r.ComposeContent = composeSourceRepository, ""
		}, ""},
		{"privileged compose", func(r *wire.CreateAppRequest) { r.ComposeContent = appsPrivilegedCompose }, smerr.ReasonComposeRejected},
		{"secret ref outside apps/", func(r *wire.CreateAppRequest) {
			r.SecretRefs = map[string]string{"db": "secret://ssh/default"}
		}, ""},
		{"secret ref that is not a secret:// path", func(r *wire.CreateAppRequest) {
			r.SecretRefs = map[string]string{"db": "file:///etc/shadow"}
		}, ""},
		{"secret ref without a name under apps/", func(r *wire.CreateAppRequest) {
			r.SecretRefs = map[string]string{"db": "secret://apps/"}
		}, ""},
		{"variable name with a dash", func(r *wire.CreateAppRequest) { r.Variables = map[string]string{"A-B": "1"} }, ""},
		{"variable value with NUL", func(r *wire.CreateAppRequest) { r.Variables = map[string]string{"AB": "a\x00b"} }, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newAppsFixture(t)

			_, err := f.apps.Create(context.Background(), f.caller(f.admin), f.createRequest(tc.mutate))

			wantAppsCode(t, err, smerr.CodeInvalidArgument)
			if tc.wantReason != "" && appsReasonOf(err) != tc.wantReason {
				t.Errorf("reason = %s, want %s", appsReasonOf(err), tc.wantReason)
			}
			if apps, _ := database.ListApps(context.Background(), f.db.Reader()); len(apps) != 0 {
				t.Errorf("a rejected request stored %d apps", len(apps))
			}
		})
	}
}

func TestAppsCreate_DuplicateNameIsConflict(t *testing.T) {
	f := newAppsFixture(t)
	f.createApp()

	_, err := f.apps.Create(context.Background(), f.caller(f.admin), f.createRequest())

	wantAppsCode(t, err, smerr.CodeConflict)
}

func TestAppsCreate_OnlyAnAdminMayWriteAndGitHubIsNotCalledForOthers(t *testing.T) {
	f := newAppsFixture(t)
	withRepository := f.createRequest(func(r *wire.CreateAppRequest) {
		r.ProviderID, r.RepositoryID = &f.ghHost.ID, &f.repoMain.ID
	})

	for name, id := range map[string]domain.ID{"operator": f.alice, "no roles": f.dave} {
		_, err := f.apps.Create(context.Background(), f.caller(id), withRepository)
		if smerr.CodeOf(err) != smerr.CodePolicyDenied {
			t.Errorf("%s: error = %v, want POLICY_DENIED", name, err)
		}
	}

	if f.gh.used() != 0 {
		t.Errorf("GitHub was called %d times for callers policy denies", f.gh.used())
	}
	if len(f.events("policy.deny")) != 2 {
		t.Errorf("denials audited = %d, want 2", len(f.events("policy.deny")))
	}
}

func TestAppsCreate_WaitsForApprovalAndAppliesExactlyWhatWasApproved(t *testing.T) {
	f := newAppsFixture(t)
	f.gated = true

	res, err := f.apps.Create(context.Background(), f.caller(f.admin), f.createRequest())

	mustf(t, err, "Create")
	if res.Pending == nil || res.Applied != nil {
		t.Fatalf("result = %+v, want a request waiting for approval", res)
	}
	if apps, _ := database.ListApps(context.Background(), f.db.Reader()); len(apps) != 0 {
		t.Fatalf("an unapproved request stored %d apps", len(apps))
	}
	// Approval itself is T9b: it rebuilds the plan with the real builder.
	p, err := payloadOf[appCreateParams](f.job(res.Pending.Job.ID))
	mustf(t, err, "the job carries appCreateParams")
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		actor, err := loadActor(ctx, tx, f.admin, f.caller(f.admin).Credential)
		if err != nil {
			return err
		}
		_, err = f.apps.applyCreate(ctx, tx, actor, p)
		return err
	})
	got, err := f.apps.Get(context.Background(), f.caller(f.admin), p.AppID)
	mustf(t, err, "Get")
	if got.Name != "web" || got.ComposeSourceHash != appsSHA256(appsWebCompose) || got.ComposeContent != appsWebCompose {
		t.Errorf("applied app = %+v, want the approved configuration", got)
	}
}

func TestAppsCreate_ApplyingRevalidatesTheApprovedConfiguration(t *testing.T) {
	f := newAppsFixture(t)
	p := appCreateParams{AppID: f.ids.NewID(), Spec: appSpec{
		Name: "web", DeployedService: "web", ImagePolicy: wire.ImagePolicy{Deployed: "ghcr.io/acme/web"},
		ComposeSource: composeSourceControlPlane, ComposeContent: appsPrivilegedCompose,
	}}

	var err error
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		actor, loadErr := loadActor(ctx, tx, f.admin, f.caller(f.admin).Credential)
		if loadErr != nil {
			return loadErr
		}
		_, err = f.apps.applyCreate(ctx, tx, actor, p)
		return nil
	})

	if appsReasonOf(err) != smerr.ReasonComposeRejected {
		t.Fatalf("applyCreate error = %v, want COMPOSE_REJECTED", err)
	}
}

// ---- repositories and the CI policy ------------------------------------------------------

func appsRepositoryRequest(f *appsFixture) func(*wire.CreateAppRequest) {
	return func(r *wire.CreateAppRequest) {
		r.ProviderID, r.RepositoryID = &f.ghHost.ID, &f.repoMain.ID
		r.CIPolicy = &wire.CIPolicy{
			Branch:         "main",
			RequiredChecks: []wire.RequiredCheck{{Name: "test", AppID: githubActionsAppID, WorkflowPath: ".github/workflows/ci.yml"}},
			DeployWorkflow: ".github/workflows/deploy.yml",
		}
	}
}

func TestAppsCreate_LinksTheRepositoryAndResolvesTheCIPolicyToNumericIDs(t *testing.T) {
	f := newAppsFixture(t)

	app := f.createApp(appsRepositoryRequest(f))

	if app.Repository == nil || app.Repository.ID == nil || app.Repository.GitHubRepositoryID != 4242 || app.Repository.Owner != "acme" {
		t.Fatalf("repository = %+v", app.Repository)
	}
	ci := app.CIPolicy
	if ci == nil || ci.RepositoryID != 4242 || ci.OwnerID != 77 {
		t.Fatalf("ci_policy = %+v, want the numeric ids of the linked repository", ci)
	}
	if len(ci.AllowedEvents) != 1 || ci.AllowedEvents[0] != "push" {
		t.Errorf("allowed_events = %v, want the push default", ci.AllowedEvents)
	}
	stored, err := database.GetRepositoryByGithubID(context.Background(), f.db.Reader(), f.ghHost.ID, 4242)
	mustf(t, err, "repository row")
	if stored.ID != *app.Repository.ID {
		t.Errorf("stored repository %s, view %s", stored.ID, *app.Repository.ID)
	}
}

func TestAppsCreate_TwoAppsShareOneRepositoryRow(t *testing.T) {
	f := newAppsFixture(t)
	f.createApp(appsRepositoryRequest(f))

	f.createApp(appsRepositoryRequest(f), func(r *wire.CreateAppRequest) {
		r.Name = "web2"
		r.CIPolicy.DeployWorkflow = ".github/workflows/deploy2.yml"
	})

	repos, err := database.ListRepositories(context.Background(), f.db.Reader())
	mustf(t, err, "ListRepositories")
	if len(repos) != 1 {
		t.Fatalf("repositories = %d, want one shared row", len(repos))
	}
}

func TestAppsCreate_RepositoryErrors(t *testing.T) {
	f := newAppsFixture(t)
	missing := int64(999)
	tests := []struct {
		name   string
		mutate func(*wire.CreateAppRequest)
		want   smerr.Code
	}{
		{"repository GitHub does not know", func(r *wire.CreateAppRequest) { r.ProviderID, r.RepositoryID = &f.ghHost.ID, &missing }, smerr.CodeNotFound},
		{"provider without repository", func(r *wire.CreateAppRequest) { r.ProviderID = &f.ghHost.ID }, smerr.CodeInvalidArgument},
		{"repository without provider", func(r *wire.CreateAppRequest) { r.RepositoryID = &f.repoMain.ID }, smerr.CodeInvalidArgument},
		{"ci policy without a repository", func(r *wire.CreateAppRequest) {
			r.CIPolicy = &wire.CIPolicy{Branch: "main"}
		}, smerr.CodeInvalidArgument},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := f.apps.Create(context.Background(), f.caller(f.admin), f.createRequest(tc.mutate))
			wantAppsCode(t, err, tc.want)
		})
	}
}

func TestAppsCreate_RepositorySourceIsAcceptedWithoutContent(t *testing.T) {
	f := newAppsFixture(t)

	app := f.createApp(appsRepositoryRequest(f), func(r *wire.CreateAppRequest) {
		r.ComposeSource, r.ComposeContent, r.SecretRefs = composeSourceRepository, "", nil
	})

	if app.ComposeSource != composeSourceRepository || app.ComposeSourceHash != "" || app.ComposeContent != "" {
		t.Errorf("app = %+v, a repository source stores no content and no hash", app)
	}
}

func TestAppsCreate_CIPolicyRules(t *testing.T) {
	actions := wire.RequiredCheck{Name: "test", AppID: githubActionsAppID, WorkflowPath: ".github/workflows/ci.yml"}
	tests := []struct {
		name   string
		mutate func(*wire.CIPolicy)
	}{
		{"owner id of another account", func(c *wire.CIPolicy) { c.OwnerID = 5 }},
		{"repository id of another repository", func(c *wire.CIPolicy) { c.RepositoryID = 5 }},
		{"no branch", func(c *wire.CIPolicy) { c.Branch = "" }},
		{"branch that climbs", func(c *wire.CIPolicy) { c.Branch = "a/../b" }},
		{"pull request event", func(c *wire.CIPolicy) { c.AllowedEvents = []string{"push", "pull_request"} }},
		{"pull request target event", func(c *wire.CIPolicy) { c.AllowedEvents = []string{"pull_request_target"} }},
		{"no required checks", func(c *wire.CIPolicy) { c.RequiredChecks = nil }},
		{"actions check without workflow path", func(c *wire.CIPolicy) {
			c.RequiredChecks = []wire.RequiredCheck{{Name: "test", AppID: githubActionsAppID}}
		}},
		{"check without app id", func(c *wire.CIPolicy) { c.RequiredChecks = []wire.RequiredCheck{{Name: "test"}} }},
		{"workflow path on another app's check", func(c *wire.CIPolicy) {
			c.RequiredChecks = []wire.RequiredCheck{{Name: "lint", AppID: 99, WorkflowPath: ".github/workflows/ci.yml"}}
		}},
		{"deploy workflow outside .github/workflows", func(c *wire.CIPolicy) { c.DeployWorkflow = "ci.yml" }},
		{"reusable workflow without ref", func(c *wire.CIPolicy) { c.DeployReusableWorkflow = "acme/shared/.github/workflows/d.yml" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newAppsFixture(t)

			_, err := f.apps.Create(context.Background(), f.caller(f.admin), f.createRequest(func(r *wire.CreateAppRequest) {
				appsRepositoryRequest(f)(r)
				r.CIPolicy.RequiredChecks = []wire.RequiredCheck{actions}
				tc.mutate(r.CIPolicy)
			}))

			wantAppsCode(t, err, smerr.CodeInvalidArgument)
		})
	}
}

// ---- Update ---------------------------------------------------------------------------

func TestAppsUpdate_ChangesTheSourceAndBumpsTheRevision(t *testing.T) {
	f := newAppsFixture(t)
	app := f.createApp()
	edited := strings.Replace(appsWebCompose, "8080", "9090", 2)

	res, err := f.apps.Update(context.Background(), f.caller(f.admin), app.ID, app.SpecRevision, wire.AppPatch{ComposeContent: &edited})

	mustf(t, err, "Update")
	got := res.Applied
	if got == nil || got.SpecRevision != 2 || got.ComposeContent != edited || got.ComposeSourceHash != appsSHA256(edited) {
		t.Fatalf("updated app = %+v", got)
	}
}

func TestAppsUpdate_StaleRevisionIsConflictAndChangesNothing(t *testing.T) {
	f := newAppsFixture(t)
	app := f.createApp()
	edited := strings.Replace(appsWebCompose, "8080", "9090", 2)

	_, err := f.apps.Update(context.Background(), f.caller(f.admin), app.ID, app.SpecRevision+5, wire.AppPatch{ComposeContent: &edited})

	wantAppsCode(t, err, smerr.CodeConflict)
	again, err := f.apps.Get(context.Background(), f.caller(f.admin), app.ID)
	mustf(t, err, "Get")
	if again.SpecRevision != 1 || again.ComposeContent != appsWebCompose {
		t.Errorf("app changed: %+v", again)
	}
}

func TestAppsUpdate_RefusesAnEmptyPatchAndInvalidContent(t *testing.T) {
	f := newAppsFixture(t)
	app := f.createApp()
	privileged := appsPrivilegedCompose

	_, emptyErr := f.apps.Update(context.Background(), f.caller(f.admin), app.ID, 1, wire.AppPatch{})
	_, invalidErr := f.apps.Update(context.Background(), f.caller(f.admin), app.ID, 1, wire.AppPatch{ComposeContent: &privileged})

	wantAppsCode(t, emptyErr, smerr.CodeInvalidArgument)
	if appsReasonOf(invalidErr) != smerr.ReasonComposeRejected {
		t.Errorf("error = %v, want COMPOSE_REJECTED", invalidErr)
	}
}

func TestAppsUpdate_ChecksTheNewSourceAgainstEveryTarget(t *testing.T) {
	f := newAppsFixture(t)
	app := f.createApp()
	f.mustTarget(app, "dev", func(p *wire.DeploymentPolicy) { p.AllowedBindAddresses = []string{"192.168.1.5"} })
	f.mustTarget(app, "staging")
	lan := appsLANCompose

	_, err := f.apps.Update(context.Background(), f.caller(f.admin), app.ID, 1, wire.AppPatch{ComposeContent: &lan})

	if appsReasonOf(err) != smerr.ReasonComposeRejected {
		t.Fatalf("error = %v, want COMPOSE_REJECTED: the staging target publishes on loopback only", err)
	}
}

func TestAppsUpdate_RefusesARepositorySourceWhileAProductionTargetExists(t *testing.T) {
	f := newAppsFixture(t)
	app := f.createApp(appsRepositoryRequest(f))
	f.mustTarget(app, f.env.Name)
	source := composeSourceRepository

	_, err := f.apps.Update(context.Background(), f.caller(f.admin), app.ID, 1, wire.AppPatch{ComposeSource: &source})

	wantAppsCode(t, err, smerr.CodeInvalidArgument)
}

// ---- targets --------------------------------------------------------------------------

func TestAppsCreateTarget_DerivesTheProjectAndStoresTheCanonicalPolicy(t *testing.T) {
	f := newAppsFixture(t)
	app := f.createApp()

	target := f.mustTarget(app, "dev", func(p *wire.DeploymentPolicy) {
		p.Rollback = ""
		p.AllowedBindAddresses = []string{"192.168.1.5", "192.168.1.5", "::ffff:10.0.0.1"}
		p.Health = &wire.HealthCheck{Type: "http", Port: 8080, Path: "/health"}
	})

	if target.ComposeProject != "sm-web-dev" || target.Environment != "dev" || target.SpecRevision != 1 {
		t.Fatalf("target = %+v", target)
	}
	policy := target.DeploymentPolicy
	if policy.Rollback != rollbackManual {
		t.Errorf("rollback = %q, want the conservative default", policy.Rollback)
	}
	if len(policy.AllowedBindAddresses) != 2 || policy.AllowedBindAddresses[0] != "10.0.0.1" {
		t.Errorf("bind addresses = %v, want deduplicated, unmapped and sorted", policy.AllowedBindAddresses)
	}
	h := policy.Health
	if h == nil || h.Scope != "node" || h.Timeout != "3s" || h.Interval != "5s" || h.Attempts != 12 {
		t.Errorf("health = %+v, want the defaults filled", h)
	}
	if got, _ := f.apps.Get(context.Background(), f.caller(f.admin), app.ID); len(got.Targets) != 1 {
		t.Errorf("the app lists %d targets, want 1", len(got.Targets))
	}
}

func TestAppsCreateTarget_PolicyRules(t *testing.T) {
	tests := []struct {
		name   string
		env    string
		mutate func(*wire.DeploymentPolicy)
	}{
		{"snapshot", "dev", func(p *wire.DeploymentPolicy) { p.Snapshot = true }},
		{"unknown rollback mode", "dev", func(p *wire.DeploymentPolicy) { p.Rollback = "sometimes" }},
		{"stateful with automatic rollback", "dev", func(p *wire.DeploymentPolicy) { p.Stateful = true }},
		{"stateful production without a backup", "prod", func(p *wire.DeploymentPolicy) { p.Stateful, p.Rollback = true, rollbackManual }},
		{"backup template other than postgres-dump", "dev", func(p *wire.DeploymentPolicy) {
			p.PreDeployBackup = &wire.BackupPolicy{Template: "mysqldump", Args: map[string]string{"container": "db", "database": "app"}}
		}},
		{"backup argument with shell syntax", "dev", func(p *wire.DeploymentPolicy) {
			p.PreDeployBackup = &wire.BackupPolicy{Template: "postgres-dump", Args: map[string]string{"container": "db; rm -rf /", "database": "app"}}
		}},
		{"backup with a missing argument", "dev", func(p *wire.DeploymentPolicy) {
			p.PreDeployBackup = &wire.BackupPolicy{Template: "postgres-dump", Args: map[string]string{"container": "db"}}
		}},
		{"backup with an extra argument", "dev", func(p *wire.DeploymentPolicy) {
			p.PreDeployBackup = &wire.BackupPolicy{Template: "postgres-dump", Args: map[string]string{"container": "db", "database": "app", "x": "y"}}
		}},
		{"backup timeout beyond the node cap", "dev", func(p *wire.DeploymentPolicy) {
			p.PreDeployBackup = &wire.BackupPolicy{Template: "postgres-dump", Args: map[string]string{"container": "db", "database": "app"}, Timeout: "2h"}
		}},
		{"unspecified bind address", "dev", func(p *wire.DeploymentPolicy) { p.AllowedBindAddresses = []string{"0.0.0.0"} }},
		{"bind address that is a name", "dev", func(p *wire.DeploymentPolicy) { p.AllowedBindAddresses = []string{"example.com"} }},
		{"command-template health", "dev", func(p *wire.DeploymentPolicy) { p.Health = &wire.HealthCheck{Type: "command-template"} }},
		{"systemd-active health", "dev", func(p *wire.DeploymentPolicy) { p.Health = &wire.HealthCheck{Type: "systemd-active"} }},
		{"node health with a URL", "dev", func(p *wire.DeploymentPolicy) {
			p.Health = &wire.HealthCheck{Type: "http", Port: 8080, Path: "/", URL: "http://example.com/"}
		}},
		{"node http health with a query", "dev", func(p *wire.DeploymentPolicy) {
			p.Health = &wire.HealthCheck{Type: "http", Port: 8080, Path: "/h?x=1"}
		}},
		{"node tcp health without a port", "dev", func(p *wire.DeploymentPolicy) { p.Health = &wire.HealthCheck{Type: "tcp"} }},
		{"health timeout out of range", "dev", func(p *wire.DeploymentPolicy) {
			p.Health = &wire.HealthCheck{Type: "tcp", Port: 8080, Timeout: "5m"}
		}},
		{"health attempts out of range", "dev", func(p *wire.DeploymentPolicy) {
			p.Health = &wire.HealthCheck{Type: "tcp", Port: 8080, Attempts: 1000}
		}},
		{"control-plane health without a URL", "dev", func(p *wire.DeploymentPolicy) {
			p.Health = &wire.HealthCheck{Type: "http", Scope: "control_plane"}
		}},
		{"control-plane health URL with userinfo", "dev", func(p *wire.DeploymentPolicy) {
			p.Health = &wire.HealthCheck{Type: "https", Scope: "control_plane", URL: "https://user:pw@example.com/"}
		}},
		{"node health on a port the model does not publish", "dev", func(p *wire.DeploymentPolicy) {
			p.Health = &wire.HealthCheck{Type: "tcp", Port: 5432}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newAppsFixture(t)
			app := f.createApp()
			env := tc.env
			if env == "prod" {
				env = f.env.Name
			}

			_, err := f.createTarget(app, env, f.node.ID, tc.mutate)

			wantAppsCode(t, err, smerr.CodeInvalidArgument)
			if targets, _ := database.ListAppTargets(context.Background(), f.db.Reader()); len(targets) != 0 {
				t.Errorf("a rejected request stored %d targets", len(targets))
			}
		})
	}
}

func TestAppsCreateTarget_AcceptsStatefulProductionWithABackupAndControlPlaneHealth(t *testing.T) {
	f := newAppsFixture(t)
	app := f.createApp()

	target := f.mustTarget(app, f.env.Name, func(p *wire.DeploymentPolicy) {
		p.Stateful, p.Rollback = true, rollbackManual
		p.PreDeployBackup = &wire.BackupPolicy{Template: "postgres-dump", Args: map[string]string{"container": "db", "database": "app"}}
		p.Health = &wire.HealthCheck{Type: "https", Scope: "control_plane", URL: "https://web.example.com/health"}
	})

	if b := target.DeploymentPolicy.PreDeployBackup; b == nil || b.Timeout != "10m0s" {
		t.Errorf("backup = %+v, want the 10m default", b)
	}
}

func TestAppsCreateTarget_NodeHealthMustUseAPublishedPort(t *testing.T) {
	f := newAppsFixture(t)
	app := f.createApp()

	target := f.mustTarget(app, "dev", func(p *wire.DeploymentPolicy) {
		p.Health = &wire.HealthCheck{Type: "tcp", Port: 8080}
	})

	if target.DeploymentPolicy.Health == nil {
		t.Fatalf("target = %+v", target)
	}
}

func TestAppsCreateTarget_FreezesTheSourceForTheTarget(t *testing.T) {
	tests := []struct {
		name       string
		content    string
		pinned     []string
		sidecars   map[string]string
		wantReason smerr.Reason
		bind       []string
	}{
		{"sidecar by tag", appsTagSidecarCompose, nil, map[string]string{"redis": "docker.io/library/redis"}, smerr.ReasonTagReference, nil},
		{"sidecar digest neither bound nor pinned", appsWithSidecars, nil, map[string]string{"redis": "docker.io/library/redis"}, smerr.ReasonDigestUnbound, nil},
		{"service the image policy does not allow", appsWithSidecars, []string{appsRedisPinned}, nil, smerr.ReasonComposeRejected, nil},
		{"publish address outside the target's bind policy", appsLANCompose, nil, nil, smerr.ReasonComposeRejected, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newAppsFixture(t)
			app := f.createApp(func(r *wire.CreateAppRequest) {
				r.ComposeContent, r.SecretRefs = tc.content, nil
				r.ImagePolicy.Pinned, r.ImagePolicy.Sidecars = tc.pinned, tc.sidecars
			})

			_, err := f.createTarget(app, "dev", f.node.ID)

			if appsReasonOf(err) != tc.wantReason {
				t.Fatalf("error = %v, want reason %s", err, tc.wantReason)
			}
		})
	}
}

func TestAppsCreateTarget_AcceptsAPinnedSidecarAndALANAddressTheTargetAllows(t *testing.T) {
	f := newAppsFixture(t)
	pinned := f.createApp(func(r *wire.CreateAppRequest) {
		r.ComposeContent, r.SecretRefs = appsWithSidecars, nil
		r.ImagePolicy.Pinned = []string{appsRedisPinned}
		r.ImagePolicy.Sidecars = map[string]string{"redis": "docker.io/library/redis"}
	})
	lan := f.createApp(func(r *wire.CreateAppRequest) { r.Name, r.ComposeContent, r.SecretRefs = "lan", appsLANCompose, nil })

	f.mustTarget(pinned, "dev")
	f.mustTarget(lan, "dev", func(p *wire.DeploymentPolicy) { p.AllowedBindAddresses = []string{"192.168.1.5"} })
}

func TestAppsCreateTarget_Conflicts(t *testing.T) {
	f := newAppsFixture(t)
	app := f.createApp()
	f.mustTarget(app, "dev")

	_, sameEnvironment := f.createTarget(app, "dev", f.node.ID)
	other := f.createApp(func(r *wire.CreateAppRequest) { r.Name = "web" + "-2" })
	_, sameProjectOnNode := f.createTarget(other, "dev", f.node.ID)

	wantAppsCode(t, sameEnvironment, smerr.CodeConflict)
	if sameProjectOnNode != nil {
		t.Errorf("a different app may share a node and environment: %v", sameProjectOnNode)
	}
}

func TestAppsCreateTarget_RefusesWhatCannotHostIt(t *testing.T) {
	f := newAppsFixture(t)
	app := f.createApp()
	repoApp := f.createApp(appsRepositoryRequest(f), func(r *wire.CreateAppRequest) {
		r.Name, r.ComposeSource, r.ComposeContent, r.SecretRefs = "fromrepo", composeSourceRepository, "", nil
	})

	_, unknownEnvironment := f.createTarget(app, "nowhere", f.node.ID)
	_, retiredNode := f.createTarget(app, "dev", f.retired.ID)
	_, unknownNode := f.createTarget(app, "dev", f.ids.NewID())
	_, repositoryInProduction := f.createTarget(repoApp, f.env.Name, f.node.ID)
	_, unknownApp := f.apps.CreateTarget(context.Background(), f.caller(f.admin), f.ids.NewID(),
		wire.CreateAppTargetRequest{Environment: "dev", NodeID: f.node.ID})

	wantAppsCode(t, unknownEnvironment, smerr.CodeInvalidArgument)
	wantAppsCode(t, retiredNode, smerr.CodeInvalidArgument)
	wantAppsCode(t, unknownNode, smerr.CodeNotFound)
	wantAppsCode(t, repositoryInProduction, smerr.CodeInvalidArgument)
	wantAppsCode(t, unknownApp, smerr.CodeNotFound)
	if _, err := f.createTarget(repoApp, "dev", f.node.ID); err != nil {
		t.Errorf("a repository source is fine outside production: %v", err)
	}
}

func TestAppsCreateTarget_WaitsForApprovalWhenPolicyAsksAndAppliesThePolicyItCarries(t *testing.T) {
	f := newAppsFixture(t)
	app := f.createApp()
	f.gated = true

	res, err := f.createTarget(app, "dev", f.node.ID)

	mustf(t, err, "CreateTarget")
	if res.Pending == nil {
		t.Fatalf("result = %+v, want a request waiting for approval", res)
	}
	if targets, _ := database.ListAppTargets(context.Background(), f.db.Reader()); len(targets) != 0 {
		t.Fatalf("an unapproved request stored %d targets", len(targets))
	}
	// Approval itself is T9b: it rebuilds the plan with the real builder.
	p, err := payloadOf[appTargetCreateParams](f.job(res.Pending.Job.ID))
	mustf(t, err, "the job carries appTargetCreateParams")
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		actor, err := loadActor(ctx, tx, f.admin, f.caller(f.admin).Credential)
		if err != nil {
			return err
		}
		_, err = f.apps.applyCreateTarget(ctx, tx, actor, p)
		return err
	})
	got, err := f.apps.GetTarget(context.Background(), f.caller(f.admin), p.TargetID)
	mustf(t, err, "GetTarget")
	if got.ComposeProject != "sm-web-dev" || got.DeploymentPolicy.Rollback != rollbackAutomatic {
		t.Errorf("applied target = %+v", got)
	}
}

func TestAppsUpdateTarget(t *testing.T) {
	f := newAppsFixture(t)
	app := f.createApp()
	target := f.mustTarget(app, "dev")
	newPolicy := wire.DeploymentPolicy{Rollback: rollbackManual, Health: &wire.HealthCheck{Type: "tcp", Port: 8080}}

	stale, staleErr := f.apps.UpdateTarget(context.Background(), f.caller(f.admin), target.ID, 9, wire.AppTargetPatch{DeploymentPolicy: &newPolicy})
	_, emptyErr := f.apps.UpdateTarget(context.Background(), f.caller(f.admin), target.ID, 1, wire.AppTargetPatch{})
	bad := wire.DeploymentPolicy{Snapshot: true}
	_, badErr := f.apps.UpdateTarget(context.Background(), f.caller(f.admin), target.ID, 1, wire.AppTargetPatch{DeploymentPolicy: &bad})
	res, err := f.apps.UpdateTarget(context.Background(), f.caller(f.admin), target.ID, 1, wire.AppTargetPatch{DeploymentPolicy: &newPolicy})

	wantAppsCode(t, staleErr, smerr.CodeConflict)
	if stale.Applied != nil {
		t.Error("a stale update applied")
	}
	wantAppsCode(t, emptyErr, smerr.CodeInvalidArgument)
	wantAppsCode(t, badErr, smerr.CodeInvalidArgument)
	mustf(t, err, "UpdateTarget")
	got := res.Applied
	if got == nil || got.SpecRevision != 2 || got.DeploymentPolicy.Rollback != rollbackManual || got.ComposeProject != "sm-web-dev" {
		t.Fatalf("updated target = %+v", got)
	}
}

func TestAppsUpdateTarget_ProductionStatefulKeepsItsBackupRule(t *testing.T) {
	f := newAppsFixture(t)
	app := f.createApp()
	target := f.mustTarget(app, f.env.Name)
	stateful := wire.DeploymentPolicy{Stateful: true, Rollback: rollbackManual}

	_, err := f.apps.UpdateTarget(context.Background(), f.caller(f.admin), target.ID, 1, wire.AppTargetPatch{DeploymentPolicy: &stateful})

	wantAppsCode(t, err, smerr.CodeInvalidArgument)
}

// ---- reads ----------------------------------------------------------------------------

func TestAppsReads_AreScopedToWhatTheCallerMayRead(t *testing.T) {
	f := newAppsFixture(t)
	a := f.createApp()
	b := f.createApp(func(r *wire.CreateAppRequest) { r.Name = "api" })
	target := f.mustTarget(a, "dev")

	list, err := f.apps.List(context.Background(), f.caller(f.alice), wire.PageQuery{Limit: 1})
	mustf(t, err, "List")
	next, err := f.apps.List(context.Background(), f.caller(f.alice), wire.PageQuery{Limit: 1, Cursor: list.NextCursor})
	mustf(t, err, "List page 2")
	denied, deniedErr := f.apps.List(context.Background(), f.caller(f.dave), wire.PageQuery{})
	_, getErr := f.apps.Get(context.Background(), f.caller(f.dave), a.ID)
	_, targetErr := f.apps.GetTarget(context.Background(), f.caller(f.dave), target.ID)
	targets, listErr := f.apps.ListTargets(context.Background(), f.caller(f.alice), a.ID)

	if len(list.Items) != 1 || list.Items[0].Name != "api" || list.NextCursor == "" {
		t.Errorf("page 1 = %+v, want api (ordered by name) and a cursor", list)
	}
	if len(next.Items) != 1 || next.Items[0].ID != a.ID || next.NextCursor != "" || len(next.Items[0].Targets) != 1 {
		t.Errorf("page 2 = %+v, want the web app with its target and no cursor", next)
	}
	if deniedErr != nil || len(denied.Items) != 0 {
		t.Errorf("a caller without app.read sees %d apps (err %v)", len(denied.Items), deniedErr)
	}
	wantAppsCode(t, getErr, smerr.CodePolicyDenied)
	wantAppsCode(t, targetErr, smerr.CodePolicyDenied)
	mustf(t, listErr, "ListTargets")
	if len(targets) != 1 || targets[0].ID != target.ID {
		t.Errorf("targets = %+v", targets)
	}
	_ = b
}

func TestAppsReads_UnknownIDsAreNotFound(t *testing.T) {
	f := newAppsFixture(t)

	_, appErr := f.apps.Get(context.Background(), f.caller(f.admin), f.ids.NewID())
	_, targetErr := f.apps.GetTarget(context.Background(), f.caller(f.admin), f.ids.NewID())
	_, listErr := f.apps.ListTargets(context.Background(), f.caller(f.admin), f.ids.NewID())

	wantAppsCode(t, appErr, smerr.CodeNotFound)
	wantAppsCode(t, targetErr, smerr.CodeNotFound)
	wantAppsCode(t, listErr, smerr.CodeNotFound)
}

func TestNewApps_RequiresItsCollaborators(t *testing.T) {
	f := newFixture(t)

	if _, err := NewApps(f.cfg, f.store, nil); err == nil {
		t.Error("NewApps without GitHub clients succeeded")
	}
	if _, err := NewApps(Config{}, f.store, &appsGitHub{}); err == nil {
		t.Error("NewApps without a database succeeded")
	}
}
