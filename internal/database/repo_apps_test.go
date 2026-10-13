package database

import (
	"context"
	"testing"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// appsWorld is a provider, node and environment an app can be placed on.
type appsWorld struct {
	provider domain.Provider
	node     domain.Node
	env      domain.Environment
}

func newAppsWorld(ctx context.Context, f *fixture, q Querier) appsWorld {
	p := f.provider(ctx, q, "gh")
	return appsWorld{
		provider: p,
		node:     f.node(ctx, q, p, "n1"),
		env: must(CreateEnvironment(ctx, q, domain.Environment{
			ID: f.ids.NewID(), Name: "prod", RiskLevel: domain.EnvironmentProduction,
		})),
	}
}

func appsRepositoryOf(f *fixture, w appsWorld, githubID int64) Repository {
	return Repository{
		ID: f.ids.NewID(), ProviderID: w.provider.ID, GithubRepositoryID: githubID, GithubOwnerID: 7,
		Owner: "acme", Name: "web", URL: "https://github.com/acme/web", DefaultBranch: "main",
		MetadataJSON: []byte(`{"private":true}`), CreatedAt: testEpoch, UpdatedAt: testEpoch,
	}
}

func appsAppOf(f *fixture, name string) App {
	return App{
		ID: f.ids.NewID(), Name: name, ManifestPath: ".supermgmt.yaml", DeployedService: "web",
		ImagePolicyJSON: []byte(`{"registry":"ghcr.io"}`), ComposeSource: "control-plane",
		ComposeContent: "services: {}", ComposeSourceHash: "sha256:aa", CreatedAt: testEpoch, UpdatedAt: testEpoch,
	}
}

func TestRepositoryRoundTripAndUniqueness(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		w := newAppsWorld(ctx, f, q)
		created := must(CreateRepository(ctx, q, appsRepositoryOf(f, w, 100)))
		if created.SpecRevision != 1 {
			t.Fatalf("new revision = %d, want 1", created.SpecRevision)
		}
		got := must(GetRepository(ctx, q, created.ID))
		if got.Owner != "acme" || string(got.MetadataJSON) != `{"private":true}` || !got.CreatedAt.Equal(testEpoch) {
			t.Fatalf("round trip: %+v", got)
		}
		byGithub := must(GetRepositoryByGithubID(ctx, q, w.provider.ID, 100))
		if byGithub.ID != created.ID {
			t.Fatalf("by github id = %v, want %v", byGithub.ID, created.ID)
		}
		_, err := GetRepositoryByGithubID(ctx, q, w.provider.ID, 101)
		wantError(t, err, smerr.CodeNotFound, "")

		_, err = CreateRepository(ctx, q, appsRepositoryOf(f, w, 100))
		wantError(t, err, smerr.CodeConflict, "")

		must(CreateRepository(ctx, q, appsRepositoryOf(f, w, 101)))
		if n := len(must(ListRepositories(ctx, q))); n != 2 {
			t.Fatalf("list = %d, want 2", n)
		}
	})
}

func TestUpdateRepositoryEnforcesIfMatch(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		w := newAppsWorld(ctx, f, q)
		r := must(CreateRepository(ctx, q, appsRepositoryOf(f, w, 100)))

		r.DefaultBranch = "trunk"
		updated := must(UpdateRepository(ctx, q, r, 1))
		if updated.SpecRevision != 2 || updated.DefaultBranch != "trunk" {
			t.Fatalf("updated = %+v", updated)
		}

		_, err := UpdateRepository(ctx, q, r, 1)
		wantError(t, err, smerr.CodeConflict, "")

		r.ID = f.ids.NewID()
		_, err = UpdateRepository(ctx, q, r, 1)
		wantError(t, err, smerr.CodeNotFound, "")
	})
}

func TestAppRoundTripKeepsOptionalFieldsNull(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		w := newAppsWorld(ctx, f, q)
		repo := must(CreateRepository(ctx, q, appsRepositoryOf(f, w, 100)))
		automation := f.identity(ctx, q, domain.ActorAutomation, "repository_id:100:workflow:deploy.yml")

		bare := appsAppOf(f, "bare")
		bare.ComposeContent, bare.ComposeSourceHash, bare.ComposeSource = "", "", "repository"
		got := must(GetApp(ctx, q, must(CreateApp(ctx, q, bare)).ID))
		if got.RepositoryID != nil || got.AutomationIdentityID != nil || got.CIPolicyJSON != nil ||
			got.ComposeContent != "" || got.ComposeSourceHash != "" {
			t.Errorf("optional fields not empty: %+v", got)
		}
		if string(got.ComposeExceptions) != "{}" || string(got.VariablesJSON) != "{}" || string(got.SecretRefsJSON) != "{}" {
			t.Errorf("json defaults = %s %s %s, want {}", got.ComposeExceptions, got.VariablesJSON, got.SecretRefsJSON)
		}

		full := appsAppOf(f, "full")
		full.RepositoryID, full.AutomationIdentityID = &repo.ID, &automation.ID
		full.CIPolicyJSON = []byte(`{"checks":["ci"]}`)
		created := must(CreateApp(ctx, q, full))
		got = must(GetApp(ctx, q, created.ID))
		if *got.RepositoryID != repo.ID || *got.AutomationIdentityID != automation.ID ||
			string(got.CIPolicyJSON) != `{"checks":["ci"]}` || got.ComposeContent != "services: {}" || got.SpecRevision != 1 {
			t.Errorf("round trip: %+v", got)
		}
		if byName := must(GetAppByName(ctx, q, "full")); byName.ID != created.ID {
			t.Errorf("by name = %v, want %v", byName.ID, created.ID)
		}
		_, err := GetAppByName(ctx, q, "nope")
		wantError(t, err, smerr.CodeNotFound, "")

		apps := must(ListApps(ctx, q))
		if len(apps) != 2 || apps[0].Name != "bare" || apps[1].Name != "full" {
			t.Errorf("list order = %v, want bare, full", []string{apps[0].Name, apps[1].Name})
		}
	})
}

func TestAppNamesAreUnique(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		must(CreateApp(ctx, q, appsAppOf(f, "web")))
		_, err := CreateApp(ctx, q, appsAppOf(f, "web"))
		wantError(t, err, smerr.CodeConflict, "")
	})
}

func TestUpdateAppEnforcesIfMatchAndClearsOptionalFields(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		a := appsAppOf(f, "web")
		a.CIPolicyJSON = []byte(`{"checks":["ci"]}`)
		a = must(CreateApp(ctx, q, a))
		other := must(CreateApp(ctx, q, appsAppOf(f, "other")))

		a.CIPolicyJSON, a.ComposeContent, a.ComposeSourceHash, a.ComposeSource = nil, "", "", "repository"
		updated := must(UpdateApp(ctx, q, a, 1))
		if updated.SpecRevision != 2 || updated.CIPolicyJSON != nil || updated.ComposeContent != "" || updated.ComposeSource != "repository" {
			t.Fatalf("updated = %+v", updated)
		}

		_, err := UpdateApp(ctx, q, a, 1)
		wantError(t, err, smerr.CodeConflict, "")

		a.Name = other.Name
		_, err = UpdateApp(ctx, q, a, 2)
		wantError(t, err, smerr.CodeConflict, "")
		if got := must(GetApp(ctx, q, a.ID)); got.SpecRevision != 2 || got.Name != "web" {
			t.Errorf("a rejected update changed the row: %+v", got)
		}
	})
}

func appsTargetOf(f *fixture, app App, w appsWorld, project string) AppTarget {
	return AppTarget{
		ID: f.ids.NewID(), AppID: app.ID, EnvironmentID: w.env.ID, NodeID: w.node.ID, ComposeProject: project,
		DeploymentPolicyJSON: []byte(`{"stateful":false}`), CreatedAt: testEpoch, UpdatedAt: testEpoch,
	}
}

func TestAppTargetRoundTripAndUniqueness(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		w := newAppsWorld(ctx, f, q)
		web, api := must(CreateApp(ctx, q, appsAppOf(f, "web"))), must(CreateApp(ctx, q, appsAppOf(f, "api")))

		created := must(CreateAppTarget(ctx, q, appsTargetOf(f, web, w, "sm-web-prod")))
		got := must(GetAppTarget(ctx, q, created.ID))
		if got.ComposeProject != "sm-web-prod" || string(got.DeploymentPolicyJSON) != `{"stateful":false}` || got.SpecRevision != 1 {
			t.Fatalf("round trip: %+v", got)
		}
		_, err := GetAppTarget(ctx, q, f.ids.NewID())
		wantError(t, err, smerr.CodeNotFound, "")

		// same (app, environment) again: UNIQUE(app_id, environment_id)
		_, err = CreateAppTarget(ctx, q, appsTargetOf(f, web, w, "sm-web-prod-2"))
		wantError(t, err, smerr.CodeConflict, "")
		// same (node, project) for another app: UNIQUE(node_id, compose_project)
		_, err = CreateAppTarget(ctx, q, appsTargetOf(f, api, w, "sm-web-prod"))
		wantError(t, err, smerr.CodeConflict, "")

		must(CreateAppTarget(ctx, q, appsTargetOf(f, api, w, "sm-api-prod")))
		if n := len(must(ListAppTargets(ctx, q))); n != 2 {
			t.Errorf("list = %d, want 2", n)
		}
		byApp := must(ListAppTargetsByApp(ctx, q, api.ID))
		if len(byApp) != 1 || byApp[0].ComposeProject != "sm-api-prod" {
			t.Errorf("by app = %+v", byApp)
		}
	})
}

func TestUpdateAppTargetEnforcesIfMatchAndKeepsTheProject(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		w := newAppsWorld(ctx, f, q)
		app := must(CreateApp(ctx, q, appsAppOf(f, "web")))
		target := must(CreateAppTarget(ctx, q, appsTargetOf(f, app, w, "sm-web-prod")))

		target.DeploymentPolicyJSON = []byte(`{"stateful":true}`)
		target.ComposeProject = "renamed"
		updated := must(UpdateAppTarget(ctx, q, target, 1))
		if updated.SpecRevision != 2 || string(updated.DeploymentPolicyJSON) != `{"stateful":true}` {
			t.Fatalf("updated = %+v", updated)
		}
		if updated.ComposeProject != "sm-web-prod" {
			t.Errorf("compose project = %q, want the immutable original", updated.ComposeProject)
		}

		_, err := UpdateAppTarget(ctx, q, target, 1)
		wantError(t, err, smerr.CodeConflict, "")
	})
}
