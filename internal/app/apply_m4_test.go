package app

import (
	"context"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/providers/github"
)

func (d *directM4Fixture) mustApp(id domain.ID) database.App {
	d.t.Helper()
	row, err := database.GetApp(context.Background(), d.db.Reader(), id)
	mustf(d.t, err, "GetApp")
	return row
}

// bumpAppRevision changes the app behind the plan's back, as a concurrent edit would.
func (d *directM4Fixture) bumpAppRevision(id domain.ID) {
	d.t.Helper()
	d.inTx(func(ctx context.Context, tx *database.Tx) error {
		row, err := database.GetApp(ctx, tx, id)
		if err != nil {
			return err
		}
		row.ManifestPath = ".other.yaml"
		_, err = database.UpdateApp(ctx, tx, row, row.SpecRevision)
		return err
	})
}

func (d *directM4Fixture) providerNamed(name string) (domain.Provider, bool) {
	d.t.Helper()
	providers, err := database.ListProviders(context.Background(), d.db.Reader())
	mustf(d.t, err, "ListProviders")
	for _, p := range providers {
		if p.Name == name {
			return p, true
		}
	}
	return domain.Provider{}, false
}

func TestApplyApproved_AppComposeEditProduction(t *testing.T) {
	d := newDirectM4Fixture(t)
	app, _ := d.productionApp()
	edited := appsWebCompose + "\n# approved edit\n"

	res, err := d.apps.Update(context.Background(), d.caller(d.admin), app.ID, app.SpecRevision, wire.AppPatch{ComposeContent: &edited})

	mustf(t, err, "Update")
	if res.Pending == nil {
		t.Fatalf("result = %+v, want a request waiting for approval", res)
	}
	if got := d.mustApp(app.ID); got.ComposeContent != appsWebCompose || got.SpecRevision != app.SpecRevision {
		t.Fatalf("an unapproved request changed the app: %+v", got)
	}
	d.approveToQuorum(res.Pending.Job)
	mustf(t, d.applyApproved(res.Pending.Job.ID), "apply")

	got := d.mustApp(app.ID)
	if got.ComposeContent != edited || got.ComposeSourceHash != appsSHA256(edited) || got.SpecRevision != app.SpecRevision+1 {
		t.Errorf("app = %+v, want exactly the approved Compose", got)
	}
	if len(d.events(appWriteAction)) < 2 {
		t.Error("the applied change was not audited")
	}
}

func TestApplyApproved_AppTargetEdit(t *testing.T) {
	d := newDirectM4Fixture(t)
	_, target := d.productionApp()
	manual := wire.DeploymentPolicy{Rollback: rollbackManual}

	res, err := d.apps.UpdateTarget(context.Background(), d.caller(d.admin), target.ID, target.SpecRevision, wire.AppTargetPatch{DeploymentPolicy: &manual})

	mustf(t, err, "UpdateTarget")
	if res.Pending == nil {
		t.Fatalf("result = %+v, want a request waiting for approval", res)
	}
	d.approveToQuorum(res.Pending.Job)
	mustf(t, d.applyApproved(res.Pending.Job.ID), "apply")
	got, err := d.apps.GetTarget(context.Background(), d.caller(d.admin), target.ID)
	mustf(t, err, "GetTarget")
	if got.DeploymentPolicy.Rollback != rollbackManual || got.SpecRevision != target.SpecRevision+1 {
		t.Errorf("target = %+v", got)
	}
}

func TestApplyApproved_StaleRevisionNothingApplied(t *testing.T) {
	d := newDirectM4Fixture(t)
	app, _ := d.productionApp()
	edited := appsWebCompose + "\n# stale\n"
	res, err := d.apps.Update(context.Background(), d.caller(d.admin), app.ID, app.SpecRevision, wire.AppPatch{ComposeContent: &edited})
	mustf(t, err, "Update")
	job := d.approveToQuorum(res.Pending.Job)

	d.bumpAppRevision(app.ID)

	if _, ok := d.claim(); ok {
		t.Fatal("a stale approved plan was claimed")
	}
	failed := d.job(job.ID)
	if failed.State != domain.JobFailed || failed.Error == nil || failed.Error.Reason != smerr.ReasonPlanStale {
		t.Fatalf("job = %s %+v, want failed PLAN_STALE", failed.State, failed.Error)
	}
	if got := d.mustApp(app.ID); got.ComposeContent != appsWebCompose {
		t.Errorf("a stale plan changed the Compose: %q", got.ComposeContent)
	}
}

func TestApplyApproved_ResourceLockedWhileADeploymentHoldsTheTarget(t *testing.T) {
	d := newDirectM4Fixture(t)
	_, target := d.productionApp()
	manual := wire.DeploymentPolicy{Rollback: rollbackManual}
	res, err := d.apps.UpdateTarget(context.Background(), d.caller(d.admin), target.ID, target.SpecRevision, wire.AppTargetPatch{DeploymentPolicy: &manual})
	mustf(t, err, "UpdateTarget")
	d.approveToQuorum(res.Pending.Job)
	claimed, ok := d.claim()
	if !ok {
		t.Fatal("the approved change was not claimable")
	}
	d.holdLock(appTargetRef(target.ID))

	err = applyHandler{inv: d.inv, apps: d.apps}.Run(context.Background(), claimed.Lease)

	wantError(t, err, smerr.CodeConflict, smerr.ReasonResourceLocked)
	got, getErr := d.apps.GetTarget(context.Background(), d.caller(d.admin), target.ID)
	mustf(t, getErr, "GetTarget")
	if got.DeploymentPolicy.Rollback != rollbackAutomatic || got.SpecRevision != target.SpecRevision {
		t.Errorf("a locked target changed: %+v", got)
	}
}

func TestApplyApproved_GitHubProvider(t *testing.T) {
	d := newDirectM4Fixture(t)
	req := wire.CreateGitHubProviderRequest{
		Type: wire.ProviderGitHub, Name: "github-acme", APIURL: "https://ghe.example.com/api/v3",
		CredentialRef: "secret://providers/github-acme/token", WebhookSecretRef: "secret://providers/github-acme/webhook", CAFile: "/etc/ssl/ghe.pem",
	}

	res, err := d.apps.CreateGitHubProvider(context.Background(), d.caller(d.admin), req)

	mustf(t, err, "CreateGitHubProvider")
	if res.Pending == nil || res.Applied != nil {
		t.Fatalf("result = %+v, provider.write is high risk and waits for approval", res)
	}
	if _, found := d.providerNamed("github-acme"); found {
		t.Fatal("an unapproved request stored the provider")
	}
	if _, err := d.approve(d.bob, res.Pending.Job); err != nil {
		t.Fatalf("approve: %v", err)
	}
	mustf(t, d.applyApproved(res.Pending.Job.ID), "apply")

	stored, found := d.providerNamed("github-acme")
	if !found || stored.Type != github.ProviderType || stored.Endpoint != req.APIURL || stored.CredentialRef != req.CredentialRef ||
		stored.Config[providerConfigCAFile] != req.CAFile || stored.Config[providerConfigWebhookSecretRef] != req.WebhookSecretRef {
		t.Errorf("provider = %+v, want the approved configuration in the client factory's convention", stored)
	}
}

func TestCreateGitHubProviderRefusesBadRequestsBeforeAnyPlan(t *testing.T) {
	d := newDirectM4Fixture(t)
	good := wire.CreateGitHubProviderRequest{Type: wire.ProviderGitHub, Name: "gh", CredentialRef: "secret://providers/gh/token"}
	cases := map[string]func(*wire.CreateGitHubProviderRequest){
		"wrong type":    func(r *wire.CreateGitHubProviderRequest) { r.Type = "proxmox" },
		"http":          func(r *wire.CreateGitHubProviderRequest) { r.APIURL = "http://api.github.com" },
		"literal token": func(r *wire.CreateGitHubProviderRequest) { r.CredentialRef = "ghp_abc" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := good
			mutate(&r)

			_, err := d.apps.CreateGitHubProvider(context.Background(), d.caller(d.admin), r)

			wantAppsCode(t, err, smerr.CodeInvalidArgument)
		})
	}
	res, err := d.apps.CreateGitHubProvider(context.Background(), d.caller(d.admin), good)
	mustf(t, err, "CreateGitHubProvider with the default api_url")
	if res.Pending == nil {
		t.Fatalf("result = %+v, want a request waiting for approval", res)
	}
	mustf(t, d.applyApproved(d.approveAndReturn(res.Pending.Job)), "apply")

	_, err = d.apps.CreateGitHubProvider(context.Background(), d.caller(d.admin), good)
	wantAppsCode(t, err, smerr.CodeConflict)
}

func (d *directM4Fixture) approveAndReturn(job jobs.Job) domain.ID {
	d.t.Helper()
	approved, err := d.approve(d.bob, job)
	mustf(d.t, err, "approve")
	return approved.ID
}

func TestApplyApprovedWithoutTheAppsCatalogFailsLoudly(t *testing.T) {
	d := newDirectM4Fixture(t)
	res, err := d.apps.CreateGitHubProvider(context.Background(), d.caller(d.admin),
		wire.CreateGitHubProviderRequest{Type: wire.ProviderGitHub, Name: "gh", CredentialRef: "secret://providers/gh/token"})
	mustf(t, err, "CreateGitHubProvider")
	d.approveAndReturn(res.Pending.Job)
	claimed, _ := d.claim()

	err = applyHandler{inv: d.inv}.Run(context.Background(), claimed.Lease)

	wantAppsCode(t, err, smerr.CodeInternal)
	if _, found := d.providerNamed("gh"); found {
		t.Error("a handler without the catalog stored the provider")
	}
}
