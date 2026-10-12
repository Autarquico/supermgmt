package app

import (
	"context"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/policy"
)

// directM4Fixture is the apps fixture with the production plan builder and an
// inventory to run approved changes.
type directM4Fixture struct {
	*appsFixture
	inv *Inventory
}

func newDirectM4Fixture(t *testing.T) *directM4Fixture {
	t.Helper()
	f := newAppsFixture(t)
	f.apps.build = build
	inv, err := NewInventory(f.cfg, InventoryOptions{Store: f.store, Connector: Connector{}, Mode: config.ModeLocal})
	mustf(t, err, "NewInventory")
	return &directM4Fixture{appsFixture: f, inv: inv}
}

func (d *directM4Fixture) applyApproved(job domain.ID) error {
	d.t.Helper()
	claimed, ok := d.claim()
	if !ok || claimed.Job.ID != job {
		d.t.Fatalf("job %s was not claimable", job)
	}
	if err := (applyHandler{inv: d.inv, apps: d.apps}).Run(context.Background(), claimed.Lease); err != nil {
		return err
	}
	return d.store.Succeed(context.Background(), claimed.Lease)
}

// productionApp is an app whose target in the production environment exists.
func (d *directM4Fixture) productionApp() (AppView, AppTargetView) {
	d.t.Helper()
	app := d.createApp()
	res, err := d.createTarget(app, d.env.Name, d.node.ID)
	mustf(d.t, err, "CreateTarget in production")
	if res.Pending == nil {
		d.t.Fatalf("a production target must wait for approval: %+v", res)
	}
	d.approveToQuorum(res.Pending.Job)
	mustf(d.t, d.applyApproved(res.Pending.Job.ID), "apply the target")
	targets, err := d.apps.ListTargets(context.Background(), d.caller(d.admin), app.ID)
	mustf(d.t, err, "ListTargets")
	if len(targets) != 1 {
		d.t.Fatalf("targets = %+v", targets)
	}
	return app, targets[0]
}

// holdLock records a lock on ref held by a job that is not a control-plane change.
func (d *directM4Fixture) holdLock(ref domain.ResourceRef) {
	d.t.Helper()
	sub, _ := d.submitReboot()
	d.inTx(func(ctx context.Context, tx *database.Tx) error {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO resource_locks (resource_type, resource_id, job_id, mode, acquired_at) VALUES (?, ?, ?, 'exclusive', 0)`,
			ref.Type, ref.ID, sub.Job.ID)
		return err
	})
}

func directM4HasInput(b built, typ domain.ResourceType, id domain.ID) bool {
	for _, in := range b.plan.Inputs {
		if in.Type == string(typ) && in.ID == id.String() {
			return true
		}
	}
	return false
}

func directM4Ptr[T any](v T) *T { return &v }

func TestDirectTargetOfAppWriteIsJudgedByTheStrictestEnvironmentOfItsTargets(t *testing.T) {
	d := newDirectM4Fixture(t)
	app, target := d.productionApp()
	patch := wire.AppPatch{ComposeContent: directM4Ptr(appsWebCompose + "\n# edit\n")}

	res, err := d.apps.Update(context.Background(), d.caller(d.admin), app.ID, app.SpecRevision, patch)

	mustf(t, err, "Update")
	if res.Pending == nil || res.Applied != nil {
		t.Fatalf("a Compose edit of a production app must wait for approval: %+v", res)
	}
	if res.Pending.Policy.Quorum != d.env.ApprovalsRequired {
		t.Errorf("quorum = %d, want the production environment's %d", res.Pending.Policy.Quorum, d.env.ApprovalsRequired)
	}
	rec, err := database.GetPlan(context.Background(), d.db.Reader(), *res.Pending.Job.PlanID)
	mustf(t, err, "GetPlan")
	rebuilt, err := rebuildCurrent(context.Background(), d.db.Reader(), rec)
	mustf(t, err, "rebuildCurrent")
	revision := rebuilt.plan.Targets[0].SpecRevision
	if rebuilt.target.Attrs.EnvironmentRisk != domain.EnvironmentProduction || revision == nil || *revision != app.SpecRevision {
		t.Errorf("target = %+v, revision %v", rebuilt.target.Attrs, revision)
	}
	if !directM4HasInput(rebuilt, domain.ResourceAppTarget, target.ID) || !directM4HasInput(rebuilt, domain.ResourceEnvironment, d.env.ID) {
		t.Errorf("inputs = %+v, want the target and its environment", rebuilt.plan.Inputs)
	}
}

func TestDirectTargetOfAppTargetCreationNamesEnvironmentAppAndNode(t *testing.T) {
	d := newDirectM4Fixture(t)
	app := d.createApp()
	p := appTargetCreateParams{
		TargetID: d.ids.NewID(), AppID: app.ID, Environment: d.env.Name, NodeID: d.node.ID,
		Policy: wire.DeploymentPolicy{Rollback: rollbackManual},
	}
	params, err := toParams(p)
	mustf(t, err, "toParams")

	b, err := build(context.Background(), d.db.Reader(), appTargetWriteAction, d.admin, appTargetRef(p.TargetID), params)

	mustf(t, err, "build")
	attrs := b.target.Attrs
	if attrs.App != "web" || attrs.Environment != d.env.Name || attrs.ApprovalsRequired != 2 || attrs.Node != d.node.Name || len(attrs.Tags) != 1 {
		t.Errorf("attributes = %+v", attrs)
	}
	if b.plan.Targets[0].SpecRevision != nil || len(b.plan.Inputs) != 3 {
		t.Errorf("a creation has no revision and three inputs; got %v and %d", b.plan.Targets[0].SpecRevision, len(b.plan.Inputs))
	}
}

func TestDirectTargetRefusesParametersThatNameAnotherTarget(t *testing.T) {
	d := newDirectM4Fixture(t)
	other := d.ids.NewID()
	providerRef := domain.ResourceRef{Type: domain.ResourceProvider, ID: other}
	cases := map[string]struct {
		action string
		ref    domain.ResourceRef
		params any
	}{
		"app creation":    {appWriteAction, appRef(other), appCreateParams{AppID: d.ids.NewID()}},
		"app update":      {appWriteAction, appRef(other), appUpdateParams{AppID: d.ids.NewID(), ExpectedRevision: 1}},
		"target creation": {appTargetWriteAction, appTargetRef(other), appTargetCreateParams{TargetID: d.ids.NewID()}},
		"target update":   {appTargetWriteAction, appTargetRef(other), appTargetUpdateParams{TargetID: d.ids.NewID(), ExpectedRevision: 1}},
		"github provider": {actionProviderWite, providerRef, githubProviderParams{
			ProviderID: d.ids.NewID(), Name: "gh", APIURL: defaultGitHubAPIURL, CredentialRef: "secret://providers/gh/token",
		}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			params, err := toParams(c.params)
			mustf(t, err, "toParams")

			_, err = build(context.Background(), d.db.Reader(), c.action, d.admin, c.ref, params)

			wantAppsCode(t, err, smerr.CodeInvalidArgument)
		})
	}
}

func TestAppTargetResolvesForDeploymentPlans(t *testing.T) {
	d := newDirectM4Fixture(t)
	_, target := d.productionApp()

	r, err := resolve(context.Background(), d.db.Reader(), appTargetRef(target.ID))

	mustf(t, err, "resolve")
	if r.revision != target.SpecRevision || r.target.Attrs.App != "web" || r.target.Attrs.Environment != d.env.Name || len(r.inputs) != 3 {
		t.Errorf("resolved = %+v", r)
	}
	if readActionFor[domain.ResourceApp] != "app.read" || readActionFor[domain.ResourceAppTarget] != "app_target.read" {
		t.Errorf("readActionFor = %v", readActionFor)
	}
	if _, known := policy.Lookup(readActionFor[domain.ResourceAppTarget]); !known {
		t.Error("the read action of an app target is not in the catalog")
	}
}

func TestChangesToAnAppOrTargetAreRefusedWhileADeploymentHoldsThem(t *testing.T) {
	d := newDirectM4Fixture(t)
	app, target := d.productionApp()
	d.holdLock(appTargetRef(target.ID))
	newPolicy := wire.DeploymentPolicy{Rollback: rollbackManual}

	_, targetErr := d.apps.UpdateTarget(context.Background(), d.caller(d.admin), target.ID, target.SpecRevision, wire.AppTargetPatch{DeploymentPolicy: &newPolicy})
	_, appErr := d.apps.Update(context.Background(), d.caller(d.admin), app.ID, app.SpecRevision, wire.AppPatch{ComposeContent: directM4Ptr(appsWebCompose + "\n# edit\n")})

	wantError(t, targetErr, smerr.CodeConflict, smerr.ReasonResourceLocked)
	wantError(t, appErr, smerr.CodeConflict, smerr.ReasonResourceLocked)
}

func TestValidateParametersChecksTheDeployRootOfNodeSetup(t *testing.T) {
	cases := map[string]struct {
		root string
		ok   bool
	}{
		"default":  {"", true},
		"absolute": {"/srv/apps", true},
		"relative": {"srv/apps", false},
		"dotdot":   {"/srv/../etc", false},
		"home":     {"/var/lib/supermgmt/x", false},
		"space":    {"/srv/my apps", false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			params := map[string]any{policy.ParamDockerAccess: "true"}
			if c.root != "" {
				params[deployRootParam] = c.root
			}

			err := validateParameters(policy.ActionNodeSetup, params)

			if c.ok && err != nil {
				t.Fatalf("validateParameters = %v", err)
			}
			if !c.ok {
				wantAppsCode(t, err, smerr.CodeInvalidArgument)
			}
		})
	}
}

func TestGitHubProviderParametersAreValidated(t *testing.T) {
	valid := githubProviderParams{ProviderID: "p1", Name: "github", APIURL: defaultGitHubAPIURL, CredentialRef: "secret://providers/github/token"}
	cases := map[string]func(*githubProviderParams){
		"http api":              func(p *githubProviderParams) { p.APIURL = "http://api.github.com" },
		"credentials in url":    func(p *githubProviderParams) { p.APIURL = "https://u:p@api.github.com" },
		"trailing slash":        func(p *githubProviderParams) { p.APIURL = "https://api.github.com/" },
		"query":                 func(p *githubProviderParams) { p.APIURL = "https://api.github.com?x=1" },
		"bad name":              func(p *githubProviderParams) { p.Name = "Git Hub" },
		"token outside prefix":  func(p *githubProviderParams) { p.CredentialRef = "secret://apps/web/token" },
		"token is not a ref":    func(p *githubProviderParams) { p.CredentialRef = "ghp_literal" },
		"webhook outside":       func(p *githubProviderParams) { p.WebhookSecretRef = "secret://other" },
		"relative ca":           func(p *githubProviderParams) { p.CAFile = "ca.pem" },
		"unclean ca":            func(p *githubProviderParams) { p.CAFile = "/etc/../ca.pem" },
		"no scheme":             func(p *githubProviderParams) { p.APIURL = "api.github.com" },
		"missing token":         func(p *githubProviderParams) { p.CredentialRef = "" },
		"webhook ref malformed": func(p *githubProviderParams) { p.WebhookSecretRef = "secret://providers/" },
	}
	if err := valid.validate(); err != nil {
		t.Fatalf("a valid provider was refused: %v", err)
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := valid
			mutate(&p)

			wantAppsCode(t, p.validate(), smerr.CodeInvalidArgument)
		})
	}
}
