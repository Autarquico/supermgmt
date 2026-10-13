package app

import (
	"context"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/providers/github"
)

const (
	automationDeployWorkflow = ".github/workflows/deploy.yml"
	automationSubjectWeb     = "repository_id:4242:workflow:" + automationDeployWorkflow
)

func withAutomation(f *appsFixture) func(*wire.CreateAppRequest) {
	return func(r *wire.CreateAppRequest) {
		appsRepositoryRequest(f)(r)
		r.AutomationIdentity = true
	}
}

func (f *appsFixture) identityOf(id domain.ID) database.Identity {
	f.t.Helper()
	identity, err := database.GetIdentity(context.Background(), f.db.Reader(), id)
	mustf(f.t, err, "GetIdentity")
	return identity
}

// openCredential records a verified Actions token of the identity.
func (f *appsFixture) openCredential(identity domain.ID, jti string) string {
	f.t.Helper()
	id := database.GithubOIDCCredentialID(github.ActionsIssuer, jti)
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		return database.InsertGithubOIDCCredential(ctx, tx, database.GithubOIDCCredential{
			ID: id, IdentityID: identity, RepositoryID: 4242, ClaimsJSON: []byte(`{}`),
			IssuedAt: f.clock.Now(), ExpiresAt: f.clock.Now().Add(10 * 60e9), CreatedAt: f.clock.Now(),
		})
	})
	return id
}

func (f *appsFixture) credentialRevoked(id string) bool {
	f.t.Helper()
	c, err := database.GetGithubOIDCCredential(context.Background(), f.db.Reader(), id)
	mustf(f.t, err, "GetGithubOIDCCredential")
	return c.RevokedAt != nil
}

func (f *appsFixture) updateApp(app AppView, patch wire.AppPatch) (AppView, error) {
	f.t.Helper()
	res, err := f.apps.Update(context.Background(), f.caller(f.admin), app.ID, app.SpecRevision, patch)
	if err != nil {
		return AppView{}, err
	}
	return *res.Applied, nil
}

func TestAutomation_CreateLinksAnIdentityThatHoldsNoRole(t *testing.T) {
	f := newAppsFixture(t)

	app := f.createApp(withAutomation(f))

	if app.AutomationIdentityID == nil {
		t.Fatal("the app has no automation identity")
	}
	identity := f.identityOf(*app.AutomationIdentityID)
	if identity.ActorType != domain.ActorAutomation || identity.Issuer != github.ActionsIssuer || identity.Subject != automationSubjectWeb {
		t.Errorf("identity = %+v", identity)
	}
	roles, err := database.ListRolesForIdentity(context.Background(), f.db.Reader(), identity.ID)
	mustf(t, err, "ListRolesForIdentity")
	if len(roles) != 0 {
		t.Errorf("the automation identity holds %d roles, want none", len(roles))
	}
	_, denied := f.apps.Create(context.Background(), f.caller(identity.ID), f.createRequest(func(r *wire.CreateAppRequest) { r.Name = "other" }))
	if smerr.CodeOf(denied) != smerr.CodePolicyDenied {
		t.Errorf("an automation identity writing apps: %v, want POLICY_DENIED", denied)
	}
}

func TestAutomation_NeedsADeployWorkflowInTheCIPolicy(t *testing.T) {
	f := newAppsFixture(t)
	tests := map[string]func(*wire.CreateAppRequest){
		"no ci policy": func(r *wire.CreateAppRequest) { r.AutomationIdentity = true },
		"no deploy workflow": func(r *wire.CreateAppRequest) {
			appsRepositoryRequest(f)(r)
			r.CIPolicy.DeployWorkflow = ""
			r.AutomationIdentity = true
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := f.apps.Create(context.Background(), f.caller(f.admin), f.createRequest(mutate))
			wantAppsCode(t, err, smerr.CodeInvalidArgument)
		})
	}
}

func TestAutomation_AnotherAppCannotTakeTheSameIdentity(t *testing.T) {
	f := newAppsFixture(t)
	f.createApp(withAutomation(f))

	_, err := f.apps.Create(context.Background(), f.caller(f.admin), f.createRequest(withAutomation(f), func(r *wire.CreateAppRequest) { r.Name = "web2" }))

	wantAppsCode(t, err, smerr.CodeConflict)
}

func TestAutomation_UnlinkingRevokesOpenCredentialsAndRelinkingReusesTheIdentity(t *testing.T) {
	f := newAppsFixture(t)
	app := f.createApp(withAutomation(f))
	identity := *app.AutomationIdentityID
	token := f.openCredential(identity, "jti-1")
	off, on := false, true

	unlinked, err := f.updateApp(app, wire.AppPatch{AutomationIdentity: &off})
	mustf(t, err, "unlink")
	relinked, relinkErr := f.updateApp(unlinked, wire.AppPatch{AutomationIdentity: &on})
	mustf(t, relinkErr, "relink")

	if unlinked.AutomationIdentityID != nil {
		t.Errorf("the app is still linked to %s", *unlinked.AutomationIdentityID)
	}
	if !f.credentialRevoked(token) {
		t.Error("unlinking left the OIDC credential usable")
	}
	if f.identityOf(identity).DisabledAt != nil {
		t.Error("unlinking must not disable the identity: its history stays")
	}
	if relinked.AutomationIdentityID == nil || *relinked.AutomationIdentityID != identity {
		t.Errorf("relinked to %v, want the same identity %s", relinked.AutomationIdentityID, identity)
	}
	if events := f.events(appWriteAction); events[1].Data["oidc_revocations"] != float64(1) {
		t.Errorf("unlink event = %+v, want the revoked count", events[1].Data)
	}
}

func TestAutomation_ChangingTheDeployWorkflowMovesTheLinkAndRevokesTheOldCredentials(t *testing.T) {
	f := newAppsFixture(t)
	app := f.createApp(withAutomation(f))
	old := *app.AutomationIdentityID
	token := f.openCredential(old, "jti-old")
	ci := *app.CIPolicy
	ci.DeployWorkflow = ".github/workflows/release.yml"

	moved, err := f.updateApp(app, wire.AppPatch{CIPolicy: &ci})

	mustf(t, err, "Update")
	if moved.AutomationIdentityID == nil || *moved.AutomationIdentityID == old {
		t.Fatalf("link = %v, want a new identity for the new workflow", moved.AutomationIdentityID)
	}
	if got := f.identityOf(*moved.AutomationIdentityID).Subject; got != "repository_id:4242:workflow:.github/workflows/release.yml" {
		t.Errorf("subject = %q", got)
	}
	if !f.credentialRevoked(token) {
		t.Error("a token for the old workflow survived the change")
	}
}

func TestAutomation_AnUnrelatedUpdateLeavesTheLinkAlone(t *testing.T) {
	f := newAppsFixture(t)
	app := f.createApp(withAutomation(f))
	token := f.openCredential(*app.AutomationIdentityID, "jti-keep")
	path := "ops/manifest.yaml"

	updated, err := f.updateApp(app, wire.AppPatch{ManifestPath: &path})

	mustf(t, err, "Update")
	if updated.AutomationIdentityID == nil || *updated.AutomationIdentityID != *app.AutomationIdentityID {
		t.Errorf("link = %v, want it kept", updated.AutomationIdentityID)
	}
	if f.credentialRevoked(token) {
		t.Error("an unrelated update revoked a credential")
	}
}

func TestAutomation_ADisabledIdentityCannotBeLinked(t *testing.T) {
	f := newAppsFixture(t)
	app := f.createApp(withAutomation(f))
	identity := *app.AutomationIdentityID
	off, on := false, true
	unlinked, err := f.updateApp(app, wire.AppPatch{AutomationIdentity: &off})
	mustf(t, err, "unlink")
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE identities SET disabled_at = ? WHERE id = ?`, f.clock.Now().UnixMilli(), identity)
		return err
	})

	_, err = f.updateApp(unlinked, wire.AppPatch{AutomationIdentity: &on})

	wantAppsCode(t, err, smerr.CodeInvalidArgument)
}
