package app

import (
	"context"
	"testing"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// Spec retire-deployments, scenario "old GitHub-authenticated jobs do not resume":
// a job submitted with a github_oidc credential is failed at claim once that
// credential reads as revoked; unlike a natural expiry, nothing excuses it.
func TestClaimFailsAJobSubmittedWithAGitHubOIDCCredentialOnceItReadsRevoked(t *testing.T) {
	f := newFixture(t)
	by := Caller{ID: f.alice, Credential: domain.CredentialContext{Kind: domain.CredentialGitHubOIDC, ID: "cred-1"}}
	created, err := f.plans.Create(context.Background(), by, f.reboot())
	if err != nil {
		t.Fatal(err)
	}
	sub, err := f.plans.Submit(context.Background(), by, created.Record.ID, created.Record.PlanHash)
	if err != nil {
		t.Fatal(err)
	}
	f.approveToQuorum(sub.Job)

	f.creds.set("cred-1", CredentialRevoked)

	wantFailedAtClaim(f, sub.Job.ID, smerr.CodeUnauthenticated, smerr.ReasonCredentialRevoked)
}
