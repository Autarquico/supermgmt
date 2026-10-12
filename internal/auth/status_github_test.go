package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/auth"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// ghStore stores an open credential of identity that lives five minutes and
// returns the caller that presents it (no scope restriction, so the production
// services can be exercised with the admin identity).
func ghStore(w *world, identity domain.ID) app.Caller {
	w.t.Helper()
	id := database.GithubOIDCCredentialID(ghIssuer, string(w.ids.NewID()))
	expires := w.clock.Now().Add(5 * time.Minute)
	must(w.t, w.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		return database.InsertGithubOIDCCredential(ctx, tx, database.GithubOIDCCredential{
			ID: id, IdentityID: identity, RepositoryID: ghRepoID, IssuedAt: w.clock.Now(), ExpiresAt: expires, CreatedAt: w.clock.Now(),
		})
	}), "InsertGithubOIDCCredential")
	return app.Caller{ID: identity, Credential: domain.CredentialContext{Kind: domain.CredentialGitHubOIDC, ID: id, ExpiresAt: &expires}}
}

// ghRevokeCredentials is what unlinking the automation identity from its app does.
func ghRevokeCredentials(w *world, identity domain.ID) {
	w.t.Helper()
	must(w.t, w.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		_, err := database.RevokeGithubOIDCCredentialsByIdentity(ctx, tx, identity, w.clock.Now())
		return err
	}), "revoke credentials")
}

func ghStateOf(w *world, caller app.Caller) app.CredentialState {
	w.t.Helper()
	state, err := auth.CredentialStatus{DB: w.db, Clock: w.clock}.Status(context.Background(), caller.Credential)
	must(w.t, err, "Status")
	return state
}

func TestCredentialStatus_GitHubOIDC(t *testing.T) {
	cases := []struct {
		name string
		do   func(w *world, c app.Caller)
		want app.CredentialState
	}{
		{"active", func(*world, app.Caller) {}, app.CredentialActive},
		{"revoked row", func(w *world, _ app.Caller) { ghRevokeCredentials(w, w.admin) }, app.CredentialRevoked},
		{"identity disabled", func(w *world, _ app.Caller) { ghDisable(w, w.admin) }, app.CredentialRevoked},
		{"natural expiry", func(w *world, _ app.Caller) { w.clock.Advance(10 * time.Minute) }, app.CredentialExpired},
		{"revoked and expired", func(w *world, _ app.Caller) {
			ghRevokeCredentials(w, w.admin)
			w.clock.Advance(10 * time.Minute)
		}, app.CredentialRevoked},
		{"disabled and expired", func(w *world, _ app.Caller) {
			ghDisable(w, w.admin)
			w.clock.Advance(10 * time.Minute)
		}, app.CredentialRevoked},
		{"missing row", func(w *world, c app.Caller) {
			must(w.t, w.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
				_, err := tx.ExecContext(ctx, `DELETE FROM github_oidc_credentials WHERE id = ?`, c.Credential.ID)
				return err
			}), "delete row")
		}, app.CredentialRevoked},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			caller := ghStore(w, w.admin)
			tc.do(w, caller)
			if got := ghStateOf(w, caller); got != tc.want {
				t.Errorf("state = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestCredentialStatusRefusesAGitHubOIDCCredentialWithoutAnID(t *testing.T) {
	w := newWorld(t)

	_, err := auth.CredentialStatus{DB: w.db}.Status(context.Background(), domain.CredentialContext{Kind: domain.CredentialGitHubOIDC})

	if smerr.CodeOf(err) != smerr.CodeUnauthenticated {
		t.Fatalf("err = %v, want UNAUTHENTICATED", err)
	}
}

func TestAnExpiredGitHubOIDCTokenStillPassesTheClaimOfAJobItSubmitted(t *testing.T) {
	w := newWorld(t)
	caller := ghStore(w, w.admin)
	job := w.submitProbe(caller)

	w.clock.Advance(time.Hour)

	if _, ok, err := w.store.Claim(context.Background(), "worker"); err != nil || !ok {
		t.Fatalf("Claim = %v, %v; want the job to run", ok, err)
	}
	ran, err := w.store.Get(context.Background(), w.db.Reader(), job.ID)
	must(t, err, "Get job")
	if ran.State != domain.JobRunning {
		t.Errorf("job = %s, want running", ran.State)
	}
}

func TestRevokingTheGitHubOIDCCredentialFailsTheClaimEvenAfterItExpired(t *testing.T) {
	w := newWorld(t)
	caller := ghStore(w, w.admin)
	job := w.submitProbe(caller)

	ghRevokeCredentials(w, w.admin)
	w.clock.Advance(time.Hour)

	w.claimFails(job.ID, smerr.CodeUnauthenticated, smerr.ReasonCredentialRevoked)
}

func TestDisablingTheIdentityFailsTheClaimOfAGitHubOIDCJob(t *testing.T) {
	w := newWorld(t)
	caller := ghStore(w, w.admin)
	job := w.submitProbe(caller)

	ghDisable(w, w.admin)

	w.claimFails(job.ID, smerr.CodeUnauthenticated, smerr.ReasonCredentialRevoked)
}

func TestARevokedGitHubOIDCCredentialFailsTheSubmission(t *testing.T) {
	w := newWorld(t)
	caller := ghStore(w, w.admin)
	ghRevokeCredentials(w, w.admin)

	_, err := w.plans.Create(context.Background(), caller, app.PlanRequest{
		Action: "node.probe", Target: domain.ResourceRef{Type: domain.ResourceNode, ID: w.node.ID},
	})

	w.wantCode(err, smerr.CodeUnauthenticated, smerr.ReasonCredentialRevoked)
}
