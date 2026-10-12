package auth_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/auth"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/providers/github"
)

const (
	ghRepoID    = int64(123)
	ghWorkflow  = ".github/workflows/deploy.yml"
	ghIssuer    = github.ActionsIssuer
	ghJWTShaped = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ4In0.c2ln"
)

// ghVerifier answers Verify with fixed claims or a fixed error.
type ghVerifier struct {
	claims github.Claims
	err    error
	seen   string
}

func (v *ghVerifier) Verify(_ context.Context, raw string) (github.Claims, error) {
	v.seen = raw
	return v.claims, v.err
}

func ghClaims(w *world) github.Claims {
	return github.Claims{
		Issuer: ghIssuer, Subject: "repo:acme/shop:ref:refs/heads/main", JTI: "jti-1",
		IssuedAt: w.clock.Now(), ExpiresAt: w.clock.Now().Add(5 * time.Minute),
		RepositoryID: ghRepoID, Repository: "acme/shop", Ref: "refs/heads/main", SHA: "abc123", EventName: "push",
		WorkflowRef: "acme/shop/" + ghWorkflow + "@refs/heads/main", Environment: "production", RunID: 555, RunAttempt: 2,
	}
}

// ghAutomation registers the automation identity of the default claims.
func ghAutomation(w *world) domain.ID {
	w.t.Helper()
	id := w.ids.NewID()
	must(w.t, w.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		return database.CreateIdentity(ctx, tx, database.Identity{
			ID: id, ActorType: domain.ActorAutomation, Issuer: ghIssuer,
			Subject: auth.AutomationSubject(ghRepoID, ghWorkflow), CreatedAt: w.clock.Now(),
		})
	}), "CreateIdentity")
	return id
}

func ghResolver(w *world, v *ghVerifier) auth.GitHubResolver {
	return auth.GitHubResolver{DB: w.db, Verifier: v, Clock: w.clock}
}

func TestGitHubResolverMapsATokenToItsAutomationIdentityWithImplicitScopes(t *testing.T) {
	w := newWorld(t)
	identity := ghAutomation(w)
	claims := ghClaims(w)

	caller, err := ghResolver(w, &ghVerifier{claims: claims}).Resolve(context.Background(), ghJWTShaped)
	must(t, err, "Resolve")

	cred := caller.Credential
	if caller.ID != identity || cred.Kind != domain.CredentialGitHubOIDC || caller.Source != "api" {
		t.Fatalf("caller = %+v", caller)
	}
	if want := database.GithubOIDCCredentialID(ghIssuer, "jti-1"); cred.ID != want {
		t.Errorf("credential id = %q, want sha256(issuer|jti) %q", cred.ID, want)
	}
	if strings.Join(cred.Scopes, ",") != "deployment.create,deployment.read" {
		t.Errorf("scopes = %v", cred.Scopes)
	}
	if cred.ExpiresAt == nil || !cred.ExpiresAt.Equal(claims.ExpiresAt) {
		t.Errorf("expires = %v, want %v", cred.ExpiresAt, claims.ExpiresAt)
	}
}

func TestGitHubResolverStoresTheClaimsButNeverTheToken(t *testing.T) {
	w := newWorld(t)
	identity := ghAutomation(w)
	caller, err := ghResolver(w, &ghVerifier{claims: ghClaims(w)}).Resolve(context.Background(), ghJWTShaped)
	must(t, err, "Resolve")

	row, err := database.GetGithubOIDCCredential(context.Background(), w.db.Reader(), caller.Credential.ID)
	must(t, err, "GetGithubOIDCCredential")

	if row.IdentityID != identity || row.RepositoryID != ghRepoID || row.RevokedAt != nil {
		t.Errorf("row = %+v", row)
	}
	var got map[string]any
	must(t, json.Unmarshal(row.ClaimsJSON, &got), "claims_json")
	want := map[string]any{
		"repository_id": float64(ghRepoID), "workflow_ref": "acme/shop/" + ghWorkflow + "@refs/heads/main", "sha": "abc123",
		"ref": "refs/heads/main", "event_name": "push", "environment": "production", "run_id": float64(555), "run_attempt": float64(2),
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("claims_json[%s] = %v, want %v", k, got[k], v)
		}
	}
	if strings.Contains(string(row.ClaimsJSON), ghJWTShaped) {
		t.Error("claims_json holds the raw token")
	}
}

func TestGitHubResolverRefusesWhatItCannotMapToAnEnabledAutomationIdentity(t *testing.T) {
	cases := []struct {
		name string
		prep func(w *world, c *github.Claims)
	}{
		{"no identity registered", func(*world, *github.Claims) {}},
		{"other repository", func(w *world, c *github.Claims) { ghAutomation(w); c.RepositoryID = 999 }},
		{"other workflow", func(w *world, c *github.Claims) {
			ghAutomation(w)
			c.WorkflowRef = "acme/shop/.github/workflows/other.yml@refs/heads/main"
		}},
		{"workflow_ref of another repository", func(w *world, c *github.Claims) {
			ghAutomation(w)
			c.WorkflowRef = "evil/shop/" + ghWorkflow + "@refs/heads/main"
		}},
		{"workflow_ref without ref", func(w *world, c *github.Claims) { ghAutomation(w); c.WorkflowRef = "acme/shop/" + ghWorkflow }},
		{"human identity with the same subject", func(w *world, c *github.Claims) {
			must(w.t, w.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
				return database.CreateIdentity(ctx, tx, database.Identity{
					ID: w.ids.NewID(), ActorType: domain.ActorHuman, Issuer: ghIssuer,
					Subject: auth.AutomationSubject(ghRepoID, ghWorkflow), CreatedAt: w.clock.Now(),
				})
			}), "CreateIdentity")
		}},
		{"disabled identity", func(w *world, c *github.Claims) { ghDisable(w, ghAutomation(w)) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			claims := ghClaims(w)
			tc.prep(w, &claims)

			_, err := ghResolver(w, &ghVerifier{claims: claims}).Resolve(context.Background(), ghJWTShaped)

			if smerr.CodeOf(err) != smerr.CodeUnauthenticated {
				t.Fatalf("err = %v, want UNAUTHENTICATED", err)
			}
			if n := ghCredentialCount(w); n != 0 {
				t.Errorf("%d credential rows written for a refused token", n)
			}
		})
	}
}

func TestGitHubResolverPassesVerifierRejectionsThroughAndStoresNothing(t *testing.T) {
	w := newWorld(t)
	ghAutomation(w)
	replay := smerr.FromReason(smerr.ReasonOIDCReplay, "token already used")

	_, err := ghResolver(w, &ghVerifier{err: replay}).Resolve(context.Background(), ghJWTShaped)

	var typed *smerr.Error
	if !errors.As(err, &typed) || typed.Reason != smerr.ReasonOIDCReplay {
		t.Fatalf("err = %v, want OIDC_REPLAY", err)
	}
	if n := ghCredentialCount(w); n != 0 {
		t.Errorf("%d credential rows written", n)
	}
}

func TestBearerResolverRoutesActionsTokensToGitHubAndTheRestToNativeTokens(t *testing.T) {
	w := newWorld(t)
	ghAutomation(w)
	issued := w.issue()
	verifier := &ghVerifier{claims: ghClaims(w)}
	router := auth.BearerResolver{Tokens: w.resolver, GitHub: ghResolver(w, verifier)}

	viaGitHub, err := router.Resolve(context.Background(), ghJWTShaped)
	must(t, err, "Resolve JWT")
	viaTokens, err := router.Resolve(context.Background(), issued.Value)
	must(t, err, "Resolve native")

	if viaGitHub.Credential.Kind != domain.CredentialGitHubOIDC || viaTokens.Credential.Kind != domain.CredentialAPIToken {
		t.Errorf("kinds = %s, %s", viaGitHub.Credential.Kind, viaTokens.Credential.Kind)
	}
	if verifier.seen != ghJWTShaped {
		t.Errorf("verifier saw %q", verifier.seen)
	}
}

func TestBearerResolverWithoutGitHubTreatsAJWTAsAMalformedToken(t *testing.T) {
	w := newWorld(t)
	router := auth.BearerResolver{Tokens: w.resolver}

	_, err := router.Resolve(context.Background(), ghJWTShaped)

	if smerr.CodeOf(err) != smerr.CodeUnauthenticated {
		t.Fatalf("err = %v, want UNAUTHENTICATED", err)
	}
}

func ghDisable(w *world, id domain.ID) {
	w.t.Helper()
	must(w.t, w.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE identities SET disabled_at = ? WHERE id = ?`, domain.UnixMillis(w.clock.Now()), id)
		return err
	}), "disable identity")
}

func ghCredentialCount(w *world) int {
	w.t.Helper()
	var n int
	must(w.t, w.db.Reader().QueryRowContext(context.Background(), `SELECT COUNT(*) FROM github_oidc_credentials`).Scan(&n), "count")
	return n
}
