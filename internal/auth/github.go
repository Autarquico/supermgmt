package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/providers/github"
)

// GitHubScopes are the implicit scopes of a github_oidc credential: it is
// usable only to request and read deployments (spec §11.1).
var GitHubScopes = []string{"deployment.create", "deployment.read"}

// GitHubResolver authenticates a GitHub Actions OIDC token presented as a
// bearer on an HTTPS request. The verifier checks the token (signature,
// audience, lifetime, replay); the resolver maps it to the pre-registered
// automation identity of its repository and workflow and records a durable
// github_oidc_credentials row, which is what CredentialStatus judges later.
// It never decides whether the claims entitle the caller to deploy a commit:
// that is github.MatchClaims, at request time.
type GitHubResolver struct {
	DB       *database.DB
	Verifier github.OIDCVerifier
	// Clock defaults to the system clock.
	Clock domain.Clock
}

var _ Resolver = GitHubResolver{}

func (r GitHubResolver) Resolve(ctx context.Context, bearer string) (app.Caller, error) {
	claims, err := r.Verifier.Verify(ctx, bearer)
	if err != nil {
		return app.Caller{}, err
	}
	identity, err := r.automationIdentity(ctx, claims)
	if err != nil {
		return app.Caller{}, err
	}
	credential, err := r.record(ctx, identity, claims)
	if err != nil {
		return app.Caller{}, err
	}
	expires := claims.ExpiresAt
	return app.Caller{
		ID:         identity,
		Credential: domain.CredentialContext{Kind: domain.CredentialGitHubOIDC, ID: credential, Scopes: GitHubScopes, ExpiresAt: &expires},
		Source:     requestSource,
	}, nil
}

// automationIdentity finds the enabled automation identity registered for the
// token's repository and workflow. Every miss is the same UNAUTHENTICATED, so
// a token cannot probe which repositories are registered.
func (r GitHubResolver) automationIdentity(ctx context.Context, c github.Claims) (domain.ID, error) {
	refused := smerr.New(smerr.CodeUnauthenticated, "", "no automation identity for this workflow")
	path, ok := workflowPath(c)
	if !ok {
		return "", refused
	}
	var id domain.ID
	err := r.DB.Reader().QueryRowContext(ctx, `
		SELECT COALESCE(MAX(id), '') FROM identities
		WHERE actor_type = ? AND issuer = ? AND subject = ? AND client_id = ''`,
		domain.ActorAutomation, c.Issuer, AutomationSubject(c.RepositoryID, path)).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("find automation identity: %w", err)
	}
	if id == "" {
		return "", refused
	}
	identity, err := database.GetIdentity(ctx, r.DB.Reader(), id)
	if err != nil {
		return "", unknownCredential(err)
	}
	if identity.DisabledAt != nil {
		return "", smerr.New(smerr.CodeUnauthenticated, "", "identity is disabled")
	}
	return id, nil
}

// AutomationSubject is the subject of the automation identity of a repository's
// deploy workflow (spec §11.1): repository_id:<id>:workflow:<path>.
func AutomationSubject(repositoryID int64, workflowPath string) string {
	return fmt.Sprintf("repository_id:%d:workflow:%s", repositoryID, workflowPath)
}

// workflowPath extracts <path> from workflow_ref = <owner>/<repo>/<path>@<ref>.
func workflowPath(c github.Claims) (string, bool) {
	if c.Repository == "" {
		return "", false
	}
	rest, ok := strings.CutPrefix(c.WorkflowRef, c.Repository+"/")
	if !ok {
		return "", false
	}
	path, _, ok := strings.Cut(rest, "@")
	return path, ok && path != ""
}

// record stores the credential row and returns its id. The row keeps the
// non-secret claims finalization binds to, so CI waits longer than the token's
// lifetime are safe; the raw token is never stored.
func (r GitHubResolver) record(ctx context.Context, identity domain.ID, c github.Claims) (string, error) {
	stored, err := json.Marshal(storedClaimsOf(c))
	if err != nil {
		return "", fmt.Errorf("encode oidc claims: %w", err)
	}
	row := database.GithubOIDCCredential{
		ID:         database.GithubOIDCCredentialID(c.Issuer, c.JTI),
		IdentityID: identity, RepositoryID: c.RepositoryID, ClaimsJSON: stored,
		IssuedAt: c.IssuedAt, ExpiresAt: c.ExpiresAt, CreatedAt: clockOrSystem(r.Clock).Now(),
	}
	err = r.DB.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		return database.InsertGithubOIDCCredential(ctx, tx, row)
	})
	if err != nil {
		return "", fmt.Errorf("record github oidc credential: %w", err)
	}
	return row.ID, nil
}

// storedClaims is the claims_json of github_oidc_credentials: the §18 claims a
// finalization binds to, under their GitHub names.
type storedClaims struct {
	RepositoryID      int64  `json:"repository_id"`
	RepositoryOwnerID int64  `json:"repository_owner_id"`
	Repository        string `json:"repository"`
	WorkflowRef       string `json:"workflow_ref"`
	JobWorkflowRef    string `json:"job_workflow_ref,omitempty"`
	SHA               string `json:"sha"`
	Ref               string `json:"ref"`
	EventName         string `json:"event_name"`
	Environment       string `json:"environment,omitempty"`
	RunID             int64  `json:"run_id"`
	RunAttempt        int64  `json:"run_attempt"`
}

func storedClaimsOf(c github.Claims) storedClaims {
	return storedClaims{
		RepositoryID: c.RepositoryID, RepositoryOwnerID: c.RepositoryOwnerID, Repository: c.Repository,
		WorkflowRef: c.WorkflowRef, JobWorkflowRef: c.JobWorkflowRef, SHA: c.SHA,
		Ref: c.Ref, EventName: c.EventName, Environment: c.Environment, RunID: c.RunID, RunAttempt: c.RunAttempt,
	}
}

// BearerResolver sends a GitHub Actions JWT to GitHub and every other bearer
// to Tokens. GitHub may be nil (no GitHub provider configured): such a JWT is
// then just a malformed token.
type BearerResolver struct {
	Tokens Resolver
	GitHub Resolver
}

var _ Resolver = BearerResolver{}

func (r BearerResolver) Resolve(ctx context.Context, bearer string) (app.Caller, error) {
	if r.GitHub != nil && looksLikeJWT(bearer) {
		return r.GitHub.Resolve(ctx, bearer)
	}
	return r.Tokens.Resolve(ctx, bearer)
}

// looksLikeJWT is true for three dot-separated segments whose header starts
// like `{"`; native tokens carry the sm prefix and never match.
func looksLikeJWT(bearer string) bool {
	return strings.HasPrefix(bearer, "eyJ") && strings.Count(bearer, ".") == 2
}
