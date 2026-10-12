package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/deployments/compose"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/providers/github"
)

// Binding of a deployed digest to the commit that built it (spec §18). A digest
// is accepted when a verified attestation proves it (a), when the verified
// claims of the requesting Actions token name the commit (b), or when the
// app's image policy pins it. Environments with require_provenance accept
// only (a) for the deployed service; pinned sidecars stay allowed.

// digestBinding is how the deployed digest was bound. The zero value means it
// was not bound here: the model pipeline then accepts it only if pinned.
type digestBinding struct {
	method     string // compose.BindingAttestation | compose.BindingOIDCClaims
	provenance json.RawMessage
	runID      *int64
	runAttempt *int64
}

func (b digestBinding) bound() bool { return b.method != "" }

// boundDigests is the pipeline's view of the binding: image reference to method.
func (b digestBinding) boundDigests(ref string) map[string]string {
	if !b.bound() {
		return map[string]string{}
	}
	return map[string]string{ref: b.method}
}

// attestationBinding looks for a verified attestation of the digest. It makes
// network calls and so runs outside any transaction. No attestation, or one
// that proves something else, is "not bound this way"; a failure to verify at
// all (an unreachable GitHub, a stale trust root) is an error to retry.
func attestationBinding(ctx context.Context, client github.Client, verifier github.AttestationVerifier, scope deploymentScope, commit, digest string) (digestBinding, error) {
	if verifier == nil || scope.repo == nil || scope.spec.CI == nil {
		return digestBinding{}, nil
	}
	repo := githubRepoOf(*scope.repo)
	bundles, err := client.Attestations(ctx, repo, digest)
	if err != nil {
		return digestBinding{}, fmt.Errorf("read the attestations of %s: %w", digest, err)
	}
	ci := scope.spec.CI
	evidence, err := verifier.Verify(bundles, digest, github.Provenance{
		RepositoryID: ci.RepositoryID, Repository: repo.Owner + "/" + repo.Name,
		WorkflowPath: ci.DeployWorkflow, Branch: ci.Branch, CommitSHA: commit,
	})
	switch {
	case errors.Is(err, github.ErrNoAttestation), errors.Is(err, github.ErrAttestationRejected):
		return digestBinding{}, nil
	case err != nil:
		return digestBinding{}, fmt.Errorf("verify the attestation of %s: %w", digest, err)
	}
	provenance, err := json.Marshal(evidence)
	if err != nil {
		return digestBinding{}, fmt.Errorf("encode attestation evidence: %w", err)
	}
	return digestBinding{
		method: compose.BindingAttestation, provenance: provenance,
		runID: nonZero(evidence.RunID), runAttempt: nonZero(evidence.RunAttempt),
	}, nil
}

// oidcBinding binds the digest by the claims stored when the requesting
// Actions token was verified, so it still holds after the token expired. It
// applies only to a github_oidc requester, never where provenance is required,
// and only while the claims still entitle this commit.
func oidcBinding(ctx context.Context, q database.Querier, dep database.Deployment, scope deploymentScope) (digestBinding, error) {
	if dep.Credential.Kind != domain.CredentialGitHubOIDC || scope.env.RequireProvenance {
		return digestBinding{}, nil
	}
	by := Caller{ID: dep.RequestedBy, Credential: dep.Credential}
	if err := requireEntitled(ctx, q, by, scope, dep.CommitSha); err != nil {
		if smerr.CodeOf(err) == smerr.CodePolicyDenied {
			return digestBinding{}, nil
		}
		return digestBinding{}, err
	}
	stored, err := database.GetGithubOIDCCredential(ctx, q, dep.Credential.ID)
	if err != nil {
		return digestBinding{}, err
	}
	var claims oidcStoredClaims
	if err := json.Unmarshal(stored.ClaimsJSON, &claims); err != nil {
		return digestBinding{}, fmt.Errorf("stored oidc claims are unreadable: %w", err)
	}
	return digestBinding{
		method: compose.BindingOIDCClaims, provenance: stored.ClaimsJSON,
		runID: nonZero(claims.RunID), runAttempt: nonZero(claims.RunAttempt),
	}, nil
}

func nonZero(n int64) *int64 {
	if n == 0 {
		return nil
	}
	return &n
}

// requireRequestedImages checks that every digest the requester named is the
// one the frozen model deploys for that service: a request cannot smuggle a
// digest the plan does not bind.
func requireRequestedImages(requested []wire.RequestedImage, frozen compose.Frozen) error {
	deployed := make(map[string]string, len(frozen.Images))
	for _, image := range frozen.Images {
		deployed[image.Service] = image.Ref
	}
	for _, image := range requested {
		ref, known := deployed[image.Service]
		switch {
		case !known:
			return invalidArgument("image service %q is not a service of the Compose model", image.Service)
		case !strings.HasSuffix(ref, "@"+image.Digest):
			return invalidArgument("image %q: the requested digest is not the one the Compose model deploys", image.Service)
		}
	}
	return nil
}

func githubRepoOf(r database.Repository) github.Repo {
	return github.Repo{
		ID: r.GithubRepositoryID, OwnerID: r.GithubOwnerID, Owner: r.Owner, Name: r.Name,
		URL: r.URL, DefaultBranch: r.DefaultBranch,
	}
}

// recordArtifact stores the verified artifact of a deployment with the
// evidence of its CI checks, and links it to the deployment. A digest bound
// only by the pinned set has no provenance method and so no artifact row.
func recordArtifact(ctx context.Context, c core, q database.Querier, dep database.Deployment, ref, digest string, b digestBinding, checks []github.CheckEvidence) error {
	if !b.bound() {
		return nil
	}
	now := c.cfg.Clock.Now()
	artifact, err := database.CreateArtifact(ctx, q, database.Artifact{
		ID: c.cfg.IDs.NewID(), AppID: dep.AppID, ImmutableRef: ref, Digest: digest, CommitSHA: dep.CommitSha,
		SourceRunID: b.runID, SourceRunAttempt: b.runAttempt, ProvenanceJSON: b.provenance,
		ProvenanceMethod: b.method, CreatedAt: now,
	})
	if err != nil {
		return err
	}
	for _, check := range checks {
		completed := check.CompletedAt
		err := database.PutArtifactCheck(ctx, q, database.ArtifactCheck{
			ArtifactID: artifact.ID, CheckName: check.CheckName, AppID: check.AppID, WorkflowPath: check.WorkflowPath,
			RunID: nonZero(check.RunID), RunAttempt: nonZero(check.RunAttempt), Conclusion: check.Conclusion,
			CompletedAt: &completed,
		})
		if err != nil {
			return err
		}
	}
	_, err = q.ExecContext(ctx, `UPDATE deployments SET artifact_id = ?, updated_at = ? WHERE id = ? AND artifact_id IS NULL`,
		artifact.ID, domain.UnixMillis(now), dep.ID)
	if err != nil {
		return fmt.Errorf("link the artifact to the deployment: %w", err)
	}
	return nil
}
