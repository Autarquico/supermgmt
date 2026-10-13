package app

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/deployments/compose"
	"github.com/autarquico/supermgmt/internal/providers/github"
)

func bindFrozen() compose.Frozen {
	return compose.Frozen{Images: []compose.ImageUse{
		{Service: "web", Ref: "ghcr.io/acme/web@" + depWebDigest, Binding: compose.BindingPinned},
		{Service: "redis", Ref: "docker.io/library/redis@sha256:" + strings.Repeat("4", 64), Binding: compose.BindingPinned},
	}}
}

func TestBinding_RequestedImagesMustBeTheOnesTheModelDeploys(t *testing.T) {
	redis := "sha256:" + strings.Repeat("4", 64)
	tests := []struct {
		name      string
		requested []wire.RequestedImage
		wantErr   bool
	}{
		{"deployed service only", []wire.RequestedImage{{Service: "web", Digest: depWebDigest}}, false},
		{"sidecar as modeled", []wire.RequestedImage{{Service: "web", Digest: depWebDigest}, {Service: "redis", Digest: redis}}, false},
		{"sidecar with another digest", []wire.RequestedImage{{Service: "web", Digest: depWebDigest}, {Service: "redis", Digest: finOtherSum}}, true},
		{"service the model does not have", []wire.RequestedImage{{Service: "web", Digest: depWebDigest}, {Service: "cache", Digest: redis}}, true},
		{"deployed service with another digest", []wire.RequestedImage{{Service: "web", Digest: finOtherSum}}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := requireRequestedImages(tc.requested, bindFrozen())

			if (err != nil) != tc.wantErr {
				t.Errorf("error = %v, want error: %v", err, tc.wantErr)
			}
		})
	}
}

func TestBinding_BoundDigestsNamesOnlyABoundImage(t *testing.T) {
	ref := "ghcr.io/acme/web@" + depWebDigest

	if got := (digestBinding{}).boundDigests(ref); len(got) != 0 {
		t.Errorf("an unbound digest listed as bound: %v", got)
	}
	if got := (digestBinding{method: compose.BindingAttestation}).boundDigests(ref); got[ref] != compose.BindingAttestation {
		t.Errorf("bound digests = %v", got)
	}
}

// ---- attestation ------------------------------------------------------------------------------------

func (f *finFixture) scope() deploymentScope {
	f.t.Helper()
	scope, err := loadDeploymentScope(context.Background(), f.db.Reader(), f.target.ID)
	mustf(f.t, err, "loadDeploymentScope")
	return scope
}

func (f *finFixture) attestation(verifier github.AttestationVerifier) (digestBinding, error) {
	client, _ := f.gh.For(context.Background(), "")
	return attestationBinding(context.Background(), client, verifier, f.scope(), depCommit, depWebDigest)
}

func TestBinding_AttestationNeedsAVerifierAndACIPolicy(t *testing.T) {
	gated := newFinFixture(t, finOptions{gated: true})
	gated.attestDigest(depWebDigest)
	plain := newFinFixture(t, finOptions{})
	plain.attestDigest(depWebDigest)

	withoutVerifier, err := gated.attestation(nil)
	mustf(t, err, "gated, no verifier")
	withoutPolicy, err := plain.attestation(plain.verify)
	mustf(t, err, "no CI policy")

	if withoutVerifier.bound() || withoutPolicy.bound() {
		t.Errorf("bound without a verifier (%v) or without a CI policy (%v)", withoutVerifier.bound(), withoutPolicy.bound())
	}
	if len(plain.verify.wanted) != 0 {
		t.Errorf("the verifier was asked without a CI policy to name the workflow: %+v", plain.verify.wanted)
	}
}

func TestBinding_AttestationOutcomes(t *testing.T) {
	tests := []struct {
		name      string
		attested  bool
		verifyErr error
		wantBound bool
		wantErr   bool
	}{
		{"verified", true, nil, true, false},
		{"no attestation on GitHub", false, nil, false, false},
		{"attestation proves something else", true, github.ErrAttestationRejected, false, false},
		{"verification cannot run", true, errors.New("trust root is stale"), false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFinFixture(t, finOptions{gated: true})
			if tc.attested {
				f.attestDigest(depWebDigest)
			}
			f.verify.err = tc.verifyErr

			got, err := f.attestation(f.verify)

			if (err != nil) != tc.wantErr || got.bound() != tc.wantBound {
				t.Fatalf("bound %v err %v; want bound %v, error %v", got.bound(), err, tc.wantBound, tc.wantErr)
			}
		})
	}
}

func TestBinding_AttestationEvidenceIsKeptAsProvenance(t *testing.T) {
	f := newFinFixture(t, finOptions{gated: true})
	f.attestDigest(depWebDigest)

	got, err := f.attestation(f.verify)

	mustf(t, err, "attestation")
	var evidence github.Evidence
	mustf(t, json.Unmarshal(got.provenance, &evidence), "provenance")
	if got.method != compose.BindingAttestation || evidence.Digest != depWebDigest || evidence.CommitSHA != depCommit ||
		*got.runID != 700 || *got.runAttempt != 2 {
		t.Errorf("binding = %+v, evidence = %+v", got, evidence)
	}
}

// ---- Actions claims -----------------------------------------------------------------------------------

func (f *finFixture) provisionalOf(caller Caller) database.Deployment {
	f.t.Helper()
	view, err := f.deployments.Create(context.Background(), caller, f.request())
	mustf(f.t, err, "Create")
	return f.row(view.ID)
}

func (f *finFixture) oidc(dep database.Deployment) (digestBinding, error) {
	return oidcBinding(context.Background(), f.db.Reader(), dep, f.scope())
}

func TestBinding_OIDCClaimsBindTheCommitTheTokenWasIssuedFor(t *testing.T) {
	f := newFinFixture(t, finOptions{gated: true})
	dep := f.provisionalOf(f.oidcCaller("jti-a"))

	got, err := f.oidc(dep)

	mustf(t, err, "oidcBinding")
	if got.method != compose.BindingOIDCClaims || *got.runID != 9 || *got.runAttempt != 1 {
		t.Errorf("binding = %+v", got)
	}
	var claims oidcStoredClaims
	mustf(t, json.Unmarshal(got.provenance, &claims), "provenance")
	if claims.SHA != depCommit || claims.WorkflowRef != depWorkflowRef {
		t.Errorf("provenance claims = %+v", claims)
	}
}

func TestBinding_OIDCClaimsDoNotBindWhatTheyAreNotEntitledTo(t *testing.T) {
	f := newFinFixture(t, finOptions{gated: true})
	dep := f.provisionalOf(f.oidcCaller("jti-b"))
	f.exec(`UPDATE github_oidc_credentials SET claims_json = replace(claims_json, ?, ?)`, depCommit, depOtherCommit)

	got, err := f.oidc(dep)

	mustf(t, err, "oidcBinding")
	if got.bound() {
		t.Errorf("claims for another commit bound the digest: %+v", got)
	}
}

func TestBinding_OnlyAnActionsTokenBindsByClaims(t *testing.T) {
	f := newFinFixture(t, finOptions{gated: true})
	dep := f.provisionalOf(f.caller(f.deployer))

	got, err := f.oidc(dep)

	mustf(t, err, "oidcBinding")
	if got.bound() {
		t.Errorf("an API token bound a digest by claims: %+v", got)
	}
}

func TestBinding_RequireProvenanceTurnsClaimsOff(t *testing.T) {
	f := newFinFixture(t, finOptions{gated: true})
	dep := f.provisionalOf(f.oidcCaller("jti-c"))
	f.exec(`UPDATE environments SET config_json = json_set(config_json, '$.require_provenance', json('true')) WHERE id = ?`, f.dev.ID)

	got, err := f.oidc(dep)

	mustf(t, err, "oidcBinding")
	if got.bound() {
		t.Errorf("claims bound a digest where provenance is required: %+v", got)
	}
}

// ---- artifacts ----------------------------------------------------------------------------------------

func (f *finFixture) record(dep database.Deployment, b digestBinding, checks []github.CheckEvidence) {
	f.t.Helper()
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		return recordArtifact(ctx, f.deployments.core, tx, dep, "ghcr.io/acme/web@"+depWebDigest, depWebDigest, b, checks)
	})
}

func TestBinding_APinnedDigestHasNoArtifact(t *testing.T) {
	f := newFinFixture(t, finOptions{pinned: true})
	dep := f.provisionalOf(f.caller(f.deployer))

	f.record(dep, digestBinding{}, []github.CheckEvidence{{CheckName: "test"}})

	if f.row(dep.ID).ArtifactID != nil {
		t.Error("a digest bound only by the pinned set got an artifact")
	}
}

func TestBinding_AnArtifactKeepsItsEvidenceAndIsLinkedToTheDeployment(t *testing.T) {
	f := newFinFixture(t, finOptions{pinned: true})
	dep := f.provisionalOf(f.caller(f.deployer))
	run, attempt := int64(700), int64(2)
	b := digestBinding{method: compose.BindingOIDCClaims, provenance: json.RawMessage(`{"run_id":700}`), runID: &run, runAttempt: &attempt}
	checks := []github.CheckEvidence{
		{CheckName: "test", AppID: githubActionsAppID, WorkflowPath: ".github/workflows/ci.yml", RunID: 700, RunAttempt: 2, Conclusion: "success", CompletedAt: f.clock.Now()},
		{CheckName: "lint", AppID: 99, Conclusion: "success", CompletedAt: f.clock.Now()},
	}

	f.record(dep, b, checks)

	row := f.row(dep.ID)
	if row.ArtifactID == nil {
		t.Fatal("the deployment is not linked to its artifact")
	}
	artifact, err := database.GetArtifact(context.Background(), f.db.Reader(), *row.ArtifactID)
	mustf(t, err, "GetArtifact")
	if artifact.AppID != dep.AppID || artifact.CommitSHA != depCommit || artifact.ProvenanceMethod != compose.BindingOIDCClaims {
		t.Errorf("artifact = %+v", artifact)
	}
	stored, err := database.ListArtifactChecks(context.Background(), f.db.Reader(), artifact.ID)
	mustf(t, err, "ListArtifactChecks")
	if len(stored) != 2 || stored[0].CheckName != "lint" || stored[1].CheckName != "test" || stored[0].WorkflowPath != "" || stored[1].RunAttempt == nil {
		t.Errorf("checks = %+v", stored)
	}
}
