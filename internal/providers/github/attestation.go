package github

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

const (
	// SLSAProvenanceV1 is the only predicate type accepted as build provenance.
	SLSAProvenanceV1 = "https://slsa.dev/provenance/v1"

	methodAttestation = "attestation"
)

var (
	// ErrNoAttestation means GitHub holds no attestation for the digest.
	ErrNoAttestation = errors.New("github: no attestation for the digest")
	// ErrAttestationRejected means no attestation proved the expected
	// provenance. The wrapped reasons are for operators, not end users.
	ErrAttestationRejected = errors.New("github: attestation rejected")

	runInvocationPattern = regexp.MustCompile(`^https://[^/]+/[^/]+/[^/]+/actions/runs/([0-9]+)(?:/attempts/([0-9]+))?$`)
	hexDigestPattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type attestationVerifier struct{ roots RootMaterials }

// NewAttestationVerifier verifies GitHub artifact attestations (spec §18 (a),
// ADR-0028) against the given trusted roots. Whatever the roots or the bundle
// lack, the answer is a rejection: there is no "unverified" outcome.
func NewAttestationVerifier(roots RootMaterials) (AttestationVerifier, error) {
	if roots == nil {
		return nil, errors.New("github: attestation verifier needs trusted roots")
	}
	return &attestationVerifier{roots: roots}, nil
}

// Verify returns the evidence of the first bundle that proves SLSA provenance
// for digest ("sha256:<hex>") matching want: signed by a Fulcio certificate
// whose SAN is the workflow at the branch, issued for the Actions issuer, and
// whose extensions carry the repository ID and commit SHA.
func (v *attestationVerifier) Verify(bundles []json.RawMessage, digest string, want Provenance) (Evidence, error) {
	sum, err := wantedSubject(digest, want)
	if err != nil {
		return Evidence{}, err
	}
	if len(bundles) == 0 {
		return Evidence{}, ErrNoAttestation
	}
	materials, err := v.roots.Materials()
	if err != nil {
		return Evidence{}, err
	}
	policy, err := provenancePolicy(sum, want)
	if err != nil {
		return Evidence{}, err
	}
	var reasons []error
	for i, raw := range bundles {
		evidence, err := verifyBundle(raw, materials, policy, digest)
		if err == nil {
			return evidence, nil
		}
		reasons = append(reasons, fmt.Errorf("bundle %d: %w", i, err))
	}
	return Evidence{}, fmt.Errorf("%w: %w", ErrAttestationRejected, errors.Join(reasons...))
}

func wantedSubject(digest string, want Provenance) ([]byte, error) {
	hexSum, ok := strings.CutPrefix(digest, "sha256:")
	if !ok || !hexDigestPattern.MatchString(hexSum) {
		return nil, fmt.Errorf("github: invalid digest %q", digest)
	}
	if err := checkProvenance(want); err != nil {
		return nil, err
	}
	sum := make([]byte, 32)
	for i := range sum {
		b, _ := strconv.ParseUint(hexSum[2*i:2*i+2], 16, 8)
		sum[i] = byte(b)
	}
	return sum, nil
}

func checkProvenance(want Provenance) error {
	owner, name, ok := strings.Cut(want.Repository, "/")
	switch {
	case want.RepositoryID <= 0:
		return errors.New("github: provenance needs a repository id")
	case !ok || !validSegment(owner) || !validSegment(name):
		return fmt.Errorf("github: provenance repository %q is not owner/name", want.Repository)
	case want.WorkflowPath == "" || strings.HasPrefix(want.WorkflowPath, "/") || strings.Contains(want.WorkflowPath, "@"):
		return fmt.Errorf("github: provenance workflow path %q is invalid", want.WorkflowPath)
	case want.Branch == "" || strings.Contains(want.Branch, "@"):
		return fmt.Errorf("github: provenance branch %q is invalid", want.Branch)
	case !commitPattern.MatchString(want.CommitSHA):
		return errors.New("github: provenance commit is not a full sha")
	}
	return nil
}

// provenancePolicy is the identity half of §18 (a): exact SAN and issuer, plus
// the repository ID and commit SHA the Fulcio extensions certify.
func provenancePolicy(sum []byte, want Provenance) (verify.PolicyBuilder, error) {
	san := "https://github.com/" + want.Repository + "/" + want.WorkflowPath + "@refs/heads/" + want.Branch
	sanMatcher, err := verify.NewSANMatcher(san, "")
	if err != nil {
		return verify.PolicyBuilder{}, err
	}
	issuerMatcher, err := verify.NewIssuerMatcher(ActionsIssuer, "")
	if err != nil {
		return verify.PolicyBuilder{}, err
	}
	identity, err := verify.NewCertificateIdentity(sanMatcher, issuerMatcher, certificate.Extensions{
		SourceRepositoryIdentifier: strconv.FormatInt(want.RepositoryID, 10),
		SourceRepositoryDigest:     want.CommitSHA,
	})
	if err != nil {
		return verify.PolicyBuilder{}, err
	}
	return verify.NewPolicy(verify.WithArtifactDigest("sha256", sum), verify.WithCertificateIdentity(identity)), nil
}

func verifyBundle(raw json.RawMessage, materials []root.TrustedMaterial, policy verify.PolicyBuilder, digest string) (Evidence, error) {
	var b bundle.Bundle
	if err := b.UnmarshalJSON(raw); err != nil {
		return Evidence{}, fmt.Errorf("unreadable bundle: %w", err)
	}
	var reasons []error
	for _, material := range materials {
		for _, verifier := range verifiersFor(material) {
			result, err := verifier.Verify(&b, policy)
			if err != nil {
				reasons = append(reasons, err)
				continue
			}
			return attestationEvidence(result, digest)
		}
	}
	return Evidence{}, errors.Join(reasons...)
}

// verifiersFor builds the two ways a signing time can be proven. Public-good
// signatures are logged in Rekor and carry integrated timestamps; GitHub's own
// instance has no transparency log and stamps with its timestamp authority.
// A bundle with neither proof fails both, whatever its certificate says.
func verifiersFor(material root.TrustedMaterial) []*verify.Verifier {
	var out []*verify.Verifier
	for _, options := range [][]verify.VerifierOption{
		{verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1)},
		{verify.WithSignedTimestamps(1)},
	} {
		if v, err := verify.NewVerifier(material, append(options, verify.WithoutStatementPredicate())...); err == nil {
			out = append(out, v)
		}
	}
	return out
}

func attestationEvidence(result *verify.VerificationResult, digest string) (Evidence, error) {
	if result.Statement == nil || result.Signature == nil || result.Signature.Certificate == nil {
		return Evidence{}, errors.New("verified bundle lacks a statement or certificate")
	}
	if got := result.Statement.GetPredicateType(); got != SLSAProvenanceV1 {
		return Evidence{}, fmt.Errorf("predicate type %q is not SLSA provenance v1", got)
	}
	cert := result.Signature.Certificate
	repoID, err := strconv.ParseInt(cert.SourceRepositoryIdentifier, 10, 64)
	if err != nil || repoID <= 0 {
		return Evidence{}, errors.New("certificate carries no repository id")
	}
	runID, attempt, err := parseRunInvocation(cert.RunInvocationURI)
	if err != nil {
		return Evidence{}, err
	}
	signedAt, err := earliestTimestamp(result.VerifiedTimestamps)
	if err != nil {
		return Evidence{}, err
	}
	return Evidence{
		Method: methodAttestation, Digest: digest,
		SubjectAltName: cert.SubjectAlternativeName, Issuer: cert.Issuer,
		RepositoryID: repoID, CommitSHA: cert.SourceRepositoryDigest,
		RunID: runID, RunAttempt: attempt,
		PredicateType: result.Statement.GetPredicateType(), SignedAt: signedAt.UTC(),
	}, nil
}

func parseRunInvocation(raw string) (runID, attempt int64, err error) {
	m := runInvocationPattern.FindStringSubmatch(raw)
	if m == nil {
		return 0, 0, errors.New("certificate carries no run invocation")
	}
	runID, err = strconv.ParseInt(m[1], 10, 64)
	if err != nil || runID <= 0 {
		return 0, 0, errors.New("certificate run id is invalid")
	}
	attempt = 1
	if m[2] != "" {
		attempt, err = strconv.ParseInt(m[2], 10, 64)
		if err != nil || attempt <= 0 {
			return 0, 0, errors.New("certificate run attempt is invalid")
		}
	}
	return runID, attempt, nil
}

func earliestTimestamp(stamps []verify.TimestampVerificationResult) (time.Time, error) {
	if len(stamps) == 0 {
		return time.Time{}, errors.New("verified bundle has no timestamp")
	}
	earliest := stamps[0].Timestamp
	for _, s := range stamps[1:] {
		if s.Timestamp.Before(earliest) {
			earliest = s.Timestamp
		}
	}
	return earliest, nil
}
