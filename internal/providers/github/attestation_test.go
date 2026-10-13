package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/providers/github/ghfake"
)

const attestDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

var attestWant = Provenance{
	RepositoryID: 42, Repository: "acme/shop", WorkflowPath: ".github/workflows/build.yml",
	Branch: "main", CommitSHA: "aabbccddeeff00112233445566778899aabbccdd",
}

func attestBuild() ghfake.Build {
	return ghfake.Build{
		Owner: "acme", Repo: "shop", RepositoryID: 42, WorkflowPath: ".github/workflows/build.yml",
		Branch: "main", CommitSHA: "aabbccddeeff00112233445566778899aabbccdd", RunID: 9001, RunAttempt: 2,
	}
}

func attestVerifier(t *testing.T, s *ghfake.Sigstore) AttestationVerifier {
	t.Helper()
	v, err := NewAttestationVerifier(StaticRoots{s.Material()})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func attestVerify(t *testing.T, v AttestationVerifier, bundles ...json.RawMessage) (Evidence, error) {
	t.Helper()
	return v.Verify(bundles, attestDigest, attestWant)
}

func attestRejected(t *testing.T, name string, err error) {
	t.Helper()
	if !errors.Is(err, ErrAttestationRejected) {
		t.Errorf("%s: err = %v; want ErrAttestationRejected", name, err)
	}
}

func TestAttestation_AcceptsMatchingProvenance(t *testing.T) {
	s := ghfake.NewSigstore(t)
	before := domain.SystemClock{}.Now().Add(-time.Minute)
	ev, err := attestVerify(t, attestVerifier(t, s), s.Attest(t, attestDigest, attestBuild()))
	if err != nil {
		t.Fatal(err)
	}
	if ev.Method != "attestation" || ev.Digest != attestDigest || ev.Issuer != ActionsIssuer ||
		ev.SubjectAltName != "https://github.com/acme/shop/.github/workflows/build.yml@refs/heads/main" ||
		ev.RepositoryID != 42 || ev.CommitSHA != attestWant.CommitSHA ||
		ev.RunID != 9001 || ev.RunAttempt != 2 || ev.PredicateType != SLSAProvenanceV1 {
		t.Errorf("evidence = %+v", ev)
	}
	if ev.SignedAt.Before(before) || ev.SignedAt.After(domain.SystemClock{}.Now().Add(time.Hour)) {
		t.Errorf("SignedAt = %v; want about now", ev.SignedAt)
	}
}

func TestAttestation_RejectsProvenanceMismatch(t *testing.T) {
	s := ghfake.NewSigstore(t)
	v := attestVerifier(t, s)
	bundle := s.Attest(t, attestDigest, attestBuild())
	otherDigest := "sha256:" + strings.Repeat("ab", 32)
	for name, want := range map[string]Provenance{
		"repository id": func() Provenance { w := attestWant; w.RepositoryID = 43; return w }(),
		"repository":    func() Provenance { w := attestWant; w.Repository = "acme/other"; return w }(),
		"owner":         func() Provenance { w := attestWant; w.Repository = "evil/shop"; return w }(),
		"workflow":      func() Provenance { w := attestWant; w.WorkflowPath = ".github/workflows/other.yml"; return w }(),
		"branch":        func() Provenance { w := attestWant; w.Branch = "release"; return w }(),
		"commit":        func() Provenance { w := attestWant; w.CommitSHA = strings.Repeat("1", 40); return w }(),
	} {
		_, err := v.Verify([]json.RawMessage{bundle}, attestDigest, want)
		attestRejected(t, name, err)
	}
	_, err := v.Verify([]json.RawMessage{bundle}, otherDigest, attestWant)
	attestRejected(t, "digest", err)
}

func TestAttestation_RejectsWrongSigner(t *testing.T) {
	s := ghfake.NewSigstore(t)
	v := attestVerifier(t, s)
	foreignIssuer := attestBuild()
	foreignIssuer.Issuer = "https://accounts.example.com"
	notProvenance := attestBuild()
	notProvenance.PredicateType = "https://spdx.dev/Document"
	for name, bundle := range map[string]json.RawMessage{
		"issuer":         s.Attest(t, attestDigest, foreignIssuer),
		"predicate type": s.Attest(t, attestDigest, notProvenance),
		"untrusted CA":   ghfake.NewSigstore(t).Attest(t, attestDigest, attestBuild()),
	} {
		_, err := attestVerify(t, v, bundle)
		attestRejected(t, name, err)
	}
}

func TestAttestation_RejectsTamperedBundle(t *testing.T) {
	s := ghfake.NewSigstore(t)
	tampered := attestTamperPayload(t, s.Attest(t, attestDigest, attestBuild()))
	_, err := attestVerify(t, attestVerifier(t, s), tampered)
	attestRejected(t, "tampered payload", err)
	timestampOnly := attestTamperPayload(t, s.Attest(t, attestDigest, attestBuild(), ghfake.WithoutTlog()))
	_, err = attestVerify(t, attestVerifier(t, s), timestampOnly)
	attestRejected(t, "tampered payload, timestamp only", err)
	_, err = attestVerify(t, attestVerifier(t, s), json.RawMessage(`{"mediaType":"nope"}`))
	attestRejected(t, "unreadable bundle", err)
}

func attestTamperPayload(t *testing.T, bundle json.RawMessage) json.RawMessage {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(bundle, &doc); err != nil {
		t.Fatal(err)
	}
	envelope := doc["dsseEnvelope"].(map[string]any)
	payload, err := base64.StdEncoding.DecodeString(envelope["payload"].(string))
	if err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(string(payload), ".github/workflows", ".github/workflowz", 1)
	if changed == string(payload) {
		t.Fatal("payload not changed")
	}
	envelope["payload"] = base64.StdEncoding.EncodeToString([]byte(changed))
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestAttestation_SigningTimeComesFromTheProofNotTheClock(t *testing.T) {
	s := ghfake.NewSigstore(t)
	v := attestVerifier(t, s)
	signed := ghfake.SignedAt(domain.SystemClock{}.Now().Add(-30 * time.Minute)) // the certificate has expired since

	if _, err := attestVerify(t, v, s.Attest(t, attestDigest, attestBuild(), signed, ghfake.WithoutTimestamp())); err != nil {
		t.Errorf("expired certificate with a transparency log entry from its lifetime: %v", err)
	}
	_, err := attestVerify(t, v, s.Attest(t, attestDigest, attestBuild(), signed, ghfake.WithoutTlog()))
	attestRejected(t, "expired certificate, timestamp after expiry, no tlog", err)
}

func TestAttestation_RejectsBundleWithoutProofOfSigningTime(t *testing.T) {
	s := ghfake.NewSigstore(t)
	bundle := s.Attest(t, attestDigest, attestBuild(), ghfake.WithoutTlog(), ghfake.WithoutTimestamp())
	_, err := attestVerify(t, attestVerifier(t, s), bundle)
	attestRejected(t, "no tlog, no timestamp", err)
}

func TestAttestation_AcceptsGitHubStyleBundleWithTimestampOnly(t *testing.T) {
	s := ghfake.NewSigstore(t)
	bundle := s.Attest(t, attestDigest, attestBuild(), ghfake.WithoutTlog())
	if _, err := attestVerify(t, attestVerifier(t, s), bundle); err != nil {
		t.Fatal(err)
	}
}

func TestAttestation_AnyMatchingBundleWins(t *testing.T) {
	s := ghfake.NewSigstore(t)
	v := attestVerifier(t, s)
	sbom := attestBuild()
	sbom.PredicateType = "https://spdx.dev/Document"
	wrongCommit := attestBuild()
	wrongCommit.CommitSHA = strings.Repeat("1", 40)
	ev, err := attestVerify(t, v,
		s.Attest(t, attestDigest, sbom),
		s.Attest(t, attestDigest, wrongCommit),
		s.Attest(t, attestDigest, attestBuild()))
	if err != nil || ev.CommitSHA != attestWant.CommitSHA {
		t.Fatalf("evidence = %+v, err = %v", ev, err)
	}
}

func TestAttestation_TrustsEveryRootButOnlyTheirs(t *testing.T) {
	ours, theirs := ghfake.NewSigstore(t), ghfake.NewSigstore(t)
	v, err := NewAttestationVerifier(StaticRoots{theirs.Material(), ours.Material()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := attestVerify(t, v, ours.Attest(t, attestDigest, attestBuild())); err != nil {
		t.Errorf("second root: %v", err)
	}
	if _, err := attestVerify(t, v, theirs.Attest(t, attestDigest, attestBuild())); err != nil {
		t.Errorf("first root: %v", err)
	}
}

func TestAttestation_NoBundleIsNotVerified(t *testing.T) {
	s := ghfake.NewSigstore(t)
	_, err := attestVerify(t, attestVerifier(t, s))
	if !errors.Is(err, ErrNoAttestation) {
		t.Errorf("err = %v; want ErrNoAttestation", err)
	}
}

func TestAttestation_RefusesMalformedQuestions(t *testing.T) {
	s := ghfake.NewSigstore(t)
	v := attestVerifier(t, s)
	bundle := s.Attest(t, attestDigest, attestBuild())
	for name, tc := range map[string]struct {
		digest string
		want   Provenance
	}{
		"digest not sha256":   {"sha1:" + strings.Repeat("a", 40), attestWant},
		"digest uppercase":    {"sha256:" + strings.Repeat("AB", 32), attestWant},
		"digest empty":        {"", attestWant},
		"no repository id":    {attestDigest, func() Provenance { w := attestWant; w.RepositoryID = 0; return w }()},
		"repository no slash": {attestDigest, func() Provenance { w := attestWant; w.Repository = "shop"; return w }()},
		"workflow with @":     {attestDigest, func() Provenance { w := attestWant; w.WorkflowPath = "a.yml@refs/heads/x"; return w }()},
		"empty branch":        {attestDigest, func() Provenance { w := attestWant; w.Branch = ""; return w }()},
		"short commit":        {attestDigest, func() Provenance { w := attestWant; w.CommitSHA = "abc123"; return w }()},
	} {
		if _, err := v.Verify([]json.RawMessage{bundle}, tc.digest, tc.want); err == nil || errors.Is(err, ErrAttestationRejected) {
			t.Errorf("%s: err = %v; want a validation error before any verification", name, err)
		}
	}
}

func TestAttestation_NeedsRoots(t *testing.T) {
	if _, err := NewAttestationVerifier(nil); err == nil {
		t.Error("a verifier without roots must be refused")
	}
}

func TestAttestation_StaleRootFailsClosed(t *testing.T) {
	s := ghfake.NewSigstore(t)
	clock := &rootTestClock{now: time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)}
	roots := NewTrustRoots(TrustRootsConfig{CacheDir: t.TempDir(), Sources: []TUFSource{{Name: "stale"}}, Clock: clock})
	roots.fetch = func(TUFSource) ([]byte, error) { return nil, errors.New("tuf repository unreachable") }
	v, err := NewAttestationVerifier(roots)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := attestVerify(t, v, s.Attest(t, attestDigest, attestBuild()))
	if !errors.Is(err, ErrTrustRootStale) || ev != (Evidence{}) {
		t.Errorf("evidence = %+v, err = %v; want zero evidence and ErrTrustRootStale", ev, err)
	}
}

func TestAttestation_VerifiesWhatGitHubServes(t *testing.T) {
	s := ghfake.NewSigstore(t)
	f, c := newEnv(t)
	repo := Repo{ID: 42, Owner: "acme", Name: "shop"}
	ghfake.ServeAttestations(f).Add("acme", "shop", attestDigest, s.Attest(t, attestDigest, attestBuild()))

	bundles, err := c.Attestations(context.Background(), repo, attestDigest)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := attestVerify(t, attestVerifier(t, s), bundles...)
	if err != nil || ev.RepositoryID != 42 {
		t.Fatalf("evidence = %+v, err = %v", ev, err)
	}
	if got := f.Rejected(); len(got) != 0 {
		t.Errorf("fake rejected requests: %v", got)
	}
}

func TestAttestation_TrustedRootDocumentRoundTrips(t *testing.T) {
	s := ghfake.NewSigstore(t)
	parsed, err := root.NewTrustedRootFromJSON(s.TrustedRootJSON(t))
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewAttestationVerifier(StaticRoots{parsed})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := attestVerify(t, v, s.Attest(t, attestDigest, attestBuild())); err != nil {
		t.Fatal(err)
	}
}
