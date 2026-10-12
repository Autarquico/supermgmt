package ghfake

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/tlog"

	"github.com/autarquico/supermgmt/internal/domain"
)

// Attestation fidelity (ADR-0028): bundles are Sigstore v0.3 bundles signed by
// a virtual Sigstore (sigstore-go pkg/testing/ca) whose Fulcio issues the
// certificates GitHub Actions gets: a URI SAN naming the workflow at its ref
// and the v2 extensions (issuer, source repository id/digest/ref/URI, run
// invocation). The timestamp authority and Rekor are the virtual Sigstore's.
// Nothing here is verified against real Fulcio output; the shapes follow the
// Fulcio OID registry as the author knows it.
const (
	// AttestIssuer is the OIDC issuer GitHub certificates carry.
	AttestIssuer = "https://token.actions.githubusercontent.com"
	// AttestPredicateSLSA is the SLSA v1 provenance predicate type.
	AttestPredicateSLSA = "https://slsa.dev/provenance/v1"

	bundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"
	statementType   = "https://in-toto.io/Statement/v1"
	payloadType     = "application/vnd.in-toto+json"
)

// Build is what one workflow run attests about an image.
type Build struct {
	Owner         string
	Repo          string
	RepositoryID  int64
	WorkflowPath  string // .github/workflows/build.yml
	Branch        string
	CommitSHA     string
	RunID         int64
	RunAttempt    int64
	Issuer        string // default AttestIssuer
	PredicateType string // default AttestPredicateSLSA
}

// AttestOption adjusts one attestation.
type AttestOption func(*attestSettings)

type attestSettings struct {
	signedAt time.Time
	tlog     bool
	tsa      bool
}

// SignedAt sets the signing time: the certificate is valid for a few minutes
// around it and the transparency log entry is integrated just after it. The
// timestamp authority stamps the real clock whatever this is (a limit of the
// virtual Sigstore), so a time in the past makes the certificate expired for
// the timestamp.
func SignedAt(t time.Time) AttestOption { return func(s *attestSettings) { s.signedAt = t } }

// WithoutTlog leaves the transparency log entry out of the bundle.
func WithoutTlog() AttestOption { return func(s *attestSettings) { s.tlog = false } }

// WithoutTimestamp leaves the RFC 3161 timestamp out of the bundle.
func WithoutTimestamp() AttestOption { return func(s *attestSettings) { s.tsa = false } }

// Sigstore is a virtual Sigstore with a GitHub-shaped Fulcio.
type Sigstore struct {
	virtual   *ca.VirtualSigstore
	fulcio    *root.FulcioCertificateAuthority
	interCert *x509.Certificate
	interKey  *ecdsa.PrivateKey
}

// wallClock is the real time the virtual Sigstore's own timestamps are signed
// at; certificates must be valid around it.
func wallClock() time.Time { return domain.SystemClock{}.Now() }

// NewSigstore makes a Sigstore with fresh keys. Its certificates and the
// timestamps it signs are valid around the real clock.
func NewSigstore(t testing.TB) *Sigstore {
	t.Helper()
	virtual, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	rootCert, rootKey, err := ca.GenerateRootCa()
	if err != nil {
		t.Fatal(err)
	}
	interKey := newKey(t)
	now := wallClock()
	interCert := signCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "ghfake fulcio", Organization: []string{"ghfake"}},
		NotBefore: now.Add(-4 * time.Hour), NotAfter: now.Add(4 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true, IsCA: true,
	}, rootCert, &interKey.PublicKey, rootKey)
	return &Sigstore{
		virtual: virtual, interCert: interCert, interKey: interKey,
		fulcio: &root.FulcioCertificateAuthority{
			URI: "https://fulcio.ghfake.invalid", Root: rootCert, Intermediates: []*x509.Certificate{interCert},
			ValidityPeriodStart: now.Add(-4 * time.Hour), ValidityPeriodEnd: now.Add(4 * time.Hour),
		},
	}
}

// Material is what a verifier must trust to accept this Sigstore's bundles.
func (s *Sigstore) Material() root.TrustedMaterial { return &sigstoreMaterial{s: s} }

// TrustedRootJSON is Material as a Sigstore trusted_root.json document, the
// form a TUF repository publishes.
func (s *Sigstore) TrustedRootJSON(t testing.TB) []byte {
	t.Helper()
	tr, err := root.NewTrustedRoot(root.TrustedRootMediaType01,
		s.fulcioAuthorities(), s.virtual.CTLogs(), s.virtual.TimestampingAuthorities(), s.virtual.RekorLogs())
	if err != nil {
		t.Fatal(err)
	}
	doc, err := tr.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func (s *Sigstore) fulcioAuthorities() []root.CertificateAuthority {
	return []root.CertificateAuthority{s.fulcio}
}

type sigstoreMaterial struct {
	root.BaseTrustedMaterial
	s *Sigstore
}

func (m *sigstoreMaterial) FulcioCertificateAuthorities() []root.CertificateAuthority {
	return m.s.fulcioAuthorities()
}

func (m *sigstoreMaterial) TimestampingAuthorities() []root.TimestampingAuthority {
	return m.s.virtual.TimestampingAuthorities()
}

func (m *sigstoreMaterial) RekorLogs() map[string]*root.TransparencyLog {
	return m.s.virtual.RekorLogs()
}

func (m *sigstoreMaterial) CTLogs() map[string]*root.TransparencyLog { return m.s.virtual.CTLogs() }

// Attest returns the JSON bundle attesting that the image with digest
// ("sha256:<hex>") was built as b describes.
func (s *Sigstore) Attest(t testing.TB, digest string, b Build, opts ...AttestOption) json.RawMessage {
	t.Helper()
	cfg := attestSettings{signedAt: wallClock(), tlog: true, tsa: true}
	for _, opt := range opts {
		opt(&cfg)
	}
	leafKey := newKey(t)
	leaf := s.leafCertificate(t, b, leafKey, cfg.signedAt)

	payload := statementJSON(t, digest, b)
	sig := signPAE(t, leafKey, payload)
	envelope := dsse.Envelope{
		PayloadType: payloadType, Payload: base64.StdEncoding.EncodeToString(payload),
		Signatures: []dsse.Signature{{Sig: base64.StdEncoding.EncodeToString(sig)}},
	}
	material := &protobundle.VerificationMaterial{
		Content: &protobundle.VerificationMaterial_Certificate{Certificate: &protocommon.X509Certificate{RawBytes: leaf.Raw}},
	}
	if cfg.tlog {
		material.TlogEntries = []*protorekor.TransparencyLogEntry{s.tlogEntry(t, leaf, &envelope, sig, cfg.signedAt.Add(time.Minute))}
	}
	if cfg.tsa {
		stamp, err := s.virtual.TimestampResponse(sig)
		if err != nil {
			t.Fatal(err)
		}
		material.TimestampVerificationData = &protobundle.TimestampVerificationData{
			Rfc3161Timestamps: []*protocommon.RFC3161SignedTimestamp{{SignedTimestamp: stamp}},
		}
	}
	return marshalBundle(t, &protobundle.Bundle{
		MediaType: bundleMediaType, VerificationMaterial: material,
		Content: &protobundle.Bundle_DsseEnvelope{DsseEnvelope: &protodsse.Envelope{
			Payload: payload, PayloadType: payloadType,
			Signatures: []*protodsse.Signature{{Sig: sig}},
		}},
	})
}

// tlogEntry is the log entry as a bundle carries it: the library's entry holds
// neither the kind/version nor the signed entry timestamp in proto form.
func (s *Sigstore) tlogEntry(t testing.TB, leaf *x509.Certificate, envelope *dsse.Envelope, sig []byte, integrated time.Time) *protorekor.TransparencyLogEntry {
	t.Helper()
	entry, err := s.virtual.GenerateTlogEntry(leaf, envelope, sig, integrated.Unix(), true)
	if err != nil {
		t.Fatal(err)
	}
	tle := entry.TransparencyLogEntry()
	var body struct {
		Kind       string `json:"kind"`
		APIVersion string `json:"apiVersion"`
	}
	if err := json.Unmarshal(tle.CanonicalizedBody, &body); err != nil {
		t.Fatal(err)
	}
	tle.KindVersion = &protorekor.KindVersion{Kind: body.Kind, Version: body.APIVersion}
	set, err := s.virtual.RekorSignPayload(tlog.RekorPayload{
		Body:           base64.StdEncoding.EncodeToString(tle.CanonicalizedBody),
		IntegratedTime: tle.IntegratedTime, LogIndex: tle.LogIndex, LogID: hex.EncodeToString(tle.LogId.KeyId),
	})
	if err != nil {
		t.Fatal(err)
	}
	tle.InclusionPromise = &protorekor.InclusionPromise{SignedEntryTimestamp: set}
	return tle
}

func marshalBundle(t testing.TB, pb *protobundle.Bundle) json.RawMessage {
	t.Helper()
	b, err := bundle.NewBundle(pb)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := b.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func (s *Sigstore) leafCertificate(t testing.TB, b Build, key *ecdsa.PrivateKey, signedAt time.Time) *x509.Certificate {
	t.Helper()
	repoURL := "https://github.com/" + b.Owner + "/" + b.Repo
	san, err := url.Parse(repoURL + "/" + b.WorkflowPath + "@refs/heads/" + b.Branch)
	if err != nil {
		t.Fatal(err)
	}
	issuer := b.Issuer
	if issuer == "" {
		issuer = AttestIssuer
	}
	extensions := []pkix.Extension{
		{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}, Value: []byte(issuer)},
		extension(t, 8, issuer),
		extension(t, 12, repoURL),
		extension(t, 13, b.CommitSHA),
		extension(t, 14, "refs/heads/"+b.Branch),
		extension(t, 15, strconv.FormatInt(b.RepositoryID, 10)),
		extension(t, 21, repoURL+"/actions/runs/"+strconv.FormatInt(b.RunID, 10)+"/attempts/"+strconv.FormatInt(b.RunAttempt, 10)),
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatal(err)
	}
	return signCert(t, &x509.Certificate{
		SerialNumber: serial, NotBefore: signedAt.Add(-time.Minute), NotAfter: signedAt.Add(10 * time.Minute),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		URIs: []*url.URL{san}, ExtraExtensions: extensions,
	}, s.interCert, &key.PublicKey, s.interKey)
}

func extension(t testing.TB, last int, value string) pkix.Extension {
	t.Helper()
	der, err := asn1.MarshalWithParams(value, "utf8")
	if err != nil {
		t.Fatal(err)
	}
	return pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, last}, Value: der}
}

func statementJSON(t testing.TB, digest string, b Build) []byte {
	t.Helper()
	sum, ok := strings.CutPrefix(digest, "sha256:")
	if !ok {
		t.Fatalf("ghfake: digest %q is not sha256:<hex>", digest)
	}
	predicate := b.PredicateType
	if predicate == "" {
		predicate = AttestPredicateSLSA
	}
	doc, err := json.Marshal(map[string]any{
		"_type":         statementType,
		"subject":       []map[string]any{{"name": "ghcr.io/" + b.Owner + "/" + b.Repo, "digest": map[string]string{"sha256": sum}}},
		"predicateType": predicate,
		"predicate": map[string]any{
			"buildDefinition": map[string]any{
				"buildType":          "https://actions.github.io/buildtypes/workflow/v1",
				"externalParameters": map[string]any{"workflow": map[string]string{"path": b.WorkflowPath}},
			},
			"runDetails": map[string]any{"builder": map[string]string{"id": "https://github.com/actions/runner"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func signPAE(t testing.TB, key *ecdsa.PrivateKey, payload []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(dsse.PAE(payloadType, payload))
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func signCert(t testing.TB, tmpl, parent *x509.Certificate, pub *ecdsa.PublicKey, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// Attestations serves the attestations endpoint of the fake:
// GET /repos/{owner}/{repo}/attestations/sha256:<hex>. An unknown digest
// answers 404 as GitHub does.
type Attestations struct {
	mu      sync.Mutex
	bundles map[string][]json.RawMessage
}

// ServeAttestations registers the attestations endpoint on f.
func ServeAttestations(f *Fake) *Attestations {
	a := &Attestations{bundles: map[string][]json.RawMessage{}}
	f.Handle("GET /repos/{owner}/{repo}/attestations/{digest}", nil, a.serve)
	return a
}

// Add makes bundle one of the attestations of digest in owner/repo.
func (a *Attestations) Add(owner, repo, digest string, b json.RawMessage) {
	a.mu.Lock()
	defer a.mu.Unlock()
	key := attestationKey(owner, repo, digest)
	a.bundles[key] = append(a.bundles[key], b)
}

func attestationKey(owner, repo, digest string) string { return owner + "/" + repo + "@" + digest }

func (a *Attestations) serve(w http.ResponseWriter, r *http.Request) {
	digest := r.PathValue("digest")
	if !validAttestationDigest(digest) {
		WriteError(w, http.StatusUnprocessableEntity, "Validation Failed: invalid subject digest")
		return
	}
	a.mu.Lock()
	held := a.bundles[attestationKey(r.PathValue("owner"), r.PathValue("repo"), digest)]
	a.mu.Unlock()
	if len(held) == 0 {
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	docs := make([]map[string]any, len(held))
	for i, b := range held {
		docs[i] = map[string]any{"bundle": b, "bundle_url": fmt.Sprintf("https://example.invalid/bundles/%d", i)}
	}
	WriteJSON(w, map[string]any{"attestations": docs})
}

func validAttestationDigest(digest string) bool {
	sum, ok := strings.CutPrefix(digest, "sha256:")
	if !ok || len(sum) != 64 {
		return false
	}
	_, err := hex.DecodeString(sum)
	return err == nil
}
