// Package github is the GitHub connector (spec §18, §21.1; ADR-0028): a
// read-only REST client over netguard with origin-pinned redirects, check
// verification, webhook signatures, GitHub Actions OIDC verification and
// artifact-attestation verification. It touches no storage; internal/app turns
// its results into rows, plans and jobs.
//
// Frozen in M4 W0. Implemented in this package by:
//
//	T5a  func New(apiURL string, caPEM []byte, token audit.Secret, opts ...Option) (Client, error)
//	T5b  func VerifyChecks(ctx context.Context, c Client, r Repo, sha string, p CIPolicy) (CheckReport, error)
//	T5b  func VerifyWebhook(secret audit.Secret, signature string, body []byte) (WebhookEvent, error)
//	T6a  func NewOIDCVerifier(...) OIDCVerifier
//	T6a  func MatchClaims(c Claims, p CIPolicy, commit string, env EnvRequirement) error
//	T6b  func NewAttestationVerifier(...) (AttestationVerifier, error)
package github

import (
	"context"
	"encoding/json"
	"time"

	// Pinned for the OIDC (T6a) and attestation (T6b) verifiers: these imports
	// keep go.mod complete for them until their files exist (ADR-0028).
	_ "github.com/go-jose/go-jose/v4/jwt"
	_ "github.com/sigstore/sigstore-go/pkg/bundle"
	_ "github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	_ "github.com/sigstore/sigstore-go/pkg/root"
	_ "github.com/sigstore/sigstore-go/pkg/tuf"
	_ "github.com/sigstore/sigstore-go/pkg/verify"

	"github.com/autarquico/supermgmt/internal/config"
)

const (
	// ProviderType is the providers.type of a GitHub provider.
	ProviderType = config.ProviderGitHub

	// ActionsIssuer is the only accepted OIDC issuer (spec §18).
	ActionsIssuer = "https://token.actions.githubusercontent.com"

	// MaxFileBytes caps a file read from a commit (manifest, Compose source).
	MaxFileBytes = 256 << 10

	// Webhook headers (spec §18).
	HeaderSignature = "X-Hub-Signature-256"
	HeaderDelivery  = "X-GitHub-Delivery"
	HeaderEvent     = "X-GitHub-Event"
	// MaxWebhookBody caps a webhook request body.
	MaxWebhookBody = 1 << 20
)

// Repo is a repository as GitHub reports it. IDs are authoritative; names are
// display only (spec §18).
type Repo struct {
	ID            int64
	OwnerID       int64
	Owner         string
	Name          string
	URL           string
	DefaultBranch string
	Private       bool
}

// Page is a GitHub list page. A returned Page with Number 0 means there is no
// next page.
type Page struct {
	Number  int
	PerPage int
}

// CheckRun is one check run on a commit.
type CheckRun struct {
	ID          int64
	Name        string
	AppID       int64
	Status      string // queued | in_progress | completed
	Conclusion  string // success | failure | … ; empty until completed
	HeadSHA     string
	SuiteID     int64
	StartedAt   time.Time
	CompletedAt time.Time
}

// WorkflowRun is the GitHub Actions run behind a check suite.
type WorkflowRun struct {
	ID         int64
	RunAttempt int64
	Path       string // .github/workflows/ci.yml
	HeadBranch string
	HeadSHA    string
	Event      string
	Status     string
	Conclusion string
}

// File is a file read from an exact commit through the contents API.
type File struct {
	Path    string
	BlobSHA string // git blob sha (plan content.manifest_blob_sha)
	Content []byte
}

// CIPolicy is apps.ci_policy_json (spec §18).
type CIPolicy struct {
	RepositoryID           int64           `json:"repository_id"`
	OwnerID                int64           `json:"owner_id"`
	Branch                 string          `json:"branch"`
	AllowedEvents          []string        `json:"allowed_events"`
	RequiredChecks         []RequiredCheck `json:"required_checks"`
	DeployWorkflow         string          `json:"deploy_workflow"`
	DeployReusableWorkflow string          `json:"deploy_reusable_workflow"`
}

// RequiredCheck is one check every deployable commit must have passed.
// WorkflowPath is required when AppID is GitHub Actions.
type RequiredCheck struct {
	Name         string `json:"name"`
	AppID        int64  `json:"app_id"`
	WorkflowPath string `json:"workflow_path"`
}

// Verdict of a check verification.
const (
	VerdictPassed  = "passed"
	VerdictPending = "pending"
	VerdictFailed  = "failed"
)

// CheckReport is the outcome of VerifyChecks. Reason is CHECK_FAILED or
// CHECK_MISSING when Verdict is failed. Evidence has one entry per passed
// required check (artifact_checks rows).
type CheckReport struct {
	Verdict  string
	Reason   string
	Evidence []CheckEvidence
}

// CheckEvidence is one artifact_checks row.
type CheckEvidence struct {
	CheckName    string
	AppID        int64
	WorkflowPath string
	RunID        int64
	RunAttempt   int64
	Conclusion   string
	CompletedAt  time.Time
}

// Claims are the verified claims of a GitHub Actions OIDC token. Numeric ids
// arrive as JSON strings and are parsed by the verifier.
type Claims struct {
	Issuer            string
	Subject           string
	Audience          []string
	JTI               string
	IssuedAt          time.Time
	ExpiresAt         time.Time
	RepositoryID      int64
	RepositoryOwnerID int64
	Repository        string // owner/name
	Ref               string // refs/heads/<branch>
	SHA               string
	EventName         string
	WorkflowRef       string // owner/repo/<path>@<ref>
	JobWorkflowRef    string // empty when absent
	Environment       string
	RunID             int64
	RunAttempt        int64
}

// EnvRequirement says whether the target environment requires the token's
// `environment` claim, and which value.
type EnvRequirement struct {
	Required bool
	Name     string
}

// Provenance is what an attestation must prove for one digest (spec §18 (a)).
type Provenance struct {
	RepositoryID int64
	Repository   string // owner/name, for the certificate SAN
	WorkflowPath string
	Branch       string
	CommitSHA    string
}

// Evidence is a verified attestation, persisted as artifacts.provenance_json.
type Evidence struct {
	Method         string    `json:"method"` // attestation
	Digest         string    `json:"digest"`
	SubjectAltName string    `json:"subject_alt_name"`
	Issuer         string    `json:"issuer"`
	RepositoryID   int64     `json:"repository_id"`
	CommitSHA      string    `json:"commit_sha"`
	RunID          int64     `json:"run_id"`
	RunAttempt     int64     `json:"run_attempt"`
	PredicateType  string    `json:"predicate_type"`
	SignedAt       time.Time `json:"signed_at"`
}

// WebhookEvent is a verified webhook delivery reduced to what re-evaluation
// needs. Type is check_run | check_suite | workflow_run; other events are
// acknowledged and ignored.
type WebhookEvent struct {
	DeliveryID   string
	Type         string
	RepositoryID int64
	HeadSHA      string
}

// Client is the read-only GitHub REST API (ADR-0028). Every call goes through
// netguard; redirects stay on the api_url origin and the token never leaves it.
type Client interface {
	Repository(ctx context.Context, id int64) (Repo, error)
	Repositories(ctx context.Context, page Page) ([]Repo, Page, error)
	CheckRuns(ctx context.Context, r Repo, sha string) ([]CheckRun, error)
	WorkflowRun(ctx context.Context, r Repo, suiteID int64) (WorkflowRun, error)
	File(ctx context.Context, r Repo, sha, path string, max int64) (File, error)
	Attestations(ctx context.Context, r Repo, digest string) ([]json.RawMessage, error)
}

// OIDCVerifier checks a GitHub Actions OIDC token: signature, aud, exp, iat,
// skew and jti replay (spec §18).
type OIDCVerifier interface {
	Verify(ctx context.Context, raw string) (Claims, error)
}

// AttestationVerifier verifies Sigstore bundles for one digest against the
// trusted roots; it never falls back to "unverified".
type AttestationVerifier interface {
	Verify(bundles []json.RawMessage, digest string, want Provenance) (Evidence, error)
}
