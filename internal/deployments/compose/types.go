// Package compose is the closed-schema Compose pipeline of spec §20.3
// (ADR-0006, ADR-0007, ADR-0010): raw checks, SuperMgmt interpolation, the
// pinned compose-go loader, the model allowlist, exceptions, image binding,
// ownership labels, the target-bound frozen public model, materialization and
// the on-node equivalence check. It never touches storage or a node.
//
// Frozen in M4 W0. Implemented in this package by:
//
//	T2a  func CheckRaw(raw []byte, t Target) error              // raw closed-schema pass (steps 1, 4–6 source forms)
//	T2a  func Interpolate(raw []byte, s Source) ([]byte, error) // step 2
//	T2b  func Load(interpolated []byte, project string) (*types.Project, error)
//	T2b  func CheckModel(p *types.Project, t Target, e Exceptions) error
//	T3a  func ValidateSource(s Source) error                   // steps 1–7, target-independent
//	T3a  func Freeze(s Source, t Target) (Frozen, error)       // steps 1–9 for one target
//	T3b  func Materialize(f Frozen, deployment domain.ID, values []ResolvedSecret) (Bundle, error)
//	T3b  func ExpectedEnvHashes(f Frozen, values []ResolvedSecret, vars map[string]string) []EnvHash
//	T3b  func Equivalent(expectedMasked json.RawMessage, cliMasked []byte) (diffs []string, err error)
package compose

import (
	"encoding/json"
	"net/netip"

	// The pinned loader (ADR-0006). Load (T2b) is its only caller; the import
	// keeps the module pinned in go.mod until then.
	_ "github.com/compose-spec/compose-go/v2/loader"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/domain"
)

// MaxRawBytes bounds the raw Compose document (spec §20.3 step 1).
const MaxRawBytes = 256 << 10

// Ownership and per-deployment labels (spec §20.3 step 9, §20.5).
const (
	LabelOwner      = "dev.supermgmt.owner"      // app_target_id; part of the public model
	LabelProject    = "dev.supermgmt.project"    // compose_project; part of the public model
	LabelDeployment = "dev.supermgmt.deployment" // deployment id; added at materialization only
)

// Image bindings (spec §18, App. C content.images[].binding).
const (
	BindingAttestation = "attestation"
	BindingOIDCClaims  = "oidc_claims"
	BindingPinned      = "pinned"
)

// Source is everything the pipeline reads that does not depend on the target:
// the app's Compose text and its control-plane configuration.
type Source struct {
	Raw             []byte
	Variables       map[string]string // apps.variables_json (non-secret)
	SecretRefs      map[string]string // apps.secret_refs_json: ref-name -> secret:// path
	Exceptions      Exceptions
	Images          ImagePolicy
	DeployedService string
	ArtifactDigest  string            // sha256:<hex> of the deployed service's image
	BoundDigests    map[string]string // repo@digest -> binding (Binding*)
}

// Target is what binds a public model to one app_target (ADR-0007): the
// ownership labels and the host addresses its ports may publish on, besides
// loopback.
type Target struct {
	Project     string
	Owner       domain.ID // app_target_id
	AllowedBind []netip.Addr
}

// Exceptions is apps.compose_exceptions_json: per service, the exact values an
// admin approved for the only exemptible keys (spec §20.3 step 7).
type Exceptions struct {
	Services map[string]ServiceExceptions `json:"services" yaml:"services"`
}

// ServiceExceptions lists exact allowed values; a model value outside them is
// rejected like any non-allowlisted key.
type ServiceExceptions struct {
	CapAdd     []string          `json:"cap_add" yaml:"cap_add"`
	Sysctls    map[string]string `json:"sysctls" yaml:"sysctls"`
	ExtraHosts []string          `json:"extra_hosts" yaml:"extra_hosts"`
	ShmSize    string            `json:"shm_size" yaml:"shm_size"`
}

// ImagePolicy is apps.image_policy_json (spec §20.3 step 8).
type ImagePolicy struct {
	Deployed string            `json:"deployed" yaml:"deployed"`
	Sidecars map[string]string `json:"sidecars" yaml:"sidecars"`
	Pinned   []string          `json:"pinned" yaml:"pinned"`
}

// HostPort is a host port the frozen model publishes. Health destinations and
// port locks are taken from these, never from user input.
type HostPort struct {
	Service string
	Addr    netip.Addr
	Port    uint16
	Proto   string // tcp | udp
}

// ImageUse is one service's frozen image reference and how it was bound.
type ImageUse struct {
	Service string
	Ref     string // repo@sha256:<hex>
	Binding string
}

// SecretUse is a `${secret:<ref>}` removed from the public model and bound to
// an exact secret version at finalization (ADR-0008).
type SecretUse struct {
	Service string
	EnvName string
	Ref     string // secret name, e.g. apps/myapp/database_url
	Version int64
}

// Frozen is the target-bound result of the pipeline. Public is the canonical
// YAML whose SHA-256 is Hash (plan content.compose_hash); Effective is the
// expected `config --format json` model with environment values masked. Neither
// ever holds a secret value.
type Frozen struct {
	Public    []byte
	Hash      string
	Effective json.RawMessage
	Images    []ImageUse
	Secrets   []SecretUse
	HostPorts []HostPort
}

// ResolvedSecret is a decrypted secret version, held in memory only while a
// deployment is staged.
type ResolvedSecret struct {
	Ref     string
	Version int64
	Value   audit.Secret
}

// Bundle is what staging writes into a fresh deployment directory: the
// materialized compose.yaml and secrets/<service>.env contents keyed by their
// path relative to that directory.
type Bundle struct {
	ComposeYAML []byte
	EnvFiles    map[string]audit.Secret
}

// EnvHash is one resolved environment entry as the node reports it: the value
// is only ever compared through its SHA-256 (ADR-0010).
type EnvHash struct {
	Service string
	EnvName string
	SHA256  string
}
