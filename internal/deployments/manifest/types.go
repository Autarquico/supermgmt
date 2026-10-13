// Package manifest parses the repository manifest `.supermgmt.yaml` (spec §19)
// and merges it with the control-plane deployment policy (§19, §19.1): the
// control plane always wins and the manifest can only tighten.
package manifest

import (
	"net/netip"
	"time"

	"github.com/autarquico/supermgmt/internal/health"
)

// Fixed manifest identifiers (spec §19).
const (
	APIVersion       = "supermgmt.dev/v1"
	Kind             = "Application"
	StrategyCompose  = "docker-compose"
	DefaultPath      = ".supermgmt.yaml"
	BackupPostgresV1 = "postgres-dump" // the only pre-deploy backup template in M4 (Q10)
)

// Manifest is the strict V1 schema of `.supermgmt.yaml`.
type Manifest struct {
	APIVersion string   `yaml:"apiVersion"`
	Kind       string   `yaml:"kind"`
	Metadata   Metadata `yaml:"metadata"`
	Spec       Spec     `yaml:"spec"`
}

type Metadata struct {
	Name string `yaml:"name"`
}

type Spec struct {
	Deployment Deployment      `yaml:"deployment"`
	Health     *ManifestHealth `yaml:"health"`
	Rollback   *Rollback       `yaml:"rollback"`
}

type Deployment struct {
	Strategy    string `yaml:"strategy"`
	ComposeFile string `yaml:"composeFile"` // used only when apps.compose_source = repository
	Service     string `yaml:"service"`     // must equal apps.deployed_service
}

// ManifestHealth is a hint: a port the frozen model publishes and a path,
// never a URL or a host name.
type ManifestHealth struct {
	Type     string        `yaml:"type"` // http | tcp | docker-health
	Port     uint16        `yaml:"port"`
	Path     string        `yaml:"path"`
	Timeout  time.Duration `yaml:"timeout"`
	Interval time.Duration `yaml:"interval"`
	Attempts int           `yaml:"attempts"`
}

type Rollback struct {
	Mode string `yaml:"mode"` // automatic | manual
}

// DeploymentPolicy is app_targets.deployment_policy_json (spec §19.1).
type DeploymentPolicy struct {
	Rollback             string        `json:"rollback"`
	Stateful             bool          `json:"stateful"`
	PreDeployBackup      *Backup       `json:"pre_deploy_backup"`
	Snapshot             bool          `json:"snapshot"` // true is INVALID_ARGUMENT in M4 (Q9)
	AllowedBindAddresses []netip.Addr  `json:"allowed_bind_addresses"`
	Health               *health.Check `json:"health"` // Origin is always control_plane
}

// Backup is deployment_policy.pre_deploy_backup.
type Backup struct {
	Template string            `json:"template"`
	Args     map[string]string `json:"args"`
	Timeout  time.Duration     `json:"timeout"`
}

// EffectivePolicy is what a deployment plan freezes (deployment_policy_hash and
// health_hash in App. C): the control-plane policy after §19 precedence.
// Rollback is the effective mode; Health is nil when neither side defines one,
// and a manifest check always has Origin manifest and node scope.
type EffectivePolicy struct {
	Rollback             string        `json:"rollback"`
	Stateful             bool          `json:"stateful"`
	PreDeployBackup      *Backup       `json:"pre_deploy_backup"`
	AllowedBindAddresses []netip.Addr  `json:"allowed_bind_addresses"`
	Health               *health.Check `json:"health"`
}
