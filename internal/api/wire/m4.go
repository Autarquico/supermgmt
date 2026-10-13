package wire

import (
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// ---- apps (spec §18, §19, §20.3; ADR-0007) ----------------------------------
//
// Durations are Go duration strings ("3s", "10m"). Compose content is the
// control-plane source text: it may hold `${secret:<ref>}` references, never a
// secret value.

// App is GET /apps/{id} and an element of GET /apps.
type App struct {
	ID                   domain.ID         `json:"id"`
	Name                 string            `json:"name"`
	Repository           *Repository       `json:"repository"`
	ManifestPath         string            `json:"manifest_path"`
	DeployedService      string            `json:"deployed_service"`
	ImagePolicy          ImagePolicy       `json:"image_policy"`
	ComposeSource        string            `json:"compose_source"` // control-plane | repository
	ComposeContent       string            `json:"compose_content"`
	ComposeSourceHash    string            `json:"compose_source_hash"`
	ComposeExceptions    ComposeExceptions `json:"compose_exceptions"`
	Variables            map[string]string `json:"variables"`
	SecretRefs           map[string]string `json:"secret_refs"` // ref-name -> secret:// path
	CIPolicy             *CIPolicy         `json:"ci_policy"`
	AutomationIdentityID *domain.ID        `json:"automation_identity_id"`
	Targets              []AppTarget       `json:"targets"`
	SpecRevision         int64             `json:"spec_revision"`
	CreatedAt            time.Time         `json:"created_at"`
	UpdatedAt            time.Time         `json:"updated_at"`
}

// ImagePolicy is apps.image_policy_json (spec §20.3 step 8).
type ImagePolicy struct {
	Deployed string            `json:"deployed"`
	Sidecars map[string]string `json:"sidecars"`
	Pinned   []string          `json:"pinned"`
}

// ComposeExceptions are the admin-approved exact values per service (spec
// §20.3 step 7).
type ComposeExceptions struct {
	Services map[string]ServiceExceptions `json:"services"`
}

type ServiceExceptions struct {
	CapAdd     []string          `json:"cap_add"`
	Sysctls    map[string]string `json:"sysctls"`
	ExtraHosts []string          `json:"extra_hosts"`
	ShmSize    string            `json:"shm_size"`
}

// CIPolicy is apps.ci_policy_json (spec §18). GitHub ids are numeric; names
// are display only.
type CIPolicy struct {
	RepositoryID           int64           `json:"repository_id"`
	OwnerID                int64           `json:"owner_id"`
	Branch                 string          `json:"branch"`
	AllowedEvents          []string        `json:"allowed_events"`
	RequiredChecks         []RequiredCheck `json:"required_checks"`
	DeployWorkflow         string          `json:"deploy_workflow"`
	DeployReusableWorkflow string          `json:"deploy_reusable_workflow"`
}

type RequiredCheck struct {
	Name         string `json:"name"`
	AppID        int64  `json:"app_id"`
	WorkflowPath string `json:"workflow_path"`
}

// AppTarget binds an app to one environment and one node (spec §20.0, §20.5).
type AppTarget struct {
	ID               domain.ID        `json:"id"`
	AppID            domain.ID        `json:"app_id"`
	EnvironmentID    domain.ID        `json:"environment_id"`
	Environment      string           `json:"environment"`
	NodeID           domain.ID        `json:"node_id"`
	ComposeProject   string           `json:"compose_project"`
	DeploymentPolicy DeploymentPolicy `json:"deployment_policy"`
	SpecRevision     int64            `json:"spec_revision"`
	CreatedAt        time.Time        `json:"created_at"`
	UpdatedAt        time.Time        `json:"updated_at"`
}

// DeploymentPolicy is app_targets.deployment_policy_json (spec §19.1).
type DeploymentPolicy struct {
	Rollback             string        `json:"rollback"` // automatic | manual
	Stateful             bool          `json:"stateful"`
	PreDeployBackup      *BackupPolicy `json:"pre_deploy_backup"`
	Snapshot             bool          `json:"snapshot"` // true is refused in M4
	AllowedBindAddresses []string      `json:"allowed_bind_addresses"`
	Health               *HealthCheck  `json:"health"`
}

type BackupPolicy struct {
	Template string            `json:"template"` // postgres-dump in M4
	Args     map[string]string `json:"args"`
	Timeout  string            `json:"timeout"`
}

// HealthCheck is a control-plane health check (spec §21). Node scope names a
// port and a path; control_plane scope names a URL.
type HealthCheck struct {
	Type     string `json:"type"`  // http | https | tcp | docker-health
	Scope    string `json:"scope"` // node | control_plane
	Port     int    `json:"port"`
	Path     string `json:"path"`
	URL      string `json:"url"`
	Timeout  string `json:"timeout"`
	Interval string `json:"interval"`
	Attempts int    `json:"attempts"`
}

// Repository is a GitHub repository: a stored row (ID set) or a listing entry
// of GET /providers/{id}/repositories (ID null until an app references it).
type Repository struct {
	ID                 *domain.ID `json:"id"`
	ProviderID         domain.ID  `json:"provider_id"`
	GitHubRepositoryID int64      `json:"github_repository_id"`
	GitHubOwnerID      int64      `json:"github_owner_id"`
	Owner              string     `json:"owner"`
	Name               string     `json:"name"`
	URL                string     `json:"url"`
	DefaultBranch      string     `json:"default_branch"`
	Private            bool       `json:"private"`
}

// CreateAppRequest is POST /apps (app.write). RepositoryID is the GitHub
// repository id under ProviderID; both are null for an app without a repository.
type CreateAppRequest struct {
	Name               string            `json:"name"`
	ProviderID         *domain.ID        `json:"provider_id"`
	RepositoryID       *int64            `json:"repository_id"`
	ManifestPath       string            `json:"manifest_path"`
	DeployedService    string            `json:"deployed_service"`
	ImagePolicy        ImagePolicy       `json:"image_policy"`
	ComposeSource      string            `json:"compose_source"`
	ComposeContent     string            `json:"compose_content"`
	ComposeExceptions  ComposeExceptions `json:"compose_exceptions"`
	Variables          map[string]string `json:"variables"`
	SecretRefs         map[string]string `json:"secret_refs"`
	CIPolicy           *CIPolicy         `json:"ci_policy"`
	AutomationIdentity bool              `json:"automation_identity"` // link repository_id:<id>:workflow:<deploy_workflow> (no role)
}

// AppPatch is PATCH /apps/{id} (with If-Match: <spec_revision>). Nil fields are
// unchanged; name, repository and deployed service are fixed at creation.
type AppPatch struct {
	ManifestPath       *string            `json:"manifest_path,omitempty"`
	ImagePolicy        *ImagePolicy       `json:"image_policy,omitempty"`
	ComposeSource      *string            `json:"compose_source,omitempty"`
	ComposeContent     *string            `json:"compose_content,omitempty"`
	ComposeExceptions  *ComposeExceptions `json:"compose_exceptions,omitempty"`
	Variables          *map[string]string `json:"variables,omitempty"`
	SecretRefs         *map[string]string `json:"secret_refs,omitempty"`
	CIPolicy           *CIPolicy          `json:"ci_policy,omitempty"`
	AutomationIdentity *bool              `json:"automation_identity,omitempty"` // false unlinks and revokes its OIDC credentials
}

// CreateAppTargetRequest is POST /apps/{id}/targets (app_target.write). The
// Compose project is derived: sm-<app>-<environment>.
type CreateAppTargetRequest struct {
	Environment      string           `json:"environment"`
	NodeID           domain.ID        `json:"node_id"`
	DeploymentPolicy DeploymentPolicy `json:"deployment_policy"`
}

// AppTargetPatch is PATCH /app-targets/{id} (with If-Match). Environment, node
// and Compose project never change.
type AppTargetPatch struct {
	DeploymentPolicy *DeploymentPolicy `json:"deployment_policy,omitempty"`
}

// CreateGitHubProviderRequest is the body of POST /providers when type is
// "github" (provider.write; ADR-0028). The token and webhook secret are
// secret:// references, never values.
type CreateGitHubProviderRequest struct {
	Type             string `json:"type"`
	Name             string `json:"name"`
	APIURL           string `json:"api_url"`
	CredentialRef    string `json:"credential_ref"`
	WebhookSecretRef string `json:"webhook_secret_ref"`
	CAFile           string `json:"ca_file"`
}

// ProviderGitHub is the type of a GitHub provider.
const ProviderGitHub = "github"

// ---- deployments (spec §20; ADR-0011, ADR-0029) -------------------------------

// Deployment is GET /deployments/{id}, an element of GET /deployments and the
// 202 answer of POST /deployments and POST /deployments/{id}/rollback. PlanHash,
// PlanID and JobID are null while the deployment is provisional (created,
// waiting_ci).
type Deployment struct {
	ID                     domain.ID        `json:"id"`
	Kind                   string           `json:"kind"` // deploy | rollback
	AppID                  domain.ID        `json:"app_id"`
	AppTargetID            domain.ID        `json:"app_target_id"`
	EnvironmentID          domain.ID        `json:"environment_id"`
	NodeID                 domain.ID        `json:"node_id"`
	CommitSHA              string           `json:"commit_sha"`
	Images                 []RequestedImage `json:"images"`
	ArtifactID             *domain.ID       `json:"artifact_id"`
	PlanID                 *domain.ID       `json:"plan_id"`
	PlanHash               *string          `json:"plan_hash"`
	JobID                  *domain.ID       `json:"job_id"`
	State                  string           `json:"state"`
	StateCode              smerr.Code       `json:"state_code"`
	StateReason            smerr.Reason     `json:"state_reason"`
	StateCause             string           `json:"state_cause,omitempty"`
	RequestedBy            domain.ID        `json:"requested_by"`
	PreviousDeploymentID   *domain.ID       `json:"previous_deployment_id"`
	RollbackOfDeploymentID *domain.ID       `json:"rollback_of_deployment_id"`
	KnownGood              bool             `json:"known_good"`
	ComposeHash            *string          `json:"compose_hash"`
	Steps                  []DeploymentStep `json:"steps"`
	CreatedAt              time.Time        `json:"created_at"`
	UpdatedAt              time.Time        `json:"updated_at"`
	FinishedAt             *time.Time       `json:"finished_at"`
}

// RequestedImage is a service's image digest as the requester named it.
type RequestedImage struct {
	Service string `json:"service"`
	Digest  string `json:"digest"` // sha256:<64 hex>
}

// DeploymentStep is one deployment_steps row (App. C step order).
type DeploymentStep struct {
	Ordinal    int        `json:"ordinal"`
	Name       string     `json:"name"`
	State      string     `json:"state"` // pending | running | succeeded | failed | skipped
	Attempt    int        `json:"attempt"`
	StartedAt  *time.Time `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
	OutputRef  string     `json:"output_ref"`
	Error      *StepError `json:"error"`
}

// StepError is why a step failed; Cause is the details.cause (e.g.
// SECRET_VERSION_GONE, IMAGE_SIZE_UNKNOWN).
type StepError struct {
	Code    smerr.Code   `json:"code"`
	Reason  smerr.Reason `json:"reason"`
	Cause   string       `json:"cause"`
	Message string       `json:"message"`
}

// CreateDeploymentRequest is POST /deployments (deployment.create). Kind is
// always "deploy"; rollbacks use POST /deployments/{id}/rollback.
type CreateDeploymentRequest struct {
	AppTargetID domain.ID        `json:"app_target_id"`
	Kind        string           `json:"kind"`
	CommitSHA   string           `json:"commit_sha"`
	Images      []RequestedImage `json:"images"`
}

// RollbackRequest is POST /deployments/{id}/rollback (deployment.rollback). A
// nil ToDeploymentID selects the newest known-good deployment of the same
// target older than {id}.
type RollbackRequest struct {
	ToDeploymentID *domain.ID `json:"to_deployment_id"`
}
