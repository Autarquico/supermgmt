package wire

import (
	"encoding/json"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// ---- identity and instance -------------------------------------------------

// Me is GET /me: the caller as the daemon authenticated it.
type Me struct {
	IdentityID   domain.ID             `json:"identity_id"`
	ActorType    domain.ActorType      `json:"actor_type"`
	DisplayName  string                `json:"display_name"`
	Credential   domain.CredentialKind `json:"credential"`
	Roles        []string              `json:"roles"`
	InstanceMode string                `json:"instance_mode"`
}

// SSHKey is GET /ssh-key: the public half of the instance identity
// secret://ssh/default (spec §8.4, ADR-0016). The private key never leaves
// the daemon.
type SSHKey struct {
	Ref               string `json:"ref"`
	Version           int    `json:"version"`
	AuthorizedKey     string `json:"authorized_key"`
	FingerprintSHA256 string `json:"fingerprint_sha256"`
}

// Health is GET /health/live and /health/ready.
type Health struct {
	Status string `json:"status"`
}

// ---- providers -------------------------------------------------------------

type Provider struct {
	ID           domain.ID             `json:"id"`
	Type         string                `json:"type"`
	Name         string                `json:"name"`
	Origin       domain.ProviderOrigin `json:"origin"`
	Status       string                `json:"status"`
	SpecRevision int64                 `json:"spec_revision"`
	LastSyncAt   *time.Time            `json:"last_sync_at"`
}

// CreateProviderRequest is POST /providers. M1 accepts only type "local",
// which is the user's consent to manage this machine (spec §14).
type CreateProviderRequest struct {
	Type string `json:"type"`
}

// ProviderLocal is the only provider type POST /providers accepts in M1.
const ProviderLocal = "local"

// ---- nodes -----------------------------------------------------------------

// Node is a node with its latest observations. Views are built from the
// database and the connection pool state; listing never dials (ADR-0014).
type Node struct {
	ID                 domain.ID              `json:"id"`
	Name               string                 `json:"name"`
	Kind               string                 `json:"kind"`
	ProviderID         domain.ID              `json:"provider_id"`
	Provider           string                 `json:"provider"`
	Origin             domain.ProviderOrigin  `json:"origin"`
	Environment        string                 `json:"environment"`
	ManagementState    domain.ManagementState `json:"management_state"`
	Reachability       domain.Reachability    `json:"reachability"`
	Endpoint           Endpoint               `json:"endpoint"`
	CredentialRef      string                 `json:"credential_ref"`
	AdminCredentialRef string                 `json:"admin_credential_ref"`
	OS                 string                 `json:"os"`
	Arch               string                 `json:"arch"`
	Tags               []string               `json:"tags"`
	Capabilities       []Capability           `json:"capabilities"`
	Addresses          []Address              `json:"addresses"`
	Connection         Connection             `json:"connection"`
	Metrics            *Metrics               `json:"metrics"`
	Setup              *Setup                 `json:"setup"`
	Proxmox            *ProxmoxGuest          `json:"proxmox"` // nil unless the node is a Proxmox node or guest
	Stale              bool                   `json:"stale"`
	SpecRevision       int64                  `json:"spec_revision"`
	LastSeenAt         *time.Time             `json:"last_seen_at"`
	UpdatedAt          time.Time              `json:"updated_at"`
}

// ProxmoxGuest is the Proxmox view of a node (ADR-0024). For a cluster
// member VMID is 0 and Type is "node". Status is the last observed power
// state. Inaccessible: the token lost the audit privilege, so the node's
// presence is unknown; Absent: the token could see it and it is gone.
type ProxmoxGuest struct {
	PVENode      string `json:"pve_node"`
	VMID         int    `json:"vmid"`
	Type         string `json:"type"`
	Status       string `json:"status"`
	Template     bool   `json:"template"`
	Inaccessible bool   `json:"inaccessible"`
	Absent       bool   `json:"absent"`
}

// Endpoint is the configured management endpoint (spec §6.4, ADR-0009 b).
type Endpoint struct {
	Host                     string `json:"host"`
	Port                     int    `json:"port"`
	User                     string `json:"user"`
	AdminUser                string `json:"admin_user"`
	HostPublicKey            string `json:"host_public_key"`
	HostKeyFingerprintSHA256 string `json:"host_key_fingerprint_sha256"`
}

type Capability struct {
	Name      string    `json:"name"`
	Available bool      `json:"available"`
	CheckedAt time.Time `json:"checked_at"`
}

type Address struct {
	Address   string `json:"address"`
	Family    string `json:"family"`
	Scope     string `json:"scope"`
	Preferred bool   `json:"preferred"`
}

// ConnState is the pool's view of a node's persistent SSH connection.
type ConnState string

const (
	ConnConnected ConnState = "connected"
	ConnIdle      ConnState = "idle"
	ConnBackoff   ConnState = "backoff"
	ConnUnknown   ConnState = "unknown"
)

type Connection struct {
	State      ConnState  `json:"state"`
	LastError  string     `json:"last_error"`
	NextDialAt *time.Time `json:"next_dial_at"`
}

// Metrics is the latest system metrics snapshot (spec §12 probe).
type Metrics struct {
	ObservedAt       time.Time `json:"observed_at"`
	CPUPercent       float64   `json:"cpu_percent"`
	MemoryUsedBytes  int64     `json:"memory_used_bytes"`
	MemoryTotalBytes int64     `json:"memory_total_bytes"`
	DiskUsedBytes    int64     `json:"disk_used_bytes"`
	DiskTotalBytes   int64     `json:"disk_total_bytes"`
	UptimeSeconds    int64     `json:"uptime_seconds"`
}

// Setup summarizes a successful node.setup (ADR-0009 f); nil when absent.
type Setup struct {
	SetupVersion   int         `json:"setup_version"`
	LogsMode       string      `json:"logs_mode"`
	DockerAccess   bool        `json:"docker_access"`
	Units          []UnitGrant `json:"units"`
	KeyFingerprint string      `json:"key_fingerprint"`
}

type UnitGrant struct {
	Unit  string               `json:"unit"`
	Verbs []domain.ServiceVerb `json:"verbs"`
}

// ScanHostKeyRequest is POST /nodes/ssh/host-key: a read-only keyscan for the
// first-trust confirmation (spec §12 steps 2-3).
type ScanHostKeyRequest struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// HostKey is a scanned host key. AuthorizedKey is the OpenSSH public key line.
type HostKey struct {
	AuthorizedKey     string `json:"authorized_key"`
	Type              string `json:"type"`
	FingerprintSHA256 string `json:"fingerprint_sha256"`
}

// AddSSHNodeRequest is POST /nodes/ssh. HostPublicKey must echo the key the
// user confirmed; a different key at first contact is SSH_HOST_KEY_MISMATCH.
// Empty User, CredentialRef and AdminCredentialRef take the configured defaults.
type AddSSHNodeRequest struct {
	Name               string   `json:"name"`
	Host               string   `json:"host"`
	Port               int      `json:"port"`
	User               string   `json:"user"`
	AdminUser          string   `json:"admin_user"`
	HostPublicKey      string   `json:"host_public_key"`
	CredentialRef      string   `json:"credential_ref"`
	AdminCredentialRef string   `json:"admin_credential_ref"`
	Environment        string   `json:"environment"`
	Tags               []string `json:"tags"`
}

// NodePatch is PATCH /nodes/{id} (with If-Match: <spec_revision>). Nil fields
// are unchanged. HostPublicKey re-pins the node to a key the operator
// confirmed from a fresh scan (ADR-0021).
type NodePatch struct {
	Name               *string   `json:"name,omitempty"`
	Environment        *string   `json:"environment,omitempty"`
	Tags               *[]string `json:"tags,omitempty"`
	AdminUser          *string   `json:"admin_user,omitempty"`
	AdminCredentialRef *string   `json:"admin_credential_ref,omitempty"`
	HostPublicKey      *string   `json:"host_public_key,omitempty"`
}

// ConnectInfo is what an interactive client needs to run OpenSSH against a
// node (spec §8.4). User is the endpoint's admin_user; HostKeyAlias names the
// single line of the temporary known_hosts.
type ConnectInfo struct {
	NodeID        domain.ID `json:"node_id"`
	Host          string    `json:"host"`
	Port          int       `json:"port"`
	User          string    `json:"user"`
	HostPublicKey string    `json:"host_public_key"`
	HostKeyAlias  string    `json:"host_key_alias"`
}

// ---- interactive sessions --------------------------------------------------

// Tool is what an interactive session runs on the node.
type Tool string

const (
	ToolShell      Tool = "shell"
	ToolLazydocker Tool = "lazydocker"
	ToolBtop       Tool = "btop"
	ToolTmux       Tool = "tmux"
)

func AllTools() []Tool { return []Tool{ToolShell, ToolLazydocker, ToolBtop, ToolTmux} }

type SessionState string

const (
	SessionIssued    SessionState = "issued"
	SessionEnded     SessionState = "ended"
	SessionAbandoned SessionState = "abandoned"
)

type EndReason string

const (
	EndExited       EndReason = "exited"
	EndLaunchFailed EndReason = "launch_failed"
	EndAbandoned    EndReason = "abandoned"
)

// OpenSessionRequest is POST /nodes/{id}/sessions.
type OpenSessionRequest struct {
	Tool Tool `json:"tool"`
}

type Session struct {
	ID        domain.ID    `json:"id"`
	NodeID    domain.ID    `json:"node_id"`
	Tool      Tool         `json:"tool"`
	State     SessionState `json:"state"`
	ExitCode  *int         `json:"exit_code"`
	EndReason *EndReason   `json:"end_reason"`
	CreatedAt time.Time    `json:"created_at"`
	EndedAt   *time.Time   `json:"ended_at"`
}

// SessionOpened answers POST /nodes/{id}/sessions.
type SessionOpened struct {
	Session     Session     `json:"session"`
	ConnectInfo ConnectInfo `json:"connect_info"`
}

// EndSessionRequest is POST /nodes/{id}/sessions/{sid}/end. Reason is exited
// (with ExitCode) or launch_failed; the first end wins.
type EndSessionRequest struct {
	Reason   EndReason `json:"reason"`
	ExitCode *int      `json:"exit_code"`
}

// ---- services --------------------------------------------------------------

// Service is one runtime-native service. Actions lists the verbs the node
// currently advertises for it (gated on node.setup, ADR-0009 g).
type Service struct {
	ID           domain.ID            `json:"id"`
	NodeID       domain.ID            `json:"node_id"`
	Node         string               `json:"node"`
	RuntimeType  domain.RuntimeType   `json:"runtime_type"`
	Kind         domain.ServiceKind   `json:"kind"`
	NativeID     string               `json:"native_id"`
	Name         string               `json:"name"`
	Status       string               `json:"status"`
	Health       string               `json:"health"`
	Metadata     map[string]any       `json:"metadata"`
	Actions      []domain.ServiceVerb `json:"actions"`
	SpecRevision int64                `json:"spec_revision"`
	LastSeenAt   *time.Time           `json:"last_seen_at"`
}

// LogChunk answers GET /services/{id}/logs: sanitized lines, oldest first.
type LogChunk struct {
	ServiceID   domain.ID `json:"service_id"`
	Lines       []string  `json:"lines"`
	Truncated   bool      `json:"truncated"`
	CollectedAt time.Time `json:"collected_at"`
}

// ---- plans, jobs, approvals ------------------------------------------------

type ResourceRef struct {
	Type domain.ResourceType `json:"type"`
	ID   domain.ID           `json:"id"`
}

// CreatePlanRequest is POST /plans (spec §23).
type CreatePlanRequest struct {
	Action     string         `json:"action"`
	Targets    []ResourceRef  `json:"targets"`
	Parameters map[string]any `json:"parameters"`
}

// Policy is the policy verdict on a plan (spec §11.3 step 10).
type Policy struct {
	Decision         string       `json:"decision"`
	ApprovalRequired bool         `json:"approval_required"`
	Quorum           int          `json:"quorum"`
	Reason           smerr.Reason `json:"reason"`
}

// CreatedPlan answers POST /plans. Plan is the canonical plan document whose
// SHA-256 is PlanHash; clients show it and send the hash back.
type CreatedPlan struct {
	PlanID    domain.ID       `json:"plan_id"`
	Plan      json.RawMessage `json:"plan"`
	PlanHash  string          `json:"plan_hash"`
	ExpiresAt time.Time       `json:"expires_at"`
	Policy    Policy          `json:"policy"`
}

// PlanHashRequest is the body of POST /plans/{id}/submit and /jobs/{id}/cancel.
type PlanHashRequest struct {
	PlanHash string `json:"plan_hash"`
}

// Submission answers a submit or a convenience action: the job and why it is
// queued or awaiting approval.
type Submission struct {
	Job    Job    `json:"job"`
	Policy Policy `json:"policy"`
}

// DecisionRequest is POST /jobs/{id}/approve and /reject. Reason is required
// to reject.
type DecisionRequest struct {
	PlanHash string `json:"plan_hash"`
	Reason   string `json:"reason"`
}

// Outcome is a human resolution of an interrupted job (spec §20.4).
type Outcome string

const (
	OutcomeSucceeded      Outcome = "succeeded"
	OutcomeFailed         Outcome = "failed"
	OutcomeRollbackFailed Outcome = "rollback_failed"
)

// ResolveRequest is POST /jobs/{id}/resolve. AssumeQuiescent is required when
// the node is unreachable and is audited.
type ResolveRequest struct {
	PlanHash        string  `json:"plan_hash"`
	Outcome         Outcome `json:"outcome"`
	Note            string  `json:"note"`
	AssumeQuiescent bool    `json:"assume_quiescent"`
}

type Job struct {
	ID          domain.ID         `json:"id"`
	Type        string            `json:"type"`
	Resource    ResourceRef       `json:"resource"`
	ActorID     domain.ID         `json:"actor_id"`
	State       domain.JobState   `json:"state"`
	Risk        domain.RiskClass  `json:"risk"`
	RetryClass  domain.RetryClass `json:"retry_class"`
	PlanID      *domain.ID        `json:"plan_id"`
	PlanHash    string            `json:"plan_hash"`
	Attempts    int               `json:"attempts"`
	MaxAttempts int               `json:"max_attempts"`
	CreatedAt   time.Time         `json:"created_at"`
	ScheduledAt time.Time         `json:"scheduled_at"`
	StartedAt   *time.Time        `json:"started_at"`
	FinishedAt  *time.Time        `json:"finished_at"`
	Error       *Failure          `json:"error"`
}

// Failure is why a job failed.
type Failure struct {
	Code    smerr.Code   `json:"code"`
	Reason  smerr.Reason `json:"reason"`
	Message string       `json:"message"`
}

// JobDetail is GET /jobs/{id}: the job and its operation intents, whose
// pre-state and evidence show what the reconciler saw (spec §20.4).
type JobDetail struct {
	Job     Job      `json:"job"`
	Intents []Intent `json:"intents"`
}

type Intent struct {
	ID           domain.ID          `json:"id"`
	Step         string             `json:"step"`
	State        domain.IntentState `json:"state"`
	Operation    string             `json:"operation"`
	Target       string             `json:"target"`
	PreState     json.RawMessage    `json:"pre_state"`
	DeadlineAt   time.Time          `json:"deadline_at"`
	DispatchedAt *time.Time         `json:"dispatched_at"`
	CompletedAt  *time.Time         `json:"completed_at"`
	Outcome      string             `json:"outcome"`
	Evidence     json.RawMessage    `json:"evidence"`
}

// Approval is one job awaiting approval with what an approver must see
// (spec §39.5): the plan it binds to and the quorum state.
type Approval struct {
	Job          Job             `json:"job"`
	Plan         json.RawMessage `json:"plan"`
	Environments []string        `json:"environments"`
	Quorum       int             `json:"quorum"`
	Approvals    int             `json:"approvals"`
	ExpiresAt    time.Time       `json:"expires_at"`
}

// ---- events ----------------------------------------------------------------

// Event is the spec §26 event shape plus seq (the follow cursor) and severity.
type Event struct {
	EventID       domain.ID       `json:"event_id"`
	Seq           int64           `json:"seq"`
	Timestamp     time.Time       `json:"timestamp"`
	Actor         Actor           `json:"actor"`
	Source        string          `json:"source"`
	Action        string          `json:"action"`
	Resource      ResourceRef     `json:"resource"`
	CorrelationID string          `json:"correlation_id"`
	Severity      domain.Severity `json:"severity"`
	Result        domain.Result   `json:"result"`
	Data          map[string]any  `json:"data"`
}

type Actor struct {
	Type domain.ActorType `json:"type"`
	ID   domain.ID        `json:"id"`
}
