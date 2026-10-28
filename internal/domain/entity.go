package domain

import "time"

// Environment is a deployment target class with its approval policy floor (spec §8.2.1).
type Environment struct {
	ID                     ID
	Name                   string
	RiskLevel              EnvironmentRiskLevel
	RequireProvenance      bool
	ApprovalsRequired      int
	AllowAutomaticRollback bool
	SpecRevision           int64
}

// Provider is an integration instance (spec §6.2).
type Provider struct {
	ID            ID
	Type          string
	Name          string
	Origin        ProviderOrigin
	Endpoint      string
	CredentialRef string
	Config        map[string]any
	Status        string
	SpecRevision  int64
	LastSyncAt    *time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// NodeEndpoint is the configured management endpoint of a node (spec §6.4).
// User is the account automated sessions use once the node has capability
// node.setup; until then they, setup and interactive sessions use AdminUser
// with AdminCredentialRef (ADR-0009 b).
type NodeEndpoint struct {
	Host               string
	Port               int
	User               string
	AdminUser          string
	AdminCredentialRef string
	HostPublicKey      string
	// Transport and TunnelHostname are owned by the tunnel jobs; static
	// configuration reconciliation never writes them (ADR-0037).
	Transport      Transport
	TunnelHostname string
}

// Node is a machine or guest. ManagementState is configured; Reachability is observed (spec §6.4).
type Node struct {
	ID              ID
	ProviderID      ID
	NativeID        string
	Name            string
	Kind            string
	EnvironmentID   *ID
	ManagementState ManagementState
	Reachability    Reachability
	Endpoint        NodeEndpoint
	CredentialRef   string
	OS              string
	Arch            string
	Tags            []string
	Metadata        map[string]any
	SpecRevision    int64
	CreatedAt       time.Time
	UpdatedAt       time.Time
	LastSeenAt      *time.Time
}

// Runtime is a service manager or container runtime detected on a node.
type Runtime struct {
	ID         ID
	NodeID     ID
	Type       string
	NativeID   string
	Version    string
	Status     string
	Metadata   map[string]any
	LastSeenAt *time.Time
}

// Service is a runtime-native process, container or unit. Status and health are separate.
type Service struct {
	ID           ID
	RuntimeID    ID
	NodeID       ID
	NativeID     string
	Name         string
	Kind         string
	Status       string
	Health       string
	Metadata     map[string]any
	SpecRevision int64
	LastSeenAt   *time.Time
}

// Event is an append-only audit record (spec §26). Seq is assigned by the store.
type Event struct {
	EventID       ID
	Seq           int64
	Timestamp     time.Time
	ActorType     ActorType
	ActorID       ID
	Source        string
	Action        string
	ResourceType  ResourceType
	ResourceID    ID
	CorrelationID string
	Severity      Severity
	Result        Result
	Data          map[string]any
}
