package domain

import (
	"fmt"
	"slices"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// parseEnum returns s as a member of all, or an INVALID_ARGUMENT error naming kind.
func parseEnum[T ~string](kind string, all []T, s string) (T, error) {
	v := T(s)
	if !slices.Contains(all, v) {
		return "", smerr.New(smerr.CodeInvalidArgument, "", fmt.Sprintf("invalid %s %q", kind, s))
	}
	return v, nil
}

// ActorType classifies who performs a request (spec §11.1).
type ActorType string

const (
	ActorHuman      ActorType = "human"
	ActorAutomation ActorType = "automation"
	ActorMCP        ActorType = "mcp"
	ActorSystem     ActorType = "system"
)

func AllActorTypes() []ActorType {
	return []ActorType{ActorHuman, ActorAutomation, ActorMCP, ActorSystem}
}

func ParseActorType(s string) (ActorType, error) { return parseEnum("actor type", AllActorTypes(), s) }
func (v ActorType) Valid() bool                  { return slices.Contains(AllActorTypes(), v) }

// CredentialKind is the credential a request authenticated with (spec §11.1).
type CredentialKind string

const (
	CredentialLocalSocket      CredentialKind = "local_socket"
	CredentialSession          CredentialKind = "session"
	CredentialAPIToken         CredentialKind = "api_token"
	CredentialMCPToken         CredentialKind = "mcp_token"
	CredentialOAuthAccessToken CredentialKind = "oauth_access_token"
	CredentialGitHubOIDC       CredentialKind = "github_oidc"
)

func AllCredentialKinds() []CredentialKind {
	return []CredentialKind{
		CredentialLocalSocket, CredentialSession, CredentialAPIToken,
		CredentialMCPToken, CredentialOAuthAccessToken, CredentialGitHubOIDC,
	}
}

func ParseCredentialKind(s string) (CredentialKind, error) {
	return parseEnum("credential kind", AllCredentialKinds(), s)
}
func (v CredentialKind) Valid() bool { return slices.Contains(AllCredentialKinds(), v) }

// ResourceType names the kinds of resources actions and locks refer to.
type ResourceType string

const (
	ResourceNode        ResourceType = "node"
	ResourceService     ResourceType = "service"
	ResourceApp         ResourceType = "app"
	ResourceAppTarget   ResourceType = "app_target"
	ResourceDeployment  ResourceType = "deployment"
	ResourceEnvironment ResourceType = "environment"
	ResourceProvider    ResourceType = "provider"
	ResourceJob         ResourceType = "job"
	ResourcePlan        ResourceType = "plan"
	ResourceEvent       ResourceType = "event"
	ResourceInstance    ResourceType = "instance"
	ResourceIdentity    ResourceType = "identity"
	ResourceSecret      ResourceType = "secret"
)

func AllResourceTypes() []ResourceType {
	return []ResourceType{
		ResourceNode, ResourceService, ResourceApp, ResourceAppTarget, ResourceDeployment,
		ResourceEnvironment, ResourceProvider, ResourceJob, ResourcePlan, ResourceEvent,
		ResourceInstance, ResourceIdentity, ResourceSecret,
	}
}

func ParseResourceType(s string) (ResourceType, error) {
	return parseEnum("resource type", AllResourceTypes(), s)
}
func (v ResourceType) Valid() bool { return slices.Contains(AllResourceTypes(), v) }

// ManagementState is the configured relationship with a node (spec §6.2).
type ManagementState string

const (
	ManagementDiscovered ManagementState = "discovered"
	ManagementManaged    ManagementState = "managed"
	ManagementRetired    ManagementState = "retired"
)

func AllManagementStates() []ManagementState {
	return []ManagementState{ManagementDiscovered, ManagementManaged, ManagementRetired}
}

func ParseManagementState(s string) (ManagementState, error) {
	return parseEnum("management state", AllManagementStates(), s)
}
func (v ManagementState) Valid() bool { return slices.Contains(AllManagementStates(), v) }

// Reachability is the observed connectivity of a node (spec §6.4).
type Reachability string

const (
	ReachabilityReachable   Reachability = "reachable"
	ReachabilityUnreachable Reachability = "unreachable"
	ReachabilityUnknown     Reachability = "unknown"
)

func AllReachabilities() []Reachability {
	return []Reachability{ReachabilityReachable, ReachabilityUnreachable, ReachabilityUnknown}
}

func ParseReachability(s string) (Reachability, error) {
	return parseEnum("reachability", AllReachabilities(), s)
}
func (v Reachability) Valid() bool { return slices.Contains(AllReachabilities(), v) }

// EnvironmentRiskLevel classifies an environment (spec §8.2.1).
type EnvironmentRiskLevel string

const (
	EnvironmentDevelopment EnvironmentRiskLevel = "development"
	EnvironmentStaging     EnvironmentRiskLevel = "staging"
	EnvironmentProduction  EnvironmentRiskLevel = "production"
)

func AllEnvironmentRiskLevels() []EnvironmentRiskLevel {
	return []EnvironmentRiskLevel{EnvironmentDevelopment, EnvironmentStaging, EnvironmentProduction}
}

func ParseEnvironmentRiskLevel(s string) (EnvironmentRiskLevel, error) {
	return parseEnum("environment risk level", AllEnvironmentRiskLevels(), s)
}
func (v EnvironmentRiskLevel) Valid() bool { return slices.Contains(AllEnvironmentRiskLevels(), v) }

// ProviderOrigin tells whether a provider is declared in config or created via the API.
type ProviderOrigin string

const (
	ProviderStatic ProviderOrigin = "static"
	ProviderAPI    ProviderOrigin = "api"
)

func AllProviderOrigins() []ProviderOrigin { return []ProviderOrigin{ProviderStatic, ProviderAPI} }
func ParseProviderOrigin(s string) (ProviderOrigin, error) {
	return parseEnum("provider origin", AllProviderOrigins(), s)
}
func (v ProviderOrigin) Valid() bool { return slices.Contains(AllProviderOrigins(), v) }

// RetryClass says how a job may be re-run (spec §20.4).
type RetryClass string

const (
	RetryIdempotent   RetryClass = "idempotent"
	RetryResumable    RetryClass = "resumable"
	RetryNonRetryable RetryClass = "non_retryable"
)

func AllRetryClasses() []RetryClass {
	return []RetryClass{RetryIdempotent, RetryResumable, RetryNonRetryable}
}

func ParseRetryClass(s string) (RetryClass, error) {
	return parseEnum("retry class", AllRetryClasses(), s)
}
func (v RetryClass) Valid() bool { return slices.Contains(AllRetryClasses(), v) }

// LockMode is the mode of a resource lock (spec §20.5).
type LockMode string

const (
	LockExclusive LockMode = "exclusive"
	LockShared    LockMode = "shared"
)

func AllLockModes() []LockMode                 { return []LockMode{LockExclusive, LockShared} }
func ParseLockMode(s string) (LockMode, error) { return parseEnum("lock mode", AllLockModes(), s) }
func (v LockMode) Valid() bool                 { return slices.Contains(AllLockModes(), v) }

// IntentState is the state of an operation intent (spec §20.4).
type IntentState string

const (
	IntentRecorded  IntentState = "recorded"
	IntentCompleted IntentState = "completed"
)

func AllIntentStates() []IntentState { return []IntentState{IntentRecorded, IntentCompleted} }
func ParseIntentState(s string) (IntentState, error) {
	return parseEnum("intent state", AllIntentStates(), s)
}
func (v IntentState) Valid() bool { return slices.Contains(AllIntentStates(), v) }

// ApprovalDecision is an approver's verdict on a plan hash (spec §11.4).
type ApprovalDecision string

const (
	DecisionApprove ApprovalDecision = "approve"
	DecisionReject  ApprovalDecision = "reject"
)

func AllApprovalDecisions() []ApprovalDecision {
	return []ApprovalDecision{DecisionApprove, DecisionReject}
}

func ParseApprovalDecision(s string) (ApprovalDecision, error) {
	return parseEnum("approval decision", AllApprovalDecisions(), s)
}
func (v ApprovalDecision) Valid() bool { return slices.Contains(AllApprovalDecisions(), v) }

// Severity grades an event (spec §26).
type Severity string

const (
	SeverityInfo    Severity = "info"
	SeverityWarning Severity = "warning"
	SeverityError   Severity = "error"
)

func AllSeverities() []Severity                { return []Severity{SeverityInfo, SeverityWarning, SeverityError} }
func ParseSeverity(s string) (Severity, error) { return parseEnum("severity", AllSeverities(), s) }
func (v Severity) Valid() bool                 { return slices.Contains(AllSeverities(), v) }

// Result is the outcome recorded on an event (spec §26).
type Result string

const (
	ResultSucceeded Result = "succeeded"
	ResultFailed    Result = "failed"
	ResultDenied    Result = "denied"
	ResultPending   Result = "pending"
)

func AllResults() []Result {
	return []Result{ResultSucceeded, ResultFailed, ResultDenied, ResultPending}
}
func ParseResult(s string) (Result, error) { return parseEnum("result", AllResults(), s) }
func (v Result) Valid() bool               { return slices.Contains(AllResults(), v) }
