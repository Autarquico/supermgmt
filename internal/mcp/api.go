// Package mcp is the MCP server of SuperMgmt (spec §24, ADR-0031): one
// *mcp.Server of the official Go SDK whose tools are API calls. It holds no
// database handle and no connector credential, so policy, audit, idempotency
// and rate limits are the API's. The same server is reached over stdio
// (`sm mcp`, the daemon socket) and over streamable HTTP (server mode, /mcp).
//
// Tool results never serialize a wire DTO directly: each tool returns an
// allowlisted view in which remote-discovered text sits under an Untrusted
// envelope, sanitized, scrubbed and bounded.
package mcp

import (
	"context"
	"log/slog"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

// API is the subset of the typed API client the tools call; *client.Client
// satisfies it (asserted in internal/cli/mcp_bridge.go).
type API interface {
	Me(ctx context.Context) (wire.Me, error)
	SSHKey(ctx context.Context) (wire.SSHKey, error)
	ListProviders(ctx context.Context, q wire.PageQuery) (wire.Page[wire.Provider], error)
	ListNodes(ctx context.Context, q wire.NodeQuery) (wire.Page[wire.Node], error)
	GetNode(ctx context.Context, id domain.ID, focus bool) (wire.Node, error)
	ListServices(ctx context.Context, node domain.ID, q wire.PageQuery) (wire.Page[wire.Service], error)
	GetService(ctx context.Context, id domain.ID) (wire.Service, error)
	ServiceLogs(ctx context.Context, id domain.ID, q wire.LogQuery) (wire.LogChunk, error)
	ListEvents(ctx context.Context, q wire.EventQuery) (wire.Page[wire.Event], error)
	CreatePlan(ctx context.Context, r wire.CreatePlanRequest) (wire.CreatedPlan, error)
	SubmitPlan(ctx context.Context, plan domain.ID, planHash string) (wire.Submission, error)
	GetPlan(ctx context.Context, id domain.ID) (wire.CreatedPlan, error)
	ListActions(ctx context.Context) (wire.Page[wire.PlannableAction], error)
	ListJobs(ctx context.Context, q wire.JobQuery) (wire.Page[wire.Job], error)
	GetJob(ctx context.Context, id domain.ID) (wire.JobDetail, error)
	CancelJob(ctx context.Context, id domain.ID, planHash string) (wire.Job, error)
	ProbeNode(ctx context.Context, id domain.ID) (wire.Submission, error)
	RefreshProvider(ctx context.Context, id domain.ID) (wire.Provider, error)
	CreateBackup(ctx context.Context) (wire.Submission, error)
	ListApprovals(ctx context.Context, q wire.PageQuery) (wire.Page[wire.Approval], error)
	ListBackups(ctx context.Context) (wire.Page[wire.Backup], error)
	ListTunnelEnrollments(ctx context.Context) (wire.Page[wire.TunnelEnrollment], error)
	ListApps(ctx context.Context, q wire.AppsQuery) (wire.Page[wire.NodeApps], error)
	ListNodeApps(ctx context.Context, node domain.ID, q wire.AppsQuery) (wire.NodeApps, error)
	GetNodeApp(ctx context.Context, node domain.ID, project string, q wire.AppsQuery) (wire.App, error)
	NodeAppStats(ctx context.Context, node domain.ID, project string) (wire.AppStats, error)
	NodeAppLogs(ctx context.Context, node domain.ID, project string, q wire.AppLogQuery) (wire.AppLogs, error)
	ListAllNodeRoutes(ctx context.Context, includeRemoved bool) (wire.Page[wire.NodeRoute], error)
	ExposeNodeRoute(ctx context.Context, node domain.ID, r wire.ExposeNodeRouteRequest) (wire.NodeRouteSubmission, error)
	ScanHostKey(ctx context.Context, r wire.ScanHostKeyRequest) (wire.HostKey, error)
	AddSSHNode(ctx context.Context, r wire.AddSSHNodeRequest) (wire.Direct[wire.Node], error)
	UnexposeNodeRoute(ctx context.Context, node domain.ID, hostname string) (wire.NodeRouteSubmission, error)
}

// Options configure the server. WriteTools is mcp.write_tools_enabled: the
// write tools are registered only when it is true. Version is the SuperMgmt
// version reported in the MCP implementation info.
type Options struct {
	WriteTools bool
	Version    string
	Log        *slog.Logger
}

// HTTPOptions configure the streamable HTTP handler (ADR-0031). A request
// carrying an Origin header must name AllowedOrigin (server.public_url's
// origin). ProtocolVersions are the MCP versions served remotely.
type HTTPOptions struct {
	AllowedOrigin    string
	ProtocolVersions []string
}

// SchemaVersion is the version of every tool's input and output schema,
// published in each tool's _meta under SchemaVersionMetaKey.
const (
	SchemaVersion        = 1
	SchemaVersionMetaKey = "dev.supermgmt/schema_version"
)

// Bounds of remote-discovered output (spec §24, ADR-0031).
const (
	MaxUntrustedBytes    = 64 << 10 // one log text or other remote text
	MaxUntrustedLines    = 500      // lines of one log text
	MaxRemoteScalarBytes = 256      // one remote string field
	MaxRemoteDepth       = 4        // nesting of remote maps and arrays
	MaxRemoteEntries     = 64       // entries per level of a remote map or array
)

// Untrusted wraps remote text handed to a model: data, never instructions.
// Text is already sanitized, scrubbed and bounded; Truncated says a bound cut
// it.
type Untrusted struct {
	Untrusted bool   `json:"untrusted_remote_output"`
	Text      string `json:"text"`
	Truncated bool   `json:"truncated"`
}

// WriteStatus is the outcome of a write tool.
type WriteStatus string

const (
	WriteApprovalRequired WriteStatus = "approval_required"
	WriteQueued           WriteStatus = "queued"
	WriteDenied           WriteStatus = "denied"
	WriteDone             WriteStatus = "done"
	WriteFailed           WriteStatus = "failed"
)

// WriteResult is the result of every write tool (spec §24). Summary is built
// from control-plane fields only, never from remote text.
type WriteResult struct {
	Status   WriteStatus `json:"status"`
	JobID    *domain.ID  `json:"job_id,omitempty"`
	PlanHash *string     `json:"plan_hash,omitempty"`
	Summary  string      `json:"summary"`
	Risk     string      `json:"risk"`
}
