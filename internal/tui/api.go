// Package tui is the Bubble Tea terminal UI (spec §22). It is an API client
// only: everything it shows or does goes through API, which *client.Client
// implements, so the UI never touches the database or a node directly.
package tui

import (
	"context"
	"os/exec"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

// API is what the TUI needs from the daemon. Every call is issued from a
// tea.Cmd with its own timeout, never from Update or View.
type API interface {
	Me(ctx context.Context) (wire.Me, error)

	ListNodes(ctx context.Context, q wire.NodeQuery) (wire.Page[wire.Node], error)
	// GetNode with focus refreshes the node's focus lease, so the daemon
	// refreshes it at the focused interval while it is on screen.
	GetNode(ctx context.Context, id domain.ID, focus bool) (wire.Node, error)
	ProbeNode(ctx context.Context, id domain.ID) (wire.Submission, error)

	ListServices(ctx context.Context, node domain.ID, q wire.PageQuery) (wire.Page[wire.Service], error)
	GetService(ctx context.Context, id domain.ID) (wire.Service, error)
	ServiceLogs(ctx context.Context, id domain.ID, q wire.LogQuery) (wire.LogChunk, error)
	ServiceAction(ctx context.Context, id domain.ID, verb domain.ServiceVerb) (wire.Submission, error)

	CreatePlan(ctx context.Context, r wire.CreatePlanRequest) (wire.CreatedPlan, error)
	SubmitPlan(ctx context.Context, plan domain.ID, planHash string) (wire.Submission, error)

	ListApprovals(ctx context.Context, q wire.PageQuery) (wire.Page[wire.Approval], error)
	Approve(ctx context.Context, job domain.ID, r wire.DecisionRequest) (wire.Job, error)
	Reject(ctx context.Context, job domain.ID, r wire.DecisionRequest) (wire.Job, error)

	ListJobs(ctx context.Context, q wire.JobQuery) (wire.Page[wire.Job], error)
	GetJob(ctx context.Context, id domain.ID) (wire.JobDetail, error)
	CancelJob(ctx context.Context, id domain.ID, planHash string) (wire.Job, error)
	ResolveJob(ctx context.Context, id domain.ID, r wire.ResolveRequest) (wire.Job, error)

	ListEvents(ctx context.Context, q wire.EventQuery) (wire.Page[wire.Event], error)

	// OpenSession issues an audited interactive session (tool is a wire.Tool)
	// and returns the isolated OpenSSH command for the handoff.
	OpenSession(ctx context.Context, node domain.ID, tool string) (Handoff, error)
}

// Handoff is an interactive session ready to take over the terminal. The TUI
// runs Cmd with tea.ExecProcess, which suspends the program and restores the
// terminal on return (spec §17.1). Done must be called exactly once, on every
// path: with the exit code when Cmd ran, or with the launch error when it
// could not start. It posts the session end and removes the temporary
// known_hosts.
type Handoff struct {
	Cmd  *exec.Cmd
	Done func(exitCode int, launchErr error)
}
