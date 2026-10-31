package mcp

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// Views are what tools return instead of wire DTOs (ADR-0031, "Output views
// by provenance"). Every field is in exactly one class:
//
//   - identifiers, enum states, hashes and timestamps are copied raw;
//   - operator-authored names are stripped to one line and capped;
//   - remote-discovered text sits under a Remote object flagged
//     untrusted_remote_output, sanitized, scrubbed and bounded.
//
// A field of a DTO that is not listed here never reaches a model.

// remoteMark opens every Remote object. Truncated says a bound cut something
// inside it.
type remoteMark struct {
	Untrusted bool `json:"untrusted_remote_output"`
	Truncated bool `json:"truncated"`
}

// remoteBuilder bounds remote fields and remembers whether any was cut.
type remoteBuilder struct{ cut bool }

func (b *remoteBuilder) scalar(raw string) string {
	text, cut := remoteScalar(raw)
	b.cut = b.cut || cut
	return text
}

func (b *remoteBuilder) object(m map[string]any) map[string]any {
	out, cut := remoteMap(m)
	b.cut = b.cut || cut
	if out == nil {
		return map[string]any{}
	}
	return out
}

func (b *remoteBuilder) mark() remoteMark { return remoteMark{Untrusted: true, Truncated: b.cut} }

// ---- nodes -------------------------------------------------------------------

type NodeView struct {
	ID              domain.ID              `json:"id"`
	Name            string                 `json:"name"`
	Kind            string                 `json:"kind"`
	Provider        string                 `json:"provider"`
	Environment     string                 `json:"environment"`
	Tags            []string               `json:"tags"`
	ManagementState domain.ManagementState `json:"management_state"`
	Reachability    domain.Reachability    `json:"reachability"`
	Stale           bool                   `json:"stale"`
	Metrics         *wire.Metrics          `json:"metrics"`
	LastSeenAt      *time.Time             `json:"last_seen_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
	Remote          NodeRemote             `json:"remote"`
}

// NodeRemote is what the node reported about itself.
type NodeRemote struct {
	remoteMark
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

func ViewNode(n wire.Node) NodeView {
	var b remoteBuilder
	remote := NodeRemote{OS: b.scalar(n.OS), Arch: b.scalar(n.Arch)}
	remote.remoteMark = b.mark()
	return NodeView{
		ID:              n.ID,
		Name:            operatorLine(n.Name),
		Kind:            n.Kind,
		Provider:        operatorLine(n.Provider),
		Environment:     operatorLine(n.Environment),
		Tags:            operatorLines(n.Tags),
		ManagementState: n.ManagementState,
		Reachability:    n.Reachability,
		Stale:           n.Stale,
		Metrics:         n.Metrics,
		LastSeenAt:      n.LastSeenAt,
		UpdatedAt:       n.UpdatedAt,
		Remote:          remote,
	}
}

// ---- services ----------------------------------------------------------------

type ServiceView struct {
	ID          domain.ID            `json:"id"`
	NodeID      domain.ID            `json:"node_id"`
	Node        string               `json:"node"`
	RuntimeType domain.RuntimeType   `json:"runtime_type"`
	Kind        domain.ServiceKind   `json:"kind"`
	Actions     []domain.ServiceVerb `json:"actions"`
	LastSeenAt  *time.Time           `json:"last_seen_at"`
	Remote      ServiceRemote        `json:"remote"`
}

// ServiceRemote is what the runtime reported. The service is addressed by
// ServiceView.ID, never by Name.
type ServiceRemote struct {
	remoteMark
	Name     string         `json:"name"`
	NativeID string         `json:"native_id"`
	Status   string         `json:"status"`
	Health   string         `json:"health"`
	Metadata map[string]any `json:"metadata"`
}

func ViewService(s wire.Service) ServiceView {
	var b remoteBuilder
	remote := ServiceRemote{
		Name:     b.scalar(s.Name),
		NativeID: b.scalar(s.NativeID),
		Status:   b.scalar(s.Status),
		Health:   b.scalar(s.Health),
		Metadata: b.object(s.Metadata),
	}
	remote.remoteMark = b.mark()
	return ServiceView{
		ID:          s.ID,
		NodeID:      s.NodeID,
		Node:        operatorLine(s.Node),
		RuntimeType: s.RuntimeType,
		Kind:        s.Kind,
		Actions:     orEmpty(s.Actions),
		LastSeenAt:  s.LastSeenAt,
		Remote:      remote,
	}
}

// ---- logs --------------------------------------------------------------------

type LogView struct {
	ServiceID   domain.ID `json:"service_id"`
	CollectedAt time.Time `json:"collected_at"`
	Log         Untrusted `json:"log"`
}

func ViewLogChunk(c wire.LogChunk) LogView {
	return LogView{
		ServiceID:   c.ServiceID,
		CollectedAt: c.CollectedAt,
		Log:         untrustedLines(c.Lines, c.Truncated),
	}
}

// ---- events ------------------------------------------------------------------

type EventView struct {
	EventID       domain.ID        `json:"event_id"`
	Seq           int64            `json:"seq"`
	Timestamp     time.Time        `json:"timestamp"`
	Actor         wire.Actor       `json:"actor"`
	Source        string           `json:"source"`
	Action        string           `json:"action"`
	Resource      wire.ResourceRef `json:"resource"`
	CorrelationID string           `json:"correlation_id"`
	Severity      domain.Severity  `json:"severity"`
	Result        domain.Result    `json:"result"`
	Remote        EventRemote      `json:"remote"`
}

// EventRemote is the event payload, which may carry remote output.
type EventRemote struct {
	remoteMark
	Data map[string]any `json:"data"`
}

func ViewEvent(e wire.Event) EventView {
	var b remoteBuilder
	remote := EventRemote{Data: b.object(e.Data)}
	remote.remoteMark = b.mark()
	return EventView{
		EventID:       e.EventID,
		Seq:           e.Seq,
		Timestamp:     e.Timestamp,
		Actor:         e.Actor,
		Source:        operatorLine(e.Source),
		Action:        operatorLine(e.Action),
		Resource:      e.Resource,
		CorrelationID: e.CorrelationID,
		Severity:      e.Severity,
		Result:        e.Result,
		Remote:        remote,
	}
}

// ---- apps --------------------------------------------------------------------

type AppView struct {
	ID              domain.ID       `json:"id"`
	Name            string          `json:"name"`
	DeployedService string          `json:"deployed_service"`
	ManifestPath    string          `json:"manifest_path"`
	Targets         []AppTargetView `json:"targets"`
	SpecRevision    int64           `json:"spec_revision"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

type AppTargetView struct {
	ID            domain.ID `json:"id"`
	EnvironmentID domain.ID `json:"environment_id"`
	Environment   string    `json:"environment"`
	NodeID        domain.ID `json:"node_id"`
}

func ViewApp(a wire.App) AppView {
	targets := make([]AppTargetView, len(a.Targets))
	for i, t := range a.Targets {
		targets[i] = AppTargetView{
			ID:            t.ID,
			EnvironmentID: t.EnvironmentID,
			Environment:   operatorLine(t.Environment),
			NodeID:        t.NodeID,
		}
	}
	return AppView{
		ID:              a.ID,
		Name:            operatorLine(a.Name),
		DeployedService: operatorLine(a.DeployedService),
		ManifestPath:    operatorLine(a.ManifestPath),
		Targets:         targets,
		SpecRevision:    a.SpecRevision,
		CreatedAt:       a.CreatedAt,
		UpdatedAt:       a.UpdatedAt,
	}
}

// ---- app routes --------------------------------------------------------------

type RouteView struct {
	ID          domain.ID   `json:"id"`
	AppTargetID domain.ID   `json:"app_target_id"`
	Hostname    string      `json:"hostname"`
	Service     string      `json:"service"`
	Port        int         `json:"port"`
	Access      string      `json:"access"`
	Phase       string      `json:"phase"`
	CreatedAt   time.Time   `json:"created_at"`
	Remote      RouteRemote `json:"remote"`
}

// RouteRemote is why a halted route is not moving, which Cloudflare's answers can shape.
type RouteRemote struct {
	remoteMark
	LastError string `json:"last_error"`
}

func ViewRoute(r wire.AppRoute) RouteView {
	var b remoteBuilder
	remote := RouteRemote{LastError: b.scalar(r.LastError)}
	remote.remoteMark = b.mark()
	return RouteView{
		ID:          r.ID,
		AppTargetID: r.AppTargetID,
		Hostname:    operatorLine(r.Hostname),
		Service:     operatorLine(r.Service),
		Port:        r.Port,
		Access:      r.Access,
		Phase:       r.Phase,
		CreatedAt:   r.CreatedAt,
		Remote:      remote,
	}
}

// ---- deployments -------------------------------------------------------------

type DeploymentView struct {
	ID                     domain.ID            `json:"id"`
	Kind                   string               `json:"kind"`
	AppID                  domain.ID            `json:"app_id"`
	AppTargetID            domain.ID            `json:"app_target_id"`
	EnvironmentID          domain.ID            `json:"environment_id"`
	NodeID                 domain.ID            `json:"node_id"`
	CommitSHA              string               `json:"commit_sha"`
	Images                 []DeploymentImage    `json:"images"`
	PlanID                 *domain.ID           `json:"plan_id"`
	PlanHash               *string              `json:"plan_hash"`
	JobID                  *domain.ID           `json:"job_id"`
	State                  string               `json:"state"`
	StateCode              smerr.Code           `json:"state_code"`
	StateReason            smerr.Reason         `json:"state_reason"`
	RequestedBy            domain.ID            `json:"requested_by"`
	PreviousDeploymentID   *domain.ID           `json:"previous_deployment_id"`
	RollbackOfDeploymentID *domain.ID           `json:"rollback_of_deployment_id"`
	KnownGood              bool                 `json:"known_good"`
	Steps                  []DeploymentStepView `json:"steps"`
	CreatedAt              time.Time            `json:"created_at"`
	UpdatedAt              time.Time            `json:"updated_at"`
	FinishedAt             *time.Time           `json:"finished_at"`
	Remote                 DeploymentRemote     `json:"remote"`
}

type DeploymentImage struct {
	Service string `json:"service"`
	Digest  string `json:"digest"`
}

// DeploymentRemote is the free-text cause of the deployment state.
type DeploymentRemote struct {
	remoteMark
	StateCause string `json:"state_cause"`
}

type DeploymentStepView struct {
	Ordinal     int           `json:"ordinal"`
	Name        string        `json:"name"`
	State       string        `json:"state"`
	Attempt     int           `json:"attempt"`
	StartedAt   *time.Time    `json:"started_at"`
	FinishedAt  *time.Time    `json:"finished_at"`
	ErrorCode   *smerr.Code   `json:"error_code"`
	ErrorReason *smerr.Reason `json:"error_reason"`
	Remote      StepRemote    `json:"remote"`
}

// StepRemote is what the step produced or failed with.
type StepRemote struct {
	remoteMark
	OutputRef  string `json:"output_ref"`
	ErrorCause string `json:"error_cause"`
	ErrorText  string `json:"error_message"`
}

func ViewDeployment(d wire.Deployment) DeploymentView {
	var b remoteBuilder
	remote := DeploymentRemote{StateCause: b.scalar(d.StateCause)}
	remote.remoteMark = b.mark()
	images := make([]DeploymentImage, len(d.Images))
	for i, img := range d.Images {
		images[i] = DeploymentImage{Service: operatorLine(img.Service), Digest: img.Digest}
	}
	steps := make([]DeploymentStepView, len(d.Steps))
	for i, s := range d.Steps {
		steps[i] = ViewDeploymentStep(s)
	}
	return DeploymentView{
		ID:                     d.ID,
		Kind:                   d.Kind,
		AppID:                  d.AppID,
		AppTargetID:            d.AppTargetID,
		EnvironmentID:          d.EnvironmentID,
		NodeID:                 d.NodeID,
		CommitSHA:              d.CommitSHA,
		Images:                 images,
		PlanID:                 d.PlanID,
		PlanHash:               d.PlanHash,
		JobID:                  d.JobID,
		State:                  d.State,
		StateCode:              d.StateCode,
		StateReason:            d.StateReason,
		RequestedBy:            d.RequestedBy,
		PreviousDeploymentID:   d.PreviousDeploymentID,
		RollbackOfDeploymentID: d.RollbackOfDeploymentID,
		KnownGood:              d.KnownGood,
		Steps:                  steps,
		CreatedAt:              d.CreatedAt,
		UpdatedAt:              d.UpdatedAt,
		FinishedAt:             d.FinishedAt,
		Remote:                 remote,
	}
}

func ViewDeploymentStep(s wire.DeploymentStep) DeploymentStepView {
	var b remoteBuilder
	remote := StepRemote{OutputRef: b.scalar(s.OutputRef)}
	view := DeploymentStepView{
		Ordinal:    s.Ordinal,
		Name:       operatorLine(s.Name),
		State:      s.State,
		Attempt:    s.Attempt,
		StartedAt:  s.StartedAt,
		FinishedAt: s.FinishedAt,
	}
	if e := s.Error; e != nil {
		view.ErrorCode, view.ErrorReason = &e.Code, &e.Reason
		remote.ErrorCause, remote.ErrorText = b.scalar(e.Cause), b.scalar(e.Message)
	}
	remote.remoteMark = b.mark()
	view.Remote = remote
	return view
}

// ---- plans and jobs ----------------------------------------------------------

// PlanView is a created plan: the hash to submit, the verdict to explain, the
// expiry, and an allowlisted view of the canonical plan so the model can say
// what it planned. Inputs and content hashes stay out; they are not for a model.
type PlanView struct {
	PlanID    domain.ID    `json:"plan_id"`
	Plan      PlanDocument `json:"plan"`
	PlanHash  string       `json:"plan_hash"`
	ExpiresAt time.Time    `json:"expires_at"`
	Policy    wire.Policy  `json:"policy"`
}

// PlanDocument is the control-plane part of the canonical plan. Parameters
// are caller-supplied free-form values, so they sit under Remote.
type PlanDocument struct {
	Version    int64               `json:"version"`
	Action     string              `json:"action"`
	Risk       domain.RiskClass    `json:"risk"`
	Targets    []PlanTargetView    `json:"targets"`
	SubActions []PlanSubActionView `json:"sub_actions"`
	Steps      []string            `json:"steps"`
	Remote     PlanRemote          `json:"remote"`
}

type PlanTargetView struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type PlanSubActionView struct {
	Action string         `json:"action"`
	Target PlanTargetView `json:"target"`
}

type PlanRemote struct {
	remoteMark
	Parameters map[string]any `json:"parameters"`
}

type planDocumentWire struct {
	Version    int64               `json:"version"`
	Action     string              `json:"action"`
	Risk       domain.RiskClass    `json:"risk"`
	Targets    []PlanTargetView    `json:"targets"`
	SubActions []PlanSubActionView `json:"sub_actions"`
	Steps      []string            `json:"steps"`
	Parameters map[string]any      `json:"parameters"`
}

func ViewCreatedPlan(p wire.CreatedPlan) (PlanView, error) {
	var doc planDocumentWire
	if len(p.Plan) > 0 {
		if err := json.Unmarshal(p.Plan, &doc); err != nil {
			return PlanView{}, fmt.Errorf("decode plan document: %w", err)
		}
	}
	var b remoteBuilder
	remote := PlanRemote{Parameters: b.object(doc.Parameters)}
	remote.remoteMark = b.mark()
	steps := make([]string, len(doc.Steps))
	for i, step := range doc.Steps {
		steps[i] = operatorLine(step)
	}
	return PlanView{
		PlanID: p.PlanID,
		Plan: PlanDocument{
			Version:    doc.Version,
			Action:     operatorLine(doc.Action),
			Risk:       doc.Risk,
			Targets:    orEmpty(doc.Targets),
			SubActions: orEmpty(doc.SubActions),
			Steps:      steps,
			Remote:     remote,
		},
		PlanHash:  p.PlanHash,
		ExpiresAt: p.ExpiresAt,
		Policy:    p.Policy,
	}, nil
}

func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

type SubmissionView struct {
	Job    JobView     `json:"job"`
	Policy wire.Policy `json:"policy"`
}

type JobView struct {
	ID          domain.ID        `json:"id"`
	Type        string           `json:"type"`
	Resource    wire.ResourceRef `json:"resource"`
	State       domain.JobState  `json:"state"`
	Risk        domain.RiskClass `json:"risk"`
	PlanID      *domain.ID       `json:"plan_id"`
	PlanHash    string           `json:"plan_hash"`
	Attempts    int              `json:"attempts"`
	MaxAttempts int              `json:"max_attempts"`
	CreatedAt   time.Time        `json:"created_at"`
	StartedAt   *time.Time       `json:"started_at"`
	FinishedAt  *time.Time       `json:"finished_at"`
	ErrorCode   *smerr.Code      `json:"error_code"`
	ErrorReason *smerr.Reason    `json:"error_reason"`
	Remote      JobRemote        `json:"remote"`
}

// JobRemote is the failure text of a job, which may quote remote output.
type JobRemote struct {
	remoteMark
	ErrorMessage string `json:"error_message"`
}

func ViewSubmission(s wire.Submission) SubmissionView {
	return SubmissionView{Job: viewJob(s.Job), Policy: s.Policy}
}

func viewJob(j wire.Job) JobView {
	var b remoteBuilder
	view := JobView{
		ID:          j.ID,
		Type:        j.Type,
		Resource:    j.Resource,
		State:       j.State,
		Risk:        j.Risk,
		PlanID:      j.PlanID,
		PlanHash:    j.PlanHash,
		Attempts:    j.Attempts,
		MaxAttempts: j.MaxAttempts,
		CreatedAt:   j.CreatedAt,
		StartedAt:   j.StartedAt,
		FinishedAt:  j.FinishedAt,
	}
	remote := JobRemote{}
	if e := j.Error; e != nil {
		view.ErrorCode, view.ErrorReason = &e.Code, &e.Reason
		remote.ErrorMessage = b.scalar(e.Message)
	}
	remote.remoteMark = b.mark()
	view.Remote = remote
	return view
}

func operatorLines(raw []string) []string {
	out := make([]string, len(raw))
	for i, s := range raw {
		out[i] = operatorLine(s)
	}
	return out
}
