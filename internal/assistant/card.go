package assistant

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/textsafe"
)

const (
	maxApprovalPages = 20
	maxCardTargets   = 10
	maxNameRunes     = 64
)

// Reader is the human client's read side of an approval card.
type Reader interface {
	GetJob(ctx context.Context, id domain.ID) (wire.JobDetail, error)
	ListApprovals(ctx context.Context, q wire.PageQuery) (wire.Page[wire.Approval], error)
	GetService(ctx context.Context, id domain.ID) (wire.Service, error)
	GetNode(ctx context.Context, id domain.ID, focus bool) (wire.Node, error)
}

// Decider is the human client's side that records a decision.
type Decider interface {
	Approve(ctx context.Context, job domain.ID, r wire.DecisionRequest) (wire.Job, error)
	Reject(ctx context.Context, job domain.ID, r wire.DecisionRequest) (wire.Job, error)
}

// Conversation is what a front end needs of a session; *Session is the real one.
type Conversation interface {
	Start(ctx context.Context) error
	Send(text string) error
	Events() <-chan Event
	Close() error
}

var _ Conversation = (*Session)(nil)

// Identity is the registered MCP client a conversation acts as, on one instance.
type Identity struct {
	ClientName string
	ClientID   domain.ID // the identity that owns the jobs the assistant submits
	Instance   string    // "the local daemon" or "profile <name>"
	Auth       Auth
}

// Launcher is how a front end that does not know registration or token
// conventions gets a conversation. Check verifies everything that can be
// refused up front (claude present, client registered and usable, token in
// place) and fails with the text to show the operator. Start launches a
// session; it is only called after Check succeeded, and the caller owns Close.
type Launcher struct {
	Check func(ctx context.Context) (Identity, error)
	Start func(ctx context.Context) (Conversation, error)
}

// CardPlan is the part of a job's plan the operator is shown.
type CardPlan struct {
	Action  string   `json:"action"`
	Risk    string   `json:"risk"`
	Steps   []string `json:"steps"`
	Targets []struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	} `json:"targets"`
}

// CardTarget is one resource of the plan as the operator knows it.
type CardTarget struct{ Type, Name string }

// Card is everything an approval prompt shows. Every text in it is one sanitised line.
type Card struct {
	Approval wire.Approval
	Plan     CardPlan
	Targets  []CardTarget // at most 10, named through the operator's own connection
	More     int          // targets beyond Targets
}

// LoadApproval reads the job through the human client and refuses anything that
// is not a job the assistant client itself submitted and that still awaits
// approval. The problem is the note to show; it is "" when the approval is returned.
func LoadApproval(ctx context.Context, r Reader, id, assistantID domain.ID, clientName string) (wire.Approval, string) {
	detail, err := r.GetJob(ctx, id)
	if err != nil {
		return wire.Approval{}, fmt.Sprintf("the assistant mentioned job %s, which could not be read: %s", id, textsafe.Line(err.Error()))
	}
	job := detail.Job
	if job.ID != id || job.State != domain.JobAwaitingApproval || job.ActorID != assistantID {
		return wire.Approval{}, fmt.Sprintf("the assistant mentioned job %s, which is not a job of the %s client waiting for approval; nothing is offered for it", id, textsafe.Line(clientName))
	}
	cursor := ""
	for range maxApprovalPages {
		page, err := r.ListApprovals(ctx, wire.PageQuery{Cursor: cursor})
		if err != nil {
			return wire.Approval{}, fmt.Sprintf("the approvals could not be read: %s", textsafe.Line(err.Error()))
		}
		for _, approval := range page.Items {
			if approval.Job.ID == id {
				return approval, ""
			}
		}
		if cursor = page.NextCursor; cursor == "" {
			break
		}
	}
	return wire.Approval{}, fmt.Sprintf("job %s is not in your approvals; nothing is offered for it", id)
}

// NewCard decodes the plan of approval and names its targets; it makes up to
// ten API calls, so a front end runs it off its render path. It is false when
// the plan cannot be read.
func NewCard(ctx context.Context, r Reader, approval wire.Approval) (Card, bool) {
	var doc CardPlan
	if json.Unmarshal(approval.Plan, &doc) != nil || doc.Action == "" {
		return Card{}, false
	}
	card := Card{Approval: approval}
	card.Plan.Action, card.Plan.Risk = textsafe.Line(doc.Action), textsafe.Line(doc.Risk)
	for _, step := range doc.Steps {
		card.Plan.Steps = append(card.Plan.Steps, textsafe.Line(step))
	}
	for i, t := range doc.Targets {
		if i == maxCardTargets {
			card.More = len(doc.Targets) - maxCardTargets
			break
		}
		card.Targets = append(card.Targets, CardTarget{Type: textsafe.Line(t.Type), Name: textsafe.Line(targetName(ctx, r, t.Type, t.ID))})
	}
	return card, true
}

// targetName is the resource as the operator knows it, read through their own
// connection, with its id kept for the record; the bare id when it cannot be read.
func targetName(ctx context.Context, r Reader, kind, id string) string {
	switch kind {
	case string(domain.ResourceService):
		if svc, err := r.GetService(ctx, domain.ID(id)); err == nil && svc.Name != "" {
			if svc.Node != "" {
				return fmt.Sprintf("%s@%s (%s)", oneRow(svc.Name), oneRow(svc.Node), id)
			}
			return fmt.Sprintf("%s (%s)", oneRow(svc.Name), id)
		}
	case string(domain.ResourceNode):
		if node, err := r.GetNode(ctx, domain.ID(id), false); err == nil && node.Name != "" {
			return fmt.Sprintf("%s (%s)", oneRow(node.Name), id)
		}
	}
	return id
}

// oneRow keeps a name reported by a remote system to a short run of words, so
// it cannot pad the card row or push other text off the screen.
func oneRow(name string) string {
	name = strings.Join(strings.Fields(name), " ")
	if r := []rune(name); len(r) > maxNameRunes {
		name = string(r[:maxNameRunes]) + "..."
	}
	return name
}

// Approve binds the decision to the hash the API reported for the job. It
// returns the note for the operator and the plain turn that tells the model.
func Approve(ctx context.Context, d Decider, approval wire.Approval) (note, outcome string) {
	id := approval.Job.ID
	job, err := d.Approve(ctx, id, wire.DecisionRequest{PlanHash: approval.Job.PlanHash})
	if err != nil {
		return fmt.Sprintf("job %s could not be approved: %s", id, textsafe.Line(err.Error())), FailedOutcome(id)
	}
	if job.State == domain.JobAwaitingApproval {
		recorded := fmt.Sprintf("%d/%d", approval.Approvals+1, approval.Quorum)
		return fmt.Sprintf("your approval of job %s is recorded (%s); it needs more approvals before it runs", id, recorded),
			fmt.Sprintf("[sm] job %s: the operator's approval was recorded (%s); it still needs more approvals and has not been queued", id, recorded)
	}
	return fmt.Sprintf("job %s approved", id), fmt.Sprintf("[sm] job %s approved by the operator", id)
}

// Reject records a rejection; the API requires a non-empty reason, which the
// caller checks.
func Reject(ctx context.Context, d Decider, approval wire.Approval, reason string) (note, outcome string) {
	id := approval.Job.ID
	reason = textsafe.Line(strings.TrimSpace(reason))
	if _, err := d.Reject(ctx, id, wire.DecisionRequest{PlanHash: approval.Job.PlanHash, Reason: reason}); err != nil {
		return fmt.Sprintf("job %s could not be rejected: %s", id, textsafe.Line(err.Error())), FailedOutcome(id)
	}
	return fmt.Sprintf("job %s rejected", id), fmt.Sprintf("[sm] job %s rejected by the operator: %s", id, reason)
}

// PendingOutcome tells the model the operator left the job undecided.
func PendingOutcome(id domain.ID) string {
	return fmt.Sprintf("[sm] job %s left pending by the operator", id)
}

// FailedOutcome tells the model a decision was not recorded.
func FailedOutcome(id domain.ID) string {
	return fmt.Sprintf("[sm] job %s: the operator's decision could not be recorded; it is still waiting for approval", id)
}

// UnaskedOutcome tells the model the operator was never asked, and why.
func UnaskedOutcome(id domain.ID, why string) string {
	return fmt.Sprintf("[sm] job %s is waiting for approval; %s, so it is still pending", id, why)
}
