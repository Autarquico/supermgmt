package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/assistant"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/textsafe"
)

const (
	maxApprovalPages = 20
	maxCardTargets   = 10
)

// approver turns the session's approval signals into decisions of the human.
// A signal is only a pointer to a job: nothing the model said is displayed or
// used; the job and its plan are read from the API and must be the
// assistant client's own.
type approver struct {
	api         assistantAPI
	out         io.Writer
	lines       <-chan string
	assistantID domain.ID
	clientName  string
	instance    string
	interactive bool
	discard     func() // drops what the terminal holds of what was typed so far
}

// settle shows a card for each signal that passes the checks, asks the
// operator, and returns the plain turn that tells the model what happened
// ("" when there is nothing to tell).
func (a *approver) settle(ctx context.Context, signals []assistant.Signal) string {
	var outcomes []string
	for _, s := range signals {
		if ctx.Err() != nil {
			break
		}
		if outcome := a.settleOne(ctx, s.JobID); outcome != "" {
			outcomes = append(outcomes, outcome)
		}
	}
	return strings.Join(outcomes, "\n")
}

func (a *approver) settleOne(ctx context.Context, id domain.ID) string {
	approval, problem := a.load(ctx, id)
	if problem != "" {
		a.note("%s", problem)
		return ""
	}
	if !a.interactive {
		a.note("job %s is waiting for approval; this input is not a terminal, so it cannot be approved here (use `sm approvals`)", id)
		return unaskedOutcome(id, "the operator could not be asked here")
	}
	doc, ok := decodeCardPlan(approval.Plan)
	if !ok {
		a.note("job %s is waiting for approval but its plan cannot be read; it was not offered (use `sm approvals --plan`)", id)
		return unaskedOutcome(id, "its plan could not be shown to the operator")
	}
	a.card(ctx, approval, doc)
	return a.decide(ctx, approval)
}

// load reads the job through the human client and refuses anything that is not
// a job the assistant client itself submitted and that still awaits approval.
func (a *approver) load(ctx context.Context, id domain.ID) (wire.Approval, string) {
	detail, err := a.api.GetJob(ctx, id)
	if err != nil {
		return wire.Approval{}, fmt.Sprintf("the assistant mentioned job %s, which could not be read: %s", id, textsafe.Line(err.Error()))
	}
	job := detail.Job
	if job.ID != id || job.State != domain.JobAwaitingApproval || job.ActorID != a.assistantID {
		return wire.Approval{}, fmt.Sprintf("the assistant mentioned job %s, which is not a job of the %s client waiting for approval; nothing is offered for it", id, textsafe.Line(a.clientName))
	}
	cursor := ""
	for range maxApprovalPages {
		page, err := a.api.ListApprovals(ctx, wire.PageQuery{Cursor: cursor})
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

type cardPlan struct {
	Action  string   `json:"action"`
	Risk    string   `json:"risk"`
	Steps   []string `json:"steps"`
	Targets []struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	} `json:"targets"`
}

func decodeCardPlan(raw json.RawMessage) (cardPlan, bool) {
	var doc cardPlan
	return doc, json.Unmarshal(raw, &doc) == nil && doc.Action != ""
}

func (a *approver) card(ctx context.Context, approval wire.Approval, doc cardPlan) {
	job := approval.Job
	w := a.out
	_, _ = fmt.Fprintf(w, "\n=== approval requested by the assistant ===\n")
	_ = fields(w, [][2]string{
		{"instance", textsafe.Line(a.instance)},
		{"requested by", fmt.Sprintf("%s (MCP client)", textsafe.Line(a.clientName))},
		{"submitted", formatTime(job.CreatedAt)},
		{"job", string(job.ID)},
		{"plan hash", job.PlanHash},
		{"approvals", fmt.Sprintf("%d/%d, expires %s", approval.Approvals, approval.Quorum, formatTime(approval.ExpiresAt))},
		{"environments", textsafe.Line(strings.Join(approval.Environments, ", "))},
	})
	_, _ = fmt.Fprintf(w, "\nAction: %s\n", textsafe.Line(doc.Action))
	for i, step := range doc.Steps {
		_, _ = fmt.Fprintf(w, "%d. %s\n", i+1, textsafe.Line(step))
	}
	if len(doc.Steps) == 0 {
		_, _ = fmt.Fprintln(w, "(no steps listed)")
	}
	_, _ = fmt.Fprintf(w, "\nImpact: %d target(s)\n", len(doc.Targets))
	for i, t := range doc.Targets {
		if i == maxCardTargets {
			_, _ = fmt.Fprintf(w, "  ... and %d more\n", len(doc.Targets)-maxCardTargets)
			break
		}
		_, _ = fmt.Fprintf(w, "  %s %s\n", textsafe.Line(t.Type), textsafe.Line(a.targetName(ctx, t.Type, t.ID)))
	}
	_, _ = fmt.Fprintf(w, "Risk: %s\n\n", textsafe.Line(doc.Risk))
}

// targetName is the resource as the operator knows it, read through their own
// connection, with its id kept for the record; the bare id when it cannot be read.
func (a *approver) targetName(ctx context.Context, kind, id string) string {
	switch kind {
	case string(domain.ResourceService):
		if svc, err := a.api.GetService(ctx, domain.ID(id)); err == nil && svc.Name != "" {
			if svc.Node != "" {
				return fmt.Sprintf("%s@%s (%s)", oneRow(svc.Name), oneRow(svc.Node), id)
			}
			return fmt.Sprintf("%s (%s)", oneRow(svc.Name), id)
		}
	case string(domain.ResourceNode):
		if node, err := a.api.GetNode(ctx, domain.ID(id), false); err == nil && node.Name != "" {
			return fmt.Sprintf("%s (%s)", oneRow(node.Name), id)
		}
	}
	return id
}

const maxNameRunes = 64

// oneRow keeps a name reported by a remote system to a short run of words, so
// it cannot pad the card row or push other text off the screen.
func oneRow(name string) string {
	name = strings.Join(strings.Fields(name), " ")
	if r := []rune(name); len(r) > maxNameRunes {
		name = string(r[:maxNameRunes]) + "..."
	}
	return name
}

// decide asks until the operator picks; there is no default. Only a line typed
// after the card is on the screen can answer it.
func (a *approver) decide(ctx context.Context, approval wire.Approval) string {
	a.dropTypedAhead()
	id := approval.Job.ID
	for {
		_, _ = fmt.Fprint(a.out, "approve, reject or leave pending? [approve/reject/leave] ")
		answer, ok := nextLine(ctx, a.lines)
		switch strings.ToLower(strings.TrimSpace(answer)) {
		case "approve":
			return a.approve(ctx, approval)
		case "reject":
			return a.reject(ctx, approval)
		case "leave":
			a.note("job %s stays pending until %s; decide it later with `sm approvals`", id, formatTime(approval.ExpiresAt))
			return pendingOutcome(id)
		}
		if !ok {
			_, _ = fmt.Fprintln(a.out)
			return pendingOutcome(id)
		}
	}
}

// dropTypedAhead discards input that arrived before the card was shown: what
// the terminal still holds, and the lines already read from it.
func (a *approver) dropTypedAhead() {
	if a.discard != nil {
		a.discard()
	}
	for {
		select {
		case _, ok := <-a.lines:
			if !ok {
				return
			}
		default:
			return
		}
	}
}

// approve binds the decision to the hash the API reported for the job.
func (a *approver) approve(ctx context.Context, approval wire.Approval) string {
	id := approval.Job.ID
	job, err := a.api.Approve(ctx, id, wire.DecisionRequest{PlanHash: approval.Job.PlanHash})
	if err != nil {
		a.note("job %s could not be approved: %s", id, textsafe.Line(err.Error()))
		return failedOutcome(id)
	}
	if job.State == domain.JobAwaitingApproval {
		recorded := fmt.Sprintf("%d/%d", approval.Approvals+1, approval.Quorum)
		a.note("your approval of job %s is recorded (%s); it needs more approvals before it runs", id, recorded)
		return fmt.Sprintf("[sm] job %s: the operator's approval was recorded (%s); it still needs more approvals and has not been queued", id, recorded)
	}
	a.note("job %s approved", id)
	return fmt.Sprintf("[sm] job %s approved by the operator", id)
}

// reject needs a reason, as the API does. At the end of input the job stays pending.
func (a *approver) reject(ctx context.Context, approval wire.Approval) string {
	id := approval.Job.ID
	var reason string
	for reason == "" {
		_, _ = fmt.Fprint(a.out, "reason (required): ")
		answer, ok := nextLine(ctx, a.lines)
		if !ok {
			_, _ = fmt.Fprintln(a.out)
			return pendingOutcome(id)
		}
		reason = textsafe.Line(strings.TrimSpace(answer))
	}
	if _, err := a.api.Reject(ctx, id, wire.DecisionRequest{PlanHash: approval.Job.PlanHash, Reason: reason}); err != nil {
		a.note("job %s could not be rejected: %s", id, textsafe.Line(err.Error()))
		return failedOutcome(id)
	}
	a.note("job %s rejected", id)
	return fmt.Sprintf("[sm] job %s rejected by the operator: %s", id, reason)
}

func pendingOutcome(id domain.ID) string {
	return fmt.Sprintf("[sm] job %s left pending by the operator", id)
}

func failedOutcome(id domain.ID) string {
	return fmt.Sprintf("[sm] job %s: the operator's decision could not be recorded; it is still waiting for approval", id)
}

func unaskedOutcome(id domain.ID, why string) string {
	return fmt.Sprintf("[sm] job %s is waiting for approval; %s, so it is still pending", id, why)
}

func (a *approver) note(format string, args ...any) { note(a.out, format, args...) }
