package cli

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/assistant"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/textsafe"
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
	approval, problem := assistant.LoadApproval(ctx, a.api, id, a.assistantID, a.clientName)
	if problem != "" {
		a.note("%s", problem)
		return ""
	}
	if !a.interactive {
		a.note("job %s is waiting for approval; this input is not a terminal, so it cannot be approved here (use `sm approvals`)", id)
		return assistant.UnaskedOutcome(id, "the operator could not be asked here")
	}
	card, ok := assistant.NewCard(ctx, a.api, approval)
	if !ok {
		a.note("job %s is waiting for approval but its plan cannot be read; it was not offered (use `sm approvals --plan`)", id)
		return assistant.UnaskedOutcome(id, "its plan could not be shown to the operator")
	}
	a.card(card)
	return a.decide(ctx, approval)
}

func (a *approver) card(c assistant.Card) {
	approval, doc, job := c.Approval, c.Plan, c.Approval.Job
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
	_, _ = fmt.Fprintf(w, "\nAction: %s\n", doc.Action)
	for i, step := range doc.Steps {
		_, _ = fmt.Fprintf(w, "%d. %s\n", i+1, step)
	}
	if len(doc.Steps) == 0 {
		_, _ = fmt.Fprintln(w, "(no steps listed)")
	}
	_, _ = fmt.Fprintf(w, "\nImpact: %d target(s)\n", len(c.Targets)+c.More)
	for _, t := range c.Targets {
		_, _ = fmt.Fprintf(w, "  %s %s\n", t.Type, t.Name)
	}
	if c.More > 0 {
		_, _ = fmt.Fprintf(w, "  ... and %d more\n", c.More)
	}
	_, _ = fmt.Fprintf(w, "Risk: %s\n\n", doc.Risk)
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
			return assistant.PendingOutcome(id)
		}
		if !ok {
			_, _ = fmt.Fprintln(a.out)
			return assistant.PendingOutcome(id)
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
	text, outcome := assistant.Approve(ctx, a.api, approval)
	a.note("%s", text)
	return outcome
}

// reject needs a reason, as the API does. At the end of input the job stays pending.
func (a *approver) reject(ctx context.Context, approval wire.Approval) string {
	var reason string
	for reason == "" {
		_, _ = fmt.Fprint(a.out, "reason (required): ")
		answer, ok := nextLine(ctx, a.lines)
		if !ok {
			_, _ = fmt.Fprintln(a.out)
			return assistant.PendingOutcome(approval.Job.ID)
		}
		reason = textsafe.Line(strings.TrimSpace(answer))
	}
	text, outcome := assistant.Reject(ctx, a.api, approval, reason)
	a.note("%s", text)
	return outcome
}

func (a *approver) note(format string, args ...any) { note(a.out, format, args...) }
