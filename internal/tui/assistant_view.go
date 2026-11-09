package tui

import (
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"

	"github.com/autarquico/supermgmt/internal/assistant"
)

// entryKind decides how a transcript line is marked and styled. Model text
// always carries the "| " marker on every row, and nothing of ours does, so a
// fake note or card inside the model's text is visibly inside the marker.
type entryKind int

const (
	kindUser entryKind = iota
	kindModel
	kindNote
	kindFail
	kindCardHead
	kindCard
	kindDim
)

// entry is one logical line of the transcript: no newline, no tab, bounded.
type entry struct {
	kind         entryKind
	prefix, text string
}

const (
	userPrefix  = "> "
	notePrefix  = "[sm] "
	modelPrefix = "| "
	labelWidth  = 14
)

// ingest makes text safe for layout: tabs become spaces, which lipgloss does
// not count as eight cells, and one line never exceeds maxLineRunes.
func ingest(s string) string {
	s = expandTabs(s)
	if r := []rune(s); len(r) > maxLineRunes {
		return string(r[:maxLineRunes]) + " [cut]"
	}
	return s
}

func expandTabs(s string) string { return strings.ReplaceAll(s, "\t", "    ") }

// lines turns text into entries, the first behind prefix and the rest behind
// the same prefix when repeat is set, else behind blanks of its width.
func lines(kind entryKind, text, prefix string, repeat bool) []entry {
	var out []entry
	for i, line := range strings.Split(text, "\n") {
		p := prefix
		if i > 0 && !repeat {
			p = strings.Repeat(" ", lipgloss.Width(prefix))
		}
		out = append(out, entry{kind: kind, prefix: p, text: ingest(safe(line))})
	}
	return out
}

func userEntries(text string) []entry  { return lines(kindUser, text, userPrefix, false) }
func modelEntries(text string) []entry { return lines(kindModel, text, modelPrefix, true) }

func noteEntries(kind entryKind, text string) []entry { return lines(kind, text, notePrefix, false) }

func (m *Model) entryStyles(k entryKind) (prefix, text lipgloss.Style) {
	plain := lipgloss.NewStyle()
	switch k {
	case kindUser:
		return m.th.accent, m.th.accent
	case kindModel, kindCard:
		return m.th.dim, plain
	case kindNote:
		return m.th.info, plain
	case kindFail:
		return m.th.bad, m.th.bad
	case kindCardHead:
		return m.th.warn.Bold(true), m.th.warn.Bold(true)
	case kindDim:
		return m.th.dim, m.th.dim
	}
	return m.th.dim, m.th.dim
}

// entryRows wraps one entry to the body width. Rows are styled here, once, so
// View never wraps anything.
func (m *Model) entryRows(e entry, bw int) []string {
	prefixStyle, textStyle := m.entryStyles(e.kind)
	pw := lipgloss.Width(e.prefix)
	parts := wrap(e.text, max(bw-2-pw, 1), "")
	rows := make([]string, len(parts))
	for i, part := range parts {
		lead := strings.Repeat(" ", pw)
		if i == 0 || e.kind == kindModel {
			lead = e.prefix
		}
		rows[i] = " " + prefixStyle.Render(lead) + textStyle.Render(part)
	}
	return rows
}

func (m *Model) allRows(bw int) []string {
	var rows []string
	for _, e := range m.asst.entries {
		rows = append(rows, m.entryRows(e, bw)...)
	}
	return rows
}

// appendEntries adds lines to the ring and wraps only them, and it follows the
// bottom unless the operator scrolled up. It returns the rows it added.
func (m *Model) appendEntries(es ...entry) int {
	a := &m.asst
	follow := a.vp.AtBottom()
	a.entries = append(a.entries, es...)
	bw, _ := m.bodySize()
	var fresh []string
	for _, e := range es {
		fresh = append(fresh, m.entryRows(e, bw)...)
	}
	if len(a.entries) > maxTranscript+trimChunk {
		drop := len(a.entries) - maxTranscript
		if a.card != nil {
			drop = min(drop, a.cardStart) // the open card is read whole
		}
		dropped := 0
		for _, e := range a.entries[:drop] {
			dropped += len(m.entryRows(e, bw))
		}
		a.entries = a.entries[drop:]
		a.cardStart -= drop
		a.rows = m.allRows(bw)
		offset := a.vp.YOffset() - dropped // read before the shorter content clamps it
		a.vp.SetContentLines(a.rows)
		if !follow { // keep what the operator is reading where it is
			a.vp.SetYOffset(max(offset, 0))
		}
	} else {
		a.rows = append(a.rows, fresh...)
	}
	a.vp.SetContentLines(a.rows)
	if follow {
		a.vp.GotoBottom()
	}
	return len(fresh)
}

// sizeAssistant fits the input and the transcript to the body, and wraps the
// transcript again when the width changed.
func (m *Model) sizeAssistant() {
	a := &m.asst
	bw, bh := m.bodySize()
	follow := a.vp.AtBottom()
	a.vp.SetWidth(max(bw, 1))
	a.vp.SetHeight(max(bh-2, 1))
	a.ask.SetWidth(max(bw-len(a.ask.Prompt)-2, 10))
	if bw != a.rowsW {
		a.rowsW = bw
		a.rows = m.allRows(bw)
		a.vp.SetContentLines(a.rows)
	}
	if follow {
		a.vp.GotoBottom()
	}
}

// cardEntries is the CLI's card, line for line, from what the API reported.
// Its lines are never cut: the operator decides on all of them.
func (m *Model) cardEntries(c assistant.Card) []entry {
	a := &m.asst
	approval, job := c.Approval, c.Approval.Job
	kv := func(label, value string) entry {
		return entry{kind: kindCard, prefix: padTo(label, labelWidth), text: expandTabs(safe(value))}
	}
	out := []entry{
		{}, // a blank row sets the card apart
		{kind: kindCardHead, text: "=== approval requested by the assistant ==="},
		kv("instance", a.ident.Instance),
		kv("requested by", a.ident.ClientName+" (MCP client)"),
		kv("submitted", m.when(job.CreatedAt)),
		kv("job", string(job.ID)),
		kv("plan hash", job.PlanHash),
		kv("approvals", fmt.Sprintf("%d/%d, expires %s", approval.Approvals, approval.Quorum, m.when(approval.ExpiresAt))),
		kv("environments", strings.Join(approval.Environments, ", ")),
		{},
		{kind: kindCard, prefix: "Action: ", text: expandTabs(c.Plan.Action)},
	}
	for i, step := range c.Plan.Steps {
		out = append(out, entry{kind: kindCard, prefix: fmt.Sprintf("%d. ", i+1), text: expandTabs(step)})
	}
	if len(c.Plan.Steps) == 0 {
		out = append(out, entry{kind: kindCard, text: "(no steps listed)"})
	}
	out = append(out, entry{}, entry{kind: kindCard, text: fmt.Sprintf("Impact: %d target(s)", len(c.Targets)+c.More)})
	for _, t := range c.Targets {
		out = append(out, entry{kind: kindCard, prefix: "  ", text: expandTabs(t.Type + " " + t.Name)})
	}
	if c.More > 0 {
		out = append(out, entry{kind: kindCard, prefix: "  ", text: fmt.Sprintf("... and %d more", c.More)})
	}
	return append(out, entry{kind: kindCard, text: "Risk: " + expandTabs(c.Plan.Risk)}, entry{})
}

// ---- screen -----------------------------------------------------------------

func (m *Model) assistantBody(bw, _ int) []string {
	a := &m.asst
	input := " " + a.ask.View()
	if a.card != nil {
		input = " " + m.th.dim.Render(clip("decide the approval above; your draft is kept", bw-2))
	}
	lines := []string{m.heading(clip(m.assistantHeading(), bw-2))}
	lines = append(lines, strings.Split(a.vp.View(), "\n")...)
	return append(lines, input)
}

func (m *Model) assistantHeading() string {
	a := &m.asst
	state := "not started: your first message starts it"
	switch {
	case a.unavailable || a.lastCheckErr != "":
		state = "not available: see below"
	case a.card != nil:
		state = "an approval is waiting"
	case a.working:
		state = "working…"
	case a.conv != nil:
		state = "ready"
	case a.ident.ClientName != "":
		state = "ended: your next message starts a new session"
	}
	text := "assistant · " + state
	if !a.vp.AtBottom() {
		text += " · scrolled (pgdn)"
	}
	return text
}

func (m *Model) assistantHints() string {
	c := m.asst.card
	switch {
	case c == nil && m.asst.working && m.asst.conv != nil:
		return "ctrl+x stop the session  pgup/pgdn scroll  esc back  ctrl+c quit"
	case c == nil:
		return "enter send  pgup/pgdn scroll  esc back  ctrl+c quit"
	case c.step == stepDeciding:
		return "recording the decision…"
	case c.step == stepConfirmApprove && !c.armed:
		return "wait, then y to approve  (any key goes back)"
	case !c.armed:
		return "reading the card…  j/k scroll  (a key restarts the wait)"
	case c.step == stepConfirmApprove:
		return "y approve  any other key goes back"
	case !m.asst.vp.AtBottom():
		return "A approve  R reject  esc leave pending  j/k g/G scroll  (more below)"
	}
	return "A approve  R reject  esc leave pending  j/k scroll  ctrl+c quit"
}

func (m *Model) cardWaitingElsewhere() bool {
	return m.asst.card != nil && m.screen != screenAssistant
}

func (m *Model) confirmingApproval() bool {
	c := m.asst.card
	return c != nil && c.step == stepConfirmApprove
}

// assistantStatus is the question or notice the status line shows for the assistant.
func (m *Model) assistantStatus() string {
	a := &m.asst
	switch {
	case m.confirmingApproval() && !a.card.armed:
		return fmt.Sprintf("approve job %s with plan hash %s ?", a.card.card.Approval.Job.ID, shortHash(a.card.card.Approval.Job.PlanHash))
	case m.confirmingApproval():
		return fmt.Sprintf("y/n: approve job %s with plan hash %s", a.card.card.Approval.Job.ID, shortHash(a.card.card.Approval.Job.PlanHash))
	case m.cardWaitingElsewhere():
		return "assistant: an approval is waiting (8)"
	}
	return ""
}
