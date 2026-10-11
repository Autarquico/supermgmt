package tui

import (
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/textsafe"
)

// chrome is the number of rows the frame uses besides the body: top border,
// separator, status line, key line and bottom border (spec §22.1).
const chrome = 5

func (m *Model) View() tea.View {
	v := tea.NewView(m.render())
	v.AltScreen = true
	v.WindowTitle = "SuperMgmt"
	return v
}

func (m *Model) bodySize() (w, h int) { return m.width - 2, m.height - chrome }

func (m *Model) render() string {
	if m.width < minWidth || m.height < minHeight {
		return fmt.Sprintf("terminal too small: SuperMgmt needs at least %dx%d", minWidth, minHeight)
	}
	bw, bh := m.bodySize()
	body := m.body(bw, bh)
	rows := make([]string, 0, m.height)
	rows = append(rows, m.topBorder(bw))
	for _, line := range fitLines(body, bw, bh) {
		rows = append(rows, "│"+line+"│")
	}
	rows = append(rows,
		"├"+strings.Repeat("─", bw)+"┤",
		"│"+padTo(cutStyled(m.statusLine(bw), bw), bw)+"│",
		"│"+padTo(cutStyled(m.keyLine(bw), bw), bw)+"│",
		"└"+strings.Repeat("─", bw)+"┘")
	return strings.Join(rows, "\n")
}

func (m *Model) topBorder(bw int) string {
	left := " SuperMgmt · " + screenTitles[m.screen] + " "
	right := " " + m.summary() + " "
	right = clip(right, max(bw-lipgloss.Width(left)-2, 0))
	fill := max(bw-lipgloss.Width(left)-lipgloss.Width(right), 0)
	return "┌" + m.th.title.Render(left) + strings.Repeat("─", fill) + m.th.dim.Render(right) + "┐"
}

// summary is the header counts: nodes, online, warnings, approvals (spec §22.1).
func (m *Model) summary() string {
	if !m.state(keyNodes).loaded {
		return "loading…"
	}
	online, warnings := 0, 0
	for _, n := range m.nodes {
		if n.Reachability == domain.ReachabilityReachable {
			online++
		}
		if n.Reachability == domain.ReachabilityUnreachable || n.Stale {
			warnings++
		}
	}
	parts := []string{
		plural(len(m.nodes), "node"), fmt.Sprintf("%d online", online), plural(warnings, "warning"),
	}
	if len(m.approvals) > 0 {
		parts = append(parts, plural(len(m.approvals), "approval"))
	}
	return strings.Join(parts, " · ")
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

func (m *Model) body(bw, bh int) []string {
	if m.confirm != nil {
		return m.confirmBody(bw)
	}
	switch m.screen {
	case screenDashboard:
		return m.dashboardBody(bw)
	case screenResources:
		return m.resourcesBody(bw, bh)
	case screenNode:
		return m.nodeBody(bw, bh)
	case screenServices:
		return m.servicesBody(bw, bh)
	case screenService:
		return m.serviceBody(bw)
	case screenLogs:
		return m.logsBody(bw)
	case screenJobs:
		return m.jobsBody(bw, bh)
	case screenJob:
		return m.jobBody(bw)
	case screenApprovals:
		return m.approvalsBody(bw, bh)
	case screenEvents:
		return m.eventsBody(bw, bh)
	case screenProviders:
		return m.providersBody(bw, bh)
	case screenSettings:
		return m.settingsBody(bw)
	case screenHelp:
		return m.helpBody(bw)
	}
	return nil
}

func (m *Model) confirmBody(bw int) []string {
	c := m.confirm
	lines := []string{"", " " + m.th.title.Render(clip(c.title, bw-2)), ""}
	for _, w := range c.warnings {
		lines = append(lines, " "+m.th.warn.Render(clip("! "+w, bw-2)))
	}
	if c.planning {
		return append(lines, " "+m.th.dim.Render("building the plan…"))
	}
	for _, l := range c.lines {
		lines = append(lines, " "+clip(l, bw-2))
	}
	if c.blocked != "" {
		lines = append(lines, "", " "+m.th.bad.Render(clip("cannot submit: "+c.blocked, bw-2)))
	}
	return lines
}

// statusLine shows the prompt, else the notice, else the load state.
func (m *Model) statusLine(bw int) string {
	switch {
	case m.prompt != nil:
		return " " + m.input.View()
	case m.notice.text != "":
		style := m.th.info
		if m.notice.isErr {
			style = m.th.bad
		}
		return " " + style.Render(clip(m.notice.text, bw-2))
	}
	return " " + m.th.dim.Render(clip(m.badge(), bw-2))
}

// badge reports loading, stale or failed data for the current screen, with
// the correlation ID of the failed call (spec §22.5).
func (m *Model) badge() string {
	var loading bool
	for _, key := range m.screenKeys() {
		st := m.state(key)
		switch {
		case st.err != nil && st.loaded:
			return "stale · " + describe(st.err)
		case st.err != nil:
			return "error · " + describe(st.err)
		case st.loading && !st.loaded:
			loading = true
		}
	}
	if loading {
		return "loading…"
	}
	return ""
}

func (m *Model) screenKeys() []loadKey {
	loaders := m.screenLoaders()
	keys := make([]loadKey, len(loaders))
	for i, l := range loaders {
		keys[i] = l.key
	}
	return keys
}

func (m *Model) keyLine(bw int) string {
	text := m.keyHints()
	switch {
	case m.confirm != nil:
		text = "y confirm  n/esc cancel"
	case m.prompt != nil:
		text = m.prompt.hint
	}
	return " " + m.th.dim.Render(clip(text, bw-2))
}

func (m *Model) keyHints() string {
	const global = "/ command  ? help  q quit"
	switch m.screen {
	case screenDashboard:
		return "1-7 screens  r refresh  " + global
	case screenResources:
		return "j/k move  enter detail  v services  s ssh  d docker  " + global
	case screenNode:
		return "v services  s ssh  d docker  p probe  esc back  " + global
	case screenServices:
		return "j/k move  enter open  l logs  esc back  " + global
	case screenService:
		return "l logs  " + m.serviceVerbHints() + "esc back  " + global
	case screenLogs:
		return "j/k scroll  G end  r refresh  esc back  " + global
	case screenJobs:
		return "j/k move  enter detail  c cancel  esc back  " + global
	case screenJob:
		return "c cancel  esc back  " + global
	case screenHelp:
		return "esc back  q quit"
	case screenApprovals:
		return "j/k move  A approve  R reject  esc back  " + global
	case screenEvents, screenProviders, screenSettings:
		return "r refresh  esc back  " + global
	}
	return "esc back  q quit"
}

func (m *Model) serviceVerbHints() string {
	var b strings.Builder
	for _, v := range []struct {
		key  string
		verb domain.ServiceVerb
	}{{"R", domain.VerbRestart}, {"S", domain.VerbStart}, {"X", domain.VerbStop}} {
		if hasVerb(m.service.Actions, v.verb) {
			fmt.Fprintf(&b, "%s %s  ", v.key, v.verb)
		}
	}
	return b.String()
}

// ---- shared formatting ------------------------------------------------------

func (m *Model) when(t time.Time) string { return t.In(m.opts.Location).Format("01-02 15:04:05") }

func (m *Model) whenPtr(t *time.Time) string {
	if t == nil {
		return "never"
	}
	return m.when(*t)
}

func shortID(id domain.ID) string {
	s := string(id)
	return s[max(len(s)-8, 0):]
}

func shortHash(h string) string {
	return h[:min(len(h), 12)]
}

func safe(s string) string { return textsafe.Line(s) }

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// marker is the selection cursor: a glyph, so selection survives without color.
func (m *Model) marker(selected bool) string {
	if selected {
		return m.th.selected.Render("▸ ")
	}
	return "  "
}

func (m *Model) rowStyle(selected bool) lipgloss.Style {
	if selected {
		return m.th.selected
	}
	return lipgloss.NewStyle()
}

func (m *Model) reachGlyph(n wire.Node) string {
	if n.Reachability == domain.ReachabilityReachable {
		return m.th.ok.Render("●")
	}
	if n.Reachability == domain.ReachabilityUnreachable {
		return m.th.bad.Render("○")
	}
	return m.th.dim.Render("◌")
}

func nodeState(n wire.Node) string {
	parts := []string{string(n.Reachability)}
	if n.Stale {
		parts = append(parts, "stale")
	}
	return strings.Join(parts, " · ")
}

// kv renders "label  value" with a dim label.
func (m *Model) kv(label, value string, bw int) string {
	const labelW = 14
	return " " + m.th.dim.Render(padTo(label, labelW)) + clip(value, max(bw-labelW-2, 0))
}

func (m *Model) heading(text string) string { return " " + m.th.title.Render(text) }

// window returns the h lines around cursor so the cursor stays visible.
func window(lines []string, cursor, h int) []string {
	if len(lines) <= h {
		return lines
	}
	start := max(cursor-h+1, 0)
	return lines[start:min(start+h, len(lines))]
}

func percent(used, total int64) string {
	if total <= 0 {
		return "-"
	}
	return fmt.Sprintf("%d%%", used*100/total)
}

func metricsLine(mt *wire.Metrics) string {
	if mt == nil {
		return "no metrics yet"
	}
	return fmt.Sprintf("CPU %.0f%%   RAM %s   DISK %s",
		mt.CPUPercent, percent(mt.MemoryUsedBytes, mt.MemoryTotalBytes), percent(mt.DiskUsedBytes, mt.DiskTotalBytes))
}
