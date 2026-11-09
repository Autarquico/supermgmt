package tui

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
)

func (m *Model) clock(t time.Time) string { return t.In(m.opts.Location).Format("15:04:05") }

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	value, suffix := float64(n), "KMGTPE"
	i := -1
	for value >= unit && i < len(suffix)-1 {
		value /= unit
		i++
	}
	if value >= 10 {
		return fmt.Sprintf("%.0f%c", value, suffix[i])
	}
	return fmt.Sprintf("%.1f%c", value, suffix[i])
}

func cpuText(r wire.ResourceUse) string { return fmt.Sprintf("cpu %.0f%%", r.CPUPercent) }

func memText(r wire.ResourceUse) string {
	mem := humanBytes(r.MemUsedBytes)
	if r.MemLimitBytes > 0 {
		mem += "/" + humanBytes(r.MemLimitBytes)
	}
	return "mem " + mem
}

func useText(r wire.ResourceUse) string { return cpuText(r) + "  " + memText(r) }

// sparkline draws values scaled between their own minimum and maximum.
func sparkline(values []uint64) string {
	const blocks = "▁▂▃▄▅▆▇█"
	if len(values) == 0 {
		return ""
	}
	lo, hi := slices.Min(values), slices.Max(values)
	runes := []rune(blocks)
	out := make([]rune, len(values))
	for i, v := range values {
		step := 0
		if hi > lo {
			step = int(float64(v-lo) * float64(len(runes)-1) / float64(hi-lo))
		}
		out[i] = runes[step]
	}
	return string(out)
}

// ---- overview ------------------------------------------------------------------------

func (m *Model) appGlyph(state string, stale bool) string {
	switch {
	case stale:
		return m.th.dim.Render("◌")
	case state == wire.AppRunning:
		return m.th.ok.Render("●")
	}
	return m.th.warn.Render("●")
}

func (m *Model) appLine(a wire.App, w int) string {
	name := cell(safe(a.Project)+fmt.Sprintf(" (%d)", len(a.Components)), 12)
	if a.Stale {
		return name + " " + safe(a.State) + " · stale, last seen " + m.when(a.ReadAt)
	}
	parts := []string{cell(safe(a.State), 8)}
	if a.RestartCount != nil {
		parts = append(parts, fmt.Sprintf("restarts %d", *a.RestartCount))
	}
	if a.Stats != nil {
		parts = append(parts, cpuText(*a.Stats), memText(*a.Stats))
	}
	if a.RecentErrors != nil && *a.RecentErrors > 0 {
		parts = append(parts, fmt.Sprintf("errors %d", *a.RecentErrors))
	}
	at := a.ReadAt
	if a.StatsAt != nil {
		at = *a.StatsAt
	}
	parts = append(parts, m.clock(at))
	return name + " " + strings.Join(parts, " ")
}

func (m *Model) appsBody(bw, bh int) []string {
	lines := []string{"", m.heading("Apps")}
	if _, ok := m.appsAPI(); !ok {
		return append(lines, "", m.th.dim.Render(" "+unavailableApps))
	}
	var rows []string
	cursorLine, sel := 0, 0
	st := m.state(keyApps)
	switch {
	case st.loaded:
		for _, n := range m.apps.nodes {
			rows = append(rows, "", m.appsNodeHeader(n, bw))
			rows = append(rows, m.appsProblem(n, bw)...)
			for _, a := range n.Apps {
				if sel == m.apps.cur {
					cursorLine = len(rows)
				}
				rows = append(rows, " "+m.marker(sel == m.apps.cur)+m.appGlyph(a.State, a.Stale)+" "+m.rowStyle(sel == m.apps.cur).Render(clip(m.appLine(a, bw), max(bw-6, 0))))
				sel++
			}
			if len(n.OtherServices) > 0 {
				rows = append(rows, "   "+m.th.dim.Render("other services"))
			}
			for _, o := range n.OtherServices {
				if sel == m.apps.cur {
					cursorLine = len(rows)
				}
				text := cell(safe(o.Name), 24) + " " + cell(safe(o.Kind), 18) + " " + cell(safe(o.Status), 10) + " " + safe(o.Health)
				rows = append(rows, " "+m.marker(sel == m.apps.cur)+m.th.dim.Render("·")+" "+m.rowStyle(sel == m.apps.cur).Render(clip(text, max(bw-6, 0))))
				sel++
			}
			if len(n.Apps) == 0 && len(n.OtherServices) == 0 && n.Problem == "" {
				rows = append(rows, "   "+m.th.dim.Render("no apps or services"))
			}
		}
		if len(m.apps.nodes) == 0 {
			rows = append(rows, "", m.th.dim.Render(" no node has apps you may read"))
		}
	default:
		for _, n := range m.nodes {
			rows = append(rows, "", " "+m.reachGlyph(n)+" "+m.th.title.Render(clip(safe(n.Name), bw-4)))
			rows = append(rows, "   "+m.th.dim.Render(m.emptyApps()))
		}
	}
	return append(lines, window(rows, cursorLine, max(bh-len(lines), 1))...)
}

func (m *Model) emptyApps() string {
	if st := m.state(keyApps); st.err != nil {
		return "apps could not be read"
	}
	return "reading apps…"
}

func (m *Model) appsNodeHeader(n wire.NodeApps, bw int) string {
	text := safe(n.Node)
	glyph := m.th.dim.Render("●")
	for _, node := range m.nodes {
		if node.ID == n.NodeID {
			glyph = m.reachGlyph(node)
			text += " · " + safe(node.Environment) + " · " + nodeState(node)
			break
		}
	}
	return " " + glyph + " " + m.th.title.Render(clip(text, bw-4))
}

// appsProblem says why the apps of a node were not read live, with what a person can do about it.
func (m *Model) appsProblem(n wire.NodeApps, bw int) []string {
	var text string
	switch n.Problem {
	case "":
		return nil
	case wire.AppsProblemDocker:
		text = "apps cannot be read: Docker is not installed or not accessible to SuperMgmt's user on this node. If it is installed, a person allows it with: " + safe(n.Hint)
	case wire.AppsProblemUnreachable:
		text = "the node cannot be reached: showing the last discovery, marked stale"
		if n.Hint != "" {
			text += ". " + safe(n.Hint)
		}
	default:
		text = "apps cannot be read: " + safe(n.Problem) + ". " + safe(n.Hint)
	}
	var out []string
	for _, l := range wrap(text, bw-4, "  ") {
		out = append(out, "   "+m.th.warn.Render(l))
	}
	return out
}

// ---- panel ---------------------------------------------------------------------------

func (m *Model) compGlyph(c wire.AppComponent) string {
	switch {
	case c.Health == "unhealthy":
		return m.th.bad.Render("●")
	case c.Status != "running":
		return m.th.warn.Render("●")
	}
	return m.th.ok.Render("●")
}

func (m *Model) appBody(bw, bh int) []string {
	a := m.apps.app
	head := fmt.Sprintf("%s on %s", safe(a.Project), safe(a.Node))
	if a.State != "" {
		head += " · " + safe(a.State)
	}
	lines := []string{"", m.heading(clip(head, bw-2))}
	if _, ok := m.appsAPI(); !ok {
		return append(lines, "", m.th.dim.Render(" "+unavailableApps))
	}
	if !m.state(keyApp).loaded {
		return append(lines, "", m.th.dim.Render(" "+m.emptyApps()))
	}
	lines = append(lines, m.kv("read", m.when(a.ReadAt), bw))
	if a.Stale {
		lines = append(lines, " "+m.th.warn.Render(clip("stale: the node cannot be read live; this is its last discovery", bw-2)))
	}
	if a.RestartCount != nil {
		lines = append(lines, m.kv("restarts", fmt.Sprint(*a.RestartCount), bw))
	}
	lines = append(lines, m.appStatsLines(bw)...)
	lines = append(lines, "", m.heading("Components"))
	for i, c := range a.Components {
		text := cell(safe(c.Name), 14) + " " + cell(safe(c.Status), 10) + " " + cell(safe(dashIfEmpty(c.Health)), 9) + " " + safe(c.Image)
		lines = append(lines, " "+m.marker(i == m.apps.comp)+m.compGlyph(c)+" "+m.rowStyle(i == m.apps.comp).Render(clip(text, max(bw-6, 0))))
	}
	if c, ok := m.selectedComponent(); ok {
		lines = append(lines, "", m.heading(clip(safe(c.Name), bw-2)))
		lines = append(lines, m.componentLines(c, bw)...)
	}
	return m.scrolled(lines, bh)
}

func (m *Model) appStatsLines(bw int) []string {
	s := m.apps.stats
	if s == nil {
		return nil
	}
	lines := []string{m.kv("now", useText(s.Total)+"  at "+m.clock(s.SampledAt), bw)}
	if len(m.apps.trend) < 2 {
		return append(lines, m.kv("memory trend", "collecting samples while this panel is open", bw))
	}
	return append(lines, m.kv("memory trend", fmt.Sprintf("%s  %d samples", sparkline(m.apps.trend), len(m.apps.trend)), bw))
}

func (m *Model) componentLines(c wire.AppComponent, bw int) []string {
	lines := []string{m.kv("image", safe(c.Image), bw), m.kv("status", safe(c.Status)+" · "+safe(dashIfEmpty(c.Health)), bw)}
	if c.StartedAt != "" {
		lines = append(lines, m.kv("started", safe(c.StartedAt), bw))
	}
	if c.RestartCount != nil {
		lines = append(lines, m.kv("restarts", fmt.Sprint(*c.RestartCount), bw))
	}
	if c.RecentErrors != nil && *c.RecentErrors > 0 {
		lines = append(lines, m.kv("errors", fmt.Sprintf("%d in the recent log", *c.RecentErrors), bw))
	}
	if s := m.apps.stats; s != nil {
		for _, u := range s.Components {
			if u.Name == c.Name {
				lines = append(lines, m.kv("use", useText(u.Use), bw))
			}
		}
	}
	lines = append(lines, m.listLines("ports", c.Ports, bw)...)
	var mounts []string
	for _, mt := range c.Mounts {
		access := "ro"
		if mt.ReadWrite {
			access = "rw"
		}
		source := mt.Name
		if source == "" {
			source = mt.Source
		}
		mounts = append(mounts, fmt.Sprintf("%s %s → %s (%s)", mt.Type, safe(source), safe(mt.Destination), access))
	}
	lines = append(lines, m.listLines("volumes", mounts, bw)...)
	if cfg := c.Config; cfg != nil {
		lines = append(lines, m.kv("restart", safe(dashIfEmpty(cfg.RestartPolicy)), bw))
		lines = append(lines, m.listLines("entrypoint", []string{strings.Join(cfg.Entrypoint, " ")}, bw)...)
		lines = append(lines, m.listLines("command", []string{strings.Join(cfg.Command, " ")}, bw)...)
		lines = append(lines, m.listLines("env", cfg.Env, bw)...)
		labels := make([]string, 0, len(cfg.Labels))
		for k, v := range cfg.Labels {
			labels = append(labels, k+"="+v)
		}
		slices.Sort(labels)
		lines = append(lines, m.listLines("labels", labels, bw)...)
	}
	return lines
}

// listLines shows items under one label, one per row; nothing when there are none.
func (m *Model) listLines(label string, items []string, bw int) []string {
	var lines []string
	for _, it := range items {
		if strings.TrimSpace(it) == "" {
			continue
		}
		name := ""
		if len(lines) == 0 {
			name = label
		}
		lines = append(lines, m.kv(name, safe(it), bw))
	}
	return lines
}

// scrolled shows the h rows of lines from the panel's scroll offset, and says when there is more.
func (m *Model) scrolled(lines []string, h int) []string {
	if len(lines) <= h {
		return lines
	}
	start := max(min(m.apps.scroll, len(lines)-(h-1)), 0)
	m.apps.scroll = start
	end := min(start+h-1, len(lines))
	return append(slices.Clone(lines[start:end]), " "+m.th.dim.Render(fmt.Sprintf("rows %d-%d of %d · pgup/pgdn scroll", start+1, end, len(lines))))
}

// ---- logs ----------------------------------------------------------------------------

func (m *Model) appLogsBody(bw int) []string {
	l := &m.apps.logs
	title := fmt.Sprintf("logs · %s · %s on %s", safe(l.component), safe(l.project), safe(m.apps.app.Node))
	lines := []string{m.heading(clip(title, bw-2)), " " + m.th.dim.Render(clip(m.appLogsStatus(), bw-2))}
	if _, ok := m.appsAPI(); !ok {
		return append(lines, m.th.dim.Render(" "+unavailableApps))
	}
	if len(l.lines) == 0 {
		empty := "loading…"
		if m.state(keyAppLogs).loaded {
			empty = "no log lines"
			if l.search != "" {
				empty = "no matches"
			}
		}
		return append(lines, m.th.dim.Render(" "+empty))
	}
	return append(lines, strings.Split(l.view.View(), "\n")...)
}

func (m *Model) appLogsStatus() string {
	l := &m.apps.logs
	if l.search != "" {
		text := fmt.Sprintf("search %q: %s", l.search, plural(len(l.lines), "match"))
		if w := l.window; w != nil {
			text += fmt.Sprintf(" · searched the last %s", plural(w.Lines, "line"))
			if w.From != nil && w.To != nil {
				text += fmt.Sprintf(" (%s to %s)", m.clock(*w.From), m.clock(*w.To))
			}
		}
		return text + " · esc clears"
	}
	text := "paused · f follows · / searches"
	if l.following {
		text = fmt.Sprintf("following · every %s · / searches", appLogsPoll)
	}
	if !l.readAt.IsZero() {
		text += " · read " + m.clock(l.readAt)
	}
	return text
}
