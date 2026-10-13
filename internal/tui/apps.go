package tui

import (
	"context"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/autarquico/supermgmt/internal/api/wire"
)

// Load keys of the M4 lists.
const (
	keyApps        loadKey = "apps"
	keyDeployments loadKey = "deployments"
)

const unavailableApps = "this daemon does not serve apps and deployments"

// appsScreen is the Applications list (spec §22). Its data arrives through
// the shared load machinery, so a slow listing never blocks Update or View.
type appsScreen struct {
	items []wire.App
	cur   int
}

func (s *appsScreen) load(m *Model) tea.Cmd {
	api, ok := m.api.(AppsAPI)
	if !ok {
		return nil
	}
	return load(m, keyApps,
		func(ctx context.Context) (wire.Page[wire.App], error) {
			return api.ListApps(ctx, wire.PageQuery{Limit: wire.MaxLimit})
		},
		func(_ *Model, page wire.Page[wire.App]) {
			s.cur = keepCursor(s.items, s.cur, page.Items, func(a wire.App) string { return string(a.ID) })
			s.items = page.Items
		})
}

func (s *appsScreen) key(key tea.KeyPressMsg) tea.Cmd {
	moveCursor(&s.cur, len(s.items), key)
	return nil
}

func (s *appsScreen) body(m *Model, bw, bh int) []string {
	lines := []string{
		m.heading("APPLICATIONS" + staleBadge(m, keyApps)),
		" " + m.th.dim.Render(clip("  "+cell("NAME", 20)+cell("REPOSITORY", 26)+"TARGETS", bw-2)),
	}
	rows := make([]string, 0, len(s.items))
	for i, a := range s.items {
		selected := i == s.cur
		text := cell(safe(a.Name), 20) + cell(repositoryName(a.Repository), 26) + targetEnvironments(a.Targets)
		rows = append(rows, " "+m.marker(selected)+m.rowStyle(selected).Render(clip(text, bw-4)))
	}
	if len(rows) == 0 {
		rows = append(rows, m.th.dim.Render(" "+clip(emptyList(m, keyApps, "no apps yet: sm apps create"), bw-2)))
	}
	return append(lines, window(rows, s.cur, max(bh-len(lines), 1))...)
}

func repositoryName(r *wire.Repository) string {
	if r == nil {
		return "-"
	}
	return safe(r.Owner + "/" + r.Name)
}

func targetEnvironments(targets []wire.AppTarget) string {
	if len(targets) == 0 {
		return "none"
	}
	names := make([]string, len(targets))
	for i, t := range targets {
		names[i] = safe(t.Environment)
	}
	return strings.Join(names, ", ")
}

// staleBadge marks a list whose last reload failed but still shows older data.
func staleBadge(m *Model, key loadKey) string {
	if st := m.state(key); st.err != nil && st.loaded {
		return " [stale]"
	}
	return ""
}

// emptyList says why a list has no rows: unavailable, failed, loading or empty.
func emptyList(m *Model, key loadKey, none string) string {
	if _, ok := m.api.(AppsAPI); !ok {
		return unavailableApps
	}
	st := m.state(key)
	switch {
	case st.err != nil:
		return "cannot load: " + describe(st.err)
	case st.loaded:
		return none
	}
	return "loading…"
}
