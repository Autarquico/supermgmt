package tui

import (
	"context"
	"slices"

	tea "charm.land/bubbletea/v2"

	"github.com/autarquico/supermgmt/internal/api/wire"
)

// deploymentsScreen is the Deployments list, newest first.
type deploymentsScreen struct {
	items []wire.Deployment
	cur   int
}

func (s *deploymentsScreen) load(m *Model) tea.Cmd {
	api, ok := m.api.(AppsAPI)
	if !ok {
		return nil
	}
	return load(m, keyDeployments,
		func(ctx context.Context) (wire.Page[wire.Deployment], error) {
			return api.ListDeployments(ctx, wire.PageQuery{Limit: 100})
		},
		func(_ *Model, page wire.Page[wire.Deployment]) {
			items := slices.Clone(page.Items)
			slices.SortStableFunc(items, func(a, b wire.Deployment) int { return b.CreatedAt.Compare(a.CreatedAt) })
			s.cur = keepCursor(s.items, s.cur, items, func(d wire.Deployment) string { return string(d.ID) })
			s.items = items
		})
}

func (s *deploymentsScreen) key(key tea.KeyPressMsg) tea.Cmd {
	moveCursor(&s.cur, len(s.items), key)
	return nil
}

// body names each deployment's app and environment from apps, which the
// deployment rows do not carry.
func (s *deploymentsScreen) body(m *Model, apps []wire.App, bw, bh int) []string {
	lines := []string{
		m.heading("DEPLOYMENTS" + staleBadge(m, keyDeployments)),
		" " + m.th.dim.Render(clip("  "+cell("ID", 9)+cell("KIND", 9)+cell("APP / ENV", 20)+cell("STATE", 14)+cell("COMMIT", 8)+"CREATED", bw-2)),
	}
	rows := make([]string, 0, len(s.items))
	for i, d := range s.items {
		selected := i == s.cur
		text := cell(shortID(d.ID), 9) + cell(safe(d.Kind), 9) + cell(appTargetLabel(apps, d), 20) +
			cell(safe(d.State), 14) + cell(d.CommitSHA[:min(len(d.CommitSHA), 7)], 8) + m.when(d.CreatedAt)
		rows = append(rows, " "+m.marker(selected)+m.styled(deploymentStyle(d, selected), clip(text, bw-4)))
	}
	if len(rows) == 0 {
		rows = append(rows, m.th.dim.Render(" "+clip(emptyList(m, keyDeployments, "no deployments yet: sm deploy"), bw-2)))
	}
	return append(lines, window(rows, s.cur, max(bh-len(lines), 1))...)
}

func deploymentStyle(d wire.Deployment, selected bool) string {
	switch {
	case selected:
		return "sel"
	case slices.Contains([]string{"failed", "rolled_back", "rollback_failed"}, d.State):
		return "bad"
	case slices.Contains([]string{"waiting_ci", "awaiting_approval", "interrupted", "rolling_back"}, d.State):
		return "warn"
	}
	return ""
}

// appTargetLabel is "app / environment"; while the apps list has not loaded or
// no longer holds the target it falls back to the short target id.
func appTargetLabel(apps []wire.App, d wire.Deployment) string {
	for _, a := range apps {
		if a.ID != d.AppID {
			continue
		}
		for _, t := range a.Targets {
			if t.ID == d.AppTargetID {
				return safe(a.Name + " / " + t.Environment)
			}
		}
		return safe(a.Name) + " / " + shortID(d.AppTargetID)
	}
	return shortID(d.AppTargetID)
}
