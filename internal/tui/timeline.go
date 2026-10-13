package tui

import (
	"context"
	"slices"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

// Load keys of the deployment detail.
const (
	keyDeployment       loadKey = "deployment"
	keyDeploymentEvents loadKey = "deployment-events"
)

const unavailableDeploy = "this daemon does not serve deployment details"

// DeployAPI is what the deployment detail, the creation wizard and the
// rollback review need. Like AppsAPI it is optional: without it the screens
// say so instead of failing. *client.Client satisfies it.
type DeployAPI interface {
	GetDeployment(ctx context.Context, id domain.ID) (wire.Deployment, error)
	CreateDeployment(ctx context.Context, r wire.CreateDeploymentRequest) (wire.Deployment, error)
	RollbackDeployment(ctx context.Context, id domain.ID, r wire.RollbackRequest) (wire.Deployment, error)
}

// timelineScreen is one deployment: its summary, its steps in execution order
// and the audit events recorded against it, oldest first. It starts from the
// row the list already holds, so it never opens empty.
type timelineScreen struct {
	id     domain.ID
	d      wire.Deployment
	events []wire.Event
}

func (s *timelineScreen) open(d wire.Deployment) {
	*s = timelineScreen{id: d.ID, d: d}
}

func (s *timelineScreen) loadDetail(m *Model) tea.Cmd {
	api, ok := m.api.(DeployAPI)
	if !ok {
		return nil
	}
	id := s.id
	return load(m, keyDeployment,
		func(ctx context.Context) (wire.Deployment, error) { return api.GetDeployment(ctx, id) },
		func(_ *Model, d wire.Deployment) {
			if s.id == id {
				s.d = d
			}
		})
}

func (s *timelineScreen) loadEvents(m *Model) tea.Cmd {
	id := s.id
	return load(m, keyDeploymentEvents,
		func(ctx context.Context) (wire.Page[wire.Event], error) {
			return m.api.ListEvents(ctx, wire.EventQuery{
				PageQuery:    wire.PageQuery{Limit: wire.MaxLimit},
				ResourceType: domain.ResourceDeployment, ResourceID: id,
			})
		},
		func(_ *Model, page wire.Page[wire.Event]) {
			if s.id != id {
				return
			}
			events := slices.Clone(page.Items)
			slices.SortStableFunc(events, func(a, b wire.Event) int { return int(a.Seq - b.Seq) })
			s.events = events
		})
}

func (s *timelineScreen) body(m *Model, bw, bh int) []string {
	d := s.d
	lines := []string{
		m.heading("DEPLOYMENT " + shortID(s.id) + staleBadge(m, keyDeployment)),
		m.kv("state", stateWithReason(d), bw),
		m.kv("kind", safe(d.Kind), bw),
		m.kv("commit", safe(d.CommitSHA), bw),
		m.kv("plan", planOrPending(d.PlanHash), bw),
		m.kv("known good", yesNo(d.KnownGood), bw),
		m.kv("created", m.when(d.CreatedAt), bw),
		m.kv("finished", finishedOrRunning(m, d), bw),
	}
	if _, ok := m.api.(DeployAPI); !ok {
		lines = append(lines, "", " "+m.th.dim.Render(clip(unavailableDeploy, bw-2)))
	} else if st := m.state(keyDeployment); st.err != nil && !st.loaded {
		lines = append(lines, "", " "+m.th.bad.Render(clip("cannot load: "+describe(st.err), bw-2)))
	}
	lines = append(lines, s.imageLines(m, bw)...)
	lines = append(lines, s.stepLines(m, bw)...)
	return append(lines, s.eventLines(m, bw, bh-len(lines))...)
}

func (s *timelineScreen) imageLines(m *Model, bw int) []string {
	lines := make([]string, 0, len(s.d.Images))
	for _, img := range s.d.Images {
		lines = append(lines, m.kv("image", safe(img.Service)+" "+safe(img.Digest), bw))
	}
	return lines
}

func (s *timelineScreen) stepLines(m *Model, bw int) []string {
	lines := []string{"", m.heading("STEPS")}
	if len(s.d.Steps) == 0 {
		return append(lines, " "+m.th.dim.Render("no steps yet: they start once CI is verified and the plan is frozen"))
	}
	steps := slices.Clone(s.d.Steps)
	slices.SortStableFunc(steps, func(a, b wire.DeploymentStep) int { return a.Ordinal - b.Ordinal })
	for _, st := range steps {
		text := cell(stepGlyph(st.State)+" "+safe(st.Name), 24) + cell(safe(st.State), 11) + stepFailure(st)
		lines = append(lines, " "+m.styled(stepStyle(st.State), clip(" "+text, bw-2)))
	}
	return lines
}

// eventLines are the newest events that fit in room rows, oldest first.
func (s *timelineScreen) eventLines(m *Model, bw, room int) []string {
	if room < 3 {
		return nil
	}
	lines := []string{"", m.heading("EVENTS")}
	switch st := m.state(keyDeploymentEvents); {
	case len(s.events) == 0 && st.err != nil:
		return append(lines, " "+m.th.bad.Render(clip("cannot load events: "+describe(st.err), bw-2)))
	case len(s.events) == 0 && st.loaded:
		return append(lines, " "+m.th.dim.Render("no events recorded"))
	case len(s.events) == 0:
		return append(lines, " "+m.th.dim.Render("loading…"))
	}
	events := s.events[max(len(s.events)-(room-len(lines)), 0):]
	for _, e := range events {
		text := cell(m.when(e.Timestamp), 16) + cell(safe(e.Action), 26) + cell(safe(string(e.Result)), 9) + shortCorrelation(e.CorrelationID)
		lines = append(lines, " "+clip(" "+text, bw-2))
	}
	return lines
}

func stateWithReason(d wire.Deployment) string {
	if d.StateReason == "" {
		return safe(d.State)
	}
	if d.StateCause != "" {
		return safe(d.State + " (" + string(d.StateReason) + ": " + d.StateCause + ")")
	}
	return safe(d.State + " (" + string(d.StateReason) + ")")
}

func planOrPending(hash *string) string {
	if hash == nil {
		return "- (set once CI is verified and the plan is frozen)"
	}
	return shortHash(safe(*hash))
}

func finishedOrRunning(m *Model, d wire.Deployment) string {
	if d.FinishedAt == nil {
		return "not finished"
	}
	return m.when(*d.FinishedAt)
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func stepGlyph(state string) string {
	switch state {
	case "succeeded":
		return "✓"
	case "failed":
		return "✗"
	case "running":
		return "▶"
	case "skipped":
		return "-"
	}
	return "·"
}

func stepStyle(state string) string {
	switch state {
	case "failed":
		return "bad"
	case "running":
		return "warn"
	}
	return ""
}

func stepFailure(st wire.DeploymentStep) string {
	if st.Error == nil {
		return ""
	}
	parts := []string{string(st.Error.Code)}
	if st.Error.Reason != "" {
		parts = append(parts, string(st.Error.Reason))
	}
	text := strings.Join(parts, "/")
	if st.Error.Cause != "" {
		text += " (" + st.Error.Cause + ")"
	}
	return safe(text)
}

func shortCorrelation(id string) string {
	return safe(id[max(len(id)-8, 0):])
}
