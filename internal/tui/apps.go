package tui

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"

	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/textsafe"
)

const (
	// appsReadTimeout bounds the reads that make the node answer live (an inspect of every container, a docker
	// stats sample, a log read): longer than an ordinary call, which only reads the daemon's own database.
	appsReadTimeout = 20 * time.Second
	// appsRefresh is how often the overview asks the nodes again by itself; r asks at once.
	appsRefresh = 30 * time.Second
	// appLogsPoll is how often a followed log asks for what came after its cursor.
	appLogsPoll = 2 * time.Second

	trendSamples  = 40   // memory samples kept while a panel is open; nothing is stored anywhere
	maxAppLogRows = 2000 // lines kept by a log view; the oldest go first

	unavailableApps = "this daemon does not serve apps"
)

// appsState is the apps screens: the overview, the panel of one app and the logs of one of its components.
// Only Update and View touch it.
type appsState struct {
	nodes []wire.NodeApps // what the overview shows, by node name
	cur   int

	node    domain.ID
	project string
	app     wire.App
	comp    int // selected component
	scroll  int
	stats   *wire.AppStats
	trend   []uint64 // memory used by the whole app, oldest first
	trendAt time.Time

	logs appLogs
}

// appLogs is the log view of one component: the lines read so far, and where a follow stands.
type appLogs struct {
	node      domain.ID
	project   string
	component string

	lines  []logLine
	cursor string // opaque: handed back to the daemon to read what came after
	rev    int    // changes whenever the lines are replaced, so a poll that raced the replacement is dropped
	seq    int    // identifies the follow session that may still poll

	following bool
	capped    bool // a search had more matches than the daemon returns
	search    string
	window    *wire.LogWindow
	readAt    time.Time

	view viewport.Model
}

// logLine is one line of the view, or the mark of lines that were not delivered.
type logLine struct {
	text string
	gap  bool
}

// AppsAPI is the live read of apps, which *client.Client implements. Like NodeRoutesAPI it is optional: without
// it the screens say the daemon does not serve apps.
type AppsAPI interface {
	ListApps(ctx context.Context, q wire.AppsQuery) (wire.Page[wire.NodeApps], error)
	GetNodeApp(ctx context.Context, node domain.ID, project string, q wire.AppsQuery) (wire.App, error)
	NodeAppStats(ctx context.Context, node domain.ID, project string) (wire.AppStats, error)
	NodeAppLogs(ctx context.Context, node domain.ID, project string, q wire.AppLogQuery) (wire.AppLogs, error)
}

// Messages of the app screens that are not load replies.
type (
	appLogsTickMsg   struct{ seq int }
	appLogsPolledMsg struct {
		seq, rev int
		logs     wire.AppLogs
		err      error
	}
	componentServiceMsg struct {
		verb    domain.ServiceVerb
		project string
		service wire.Service
		err     error
	}
)

func (m *Model) appsAPI() (AppsAPI, bool) {
	api, ok := m.api.(AppsAPI)
	return api, ok
}

func (m *Model) appsTimeout() time.Duration { return max(m.opts.Timeout, appsReadTimeout) }

// ---- overview ----------------------------------------------------------------------

// appRow is one selectable row of the overview: an app or a service that belongs to none.
type appRow struct {
	node  int
	app   int // index in the node's apps, or -1
	other int // index in the node's other services, or -1
}

func (s *appsState) rows() []appRow {
	var rows []appRow
	for i, n := range s.nodes {
		for j := range n.Apps {
			rows = append(rows, appRow{node: i, app: j, other: -1})
		}
		for j := range n.OtherServices {
			rows = append(rows, appRow{node: i, app: -1, other: j})
		}
	}
	return rows
}

func (s *appsState) rowID(r appRow) string {
	n := s.nodes[r.node]
	if r.app >= 0 {
		return string(n.NodeID) + "/" + n.Apps[r.app].Project
	}
	return string(n.NodeID) + "/service/" + string(n.OtherServices[r.other].ServiceID)
}

// loadApps asks for every node's apps with their resource use and error counts. It is the one read that makes
// every node answer live, so the screen paints first and this follows.
func (m *Model) loadApps() tea.Cmd {
	api, ok := m.appsAPI()
	if !ok {
		return nil
	}
	return loadWithin(m, keyApps, m.appsTimeout(),
		func(ctx context.Context) (wire.Page[wire.NodeApps], error) {
			return api.ListApps(ctx, wire.AppsQuery{Stats: true, Errors: true})
		},
		func(m *Model, page wire.Page[wire.NodeApps]) {
			s := &m.apps
			var curID string
			if rows := s.rows(); s.cur >= 0 && s.cur < len(rows) {
				curID = s.rowID(rows[s.cur])
			}
			nodes := slices.Clone(page.Items)
			slices.SortStableFunc(nodes, func(a, b wire.NodeApps) int { return strings.Compare(a.Node, b.Node) })
			for _, n := range nodes {
				slices.SortStableFunc(n.Apps, func(a, b wire.App) int { return strings.Compare(a.Project, b.Project) })
			}
			s.nodes = nodes
			rows := s.rows()
			s.cur = max(min(s.cur, len(rows)-1), 0)
			if i := slices.IndexFunc(rows, func(r appRow) bool { return s.rowID(r) == curID }); i >= 0 {
				s.cur = i
			}
		})
}

func (m *Model) appsKey(key tea.KeyPressMsg) tea.Cmd {
	rows := m.apps.rows()
	moveCursor(&m.apps.cur, len(rows), key)
	if key.String() != "enter" || m.apps.cur >= len(rows) {
		return nil
	}
	r := rows[m.apps.cur]
	n := m.apps.nodes[r.node]
	if r.app >= 0 {
		return m.openApp(n.NodeID, n.Node, n.Apps[r.app].Project)
	}
	o := n.OtherServices[r.other]
	m.node = n.NodeID
	return m.openService(wire.Service{ID: o.ServiceID, NodeID: n.NodeID, Node: n.Node, Name: o.Name, Status: o.Status, Health: o.Health}, screenService)
}

// ---- panel -------------------------------------------------------------------------

func (m *Model) openApp(node domain.ID, nodeName, project string) tea.Cmd {
	m.apps.node, m.apps.project = node, project
	m.apps.app = wire.App{Project: project, NodeID: node, Node: nodeName}
	m.apps.comp, m.apps.scroll = 0, 0
	m.apps.stats, m.apps.trend, m.apps.trendAt = nil, nil, time.Time{}
	m.state(keyApp).loaded, m.state(keyAppStats).loaded = false, false
	return m.push(screenApp)
}

func (m *Model) loadApp() tea.Cmd {
	api, ok := m.appsAPI()
	if !ok {
		return nil
	}
	node, project := m.apps.node, m.apps.project
	return loadWithin(m, keyApp, m.appsTimeout(),
		func(ctx context.Context) (wire.App, error) {
			return api.GetNodeApp(ctx, node, project, wire.AppsQuery{Errors: true})
		},
		func(m *Model, a wire.App) {
			if m.apps.node != node || m.apps.project != project {
				return
			}
			m.apps.comp = keepCursor(m.apps.app.Components, m.apps.comp, a.Components, func(c wire.AppComponent) string { return c.Name })
			m.apps.app = a
		})
}

// loadAppStats takes one sample. The trend is the samples taken while the panel is open: kept in memory, never
// written anywhere, gone with the panel.
func (m *Model) loadAppStats() tea.Cmd {
	api, ok := m.appsAPI()
	if !ok {
		return nil
	}
	node, project := m.apps.node, m.apps.project
	return loadWithin(m, keyAppStats, m.appsTimeout(),
		func(ctx context.Context) (wire.AppStats, error) { return api.NodeAppStats(ctx, node, project) },
		func(m *Model, s wire.AppStats) {
			if m.apps.node != node || m.apps.project != project {
				return
			}
			m.apps.stats = &s
			if s.SampledAt.After(m.apps.trendAt) { // a single-flight sample may answer two reads
				m.apps.trendAt = s.SampledAt
				m.apps.trend = append(m.apps.trend, s.Total.MemUsedBytes)
				if over := len(m.apps.trend) - trendSamples; over > 0 {
					m.apps.trend = m.apps.trend[over:]
				}
			}
		})
}

func (m *Model) selectedComponent() (wire.AppComponent, bool) {
	cs := m.apps.app.Components
	if m.apps.comp < 0 || m.apps.comp >= len(cs) {
		return wire.AppComponent{}, false
	}
	return cs[m.apps.comp], true
}

func (m *Model) appKey(key tea.KeyPressMsg) tea.Cmd {
	before := m.apps.comp
	moveCursor(&m.apps.comp, len(m.apps.app.Components), key)
	if m.apps.comp != before {
		m.apps.scroll = 0
	}
	switch key.String() {
	case "pgdown":
		m.apps.scroll += max(m.height-chrome-2, 1)
	case "pgup":
		m.apps.scroll = max(m.apps.scroll-max(m.height-chrome-2, 1), 0)
	case "l", "enter":
		if c, ok := m.selectedComponent(); ok {
			return m.openAppLogs(c.Name)
		}
	case "R":
		return m.componentAction(domain.VerbRestart)
	case "S":
		return m.componentAction(domain.VerbStart)
	case "X":
		return m.componentAction(domain.VerbStop)
	}
	return nil
}

// componentAction is the service action flow on the service behind the selected component: the same plan, the
// same policy and approval, the same audit. There is no action for a whole app.
func (m *Model) componentAction(verb domain.ServiceVerb) tea.Cmd {
	c, ok := m.selectedComponent()
	switch {
	case !ok:
		return nil
	case m.apps.app.Stale:
		m.notice = notice{text: fmt.Sprintf("cannot %s %s: %s", verb, safe(c.Name), m.appUnreadable()), isErr: true}
		return nil
	case c.ServiceID == "":
		m.notice = notice{text: fmt.Sprintf("cannot %s %s: discovery has no service for it yet (r refreshes)", verb, safe(c.Name)), isErr: true}
		return nil
	}
	api, id, project, timeout, parent := m.api, c.ServiceID, m.apps.project, m.opts.Timeout, m.ctx
	return func() tea.Msg {
		s, err := within(parent, timeout, func(ctx context.Context) (wire.Service, error) { return api.GetService(ctx, id) })
		return componentServiceMsg{verb: verb, project: project, service: s, err: err}
	}
}

// appUnreadable is why the open app is only its last discovery, with the hint the overview gives.
func (m *Model) appUnreadable() string {
	if text := problemText(m.apps.app.Problem, m.apps.app.Hint); text != "" {
		return text
	}
	return "the node cannot be read live, this is its last discovery"
}

func (m *Model) onComponentService(msg componentServiceMsg) tea.Cmd {
	if m.screen != screenApp || m.apps.project != msg.project {
		return nil
	}
	if msg.err != nil {
		m.failure("cannot read the service", msg.err)
		return nil
	}
	m.svcID, m.service = msg.service.ID, msg.service
	return m.serviceAction(msg.verb)
}

// ---- logs --------------------------------------------------------------------------

func (m *Model) openAppLogs(component string) tea.Cmd {
	l := &m.apps.logs
	*l = appLogs{node: m.apps.node, project: m.apps.project, component: component, seq: l.seq + 1, rev: l.rev + 1, view: l.view}
	l.view.SetContent("")
	m.state(keyAppLogs).loaded = false
	return m.push(screenAppLogs)
}

func (m *Model) loadAppLogs() tea.Cmd {
	api, ok := m.appsAPI()
	if !ok {
		return nil
	}
	l := &m.apps.logs
	node, project, q := l.node, l.project, wire.AppLogQuery{Component: l.component, Search: l.search}
	return loadWithin(m, keyAppLogs, m.appsTimeout(),
		func(ctx context.Context) (wire.AppLogs, error) { return api.NodeAppLogs(ctx, node, project, q) },
		func(m *Model, logs wire.AppLogs) {
			l := &m.apps.logs
			if l.node != node || l.project != project || l.component != q.Component || l.search != q.Search {
				return
			}
			l.lines, l.capped, l.rev = nil, false, l.rev+1
			l.append(logs)
			l.cursor, l.window = logs.Cursor, logs.Window
			m.sizeAppLogs()
			l.view.GotoBottom()
		})
}

// append adds what a read returned; lines the daemon did not deliver show as a gap.
func (l *appLogs) append(logs wire.AppLogs) {
	switch {
	case logs.Truncated && l.search != "": // a cap on matches, not lines missing from the log
		l.capped = true
	case logs.Gap || logs.Truncated:
		l.lines = append(l.lines, logLine{gap: true})
	}
	for _, text := range logs.Lines {
		l.lines = append(l.lines, logLine{text: text})
	}
	if over := len(l.lines) - maxAppLogRows; over > 0 {
		l.lines = l.lines[over:]
	}
	l.readAt = logs.CollectedAt
}

func (m *Model) reloadAppLogs() tea.Cmd { return m.reload(true, loader{keyAppLogs, m.loadAppLogs}) }

// appLogsKey takes the keys this screen owns before the global ones: / searches the lines here instead of
// opening the palette, and esc first clears a search. It reports whether it took the key.
func (m *Model) appLogsKey(key tea.KeyPressMsg) (tea.Cmd, bool) {
	l := &m.apps.logs
	switch key.String() {
	case "/":
		return m.openPrompt("search", "enter searches the recent lines · empty clears · esc cancels", (*Model).submitAppLogsSearch), true
	case "esc":
		if l.search == "" {
			return nil, false
		}
		l.search = ""
		return m.reloadAppLogs(), true
	case "f":
		if l.following {
			l.following = false
			return nil, true
		}
		l.following, l.seq = true, l.seq+1
		if l.search == "" {
			return m.appLogsTick(), true
		}
		l.search = ""
		return tea.Batch(m.reloadAppLogs(), m.appLogsTick()), true
	}
	return nil, false
}

func (m *Model) submitAppLogsSearch(term string) tea.Cmd {
	l := &m.apps.logs
	l.search, l.following = term, false
	return m.reloadAppLogs()
}

func (m *Model) appLogsKeyScroll(key tea.KeyPressMsg) tea.Cmd {
	switch key.String() {
	case "G":
		m.apps.logs.view.GotoBottom()
	case "g":
		m.apps.logs.view.GotoTop()
	default:
		m.apps.logs.view, _ = m.apps.logs.view.Update(key)
	}
	return nil
}

// following says whether the poll that carries seq may still run: only while this screen is up and the follow
// it belongs to is on. Leaving the screen ends the polling, whichever way it is left.
func (m *Model) following(seq int) bool {
	return m.screen == screenAppLogs && m.apps.logs.following && m.apps.logs.seq == seq
}

// endFollowOffScreen turns the follow off when its poll finds the logs screen covered (help over it): the chain of
// polls ends there, so the screen must stop saying it follows.
func (m *Model) endFollowOffScreen(seq int) {
	if l := &m.apps.logs; l.following && l.seq == seq {
		l.following = false
	}
}

func (m *Model) appLogsTick() tea.Cmd {
	seq := m.apps.logs.seq
	return tea.Tick(appLogsPoll, func(time.Time) tea.Msg { return appLogsTickMsg{seq: seq} })
}

func (m *Model) onAppLogsTick(msg appLogsTickMsg) tea.Cmd {
	api, ok := m.appsAPI()
	l := &m.apps.logs
	if !ok || !m.following(msg.seq) {
		m.endFollowOffScreen(msg.seq)
		return nil
	}
	if l.cursor == "" { // nothing was read yet: there is nothing to follow from
		return m.appLogsTick()
	}
	node, project, q, rev, parent, timeout := l.node, l.project, wire.AppLogQuery{Component: l.component, Cursor: l.cursor}, l.rev, m.ctx, m.appsTimeout()
	return func() tea.Msg {
		logs, err := within(parent, timeout, func(ctx context.Context) (wire.AppLogs, error) {
			return api.NodeAppLogs(ctx, node, project, q)
		})
		return appLogsPolledMsg{seq: msg.seq, rev: rev, logs: logs, err: err}
	}
}

func (m *Model) onAppLogsPolled(msg appLogsPolledMsg) tea.Cmd {
	if !m.following(msg.seq) {
		m.endFollowOffScreen(msg.seq)
		return nil
	}
	l := &m.apps.logs
	switch {
	case msg.err != nil:
		m.failure("log follow", msg.err)
	case msg.rev == l.rev:
		atEnd := l.view.AtBottom()
		l.append(msg.logs)
		l.cursor = msg.logs.Cursor
		m.sizeAppLogs()
		if atEnd {
			l.view.GotoBottom()
		}
	}
	return m.appLogsTick()
}

func (m *Model) sizeAppLogs() {
	bw, bh := m.bodySize()
	l := &m.apps.logs
	l.view.SetWidth(max(bw, 1))
	l.view.SetHeight(max(bh-2, 1))
	rows := make([]string, len(l.lines))
	for i, ln := range l.lines {
		rows[i] = m.logRow(ln, l.search, bw)
	}
	l.view.SetContentLines(rows)
}

func (m *Model) logRow(ln logLine, term string, bw int) string {
	if ln.gap {
		return " " + m.th.warn.Render(clip("── gap: lines are missing here ──", bw-2))
	}
	return " " + m.highlight(clip(textsafe.Line(ln.text), bw-2), term)
}

// highlight marks the matches of term in text, ignoring case like the search does.
func (m *Model) highlight(text, term string) string {
	spans := matchSpans(text, term)
	if len(spans) == 0 {
		return text
	}
	runes := []rune(text)
	var b strings.Builder
	at := 0
	for _, s := range spans {
		b.WriteString(string(runes[at:s[0]]))
		b.WriteString(m.th.match.Render(string(runes[s[0]:s[1]])))
		at = s[1]
	}
	b.WriteString(string(runes[at:]))
	return b.String()
}

// matchSpans returns the rune ranges of the non-overlapping, case-insensitive matches of term in text.
func matchSpans(text, term string) [][2]int {
	t, q := foldRunes(text), foldRunes(term)
	if len(q) == 0 {
		return nil
	}
	var spans [][2]int
	for i := 0; i+len(q) <= len(t); {
		if slices.Equal(t[i:i+len(q)], q) {
			spans = append(spans, [2]int{i, i + len(q)})
			i += len(q)
			continue
		}
		i++
	}
	return spans
}

func foldRunes(s string) []rune {
	runes := []rune(s)
	for i, r := range runes {
		runes[i] = unicode.ToLower(r)
	}
	return runes
}

// commandApps is `apps` (the overview) or `apps <node> <project>` (that app's panel).
func (m *Model) commandApps(args []string) tea.Cmd {
	switch len(args) {
	case 0:
		return m.jump(screenApps)
	case 2:
		n, err := m.resolveNode(args[0])
		if err != nil {
			m.notice = notice{text: err.Error(), isErr: true}
			return nil
		}
		return m.openApp(n.ID, n.Name, args[1])
	}
	m.notice = notice{text: "usage: apps [<node> <project>]", isErr: true}
	return nil
}
