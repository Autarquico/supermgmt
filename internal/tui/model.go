package tui

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"charm.land/bubbles/v2/textinput"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

const (
	// DefaultTimeout bounds every API call the TUI makes.
	DefaultTimeout = 2 * time.Second
	// DefaultRefresh is how often the current screen reloads.
	DefaultRefresh = 5 * time.Second

	minWidth, minHeight = 40, 10
)

// Options configures the TUI.
type Options struct {
	// Timeout bounds each API call (default DefaultTimeout).
	Timeout time.Duration
	// Refresh is the reload period of the current screen. Zero disables the
	// periodic reload; Run applies DefaultRefresh when it is zero.
	Refresh time.Duration
	// Location formats times (default time.Local).
	Location *time.Location
	// Presence, when set, runs for the life of the TUI and tells the daemon
	// a client is connected (client.HoldPresence).
	Presence func(ctx context.Context) error
	// Follow, when set, streams audit events for the life of the TUI
	// (client.FollowEvents, which reconnects with Last-Event-ID). Each event
	// refreshes the current screen at once; the periodic refresh stays as the
	// fallback. It returns only for good, and the TUI then says so.
	Follow func(ctx context.Context, handle func(wire.Event) error) error
	// Settings describes the connection for the read-only Settings screen.
	Settings Settings
}

// Settings is what the Settings screen shows besides the caller's identity.
type Settings struct {
	// Profile is the current profile name, "" without one.
	Profile string
	// Server is the remote server origin, "" for the local daemon.
	Server string
}

type screen int

const (
	screenDashboard screen = iota
	screenResources
	screenNode
	screenServices
	screenService
	screenLogs
	screenJobs
	screenJob
	screenApprovals
	screenEvents
	screenProviders
	screenSettings
	screenHelp
)

var screenTitles = map[screen]string{
	screenDashboard: "Dashboard", screenResources: "Resources", screenNode: "Node", screenServices: "Services",
	screenService: "Service", screenLogs: "Logs", screenJobs: "Jobs", screenJob: "Job",
	screenApprovals: "Approvals", screenEvents: "Events", screenProviders: "Providers",
	screenSettings: "Settings", screenHelp: "Help",
}

// Model is the Bubble Tea model. It is only ever touched by Update and View;
// every API call runs in a tea.Cmd.
type Model struct {
	api  API
	opts Options
	ctx  context.Context //nolint:containedctx // cancels in-flight commands when the program ends
	th   theme

	width, height int
	screen        screen
	back          []screen
	loads         map[loadKey]*loadState

	me        wire.Me
	nodes     []wire.Node
	nodeCur   int
	node      domain.ID // node whose detail or services are open
	nodeFull  wire.Node
	services  []wire.Service
	svcCur    int
	svcCache  map[domain.ID][]wire.Service
	service   wire.Service
	svcID     domain.ID
	logs      wire.LogChunk
	logsView  viewport.Model
	logsFor   domain.ID
	jobs      []wire.Job
	jobCur    int
	jobID     domain.ID
	jobDetail wire.JobDetail
	approvals []wire.Approval
	apprCur   int
	events    []wire.Event
	providers []wire.Provider

	// followState is where the live event stream stands, for the Settings
	// screen: "" when no stream was asked for.
	followState string

	notice     notice
	prompt     *prompt
	confirm    *confirmation
	acting     bool // a mutation is in flight: further ones wait
	handingOff bool // a session is being issued or ended: input is ignored
	planSeq    int  // identifies the confirmation a plan reply belongs to
	input      textinput.Model
}

type notice struct {
	text  string
	isErr bool
}

// New builds the model. It issues no calls until Init.
func New(api API, o Options) *Model {
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
	if o.Location == nil {
		o.Location = time.Local
	}
	input := textinput.New()
	styles := input.Styles()
	styles.Cursor.Blink = false // a solid cursor: no blink timers to drive
	input.SetStyles(styles)
	return &Model{
		api: api, opts: o, ctx: context.Background(), th: newTheme(),
		width: 80, height: 24, screen: screenDashboard,
		loads: map[loadKey]*loadState{}, svcCache: map[domain.ID][]wire.Service{},
		logsView: viewport.New(), input: input,
	}
}

// Run shows the TUI until the user quits or ctx ends.
func Run(ctx context.Context, api API, o Options) error {
	if o.Refresh == 0 {
		o.Refresh = DefaultRefresh
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if o.Presence != nil {
		go func() { _ = o.Presence(ctx) }()
	}
	model := New(api, o)
	model.ctx = ctx
	if o.Follow != nil {
		model.followState = followLive
	}
	program := tea.NewProgram(model, tea.WithContext(ctx))
	if o.Follow != nil {
		go follow(ctx, o.Follow, program.Send)
	}
	_, err := program.Run()
	return err
}

// Where the live event stream stands (Settings screen).
const (
	followLive    = "live"
	followStopped = "stopped"
)

// streamEventMsg is one audit event from the live stream; streamEndedMsg says
// the stream ended for good.
type (
	streamEventMsg struct{ event wire.Event }
	streamEndedMsg struct{ err error }
)

// follow runs the event stream and turns it into messages. A stream that was
// cancelled with the program says nothing.
func follow(ctx context.Context, stream func(context.Context, func(wire.Event) error) error, send func(tea.Msg)) {
	err := stream(ctx, func(e wire.Event) error {
		send(streamEventMsg{event: e})
		return nil
	})
	if ctx.Err() == nil {
		send(streamEndedMsg{err: err})
	}
}

type tickMsg struct{}

func (m *Model) tick() tea.Cmd {
	if m.opts.Refresh <= 0 {
		return nil
	}
	return tea.Tick(m.opts.Refresh, func(time.Time) tea.Msg { return tickMsg{} })
}

func (m *Model) Init() tea.Cmd {
	return tea.Batch(m.reload(true, m.screenLoaders()...), m.tick())
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.sizeLogs()
		return m, nil
	case tickMsg:
		return m, tea.Batch(m.reload(false, m.screenLoaders()...), m.tick())
	case streamEventMsg:
		return m, m.reload(false, m.screenLoaders()...)
	case streamEndedMsg:
		m.onStreamEnded(msg)
		return m, nil
	case loadedMsg:
		m.onLoaded(msg)
		return m, nil
	case actedMsg:
		return m, m.onActed(msg)
	case planMsg:
		m.onPlan(msg)
		return m, nil
	case handoffOpenedMsg:
		return m, m.onHandoffOpened(msg)
	case handoffReturnedMsg:
		return m, m.onHandoffReturned(msg)
	case handoffEndedMsg:
		return m, m.onHandoffEnded(msg)
	case tea.KeyPressMsg:
		return m, m.onKey(msg)
	case tea.PasteMsg:
		if m.prompt != nil {
			var cmd tea.Cmd
			m.input, cmd = m.input.Update(msg)
			return m, cmd
		}
	}
	return m, nil
}

func (m *Model) onStreamEnded(msg streamEndedMsg) {
	m.followState = followStopped
	reason := "the server ended it"
	if msg.err != nil {
		reason = describe(msg.err)
	}
	m.notice = notice{text: "live updates stopped (" + reason + "); the screen still refreshes every few seconds", isErr: true}
}

// screenLoaders are the reloads the current screen needs. Nodes and approvals
// are always loaded: the header counts them.
func (m *Model) screenLoaders() []loader {
	always := []loader{{keyMe, m.loadMe}, {keyNodes, m.loadNodes}, {keyApprovals, m.loadApprovals}}
	switch m.screen {
	case screenDashboard:
		return append(always, loader{keyJobs, m.loadJobs})
	case screenNode:
		return append(always, loader{keyNode, m.loadNode}, loader{keyServices, m.loadServices})
	case screenServices:
		return append(always, loader{keyServices, m.loadServices})
	case screenService:
		return append(always, loader{keyService, m.loadService})
	case screenLogs:
		return append(always, loader{keyLogs, m.loadLogs})
	case screenJobs:
		return append(always, loader{keyJobs, m.loadJobs})
	case screenJob:
		return append(always, loader{keyJob, m.loadJob})
	case screenEvents:
		return append(always, loader{keyEvents, m.loadEvents})
	case screenProviders:
		return append(always, loader{keyProviders, m.loadProviders})
	case screenResources, screenApprovals, screenSettings, screenHelp:
		return always
	}
	return always
}

// push moves to a screen, remembering where it came from.
func (m *Model) push(to screen) tea.Cmd {
	m.back = append(m.back, m.screen)
	m.screen = to
	return m.reload(true, m.screenLoaders()...)
}

// jump moves to a top-level screen and forgets the trail.
func (m *Model) jump(to screen) tea.Cmd {
	m.back, m.screen = nil, to
	return m.reload(true, m.screenLoaders()...)
}

func (m *Model) pop() tea.Cmd {
	if len(m.back) == 0 {
		return nil
	}
	m.screen, m.back = m.back[len(m.back)-1], m.back[:len(m.back)-1]
	return m.reload(true, m.screenLoaders()...)
}

func (m *Model) onKey(key tea.KeyPressMsg) tea.Cmd {
	if m.handingOff {
		return nil
	}
	m.notice = notice{}
	switch {
	case m.prompt != nil:
		return m.promptKey(key)
	case m.confirm != nil:
		return m.confirmKey(key)
	}
	switch key.String() {
	case "q", "ctrl+c":
		return tea.Quit
	case "?":
		if m.screen == screenHelp {
			return m.pop()
		}
		return m.push(screenHelp)
	case "/":
		return m.openPalette()
	case "1":
		return m.jump(screenDashboard)
	case "2":
		return m.jump(screenResources)
	case "3":
		return m.jump(screenJobs)
	case "4":
		return m.jump(screenApprovals)
	case "5":
		return m.jump(screenEvents)
	case "6":
		return m.jump(screenProviders)
	case "7":
		return m.jump(screenSettings)
	case "r":
		return m.reload(true, m.screenLoaders()...)
	case "esc":
		return m.pop()
	}
	return m.screenKey(key)
}

func (m *Model) screenKey(key tea.KeyPressMsg) tea.Cmd {
	switch m.screen {
	case screenResources:
		return m.resourcesKey(key)
	case screenNode:
		return m.nodeKey(key)
	case screenServices:
		return m.servicesKey(key)
	case screenService:
		return m.serviceKey(key)
	case screenLogs:
		return m.logsKey(key)
	case screenJobs:
		return m.jobsKey(key)
	case screenJob:
		return m.jobKey(key)
	case screenApprovals:
		return m.approvalsKey(key)
	case screenDashboard, screenEvents, screenProviders, screenSettings, screenHelp:
		return nil
	}
	return nil
}

// moveCursor applies j/k/arrows/home/end to a cursor over n rows.
func moveCursor(cur *int, n int, key tea.KeyPressMsg) {
	switch key.String() {
	case "j", "down":
		*cur = min(*cur+1, n-1)
	case "k", "up":
		*cur = max(*cur-1, 0)
	case "g", "home":
		*cur = 0
	case "G", "end":
		*cur = max(n-1, 0)
	}
	*cur = max(min(*cur, n-1), 0)
}

// keepCursor returns the index of the previously selected item in updated, or
// the old index clamped when it is gone.
func keepCursor[T any](old []T, cur int, updated []T, id func(T) string) int {
	if cur >= 0 && cur < len(old) {
		want := id(old[cur])
		if i := slices.IndexFunc(updated, func(t T) bool { return id(t) == want }); i >= 0 {
			return i
		}
	}
	return max(min(cur, len(updated)-1), 0)
}

// ---- loaders ---------------------------------------------------------------

func (m *Model) loadMe() tea.Cmd {
	return load(m, keyMe, m.api.Me, func(m *Model, me wire.Me) { m.me = me })
}

func (m *Model) loadNodes() tea.Cmd {
	return load(m, keyNodes,
		func(ctx context.Context) (wire.Page[wire.Node], error) {
			return m.api.ListNodes(ctx, wire.NodeQuery{PageQuery: wire.PageQuery{Limit: wire.MaxLimit}})
		},
		func(m *Model, page wire.Page[wire.Node]) {
			nodes := slices.Clone(page.Items)
			slices.SortStableFunc(nodes, func(a, b wire.Node) int {
				return strings.Compare(a.Provider+"\x00"+a.Name, b.Provider+"\x00"+b.Name)
			})
			m.nodeCur = keepCursor(m.nodes, m.nodeCur, nodes, func(n wire.Node) string { return string(n.ID) })
			m.nodes = nodes
		})
}

func (m *Model) loadNode() tea.Cmd {
	id := m.node
	return load(m, keyNode,
		func(ctx context.Context) (wire.Node, error) { return m.api.GetNode(ctx, id, true) },
		func(m *Model, n wire.Node) {
			if m.node == id {
				m.nodeFull = n
			}
		})
}

func (m *Model) loadServices() tea.Cmd {
	id := m.node
	return load(m, keyServices,
		func(ctx context.Context) (wire.Page[wire.Service], error) {
			return m.api.ListServices(ctx, id, wire.PageQuery{Limit: wire.MaxLimit})
		},
		func(m *Model, page wire.Page[wire.Service]) {
			m.svcCache[id] = page.Items
			if m.node != id {
				return
			}
			m.svcCur = keepCursor(m.services, m.svcCur, page.Items, func(s wire.Service) string { return string(s.ID) })
			m.services = page.Items
		})
}

func (m *Model) loadService() tea.Cmd {
	id := m.svcID
	return load(m, keyService,
		func(ctx context.Context) (wire.Service, error) { return m.api.GetService(ctx, id) },
		func(m *Model, s wire.Service) {
			if m.svcID == id {
				m.service = s
			}
		})
}

func (m *Model) loadLogs() tea.Cmd {
	id := m.svcID
	return load(m, keyLogs,
		func(ctx context.Context) (wire.LogChunk, error) { return m.api.ServiceLogs(ctx, id, wire.LogQuery{}) },
		func(m *Model, chunk wire.LogChunk) {
			if m.svcID != id {
				return
			}
			follow := m.logsFor != id || m.logsView.AtBottom()
			m.logs, m.logsFor = chunk, id
			m.sizeLogs()
			if follow {
				m.logsView.GotoBottom()
			}
		})
}

func (m *Model) loadJobs() tea.Cmd {
	return load(m, keyJobs,
		func(ctx context.Context) (wire.Page[wire.Job], error) {
			return m.api.ListJobs(ctx, wire.JobQuery{PageQuery: wire.PageQuery{Limit: 100}})
		},
		func(m *Model, page wire.Page[wire.Job]) {
			m.jobCur = keepCursor(m.jobs, m.jobCur, page.Items, func(j wire.Job) string { return string(j.ID) })
			m.jobs = page.Items
		})
}

func (m *Model) loadJob() tea.Cmd {
	id := m.jobID
	return load(m, keyJob,
		func(ctx context.Context) (wire.JobDetail, error) { return m.api.GetJob(ctx, id) },
		func(m *Model, d wire.JobDetail) {
			if m.jobID == id {
				m.jobDetail = d
			}
		})
}

func (m *Model) loadApprovals() tea.Cmd {
	return load(m, keyApprovals,
		func(ctx context.Context) (wire.Page[wire.Approval], error) {
			return m.api.ListApprovals(ctx, wire.PageQuery{Limit: 100})
		},
		func(m *Model, page wire.Page[wire.Approval]) {
			m.apprCur = keepCursor(m.approvals, m.apprCur, page.Items, func(a wire.Approval) string { return string(a.Job.ID) })
			m.approvals = page.Items
		})
}

func (m *Model) loadEvents() tea.Cmd {
	return load(m, keyEvents,
		func(ctx context.Context) (wire.Page[wire.Event], error) {
			return m.api.ListEvents(ctx, wire.EventQuery{PageQuery: wire.PageQuery{Limit: 100}})
		},
		func(m *Model, page wire.Page[wire.Event]) {
			events := slices.Clone(page.Items)
			slices.SortStableFunc(events, func(a, b wire.Event) int { return int(b.Seq - a.Seq) })
			m.events = events
		})
}

func (m *Model) loadProviders() tea.Cmd {
	return load(m, keyProviders,
		func(ctx context.Context) (wire.Page[wire.Provider], error) {
			return m.api.ListProviders(ctx, wire.PageQuery{Limit: wire.MaxLimit})
		},
		func(m *Model, page wire.Page[wire.Provider]) {
			providers := slices.Clone(page.Items)
			slices.SortStableFunc(providers, func(a, b wire.Provider) int { return strings.Compare(a.Type+"\x00"+a.Name, b.Type+"\x00"+b.Name) })
			m.providers = providers
		})
}

// ---- selection helpers -----------------------------------------------------

func (m *Model) selectedNode() (wire.Node, bool) {
	if m.nodeCur < 0 || m.nodeCur >= len(m.nodes) {
		return wire.Node{}, false
	}
	return m.nodes[m.nodeCur], true
}

// openNode selects a node and moves to a screen that shows it.
func (m *Model) openNode(n wire.Node, to screen) tea.Cmd {
	m.node, m.nodeFull, m.services, m.svcCur = n.ID, n, m.svcCache[n.ID], 0
	m.state(keyNode).loaded, m.state(keyServices).loaded = false, false
	return m.push(to)
}

func (m *Model) openService(s wire.Service, to screen) tea.Cmd {
	m.svcID, m.service = s.ID, s
	m.state(keyService).loaded = false
	if to == screenLogs {
		m.logsFor, m.logs = "", wire.LogChunk{}
		m.logsView.SetContent("")
		m.state(keyLogs).loaded = false
	}
	return m.push(to)
}

func (m *Model) failure(what string, err error) {
	m.notice = notice{text: what + ": " + describe(err), isErr: true}
}

func (m *Model) say(format string, args ...any) {
	m.notice = notice{text: fmt.Sprintf(format, args...)}
}
