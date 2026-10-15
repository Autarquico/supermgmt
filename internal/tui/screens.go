package tui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

// splitMinWidth is the body width from which two panes fit side by side.
const splitMinWidth = 70

func isActive(s domain.JobState) bool {
	return !slices.Contains([]domain.JobState{domain.JobSucceeded, domain.JobFailed, domain.JobCancelled}, s)
}

// ---- dashboard ---------------------------------------------------------------

func (m *Model) dashboardBody(bw int) []string {
	var attention []wire.Node
	reachable := 0
	nodes, guests := m.countNodesAndGuests()
	for _, n := range m.nodes {
		if isGuest(n) {
			continue
		}
		if n.Reachability == domain.ReachabilityReachable {
			reachable++
		}
		if n.Reachability == domain.ReachabilityUnreachable || n.Stale {
			attention = append(attention, n)
		}
	}
	var active []wire.Job
	for _, j := range m.jobs {
		if isActive(j.State) {
			active = append(active, j)
		}
	}
	lines := []string{
		"",
		m.kv("NODES", nodesSummary(nodes, guests, reachable, len(attention)), bw),
		m.kv("APPROVALS", fmt.Sprintf("%d awaiting", len(m.approvals)), bw),
		m.kv("JOBS", fmt.Sprintf("%d active", len(active)), bw),
		"",
		m.heading("Needs attention"),
	}
	for _, n := range attention {
		lines = append(lines, "   "+m.reachGlyph(n)+" "+clip(safe(n.Name)+"  "+nodeState(n)+attentionDetail(n), bw-6))
	}
	if len(attention) == 0 {
		lines = append(lines, m.th.dim.Render("   all nodes reachable and fresh"))
	}
	lines = append(lines, "", m.heading("Awaiting approval"))
	for _, a := range m.approvals {
		lines = append(lines, "   "+clip(fmt.Sprintf("%s  %s  %d/%d", safe(a.Job.Type), strings.Join(a.Environments, ","), a.Approvals, a.Quorum), bw-4))
	}
	if len(m.approvals) == 0 {
		lines = append(lines, m.th.dim.Render("   nothing is waiting"))
	}
	lines = append(lines, "", m.heading("Active jobs"))
	for _, j := range active {
		lines = append(lines, "   "+clip(fmt.Sprintf("%s  %s  %s", shortID(j.ID), safe(j.Type), j.State), bw-4))
	}
	if len(active) == 0 {
		lines = append(lines, m.th.dim.Render("   no active jobs"))
	}
	return lines
}

func nodesSummary(nodes, guests, reachable, attention int) string {
	text := fmt.Sprintf("%d total", nodes)
	if guests > 0 {
		text += fmt.Sprintf(" · %d guests", guests)
	}
	return text + fmt.Sprintf(" · %d reachable · %d need attention", reachable, attention)
}

func attentionDetail(n wire.Node) string {
	if n.Connection.LastError != "" {
		return " · " + safe(n.Connection.LastError)
	}
	return ""
}

// ---- resources (tree + detail) ----------------------------------------------------

func (m *Model) resourcesBody(bw, bh int) []string {
	if bw < splitMinWidth {
		return m.nodeTree(bw, bh)
	}
	leftW := min(32, bw/3)
	rightW := bw - leftW - 1
	return sideBySide(m.nodeTree(leftW, bh), m.nodeSummary(rightW), leftW, rightW, bh)
}

func (m *Model) nodeTree(w, h int) []string {
	lines := []string{m.heading("RESOURCES"), ""}
	cursorRow := 0
	provider := "\x00"
	for i, n := range m.nodes {
		if n.Provider != provider {
			provider = n.Provider
			lines = append(lines, " "+m.th.dim.Render("▼ "+clip(safe(provider), w-4)))
		}
		selected := i == m.nodeCur
		if selected {
			cursorRow = len(lines)
		}
		indent := treeIndent(n)
		name := clip(safe(n.Name)+nodeBadges(n), w-4-len(indent))
		lines = append(lines, indent+m.marker(selected)+m.nodeGlyph(n)+" "+m.rowStyle(selected).Render(name))
	}
	if len(m.nodes) == 0 {
		lines = append(lines, m.th.dim.Render(" "+clip(m.emptyNodes(), w-2)))
	}
	return append(lines[:2:2], window(lines[2:], cursorRow-2, max(h-2, 1))...)
}

// isGuest reports whether n is a Proxmox VM or container: it has no SSH
// endpoint, so sessions and probes do not apply to it.
func isGuest(n wire.Node) bool {
	return n.Proxmox != nil && n.Proxmox.Type != proxmoxClusterNode
}

func (m *Model) countNodesAndGuests() (nodes, guests int) {
	for _, n := range m.nodes {
		if isGuest(n) {
			guests++
		}
	}
	return len(m.nodes) - guests, guests
}

// treeIndent nests a Proxmox guest under its cluster node.
func treeIndent(n wire.Node) string {
	if isGuest(n) {
		return "    "
	}
	return "  "
}

// nodeBadges are the words that must survive without color: stale data and,
// for Proxmox, what the sync could not confirm about the object.
func nodeBadges(n wire.Node) string {
	var badges []string
	if n.Stale {
		badges = append(badges, "[stale]")
	}
	if g := n.Proxmox; g != nil {
		if g.Template {
			badges = append(badges, "[template]")
		}
		if g.Absent {
			badges = append(badges, "[absent]")
		}
		if g.Inaccessible {
			badges = append(badges, "[inaccessible]")
		}
	}
	if len(badges) == 0 {
		return ""
	}
	return " " + strings.Join(badges, " ")
}

func (m *Model) emptyNodes() string {
	if m.state(keyNodes).loaded {
		return "no nodes yet: sm nodes add"
	}
	return "loading…"
}

func (m *Model) nodeSummary(w int) []string {
	n, ok := m.selectedNode()
	if !ok {
		return []string{m.heading("DETAIL")}
	}
	return append([]string{m.heading("DETAIL"), ""}, m.nodeFacts(n, w)...)
}

// nodeFacts is the node block shared by the resources pane and the node screen.
func (m *Model) nodeFacts(n wire.Node, w int) []string {
	state := nodeState(n)
	if n.Proxmox != nil {
		state = proxmoxState(n)
	}
	lines := []string{
		" " + m.nodeGlyph(n) + " " + m.th.title.Render(clip(safe(n.Name), w-6)) + m.th.dim.Render(" "+clip(state, max(w-lenRunes(n.Name)-6, 0))),
		m.kv("environment", safe(n.Environment), w),
		m.kv("provider", providerText(n), w),
	}
	if n.Proxmox != nil {
		lines = append(lines, m.kv("proxmox", proxmoxIdentity(n), w), m.kv("management", string(n.ManagementState), w))
	}
	lines = append(lines, m.kv("metrics", metricsLine(n.Metrics), w), m.kv("capabilities", capabilityNames(n), w))
	if n.Proxmox == nil {
		lines = append(lines, m.kv("setup", setupSummary(n), w))
	}
	return lines
}

const proxmoxClusterNode = "node"

// proxmoxIdentity is "qemu/100 on pve1", or "cluster node" for the host.
func proxmoxIdentity(n wire.Node) string {
	g := n.Proxmox
	if g.Type == proxmoxClusterNode {
		return "cluster node " + safe(g.PVENode)
	}
	return fmt.Sprintf("%s/%d on %s", safe(g.Type), g.VMID, safe(g.PVENode))
}

// proxmoxState is the power state, or why there is none to show.
func proxmoxState(n wire.Node) string {
	g := n.Proxmox
	switch {
	case g.Absent:
		return "absent · gone from Proxmox"
	case g.Inaccessible:
		return "inaccessible · the token cannot see it"
	}
	parts := []string{safe(g.Status)}
	if g.Template {
		parts = append(parts, "template")
	}
	if n.Stale {
		parts = append(parts, "stale")
	}
	return strings.Join(parts, " · ")
}

// nodeGlyph is the reachability glyph, or for a Proxmox object its power
// state: running filled, stopped hollow, anything unconfirmed dotted.
func (m *Model) nodeGlyph(n wire.Node) string {
	g := n.Proxmox
	if g == nil {
		return m.reachGlyph(n)
	}
	switch {
	case g.Absent || g.Inaccessible:
		return m.th.dim.Render("◌")
	case g.Status == "running" || g.Status == "online":
		return m.th.ok.Render("●")
	case g.Status == "stopped" || g.Status == "offline":
		return m.th.dim.Render("○")
	}
	return m.th.dim.Render("◌")
}

func lenRunes(s string) int { return len([]rune(s)) }

func capabilityNames(n wire.Node) string {
	var names []string
	for _, c := range n.Capabilities {
		if c.Available {
			names = append(names, safe(c.Name))
		}
	}
	slices.Sort(names)
	if len(names) == 0 {
		return "none yet"
	}
	return strings.Join(names, " ")
}

// setupSummary offers setup only where it can run: SSH nodes on Linux. The OS
// is the probe's display name, and macOS is the one non-Linux system it names.
func setupSummary(n wire.Node) string {
	switch {
	case n.Setup != nil:
	case n.Kind != "ssh":
		return "not available (SSH nodes only)"
	case strings.HasPrefix(n.OS, "macOS"):
		return "not available (Linux only)"
	default:
		return "not done (/ setup " + safe(n.Name) + ")"
	}
	text := fmt.Sprintf("done · %d unit grant(s) · logs %s", len(n.Setup.Units), safe(n.Setup.LogsMode))
	if n.Setup.DockerAccess {
		text += " · docker access"
	}
	return text
}

func (m *Model) resourcesKey(key tea.KeyPressMsg) tea.Cmd {
	moveCursor(&m.nodeCur, len(m.nodes), key)
	n, ok := m.selectedNode()
	if !ok {
		return nil
	}
	return m.nodeShortcuts(n, key, true)
}

// nodeShortcuts are the keys shared by the tree and the node screen.
func (m *Model) nodeShortcuts(n wire.Node, key tea.KeyPressMsg, fromTree bool) tea.Cmd {
	if k := key.String(); isGuest(n) && (k == "s" || k == "d" || k == "p") {
		m.notice = notice{text: safe(n.Name) + " is a Proxmox guest: it has no SSH endpoint (use the power command)", isErr: true}
		return nil
	}
	switch key.String() {
	case "enter":
		if fromTree {
			return m.openNode(n, screenNode)
		}
	case "v":
		return m.openNode(n, screenServices)
	case "s":
		return m.startHandoff(n, wire.ToolShell)
	case "d":
		return m.startHandoff(n, wire.ToolLazydocker)
	case "p":
		if !fromTree {
			return m.probeNode(n)
		}
	}
	return nil
}

// ---- node detail -----------------------------------------------------------------

func (m *Model) nodeBody(bw, bh int) []string {
	n := m.nodeFull
	lines := append([]string{""}, m.nodeFacts(n, bw)...)
	lines = append(lines, m.nodeDetailRows(n, bw)...)
	lines = append(lines,
		"",
		m.heading("Services")+m.th.dim.Render("  v opens the full list"),
	)
	room := max(bh-len(lines), 0)
	for _, s := range m.services[:min(len(m.services), room)] {
		lines = append(lines, "   "+m.serviceRow(s, bw-4, false))
	}
	if len(m.services) == 0 {
		lines = append(lines, m.th.dim.Render("   "+m.emptyServices()))
	}
	return lines
}

// nodeDetailRows are the rows below the facts. A Proxmox object has no SSH
// endpoint, connection or OS of its own: its identity is already in the facts.
func (m *Model) nodeDetailRows(n wire.Node, bw int) []string {
	common := []string{
		m.kv("last seen", m.whenPtr(n.LastSeenAt), bw),
		m.kv("addresses", addressText(n), bw),
		m.kv("tags", safe(dashIfEmpty(strings.Join(n.Tags, " "))), bw),
	}
	if n.Proxmox != nil {
		return common
	}
	return append([]string{
		m.kv("management", string(n.ManagementState), bw),
		m.kv("os", safe(n.OS+" "+n.Arch), bw),
		m.kv("endpoint", safe(fmt.Sprintf("%s@%s:%d (admin %s)", n.Endpoint.User, n.Endpoint.Host, n.Endpoint.Port, n.Endpoint.AdminUser)), bw),
		m.kv("connection", connectionText(n), bw),
	}, common...)
}

func (m *Model) emptyServices() string {
	if m.state(keyServices).loaded {
		return "no services discovered"
	}
	return "loading…"
}

func connectionText(n wire.Node) string {
	text := string(n.Connection.State)
	if n.Connection.LastError != "" {
		text += " · " + safe(n.Connection.LastError)
	}
	return text
}

func addressText(n wire.Node) string {
	var addrs []string
	for _, a := range n.Addresses {
		addrs = append(addrs, safe(a.Address))
	}
	return dashIfEmpty(strings.Join(addrs, " "))
}

func (m *Model) nodeKey(key tea.KeyPressMsg) tea.Cmd {
	return m.nodeShortcuts(m.nodeFull, key, false)
}

// ---- services --------------------------------------------------------------------

func (m *Model) serviceGlyph(s wire.Service) string {
	switch s.Health {
	case "healthy":
		return m.th.ok.Render("●")
	case "unhealthy":
		return m.th.bad.Render("●")
	}
	return m.th.dim.Render("●")
}

func (m *Model) serviceRow(s wire.Service, w int, selected bool) string {
	nameW := max(w/3, 12)
	text := cell(safe(s.Name), nameW) + " " + cell(string(s.RuntimeType), 8) + " " + cell(safe(s.Status), 10) + " " + safe(s.Health)
	return m.marker(selected) + m.serviceGlyph(s) + " " + m.rowStyle(selected).Render(clip(text, max(w-5, 0)))
}

func (m *Model) servicesBody(bw, bh int) []string {
	lines := []string{"", m.heading(fmt.Sprintf("Services on %s (%d)", safe(m.nodeFull.Name), len(m.services))), ""}
	var rows []string
	for i, s := range m.services {
		rows = append(rows, " "+m.serviceRow(s, bw-2, i == m.svcCur))
	}
	if len(rows) == 0 {
		rows = append(rows, m.th.dim.Render(" "+m.emptyServices()))
	}
	return append(lines, window(rows, m.svcCur, max(bh-len(lines), 1))...)
}

func (m *Model) servicesKey(key tea.KeyPressMsg) tea.Cmd {
	moveCursor(&m.svcCur, len(m.services), key)
	if m.svcCur >= len(m.services) {
		return nil
	}
	s := m.services[m.svcCur]
	switch key.String() {
	case "enter":
		return m.openService(s, screenService)
	case "l":
		return m.openService(s, screenLogs)
	}
	return nil
}

func (m *Model) serviceBody(bw int) []string {
	s := m.service
	lines := []string{
		"",
		" " + m.serviceGlyph(s) + " " + m.th.title.Render(clip(safe(s.Name), bw-4)),
		m.kv("node", safe(s.Node), bw),
		m.kv("runtime", string(s.RuntimeType)+" · "+string(s.Kind), bw),
		m.kv("native id", safe(s.NativeID), bw),
		m.kv("status", safe(s.Status), bw),
		m.kv("health", safe(dashIfEmpty(s.Health)), bw),
		m.kv("actions", actionText(s), bw),
		m.kv("last seen", m.whenPtr(s.LastSeenAt), bw),
	}
	keys := make([]string, 0, len(s.Metadata))
	for k := range s.Metadata {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if len(keys) > 0 {
		lines = append(lines, "", m.heading("Metadata"))
	}
	for _, k := range keys {
		lines = append(lines, m.kv(safe(k), safe(fmt.Sprint(s.Metadata[k])), bw))
	}
	return lines
}

func actionText(s wire.Service) string {
	if len(s.Actions) == 0 {
		return "none (the node needs setup for start, stop and restart)"
	}
	verbs := make([]string, len(s.Actions))
	for i, v := range s.Actions {
		verbs[i] = string(v)
	}
	return strings.Join(verbs, " ")
}

func (m *Model) serviceKey(key tea.KeyPressMsg) tea.Cmd {
	switch key.String() {
	case "l":
		return m.openService(m.service, screenLogs)
	case "R":
		return m.serviceAction(domain.VerbRestart)
	case "S":
		return m.serviceAction(domain.VerbStart)
	case "X":
		return m.serviceAction(domain.VerbStop)
	}
	return nil
}

// ---- logs ------------------------------------------------------------------------

// sizeLogs fits the viewport to the body and reloads its (clipped) content.
func (m *Model) sizeLogs() {
	bw, bh := m.bodySize()
	m.logsView.SetWidth(max(bw, 1))
	m.logsView.SetHeight(max(bh-1, 1))
	lines := make([]string, len(m.logs.Lines))
	for i, l := range m.logs.Lines {
		lines[i] = " " + clip(safe(l), bw-2)
	}
	m.logsView.SetContentLines(lines)
}

func (m *Model) logsBody(bw int) []string {
	title := fmt.Sprintf("logs · %s on %s", safe(m.service.Name), safe(m.service.Node))
	if m.logs.Truncated {
		title += " · truncated"
	}
	if m.state(keyLogs).loaded {
		title += fmt.Sprintf(" · %s · %.0f%%", m.when(m.logs.CollectedAt), m.logsView.ScrollPercent()*100)
	}
	lines := []string{m.heading(clip(title, bw-2))}
	if len(m.logs.Lines) == 0 {
		return append(lines, m.th.dim.Render(" "+m.emptyLogs()))
	}
	return append(lines, strings.Split(m.logsView.View(), "\n")...)
}

func (m *Model) emptyLogs() string {
	if m.state(keyLogs).loaded {
		return "no log lines"
	}
	return "loading…"
}

func (m *Model) logsKey(key tea.KeyPressMsg) tea.Cmd {
	switch key.String() {
	case "G":
		m.logsView.GotoBottom()
	case "g":
		m.logsView.GotoTop()
	default:
		m.logsView, _ = m.logsView.Update(key)
	}
	return nil
}

// ---- jobs ------------------------------------------------------------------------

func (m *Model) jobStyle(j wire.Job, selected bool) string {
	switch {
	case selected:
		return "sel"
	case j.State == domain.JobFailed:
		return "bad"
	case j.State == domain.JobAwaitingApproval, j.State == domain.JobInterrupted:
		return "warn"
	}
	return ""
}

func (m *Model) jobsBody(bw, bh int) []string {
	head := " " + m.th.dim.Render(clip("  "+cell("JOB", 9)+cell("TYPE", 20)+cell("STATE", 18)+cell("RISK", 8)+"CREATED", bw-2))
	lines := []string{head}
	var rows []string
	for i, j := range m.jobs {
		selected := i == m.jobCur
		text := cell(shortID(j.ID), 9) + cell(safe(j.Type), 20) + cell(string(j.State), 18) + cell(string(j.Risk), 8) + m.when(j.CreatedAt)
		rows = append(rows, " "+m.marker(selected)+m.styled(m.jobStyle(j, selected), clip(text, bw-4)))
	}
	if len(rows) == 0 {
		rows = append(rows, m.th.dim.Render(" "+m.emptyJobs()))
	}
	return append(lines, window(rows, m.jobCur, max(bh-1, 1))...)
}

func (m *Model) emptyJobs() string {
	if m.state(keyJobs).loaded {
		return "no jobs yet"
	}
	return "loading…"
}

func (m *Model) styled(kind, text string) string {
	switch kind {
	case "sel":
		return m.th.selected.Render(text)
	case "bad":
		return m.th.bad.Render(text)
	case "warn":
		return m.th.warn.Render(text)
	}
	return text
}

func (m *Model) jobsKey(key tea.KeyPressMsg) tea.Cmd {
	moveCursor(&m.jobCur, len(m.jobs), key)
	if m.jobCur >= len(m.jobs) {
		return nil
	}
	j := m.jobs[m.jobCur]
	switch key.String() {
	case "enter":
		m.jobID, m.jobDetail = j.ID, wire.JobDetail{Job: j}
		m.state(keyJob).loaded = false
		return m.push(screenJob)
	case "c":
		return m.cancelJob(j)
	}
	return nil
}

func (m *Model) jobBody(bw int) []string {
	j := m.jobDetail.Job
	lines := []string{
		"",
		" " + m.th.title.Render(clip(safe(j.Type)+"  "+string(j.State), bw-2)),
		m.kv("job", string(j.ID), bw),
		m.kv("resource", string(j.Resource.Type)+" "+string(j.Resource.ID), bw),
		m.kv("risk", string(j.Risk)+" · "+string(j.RetryClass), bw),
		m.kv("attempts", fmt.Sprintf("%d/%d", j.Attempts, j.MaxAttempts), bw),
		m.kv("created", m.when(j.CreatedAt), bw),
		m.kv("finished", m.whenPtr(j.FinishedAt), bw),
		m.kv("plan", shortHash(j.PlanHash), bw),
	}
	if j.Error != nil {
		lines = append(lines, m.kv("error", safe(string(j.Error.Code)+": "+j.Error.Message), bw))
	}
	for i, in := range m.jobDetail.Intents {
		lines = append(lines, "", m.heading(fmt.Sprintf("Intent %d · %s %s", i+1, safe(in.Operation), safe(in.Target))),
			m.kv("state", string(in.State)+" · outcome "+dashIfEmpty(safe(in.Outcome)), bw),
			m.kv("pre-state", compactJSON(in.PreState), bw),
			m.kv("evidence", compactJSON(in.Evidence), bw))
	}
	return lines
}

func compactJSON(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "-"
	}
	var b bytes.Buffer
	if err := json.Compact(&b, raw); err != nil {
		return "(unreadable)"
	}
	return safe(b.String())
}

func (m *Model) jobKey(key tea.KeyPressMsg) tea.Cmd {
	if key.String() == "c" {
		return m.cancelJob(m.jobDetail.Job)
	}
	return nil
}

// ---- approvals (spec §39.5) --------------------------------------------------------

func (m *Model) approvalsBody(bw, bh int) []string {
	if len(m.approvals) == 0 {
		return []string{"", m.th.dim.Render(" " + m.emptyApprovals())}
	}
	if bw < splitMinWidth {
		return m.approvalView(m.approvals[m.apprCur], bw)
	}
	leftW := min(34, bw/3)
	rightW := bw - leftW - 1
	return sideBySide(m.approvalList(leftW, bh), m.approvalView(m.approvals[m.apprCur], rightW), leftW, rightW, bh)
}

func (m *Model) emptyApprovals() string {
	if m.state(keyApprovals).loaded {
		return "nothing is waiting for approval"
	}
	return "loading…"
}

func (m *Model) approvalList(w, h int) []string {
	lines := []string{m.heading("AWAITING APPROVAL"), ""}
	var rows []string
	for i, a := range m.approvals {
		selected := i == m.apprCur
		text := fmt.Sprintf("%s %s %d/%d", shortID(a.Job.ID), safe(a.Job.Type), a.Approvals, a.Quorum)
		rows = append(rows, " "+m.marker(selected)+m.rowStyle(selected).Render(clip(text, w-4)))
	}
	return append(lines, window(rows, m.apprCur, max(h-2, 1))...)
}

// approvalView is the plan an approver decides on: steps, impact, risk, and the
// exact hash the decision binds to.
func (m *Model) approvalView(a wire.Approval, w int) []string {
	lines := []string{"", " " + m.th.title.Render(clip("PLAN #"+shortHash(a.Job.PlanHash), w-2)), ""}
	if doc, ok := decodePlan(a.Plan); ok {
		for _, l := range docLines(doc) {
			lines = append(lines, " "+clip(l, w-2))
		}
	} else {
		lines = append(lines, m.th.warn.Render(" the plan could not be read: do not approve it"))
	}
	lines = append(lines, "",
		" "+clip(fmt.Sprintf("Environments: %s", safe(dashIfEmpty(strings.Join(a.Environments, ", ")))), w-2),
		" "+clip(fmt.Sprintf("Approvals: %d/%d · expires %s", a.Approvals, a.Quorum, m.when(a.ExpiresAt)), w-2),
		"",
		" "+m.th.accent.Render("[A] Approve")+"  "+m.th.bad.Render("[R] Reject"))
	return lines
}

func (m *Model) approvalsKey(key tea.KeyPressMsg) tea.Cmd {
	moveCursor(&m.apprCur, len(m.approvals), key)
	a, ok := m.selectedApproval()
	if !ok {
		return nil
	}
	switch key.String() {
	case "A":
		return m.approve(a)
	case "R":
		return m.rejectWithReason(a)
	}
	return nil
}

// ---- events -----------------------------------------------------------------------

func (m *Model) eventsBody(bw, bh int) []string {
	head := " " + m.th.dim.Render(clip(cell("TIME", 15)+cell("SEV", 9)+cell("ACTION", 24)+cell("RESULT", 10)+"CORRELATION", bw-2))
	var rows []string
	for _, e := range m.events {
		text := cell(m.when(e.Timestamp), 15) + cell(string(e.Severity), 9) + cell(safe(e.Action), 24) + cell(string(e.Result), 10) + safe(e.CorrelationID)
		rows = append(rows, " "+m.styled(severityStyles[e.Severity], clip(text, bw-2)))
	}
	if len(rows) == 0 {
		rows = append(rows, m.th.dim.Render(" "+m.emptyEvents()))
	}
	return append([]string{head}, rows[:min(len(rows), max(bh-1, 1))]...)
}

var severityStyles = map[domain.Severity]string{domain.SeverityError: "bad", domain.SeverityWarning: "warn"}

func (m *Model) emptyEvents() string {
	if m.state(keyEvents).loaded {
		return "no events yet"
	}
	return "loading…"
}

// ---- providers (read-only) ----------------------------------------------------------

func (m *Model) providersBody(bw, bh int) []string {
	head := " " + m.th.dim.Render(clip(cell("NAME", 22)+cell("TYPE", 12)+cell("ORIGIN", 10)+cell("STATUS", 10)+"LAST SYNC", bw-2))
	var rows []string
	for _, p := range m.providers {
		text := cell(safe(p.Name), 22) + cell(safe(p.Type), 12) + cell(string(p.Origin), 10) + cell(safe(p.Status), 10) + m.whenPtr(p.LastSyncAt)
		rows = append(rows, " "+clip(text, bw-2))
		if p.LastError != "" {
			rows = append(rows, "   "+m.th.bad.Render(clip("! "+safe(p.LastError), bw-4)))
		}
	}
	if len(rows) == 0 {
		rows = append(rows, m.th.dim.Render(" "+m.emptyProviders()))
	}
	return append([]string{head}, rows[:min(len(rows), max(bh-1, 1))]...)
}

func (m *Model) emptyProviders() string {
	if m.state(keyProviders).loaded {
		return "no providers yet"
	}
	return "loading…"
}

// ---- settings (read-only) -------------------------------------------------------------

func (m *Model) settingsBody(bw int) []string {
	server, profile := m.opts.Settings.Server, m.opts.Settings.Profile
	if server == "" {
		server = "this machine (local daemon)"
	}
	lines := []string{
		"",
		m.heading("Connection"),
		m.kv("mode", dashIfEmpty(safe(m.me.InstanceMode)), bw),
		m.kv("profile", dashIfEmpty(safe(profile)), bw),
		m.kv("server", safe(server), bw),
		m.kv("updates", m.updatesText(), bw),
		"",
		m.heading("Identity"),
		m.kv("name", dashIfEmpty(safe(m.me.DisplayName)), bw),
		m.kv("id", dashIfEmpty(string(m.me.IdentityID)), bw),
		m.kv("type", dashIfEmpty(string(m.me.ActorType)), bw),
		m.kv("credential", dashIfEmpty(string(m.me.Credential)), bw),
		m.kv("roles", dashIfEmpty(safe(strings.Join(m.me.Roles, ", "))), bw),
	}
	if !m.state(keyMe).loaded {
		lines = append(lines, "", m.th.dim.Render(" loading…"))
	}
	return lines
}

func (m *Model) updatesText() string {
	refresh := "refresh on demand (r)"
	if m.opts.Refresh > 0 {
		refresh = "refresh every " + m.opts.Refresh.String()
	}
	switch m.followState {
	case followLive:
		return "live (server events), " + refresh
	case followStopped:
		return "live stream stopped, " + refresh
	}
	return refresh
}

// ---- help -------------------------------------------------------------------------

func (m *Model) helpBody(bw int) []string {
	rows := [][2]string{
		{"1-7", "Dashboard, Resources, Jobs, Approvals, Events, Providers, Settings"},
		{"8 9", "Applications, Deployments"},
		{"j k / arrows", "move; g top, G bottom"},
		{"enter", "open the selected item"},
		{"esc", "back"},
		{"v", "services of the node"},
		{"l", "logs of the service"},
		{"s", "SSH shell on the node (your own credentials)"},
		{"d", "lazydocker on the node, when Docker is available"},
		{"p", "probe the node (Node screen)"},
		{"R S X", "restart, start, stop the service (opens a plan to confirm)"},
		{"A R", "approve or reject the plan on screen (Approvals)"},
		{"c", "cancel a job (asks first)"},
		{"r", "refresh the screen"},
		{"/", "command palette"},
		{"q", "quit"},
	}
	lines := []string{"", m.heading("Keys")}
	for _, r := range rows {
		lines = append(lines, m.kv(r[0], r[1], bw))
	}
	lines = append(lines, "", m.heading("Palette"), " "+m.th.dim.Render(clip(paletteHint, bw-2)),
		" "+m.th.dim.Render(clip("Destructive actions never run at once: they open a plan and wait for y.", bw-2)))
	return lines
}

func providerText(n wire.Node) string {
	if n.Provider == n.Kind {
		return safe(n.Provider)
	}
	return safe(n.Provider + " · " + n.Kind)
}
