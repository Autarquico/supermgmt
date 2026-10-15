package tui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/textsafe"
)

const (
	logsModeDefault = "journal-group"
	logsModeBroker  = "broker"
	decisionAllow   = "allow"

	dockerRootWarning = "docker access adds supermgmt to the docker group, which is equivalent to root on the node"
)

// ---- mutations ---------------------------------------------------------------

// actedMsg is the reply of one mutation. Mutations are never generation-gated:
// every reply is reported, and only one runs at a time.
type actedMsg struct {
	notice   string
	err      error
	readOnly bool // changes nothing on a node: a timeout needs no warning
}

// refreshTimeout bounds a discovery run from the palette: it reads a whole
// cluster, so it gets longer than an ordinary call.
const refreshTimeout = 30 * time.Second

// act runs one mutation as a command. A timeout does not mean it failed.
func (m *Model) act(call func(ctx context.Context) (string, error)) tea.Cmd {
	return m.run(m.opts.Timeout, false, call)
}

func (m *Model) run(timeout time.Duration, readOnly bool, call func(ctx context.Context) (string, error)) tea.Cmd {
	if m.acting {
		m.notice = notice{text: "another action is still in progress", isErr: true}
		return nil
	}
	m.acting = true
	parent := m.ctx
	return func() tea.Msg {
		text, err := within(parent, timeout, call)
		return actedMsg{notice: text, err: err, readOnly: readOnly}
	}
}

func (m *Model) onActed(msg actedMsg) tea.Cmd {
	m.acting = false
	if msg.err != nil {
		var timeout timeoutError
		text := "action failed: " + describe(msg.err)
		if errors.As(msg.err, &timeout) && !msg.readOnly {
			text += "; it may still have been applied, check Jobs before retrying"
		}
		m.notice = notice{text: text, isErr: true}
		return nil
	}
	m.notice = notice{text: msg.notice}
	return m.reload(true, append(m.screenLoaders(), loader{keyJobs, m.loadJobs}, loader{keyApprovals, m.loadApprovals})...)
}

func submissionNotice(sub wire.Submission) string {
	if sub.Job.State == domain.JobAwaitingApproval {
		return fmt.Sprintf("job %s is waiting for approval (4 Approvals)", shortID(sub.Job.ID))
	}
	return fmt.Sprintf("job %s %s", shortID(sub.Job.ID), sub.Job.State)
}

// ---- confirmation ------------------------------------------------------------

// confirmation is the plan or confirmation a destructive shortcut opens
// (spec §22.2): nothing runs until the user presses y.
type confirmation struct {
	seq      int
	title    string
	warnings []string
	details  []string // shown above the plan once it arrives
	lines    []string
	planning bool
	blocked  string // why it cannot be submitted
	run      func(ctx context.Context) (string, error)
}

type planMsg struct {
	seq  int
	plan wire.CreatedPlan
	err  error
}

// planFor asks the daemon to build and evaluate a plan, then shows it.
func (m *Model) planFor(title string, warnings []string, req wire.CreatePlanRequest) tea.Cmd {
	m.planSeq++
	seq, timeout, parent := m.planSeq, m.opts.Timeout, m.ctx
	m.confirm = &confirmation{seq: seq, title: title, warnings: warnings, planning: true}
	return func() tea.Msg {
		plan, err := within(parent, timeout, func(ctx context.Context) (wire.CreatedPlan, error) {
			return m.api.CreatePlan(ctx, req)
		})
		return planMsg{seq: seq, plan: plan, err: err}
	}
}

func (m *Model) onPlan(msg planMsg) {
	if m.confirm == nil || m.confirm.seq != msg.seq {
		return
	}
	if msg.err != nil {
		m.confirm = nil
		m.failure("cannot plan", msg.err)
		return
	}
	c := m.confirm
	c.planning = false
	c.lines = append(slices.Clone(c.details), planLines(msg.plan)...)
	switch {
	case msg.plan.Policy.Decision != decisionAllow:
		c.blocked = "policy: " + textsafe.Line(msg.plan.Policy.Decision)
		if r := string(msg.plan.Policy.Reason); r != "" {
			c.blocked += " (" + textsafe.Line(r) + ")"
		}
	case msg.plan.Policy.ApprovalRequired:
		c.lines = append(c.lines, fmt.Sprintf("Needs %d approval(s) before it runs.", max(msg.plan.Policy.Quorum, 1)))
	default:
		c.lines = append(c.lines, "Runs as soon as it is submitted.")
	}
	api, id, hash := m.api, msg.plan.PlanID, msg.plan.PlanHash
	c.run = func(ctx context.Context) (string, error) {
		sub, err := api.SubmitPlan(ctx, id, hash)
		return submissionNotice(sub), err
	}
}

func (m *Model) confirmKey(key tea.KeyPressMsg) tea.Cmd {
	c := m.confirm
	switch key.String() {
	case "esc", "n", "ctrl+c", "q":
		m.confirm = nil
	case "y", "enter":
		switch {
		case c.planning:
			m.notice = notice{text: "the plan is still being built"}
		case c.blocked != "":
			m.notice = notice{text: "cannot submit: " + c.blocked, isErr: true}
		default:
			m.confirm = nil
			return m.act(c.run)
		}
	}
	return nil
}

// planDoc is the part of the canonical plan (Appendix C) an approver reads.
type planDoc struct {
	Action  string   `json:"action"`
	Actor   string   `json:"actor"`
	Risk    string   `json:"risk"`
	Steps   []string `json:"steps"`
	Targets []struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	} `json:"targets"`
}

func decodePlan(raw json.RawMessage) (planDoc, bool) {
	var doc planDoc
	return doc, json.Unmarshal(raw, &doc) == nil && doc.Action != ""
}

// planLines is the spec §39.5 body: numbered steps, impact and risk.
func planLines(plan wire.CreatedPlan) []string {
	doc, ok := decodePlan(plan.Plan)
	if !ok {
		return []string{"(the plan could not be read)", "plan " + shortHash(plan.PlanHash)}
	}
	return append(docLines(doc), "plan "+shortHash(plan.PlanHash))
}

func docLines(doc planDoc) []string {
	lines := []string{"Action: " + textsafe.Line(doc.Action)}
	for i, step := range doc.Steps {
		lines = append(lines, fmt.Sprintf("%d. %s", i+1, textsafe.Line(step)))
	}
	if len(doc.Steps) == 0 {
		lines = append(lines, "(no steps listed)")
	}
	lines = append(lines, "", fmt.Sprintf("Impact: %d target(s)", len(doc.Targets)), "Risk: "+textsafe.Line(doc.Risk))
	return lines
}

// ---- service, setup, job actions ----------------------------------------------

func (m *Model) serviceAction(verb domain.ServiceVerb) tea.Cmd {
	s := m.service
	if !hasVerb(s.Actions, verb) {
		m.notice = notice{text: fmt.Sprintf("%s is not available for %s: the node needs setup (/ setup %s)", verb, s.Name, s.Node), isErr: true}
		return nil
	}
	title := fmt.Sprintf("%s %s on %s", verb, s.Name, s.Node)
	return m.planFor(textsafe.Line(title), nil, wire.CreatePlanRequest{
		Action:  verb.Action(),
		Targets: []wire.ResourceRef{{Type: domain.ResourceService, ID: s.ID}},
	})
}

func hasVerb(verbs []domain.ServiceVerb, verb domain.ServiceVerb) bool {
	for _, v := range verbs {
		if v == verb {
			return true
		}
	}
	return false
}

// setupNode plans node.setup from the palette words after the node name.
// Without unit words the node keeps the grants it has.
func (m *Model) setupNode(n wire.Node, words []string) tea.Cmd {
	w, err := parseSetupWords(words)
	if err != nil {
		m.notice = notice{text: "setup: " + err.Error(), isErr: true}
		return nil
	}
	grants, kept, err := wire.SetupUnits(w.units, w.noUnits, n.Setup)
	if err != nil {
		m.notice = notice{text: "setup: " + err.Error(), isErr: true}
		return nil
	}
	mode := logsModeDefault
	if w.broker {
		mode = logsModeBroker
	}
	var warnings []string
	if w.docker {
		warnings = append(warnings, dockerRootWarning)
	}
	params := wire.SetupParameters(w.docker, mode, grants)
	details := []string{textsafe.Line(wire.UnitsChange(n.Setup, grants, kept))}
	if w.tunnel {
		params["tunnel"] = "true"
		details = append([]string{textsafe.Line(transportPreview(n.Endpoint.TunnelHostname))}, details...)
	}
	cmd := m.planFor("Set up "+textsafe.Line(n.Name), warnings, wire.CreatePlanRequest{
		Action:     "node.setup",
		Targets:    []wire.ResourceRef{{Type: domain.ResourceNode, ID: n.ID}},
		Parameters: params,
	})
	m.confirm.details = details
	return cmd
}

func transportPreview(hostname string) string {
	if hostname == "" {
		return "transport: cloudflare (experimental)"
	}
	return "transport: cloudflare (experimental) via " + hostname
}

// disableTunnel plans node.tunnel.disable: the node goes back to direct SSH.
func (m *Model) disableTunnel(n wire.Node) tea.Cmd {
	cmd := m.planFor("Disable the tunnel on "+textsafe.Line(n.Name), nil, wire.CreatePlanRequest{
		Action:  "node.tunnel.disable",
		Targets: []wire.ResourceRef{{Type: domain.ResourceNode, ID: n.ID}},
	})
	m.confirm.details = []string{textsafe.Line("transport: " + string(n.Endpoint.Transport.Effective()) + " -> direct (Cloudflare Tunnel support is experimental)")}
	return cmd
}

type setupWords struct {
	docker, broker, noUnits, tunnel bool
	units                           []string
}

// parseSetupWords reads "docker", "broker", "tunnel", "no-units" and "unit <spec>"
// (repeatable) in one pass; the word after "unit" is always a unit.
func parseSetupWords(words []string) (setupWords, error) {
	var w setupWords
	for len(words) > 0 {
		word := words[0]
		words = words[1:]
		switch word {
		case "docker":
			w.docker = true
		case "broker":
			w.broker = true
		case "tunnel":
			w.tunnel = true
		case "no-units":
			w.noUnits = true
		case "unit":
			if len(words) == 0 {
				return setupWords{}, fmt.Errorf("unit needs a unit name, as in unit nginx.service")
			}
			w.units = append(w.units, words[0])
			words = words[1:]
		default:
			return setupWords{}, fmt.Errorf("unknown word %q (docker, broker, tunnel, unit <unit>[:verbs], no-units)", word)
		}
	}
	return w, nil
}

func (m *Model) probeNode(n wire.Node) tea.Cmd {
	api := m.api
	return m.act(func(ctx context.Context) (string, error) {
		sub, err := api.ProbeNode(ctx, n.ID)
		return "probe of " + textsafe.Line(n.Name) + ": " + submissionNotice(sub), err
	})
}

func (m *Model) cancelJob(j wire.Job) tea.Cmd {
	if !isActive(j.State) {
		m.notice = notice{text: fmt.Sprintf("job %s already finished (%s)", shortID(j.ID), j.State)}
		return nil
	}
	api := m.api
	m.confirm = &confirmation{
		title: fmt.Sprintf("Cancel job %s (%s)", shortID(j.ID), textsafe.Line(j.Type)),
		lines: []string{"State: " + string(j.State), "plan " + shortHash(j.PlanHash)},
		run: func(ctx context.Context) (string, error) {
			job, err := api.CancelJob(ctx, j.ID, j.PlanHash)
			return fmt.Sprintf("job %s %s", shortID(job.ID), job.State), err
		},
	}
	return nil
}

// ---- approvals (spec §39.5) ----------------------------------------------------

func (m *Model) selectedApproval() (wire.Approval, bool) {
	if m.apprCur < 0 || m.apprCur >= len(m.approvals) {
		return wire.Approval{}, false
	}
	return m.approvals[m.apprCur], true
}

func (m *Model) approve(a wire.Approval) tea.Cmd {
	api := m.api
	return m.act(func(ctx context.Context) (string, error) {
		job, err := api.Approve(ctx, a.Job.ID, wire.DecisionRequest{PlanHash: a.Job.PlanHash})
		return fmt.Sprintf("approved job %s (%s)", shortID(job.ID), job.State), err
	})
}

func (m *Model) rejectWithReason(a wire.Approval) tea.Cmd {
	api := m.api
	return m.openPrompt("reject reason:", "why is this plan rejected?", func(m *Model, reason string) tea.Cmd {
		if reason == "" {
			m.notice = notice{text: "a reason is required to reject", isErr: true}
			return nil
		}
		return m.act(func(ctx context.Context) (string, error) {
			job, err := api.Reject(ctx, a.Job.ID, wire.DecisionRequest{PlanHash: a.Job.PlanHash, Reason: reason})
			return fmt.Sprintf("rejected job %s (%s)", shortID(job.ID), job.State), err
		})
	})
}

// ---- prompt and command palette ---------------------------------------------------

type prompt struct {
	hint   string
	submit func(m *Model, text string) tea.Cmd
}

func (m *Model) openPrompt(label, hint string, submit func(m *Model, text string) tea.Cmd) tea.Cmd {
	m.input.Reset()
	m.input.Prompt = label + " "
	m.input.SetWidth(max(m.width-len(label)-6, 10))
	_ = m.input.Focus() // the cursor stays solid: no blink timers
	m.prompt = &prompt{hint: hint, submit: submit}
	return nil
}

func (m *Model) promptKey(key tea.KeyPressMsg) tea.Cmd {
	switch key.String() {
	case "esc", "ctrl+c":
		m.prompt = nil
		m.input.Blur()
		return nil
	case "enter":
		submit, text := m.prompt.submit, strings.TrimSpace(m.input.Value())
		m.prompt = nil
		m.input.Blur()
		return submit(m, text)
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(key)
	return cmd
}

const (
	paletteHint     = "ssh <node> [tool] · logs <service> · services <node> · setup <node> [docker] [broker] [tunnel] [unit <unit>[:verbs]]… [no-units] · tunnel-disable <node> · probe <node> · power <node> <verb> · refresh [proxmox [provider]] · deploy <app> <env> · rollback <app> <env>"
	paletteShortcut = "ssh · logs · services · setup · probe · power · refresh · deploy · rollback   (? arguments)"
)

func (m *Model) openPalette() tea.Cmd {
	return m.openPrompt("/", paletteShortcut, (*Model).runCommand)
}

func (m *Model) runCommand(line string) tea.Cmd {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return nil
	}
	cmd, args := fields[0], fields[1:]
	switch cmd {
	case "refresh":
		return m.commandRefresh(args)
	case "power":
		return m.commandPower(args)
	case "logs":
		return m.commandLogs(args)
	case wizardDeploy, wizardRollback:
		return m.commandDeploy(cmd, args)
	case "ssh", "services", "setup", "tunnel-disable", "probe":
		return m.commandOnNode(cmd, args)
	}
	m.notice = notice{text: fmt.Sprintf("unknown command %q: %s", cmd, paletteHint), isErr: true}
	return nil
}

// commandDeploy starts the creation wizard or the rollback review of an
// app's environment.
func (m *Model) commandDeploy(cmd string, args []string) tea.Cmd {
	if len(args) != 2 {
		m.notice = notice{text: "usage: " + cmd + " <app> <environment>", isErr: true}
		return nil
	}
	return m.startWizard(cmd, args[0], args[1])
}

func (m *Model) commandRefresh(args []string) tea.Cmd {
	switch {
	case len(args) == 0:
		return m.reload(true, m.screenLoaders()...)
	case args[0] == providerTypeProxmox && len(args) <= 2:
		return m.refreshProxmox(strings.Join(args[1:], ""))
	}
	m.notice = notice{text: "usage: refresh [proxmox [provider]]", isErr: true}
	return nil
}

// refreshProxmox runs a discovery now on every Proxmox provider, or on the
// one named. Nothing changes on the cluster: only what SuperMgmt knows of it.
func (m *Model) refreshProxmox(name string) tea.Cmd {
	api := m.api
	m.say("refreshing Proxmox…")
	return m.run(refreshTimeout, true, func(ctx context.Context) (string, error) {
		page, err := api.ListProviders(ctx, wire.PageQuery{Limit: wire.MaxLimit})
		if err != nil {
			return "", err
		}
		var refreshed, failed []string
		for _, p := range page.Items {
			if p.Type != providerTypeProxmox || (name != "" && !strings.EqualFold(p.Name, name)) {
				continue
			}
			got, err := api.RefreshProvider(ctx, p.ID)
			switch {
			case err != nil:
				return "", fmt.Errorf("%s: %w", p.Name, err)
			case got.Status != providerStatusOK:
				failed = append(failed, textsafe.Line(p.Name+": "+dashIfEmpty(got.LastError)))
			default:
				refreshed = append(refreshed, textsafe.Line(p.Name))
			}
		}
		switch {
		case len(failed) > 0:
			return "", errors.New(strings.Join(failed, "; "))
		case len(refreshed) == 0 && name != "":
			return "", fmt.Errorf("no Proxmox provider named %q", name)
		case len(refreshed) == 0:
			return "", errors.New("no Proxmox provider is configured")
		}
		return "refreshed " + strings.Join(refreshed, ", "), nil
	})
}

// commandPower opens the plan of a power action on a Proxmox guest. stop is
// high risk: the plan shows it and whether it waits for approval.
func (m *Model) commandPower(args []string) tea.Cmd {
	if len(args) != 2 {
		m.notice = notice{text: "usage: power <node> <" + strings.Join(powerVerbs, "|") + ">", isErr: true}
		return nil
	}
	n, err := m.resolveNode(args[0])
	if err == nil {
		err = powerTargetError(n, args[1])
	}
	if err != nil {
		m.notice = notice{text: err.Error(), isErr: true}
		return nil
	}
	verb := args[1]
	var warnings []string
	if verb == "stop" {
		warnings = append(warnings, "stop cuts the guest's power without a clean shutdown; shutdown lets its OS stop first")
	}
	return m.planFor(textsafe.Line(fmt.Sprintf("Power %s: %s", verb, n.Name)), warnings, wire.CreatePlanRequest{
		Action:     actionProxmoxVMPower,
		Targets:    []wire.ResourceRef{{Type: domain.ResourceNode, ID: n.ID}},
		Parameters: map[string]any{"verb": verb},
	})
}

const (
	actionProxmoxVMPower = "proxmox.vm.power"
	providerTypeProxmox  = "proxmox"
	providerStatusOK     = "ok"
)

var powerVerbs = []string{"start", "shutdown", "reboot", "stop"}

// powerTargetError says why a node cannot be powered, before asking the daemon.
func powerTargetError(n wire.Node, verb string) error {
	name := textsafe.Line(n.Name)
	switch g := n.Proxmox; {
	case !slices.Contains(powerVerbs, verb):
		return fmt.Errorf("unknown power action %q: want %s", verb, strings.Join(powerVerbs, ", "))
	case g == nil || g.Type == proxmoxClusterNode:
		return fmt.Errorf("%s is not a Proxmox VM or container", name)
	case g.Template:
		return fmt.Errorf("%s is a template and cannot be powered", name)
	case g.Absent:
		return fmt.Errorf("%s is gone from Proxmox (absent)", name)
	case g.Inaccessible:
		return fmt.Errorf("%s is inaccessible: the token cannot see it", name)
	}
	return nil
}

func (m *Model) commandLogs(args []string) tea.Cmd {
	if len(args) != 1 {
		m.notice = notice{text: "usage: logs <service>", isErr: true}
		return nil
	}
	s, err := m.resolveService(args[0])
	if err != nil {
		m.notice = notice{text: err.Error(), isErr: true}
		return nil
	}
	m.node = s.NodeID
	return m.openService(s, screenLogs)
}

func (m *Model) commandOnNode(cmd string, args []string) tea.Cmd {
	if len(args) == 0 {
		m.notice = notice{text: "usage: " + cmd + " <node>", isErr: true}
		return nil
	}
	n, err := m.resolveNode(args[0])
	if err != nil {
		m.notice = notice{text: err.Error(), isErr: true}
		return nil
	}
	rest := args[1:]
	switch cmd {
	case "services":
		return m.openNode(n, screenServices)
	case "probe":
		return m.probeNode(n)
	case "setup":
		return m.setupNode(n, rest)
	case "tunnel-disable":
		return m.disableTunnel(n)
	}
	tool := wire.ToolShell
	if len(rest) > 0 {
		tool = wire.Tool(rest[0])
	}
	return m.startHandoff(n, tool)
}

// resolveNode finds a node by id, exact name, or unique name prefix.
func (m *Model) resolveNode(ref string) (wire.Node, error) {
	var prefixed []wire.Node
	for _, n := range m.nodes {
		if string(n.ID) == ref || strings.EqualFold(n.Name, ref) {
			return n, nil
		}
		if strings.HasPrefix(strings.ToLower(n.Name), strings.ToLower(ref)) {
			prefixed = append(prefixed, n)
		}
	}
	switch len(prefixed) {
	case 0:
		return wire.Node{}, fmt.Errorf("no node matches %q", ref)
	case 1:
		return prefixed[0], nil
	}
	names := make([]string, len(prefixed))
	for i, n := range prefixed {
		names[i] = n.Name
	}
	return wire.Node{}, fmt.Errorf("%q matches several nodes: %s", ref, strings.Join(names, ", "))
}

// resolveService finds a service among those already loaded for any node.
func (m *Model) resolveService(ref string) (wire.Service, error) {
	var found []wire.Service
	for _, list := range m.svcCache {
		for _, s := range list {
			if string(s.ID) == ref || strings.EqualFold(s.Name, ref) {
				found = append(found, s)
			}
		}
	}
	switch len(found) {
	case 0:
		return wire.Service{}, fmt.Errorf("service %q is not loaded yet: open its node's services first (/ services <node>)", ref)
	case 1:
		return found[0], nil
	}
	return wire.Service{}, fmt.Errorf("%q exists on several nodes; open the node's services and pick it there", ref)
}
