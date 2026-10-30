package tui

import (
	"context"
	"regexp"
	"sync"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

var epoch = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

const (
	idWeb     domain.ID = "0192a000-0000-7000-8000-00000000a001"
	idDB      domain.ID = "0192a000-0000-7000-8000-00000000a002"
	idLaptop  domain.ID = "0192a000-0000-7000-8000-00000000a003"
	idLab     domain.ID = "0192a000-0000-7000-8000-00000000a004"
	idAPI     domain.ID = "0192a000-0000-7000-8000-00000000b001"
	idRedis   domain.ID = "0192a000-0000-7000-8000-00000000b002"
	idJob     domain.ID = "0192a000-0000-7000-8000-00000000c001"
	idJobDone domain.ID = "0192a000-0000-7000-8000-00000000c002"
	idPlan    domain.ID = "0192a000-0000-7000-8000-00000000d001"
	planHash            = "5f1d2c3b4a69788796a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3"
	jobHash             = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
)

// fakeAPI is a tui.API with fixture data. Hooks run first on every call and
// may block or fail it; calls are counted per method.
type fakeAPI struct {
	mu    sync.Mutex
	calls map[string]int
	hooks map[string]func(ctx context.Context) error

	providers []wire.Provider
	nodes     []wire.Node
	services  map[domain.ID][]wire.Service
	jobs      []wire.Job
	approvals []wire.Approval
	events    []wire.Event
	plan      wire.CreatedPlan
	handoff   func(ctx context.Context, node domain.ID, tool string) (Handoff, error)

	approved, rejected []wire.DecisionRequest
	submitted          []domain.ID
	planRequests       []wire.CreatePlanRequest
	cancelled          []string
	refreshed          []domain.ID
	enrollments        []wire.StartTunnelEnrollmentRequest
	refreshOutcome     map[domain.ID]wire.Provider // what a refresh answers; default: the provider, status ok
}

func (f *fakeAPI) enter(ctx context.Context, name string) error {
	f.mu.Lock()
	f.calls[name]++
	hook := f.hooks[name]
	f.mu.Unlock()
	if hook != nil {
		return hook(ctx)
	}
	return nil
}

func (f *fakeAPI) count(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[name]
}

func (f *fakeAPI) hook(name string, fn func(ctx context.Context) error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hooks[name] = fn
}

func (f *fakeAPI) Me(ctx context.Context) (wire.Me, error) {
	return wire.Me{
		IdentityID: idLaptop, ActorType: domain.ActorHuman, DisplayName: "alex", Credential: domain.CredentialSession,
		InstanceMode: "local", Roles: []string{"admin"},
	}, f.enter(ctx, "Me")
}

func (f *fakeAPI) ListProviders(ctx context.Context, _ wire.PageQuery) (wire.Page[wire.Provider], error) {
	if err := f.enter(ctx, "ListProviders"); err != nil {
		return wire.Page[wire.Provider]{}, err
	}
	return wire.Page[wire.Provider]{Items: f.providers}, nil
}

func (f *fakeAPI) RefreshProvider(ctx context.Context, id domain.ID) (wire.Provider, error) {
	err := f.enter(ctx, "RefreshProvider")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refreshed = append(f.refreshed, id)
	if p, ok := f.refreshOutcome[id]; ok {
		return p, err
	}
	for _, p := range f.providers {
		if p.ID == id {
			p.Status = "ok"
			return p, err
		}
	}
	return wire.Provider{}, err
}

func (f *fakeAPI) ListNodes(ctx context.Context, _ wire.NodeQuery) (wire.Page[wire.Node], error) {
	if err := f.enter(ctx, "ListNodes"); err != nil {
		return wire.Page[wire.Node]{}, err
	}
	return wire.Page[wire.Node]{Items: f.nodes}, nil
}

func (f *fakeAPI) GetNode(ctx context.Context, id domain.ID, _ bool) (wire.Node, error) {
	if err := f.enter(ctx, "GetNode"); err != nil {
		return wire.Node{}, err
	}
	for _, n := range f.nodes {
		if n.ID == id {
			return n, nil
		}
	}
	return wire.Node{}, context.Canceled
}

func (f *fakeAPI) ProbeNode(ctx context.Context, _ domain.ID) (wire.Submission, error) {
	err := f.enter(ctx, "ProbeNode")
	return wire.Submission{Job: wire.Job{ID: idJob, State: domain.JobQueued}}, err
}

func (f *fakeAPI) StartTunnelEnrollment(ctx context.Context, r wire.StartTunnelEnrollmentRequest) (wire.Direct[wire.TunnelEnrollment], error) {
	err := f.enter(ctx, "StartTunnelEnrollment")
	f.mu.Lock()
	f.enrollments = append(f.enrollments, r)
	f.mu.Unlock()
	return wire.Direct[wire.TunnelEnrollment]{Applied: &wire.TunnelEnrollment{Name: r.Name, Phase: "started"}}, err
}

func (f *fakeAPI) ListServices(ctx context.Context, node domain.ID, _ wire.PageQuery) (wire.Page[wire.Service], error) {
	if err := f.enter(ctx, "ListServices"); err != nil {
		return wire.Page[wire.Service]{}, err
	}
	return wire.Page[wire.Service]{Items: f.services[node]}, nil
}

func (f *fakeAPI) GetService(ctx context.Context, id domain.ID) (wire.Service, error) {
	if err := f.enter(ctx, "GetService"); err != nil {
		return wire.Service{}, err
	}
	for _, list := range f.services {
		for _, s := range list {
			if s.ID == id {
				return s, nil
			}
		}
	}
	return wire.Service{}, context.Canceled
}

func (f *fakeAPI) ServiceLogs(ctx context.Context, id domain.ID, _ wire.LogQuery) (wire.LogChunk, error) {
	err := f.enter(ctx, "ServiceLogs")
	lines := make([]string, 40)
	for i := range lines {
		lines[i] = "line " + string(rune('A'+i%26)) + " of the api log"
	}
	return wire.LogChunk{ServiceID: id, Lines: lines, CollectedAt: epoch}, err
}

func (f *fakeAPI) ServiceAction(ctx context.Context, _ domain.ID, _ domain.ServiceVerb) (wire.Submission, error) {
	return wire.Submission{}, f.enter(ctx, "ServiceAction")
}

func (f *fakeAPI) CreatePlan(ctx context.Context, r wire.CreatePlanRequest) (wire.CreatedPlan, error) {
	f.mu.Lock()
	f.planRequests = append(f.planRequests, r)
	f.mu.Unlock()
	return f.plan, f.enter(ctx, "CreatePlan")
}

func (f *fakeAPI) SubmitPlan(ctx context.Context, plan domain.ID, hash string) (wire.Submission, error) {
	err := f.enter(ctx, "SubmitPlan")
	f.mu.Lock()
	f.submitted = append(f.submitted, plan)
	f.mu.Unlock()
	state := domain.JobQueued
	if f.plan.Policy.ApprovalRequired {
		state = domain.JobAwaitingApproval
	}
	_ = hash
	return wire.Submission{Job: wire.Job{ID: idJob, State: state}}, err
}

func (f *fakeAPI) ListApprovals(ctx context.Context, _ wire.PageQuery) (wire.Page[wire.Approval], error) {
	if err := f.enter(ctx, "ListApprovals"); err != nil {
		return wire.Page[wire.Approval]{}, err
	}
	return wire.Page[wire.Approval]{Items: f.approvals}, nil
}

func (f *fakeAPI) Approve(ctx context.Context, job domain.ID, r wire.DecisionRequest) (wire.Job, error) {
	err := f.enter(ctx, "Approve")
	f.mu.Lock()
	f.approved = append(f.approved, r)
	f.mu.Unlock()
	return wire.Job{ID: job, State: domain.JobQueued}, err
}

func (f *fakeAPI) Reject(ctx context.Context, job domain.ID, r wire.DecisionRequest) (wire.Job, error) {
	err := f.enter(ctx, "Reject")
	f.mu.Lock()
	f.rejected = append(f.rejected, r)
	f.mu.Unlock()
	return wire.Job{ID: job, State: domain.JobCancelled}, err
}

func (f *fakeAPI) ListJobs(ctx context.Context, _ wire.JobQuery) (wire.Page[wire.Job], error) {
	if err := f.enter(ctx, "ListJobs"); err != nil {
		return wire.Page[wire.Job]{}, err
	}
	return wire.Page[wire.Job]{Items: f.jobs}, nil
}

func (f *fakeAPI) GetJob(ctx context.Context, id domain.ID) (wire.JobDetail, error) {
	if err := f.enter(ctx, "GetJob"); err != nil {
		return wire.JobDetail{}, err
	}
	for _, j := range f.jobs {
		if j.ID == id {
			return wire.JobDetail{Job: j, Intents: []wire.Intent{{
				ID: "intent-1", Step: "restart", State: domain.IntentCompleted, Operation: "service.restart",
				Target: "sm-demo.service", Outcome: "complete",
				PreState: []byte(`{"invocation_id":"aaa","active_state":"active"}`),
				Evidence: []byte(`{"proof":"systemd_no_jobs","invocation_id":"bbb"}`),
			}}}, nil
		}
	}
	return wire.JobDetail{}, context.Canceled
}

func (f *fakeAPI) CancelJob(ctx context.Context, id domain.ID, hash string) (wire.Job, error) {
	err := f.enter(ctx, "CancelJob")
	f.mu.Lock()
	f.cancelled = append(f.cancelled, hash)
	f.mu.Unlock()
	return wire.Job{ID: id, State: domain.JobCancelled}, err
}

func (f *fakeAPI) ResolveJob(context.Context, domain.ID, wire.ResolveRequest) (wire.Job, error) {
	return wire.Job{}, nil
}

func (f *fakeAPI) ListEvents(ctx context.Context, _ wire.EventQuery) (wire.Page[wire.Event], error) {
	if err := f.enter(ctx, "ListEvents"); err != nil {
		return wire.Page[wire.Event]{}, err
	}
	return wire.Page[wire.Event]{Items: f.events}, nil
}

func (f *fakeAPI) OpenSession(ctx context.Context, node domain.ID, tool string) (Handoff, error) {
	if err := f.enter(ctx, "OpenSession"); err != nil {
		return Handoff{}, err
	}
	return f.handoff(ctx, node, tool)
}

func newFake() *fakeAPI {
	caps := func(names ...string) []wire.Capability {
		out := make([]wire.Capability, len(names))
		for i, n := range names {
			out[i] = wire.Capability{Name: n, Available: true, CheckedAt: epoch}
		}
		return out
	}
	seen := epoch.Add(-time.Minute)
	f := &fakeAPI{calls: map[string]int{}, hooks: map[string]func(context.Context) error{}}
	f.providers = []wire.Provider{
		{ID: "0192a000-0000-7000-8000-00000000e001", Type: "ssh", Name: "ssh", Origin: domain.ProviderStatic, Status: "ready", LastSyncAt: &seen},
		{ID: "0192a000-0000-7000-8000-00000000e002", Type: "local", Name: "local", Origin: domain.ProviderAPI, Status: "ready"},
	}
	f.nodes = []wire.Node{
		{
			ID: idWeb, Name: "web-1", Kind: "ssh", Provider: "ssh", Environment: "production", ManagementState: domain.ManagementManaged,
			Reachability: domain.ReachabilityReachable, OS: "debian 13", Arch: "amd64", Tags: []string{"edge"}, LastSeenAt: &seen,
			Endpoint:     wire.Endpoint{Host: "10.0.0.5", Port: 22, User: "supermgmt", AdminUser: "alex"},
			Capabilities: caps("node.ssh", "docker.read", "tool.lazydocker", "service.read", "service.restart"),
			Metrics:      &wire.Metrics{CPUPercent: 17, MemoryUsedBytes: 41, MemoryTotalBytes: 100, DiskUsedBytes: 38, DiskTotalBytes: 100},
			Setup:        &wire.Setup{SetupVersion: 1, LogsMode: "journal-group", DockerAccess: true, Units: []wire.UnitGrant{{Unit: "sm-demo.service"}}},
			Addresses:    []wire.Address{{Address: "10.0.0.5"}}, Connection: wire.Connection{State: wire.ConnConnected},
		},
		{
			ID: idDB, Name: "db-1", Kind: "ssh", Provider: "ssh", Environment: "production", ManagementState: domain.ManagementManaged,
			Reachability: domain.ReachabilityReachable, Capabilities: caps("node.ssh", "service.read"), LastSeenAt: &seen,
			Endpoint: wire.Endpoint{Host: "10.0.0.6", Port: 22, User: "alex", AdminUser: "alex"},
		},
		{
			ID: idLaptop, Name: "laptop", Kind: "local", Provider: "local", Environment: "dev", ManagementState: domain.ManagementManaged,
			Reachability: domain.ReachabilityReachable, Capabilities: caps("node.read"), LastSeenAt: &seen,
		},
		{
			ID: idLab, Name: "lab-1", Kind: "ssh", Provider: "ssh", Environment: "staging", ManagementState: domain.ManagementManaged,
			Reachability: domain.ReachabilityUnreachable, Stale: true, Capabilities: caps("node.ssh"),
			Endpoint:   wire.Endpoint{Host: "10.0.0.9", Port: 22, User: "alex", AdminUser: "alex"},
			Connection: wire.Connection{State: wire.ConnBackoff, LastError: "dial tcp 10.0.0.9:22: i/o timeout"},
		},
	}
	f.services = map[domain.ID][]wire.Service{
		idWeb: {
			{
				ID: idAPI, NodeID: idWeb, Node: "web-1", RuntimeType: domain.RuntimeSystemd, Kind: domain.ServiceSystemdUnit, NativeID: "sm-demo.service", Name: "sm-demo.service",
				Status: "active", Health: "healthy", Actions: []domain.ServiceVerb{domain.VerbRestart, domain.VerbStart, domain.VerbStop}, LastSeenAt: &seen,
				Metadata: map[string]any{"sub_state": "running"},
			},
			{
				ID: idRedis, NodeID: idWeb, Node: "web-1", RuntimeType: domain.RuntimeDocker, Kind: domain.ServiceDockerContainer, NativeID: "sm-demo-web", Name: "sm-demo-web",
				Status: "running", Health: "unhealthy",
			},
		},
	}
	started := epoch.Add(-time.Hour)
	f.jobs = []wire.Job{
		{
			ID: idJob, Type: "service.restart", Resource: wire.ResourceRef{Type: domain.ResourceService, ID: idAPI}, State: domain.JobAwaitingApproval,
			Risk: domain.RiskHigh, RetryClass: domain.RetryNonRetryable, PlanHash: jobHash, MaxAttempts: 1, CreatedAt: epoch.Add(-time.Minute),
		},
		{
			ID: idJobDone, Type: "node.probe", Resource: wire.ResourceRef{Type: domain.ResourceNode, ID: idWeb}, State: domain.JobSucceeded,
			Risk: domain.RiskRead, Attempts: 1, MaxAttempts: 3, CreatedAt: started, StartedAt: &started, FinishedAt: &started,
		},
	}
	f.plan = wire.CreatedPlan{
		PlanID: idPlan, PlanHash: planHash, ExpiresAt: epoch.Add(24 * time.Hour),
		Plan:   []byte(`{"action":"service.restart","risk":"high","steps":["Stop sm-demo.service","Start sm-demo.service","Confirm the unit is active"],"targets":[{"type":"service","id":"` + string(idAPI) + `"}]}`),
		Policy: wire.Policy{Decision: "allow", ApprovalRequired: true, Quorum: 1},
	}
	f.approvals = []wire.Approval{{Job: f.jobs[0], Plan: f.plan.Plan, Environments: []string{"production"}, Quorum: 1, ExpiresAt: epoch.Add(24 * time.Hour)}}
	f.events = []wire.Event{
		{EventID: "e1", Seq: 1, Timestamp: epoch.Add(-2 * time.Minute), Action: "node.probe", Severity: domain.SeverityInfo, Result: domain.ResultSucceeded, CorrelationID: "c-111"},
		{EventID: "e2", Seq: 2, Timestamp: epoch.Add(-time.Minute), Action: "service.restart", Severity: domain.SeverityWarning, Result: domain.ResultPending, CorrelationID: "c-222"},
	}
	return f
}

// harness drives a Model the way the Bubble Tea runtime does: it runs the
// commands Update returns and feeds their messages back.
type harness struct {
	t *testing.T
	m *Model
}

func newHarness(t *testing.T, api API, w, h int) *harness {
	t.Helper()
	m := New(api, Options{Timeout: time.Second, Location: time.UTC})
	hs := &harness{t: t, m: m}
	hs.send(tea.WindowSizeMsg{Width: w, Height: h})
	return hs
}

func (h *harness) send(msg tea.Msg) tea.Cmd {
	_, cmd := h.m.Update(msg)
	return cmd
}

// drain runs cmd and everything it leads to until no command is left.
func (h *harness) drain(cmd tea.Cmd) {
	h.t.Helper()
	queue := []tea.Cmd{cmd}
	for len(queue) > 0 {
		c := queue[0]
		queue = queue[1:]
		if c == nil {
			continue
		}
		msg := c()
		if batch, ok := msg.(tea.BatchMsg); ok {
			queue = append(queue, batch...)
			continue
		}
		queue = append(queue, h.send(msg))
	}
}

func (h *harness) start() {
	h.t.Helper()
	h.drain(h.m.Init())
}

// press sends a key and drains what it triggers.
func (h *harness) press(keys ...string) {
	h.t.Helper()
	for _, k := range keys {
		h.drain(h.send(keyMsg(k)))
	}
}

func (h *harness) typeText(s string) {
	h.t.Helper()
	for _, r := range s {
		h.press(string(r))
	}
}

func (h *harness) view() string { return stripANSI(h.m.render()) }

func keyMsg(name string) tea.KeyPressMsg {
	switch name {
	case "enter":
		return tea.KeyPressMsg{Code: tea.KeyEnter}
	case "esc":
		return tea.KeyPressMsg{Code: tea.KeyEscape}
	case "down":
		return tea.KeyPressMsg{Code: tea.KeyDown}
	case "up":
		return tea.KeyPressMsg{Code: tea.KeyUp}
	case "ctrl+c":
		return tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl}
	}
	r := []rune(name)
	return tea.KeyPressMsg{Code: r[0], Text: name}
}

var ansiPattern = regexp.MustCompile("\x1b\\[[0-9;:?]*[ -/]*[@-~]|\x1b\\][^\a\x1b]*(\a|\x1b\\\\)")

func stripANSI(s string) string { return ansiPattern.ReplaceAllString(s, "") }
