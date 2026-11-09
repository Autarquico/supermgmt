package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/assistant"
	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/domain"
)

const (
	asstIdentity domain.ID = "0192a000-0000-7000-8000-00000000d001"
	asstOther    domain.ID = "0192a000-0000-7000-8000-00000000d002"
	asstJob      domain.ID = "0192a000-0000-7000-8000-00000000b101"
	asstOtherJob domain.ID = "0192a000-0000-7000-8000-00000000b102"
	asstService  domain.ID = "0192a000-0000-7000-8000-00000000c101"
	asstNode     domain.ID = "0192a000-0000-7000-8000-00000000c201"
	asstAPIHash            = "sha256:api-hash"
	asstPlan               = `{"action":"service.restart","risk":"medium","steps":["restart nginx on web-1"],"targets":[` +
		`{"type":"service","id":"0192a000-0000-7000-8000-00000000c101"},{"type":"node","id":"0192a000-0000-7000-8000-00000000c201"},` +
		`{"type":"service","id":"0192a000-0000-7000-8000-00000000c999"}]}`
)

type asstAPI struct {
	mu         sync.Mutex
	clients    []wire.MCPClient
	jobs       map[domain.ID]wire.Job
	approvals  []wire.Approval
	approved   []wire.DecisionRequest
	rejected   []wire.DecisionRequest
	getJobs    int
	listed     int
	approveErr error
}

func (a *asstAPI) ListMCPClients(context.Context) (wire.Page[wire.MCPClient], error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.listed++
	return wire.Page[wire.MCPClient]{Items: a.clients}, nil
}

func (a *asstAPI) GetJob(_ context.Context, id domain.ID) (wire.JobDetail, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.getJobs++
	job, ok := a.jobs[id]
	if !ok {
		return wire.JobDetail{}, errors.New("not found")
	}
	return wire.JobDetail{Job: job}, nil
}

func (a *asstAPI) ListApprovals(context.Context, wire.PageQuery) (wire.Page[wire.Approval], error) {
	return wire.Page[wire.Approval]{Items: a.approvals}, nil
}

func (a *asstAPI) GetService(_ context.Context, id domain.ID) (wire.Service, error) {
	if id == asstService {
		return wire.Service{ID: id, Name: "nginx", Node: "web-1"}, nil
	}
	return wire.Service{}, errors.New("not found")
}

func (a *asstAPI) GetNode(_ context.Context, id domain.ID, _ bool) (wire.Node, error) {
	if id == asstNode {
		return wire.Node{ID: id, Name: "web-1"}, nil
	}
	return wire.Node{}, errors.New("not found")
}

// Approve records the approval; the job leaves awaiting_approval only when the
// approval completes its quorum, as the real API does.
func (a *asstAPI) Approve(_ context.Context, id domain.ID, r wire.DecisionRequest) (wire.Job, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.approveErr != nil {
		return wire.Job{}, a.approveErr
	}
	a.approved = append(a.approved, r)
	job := a.jobs[id]
	for _, approval := range a.approvals {
		if approval.Job.ID == id && approval.Approvals+1 >= approval.Quorum {
			job.State = domain.JobQueued
		}
	}
	return job, nil
}

func (a *asstAPI) Reject(_ context.Context, id domain.ID, r wire.DecisionRequest) (wire.Job, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.rejected = append(a.rejected, r)
	return a.jobs[id], nil
}

// closeEvents in a scripted turn closes the event channel, as a session does after KindEnded.
var closeEvents = assistant.Event{}

// asstSession replays one scripted turn per Send.
type asstSession struct {
	events  chan assistant.Event
	turns   [][]assistant.Event
	sent    []string
	sendErr error // Send fails with it after replaying the next turn
}

func (s *asstSession) Start(context.Context) error    { return nil }
func (s *asstSession) Close() error                   { return nil }
func (s *asstSession) Events() <-chan assistant.Event { return s.events }

func (s *asstSession) Send(text string) error {
	s.sent = append(s.sent, text)
	if len(s.turns) == 0 {
		s.events <- assistant.Event{Kind: assistant.KindTurnDone}
		return nil
	}
	for _, ev := range s.turns[0] {
		if ev == closeEvents {
			close(s.events)
			continue
		}
		s.events <- ev
	}
	s.turns = s.turns[1:]
	return s.sendErr
}

func turn(events ...assistant.Event) []assistant.Event {
	return append(events, assistant.Event{Kind: assistant.KindTurnDone})
}

func said(text string) assistant.Event { return assistant.Event{Kind: assistant.KindText, Text: text} }

func approvalEvent(id domain.ID) assistant.Event {
	return assistant.Event{Kind: assistant.KindApproval, Approval: &assistant.Signal{JobID: id, Tool: "infra_restart_service"}}
}

// syncBuffer is the terminal: written by the command, read by the operator.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// operator types one line each time a prompt is waiting on the screen, never
// before: input typed ahead of a card is discarded, so a script must not do it.
type operator struct {
	screen *syncBuffer
	lines  []string
	seen   int
}

var promptEnds = []string{"> ", "] ", "reason (required): "}

func (o *operator) Read(p []byte) (int, error) {
	for range 5000 {
		out := o.screen.String()
		if len(out) > o.seen && endsWithAny(out, promptEnds) {
			o.seen = len(out)
			if len(o.lines) == 0 {
				return 0, io.EOF
			}
			line := o.lines[0] + "\n"
			o.lines = o.lines[1:]
			return copy(p, line), nil
		}
		time.Sleep(time.Millisecond)
	}
	return 0, io.EOF
}

func endsWithAny(s string, suffixes []string) bool {
	for _, suffix := range suffixes {
		if strings.HasSuffix(s, suffix) {
			return true
		}
	}
	return false
}

type asstRig struct {
	api         *asstAPI
	session     *asstSession
	cfg         assistant.Config
	launched    bool
	where       target
	interactive bool
	keychain    bool
	width       int
	claudeErr   error
	flushes     int
	rawStdin    io.Reader // replaces the operator when set
}

func newAsstRig(turns ...[]assistant.Event) *asstRig {
	active := wire.MCPClient{ID: "c1", IdentityID: asstIdentity, Name: "assistant", State: wire.MCPClientActive, OverHTTPS: true}
	pending := wire.Job{
		ID: asstJob, ActorID: asstIdentity, State: domain.JobAwaitingApproval, PlanHash: asstAPIHash,
		CreatedAt: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC),
	}
	other := wire.Job{ID: asstOtherJob, ActorID: asstOther, State: domain.JobAwaitingApproval, PlanHash: "sha256:other"}
	return &asstRig{
		api: &asstAPI{
			clients: []wire.MCPClient{active},
			jobs:    map[domain.ID]wire.Job{asstJob: pending, asstOtherJob: other},
			approvals: []wire.Approval{
				{Job: pending, Plan: []byte(asstPlan), Quorum: 1},
				{Job: other, Plan: []byte(asstPlan), Quorum: 1},
			},
		},
		session:     &asstSession{events: make(chan assistant.Event, 64), turns: turns},
		interactive: true,
		keychain:    true,
	}
}

// run executes `sm assistant args...` with the operator typing stdin's lines, each
// once the screen asks for it, and returns what it printed.
func (r *asstRig) run(t *testing.T, stdin string, env []string, args ...string) (string, error) {
	t.Helper()
	return r.runCtx(context.Background(), t, stdin, env, args...)
}

func (r *asstRig) runCtx(ctx context.Context, t *testing.T, stdin string, env []string, args ...string) (string, error) {
	t.Helper()
	if env == nil {
		env = []string{"HOME=" + t.TempDir()}
	}
	deps := assistantDeps{
		connect: func(*cobra.Command) (assistantAPI, target, error) { return r.api, r.where, nil },
		nativeStore: func() (client.CredentialStore, bool) {
			return asstStore{}, r.keychain
		},
		executable: func() (string, error) { return "/usr/local/bin/sm", nil },
		newSession: func(cfg assistant.Config) (assistant.Conversation, error) {
			r.cfg, r.launched = cfg, true
			return r.session, nil
		},
		interactive:     func(*cobra.Command) bool { return r.interactive },
		claudeAvailable: func() error { return r.claudeErr },
		flushInput:      func(*cobra.Command) { r.flushes++ },
		termWidth:       func(*cobra.Command) int { return r.width },
	}
	cmd := newAssistantCmdWith(env, deps) //nolint:contextcheck // the context reaches the command through ExecuteContext
	screen := &syncBuffer{}
	cmd.SetOut(screen)
	cmd.SetErr(screen)
	in := r.rawStdin
	if in == nil {
		var lines []string
		if stdin != "" {
			lines = strings.Split(strings.TrimSuffix(stdin, "\n"), "\n")
		}
		in = &operator{screen: screen, lines: lines}
	}
	cmd.SetIn(in)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(ctx)
	return screen.String(), err
}

type asstStore struct{}

func (asstStore) Get(context.Context, string) (string, error)         { return "smm_AbCdEfGhIjKlMnOp", nil }
func (asstStore) Set(context.Context, string, string) (string, error) { return "", nil }
func (asstStore) Delete(context.Context, string) error                { return nil }

func TestAssistantMissingClientPrintsTheAddLineAndDoesNotLaunch(t *testing.T) {
	r := newAsstRig()
	r.api.clients = nil
	_, err := r.run(t, "", nil)
	if err == nil || !strings.Contains(err.Error(), "sm mcp clients add assistant --keychain supermgmt-assistant") ||
		!strings.Contains(err.Error(), "approval may be needed") {
		t.Fatalf("error = %v", err)
	}
	if strings.Contains(err.Error(), "--https") || r.launched {
		t.Fatalf("local target must not ask for --https and must not launch: %v launched=%v", err, r.launched)
	}
}

func TestAssistantWithoutKeychainUsesATokenFile(t *testing.T) {
	r := newAsstRig()
	r.api.clients, r.keychain = nil, false
	home := t.TempDir()
	_, err := r.run(t, "", []string{"HOME=" + home})
	want := "--token-file " + shellQuoted(filepath.Join(filepath.Dir(localPaths([]string{"HOME=" + home}).Config), "assistant.token"))
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %v, want %q", err, want)
	}
}

func TestAssistantChecksForClaudeBeforeAnythingIsRegistered(t *testing.T) {
	r := newAsstRig()
	r.api.clients = nil
	r.claudeErr = assistant.ErrClaudeNotFound
	_, err := r.run(t, "", nil)
	if !errors.Is(err, assistant.ErrClaudeNotFound) || r.api.listed != 0 || r.launched {
		t.Fatalf("err=%v listed=%d launched=%v", err, r.api.listed, r.launched)
	}
}

func TestAssistantStopsBeforeLaunchingWhenTheTokenExpired(t *testing.T) {
	r := newAsstRig()
	expired := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	r.api.clients[0].TokenExpiresAt = &expired
	_, err := r.run(t, "", nil)
	if err == nil || !strings.Contains(err.Error(), "expired") || !strings.Contains(err.Error(), "sm mcp clients remove assistant") || r.launched {
		t.Fatalf("error = %v launched=%v", err, r.launched)
	}
}

func TestAssistantRemoteTargetNeedsHTTPS(t *testing.T) {
	r := newAsstRig()
	r.where = target{name: "prod", remote: &client.Profile{URL: "https://sm.example"}}
	r.api.clients[0].OverHTTPS = false
	_, err := r.run(t, "", nil)
	if err == nil || !strings.Contains(err.Error(), "--https") || r.launched {
		t.Fatalf("error = %v launched=%v", err, r.launched)
	}
	r.api.clients = nil
	_, err = r.run(t, "", nil)
	if err == nil || !strings.Contains(err.Error(), "sm mcp clients add assistant --keychain supermgmt-assistant-p4-prod --https") {
		t.Fatalf("missing remote client: %v", err)
	}
}

func TestAssistantTokenLocationBelongsToOneClientOnOneTarget(t *testing.T) {
	deps := assistantDeps{nativeStore: func() (client.CredentialStore, bool) { return asstStore{}, true }}
	env := []string{"HOME=" + t.TempDir()}
	remote := func(name string) target { return target{name: name, remote: &client.Profile{URL: "https://" + name}} }
	cases := []struct {
		client string
		where  target
		want   string
	}{
		{"assistant", target{}, "supermgmt-assistant"},
		{"assistant", remote("prod"), "supermgmt-assistant-p4-prod"},
		{"assistant", remote("staging"), "supermgmt-assistant-p7-staging"},
		{"other", target{}, "supermgmt-assistant-c-other"},
		{"other", remote("prod"), "supermgmt-assistant-p4-prod-c-other"},
		{"a/b c", target{}, "supermgmt-assistant-c-a_b_c"},
		{"lab", target{}, "supermgmt-assistant-c-lab"},
		{"assistant", remote("lab"), "supermgmt-assistant-p3-lab"},
		{"x-p3-y", target{}, "supermgmt-assistant-c-x-p3-y"},
		{"c-y", remote("x"), "supermgmt-assistant-p1-x-c-c-y"},
		{"y", remote("x-c"), "supermgmt-assistant-p3-x-c-c-y"},
	}
	seen := map[string]bool{}
	for _, c := range cases {
		got := assistantTokenAt(env, deps, c.client, c.where).keychain
		if got != c.want {
			t.Errorf("%s on %+v: %q, want %q", c.client, c.where, got, c.want)
		}
		if seen[got] {
			t.Errorf("%q is the location of two targets", got)
		}
		seen[got] = true
	}
	deps.nativeStore = func() (client.CredentialStore, bool) { return nil, false }
	file := assistantTokenAt(env, deps, "other", remote("prod")).file
	if filepath.Base(file) != "assistant-p4-prod-c-other.token" {
		t.Errorf("file = %s", file)
	}
}

// The recipe printed for a client that must be replaced is run as printed: the
// removal frees nothing on its own, so the add only succeeds because of the
// step in between.
func TestAssistantReplaceRecipeWorksAsPrintedWithATokenFile(t *testing.T) {
	r := newAsstRig()
	r.keychain = false
	r.where = target{name: "prod", remote: &client.Profile{URL: "https://sm.example"}}
	r.api.clients[0].OverHTTPS = false
	home := t.TempDir()
	env := []string{"HOME=" + home}
	token := assistantTokenAt(env, assistantDeps{nativeStore: func() (client.CredentialStore, bool) { return nil, false }}, "assistant", r.where)
	if err := os.MkdirAll(filepath.Dir(token.file), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(token.file, []byte("smm_old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := r.run(t, "", env)
	if err == nil {
		t.Fatal("a client without --https on a remote target was accepted")
	}
	var steps []string
	for _, line := range strings.Split(err.Error(), "\n") {
		if strings.HasPrefix(line, "  ") {
			steps = append(steps, strings.TrimSpace(line))
		}
	}
	if len(steps) != 3 || !strings.HasPrefix(steps[0], "sm mcp clients remove ") || !strings.HasPrefix(steps[2], "sm mcp clients add ") {
		t.Fatalf("steps = %q", steps)
	}
	if sink, err := openFileSink(token.file); err == nil {
		sink.Abandon()
		t.Fatal("the location was free before the printed step ran")
	}
	path, ok := strings.CutPrefix(steps[1], "rm -f ")
	if !ok || path != shellQuoted(token.file) || !strings.Contains(steps[2], "--token-file "+shellQuoted(token.file)) {
		t.Fatalf("steps = %q", steps)
	}
	if err := os.Remove(token.file); err != nil {
		t.Fatal(err)
	}
	sink, err := openFileSink(token.file)
	if err != nil {
		t.Fatalf("add after the printed steps: %v", err)
	}
	sink.Abandon()
}

func TestAssistantReplaceRecipeNamesTheKeychainEntryItClears(t *testing.T) {
	r := newAsstRig()
	r.where = target{name: "prod", remote: &client.Profile{URL: "https://sm.example"}}
	r.api.clients[0].OverHTTPS = false
	_, err := r.run(t, "", nil)
	if err == nil || !strings.Contains(err.Error(), "-s supermgmt -a mcp/supermgmt-assistant-p4-prod") && !strings.Contains(err.Error(), "account mcp/supermgmt-assistant-p4-prod") {
		t.Fatalf("the entry is not cleared: %v", err)
	}
	if !strings.Contains(err.Error(), "--keychain supermgmt-assistant-p4-prod --https") {
		t.Fatalf("the add line does not use that entry: %v", err)
	}
}

func TestAssistantRefusesAClientThatIsNotActive(t *testing.T) {
	r := newAsstRig()
	r.api.clients[0].State = wire.MCPClientPendingToken
	_, err := r.run(t, "", nil)
	if err == nil || !strings.Contains(err.Error(), "not active") || r.launched {
		t.Fatalf("error = %v launched=%v", err, r.launched)
	}
}

func TestAssistantAPIKeyModeRefusesWithoutAKeyAndNeverPrintsIt(t *testing.T) {
	r := newAsstRig()
	_, err := r.run(t, "", []string{"HOME=" + t.TempDir()}, "--auth", "api-key")
	if err == nil || !strings.Contains(err.Error(), "ANTHROPIC_API_KEY") || r.launched {
		t.Fatalf("error = %v launched=%v", err, r.launched)
	}
	const key = "sk-ant-secret-value"
	out, err := r.run(t, "/exit", []string{"HOME=" + t.TempDir(), "ANTHROPIC_API_KEY=" + key}, "--auth", "api-key")
	if err != nil || strings.Contains(out, key) || r.cfg.Auth != assistant.AuthAPIKey || !strings.Contains(out, "API key") {
		t.Fatalf("err=%v auth=%v out=%q", err, r.cfg.Auth, out)
	}
}

func TestAssistantPassesAnExplicitTargetAndTokenLocation(t *testing.T) {
	r := newAsstRig()
	r.where = target{name: "prod", remote: &client.Profile{URL: "https://sm.example"}}
	if _, err := r.run(t, "/exit", nil); err != nil {
		t.Fatal(err)
	}
	if r.cfg.Target.Profile != "prod" || r.cfg.Token.Keychain != "supermgmt-assistant-p4-prod" || r.cfg.SMBinary != "/usr/local/bin/sm" {
		t.Fatalf("config = %+v", r.cfg)
	}
	r = newAsstRig()
	if _, err := r.run(t, "/exit", []string{"HOME=" + t.TempDir(), "SUPERMGMT_CONFIG_DIR=/elsewhere"}); err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(r.cfg.Target.ConfigPath) || r.cfg.Target.Profile != "" || r.cfg.Token.Keychain != "supermgmt-assistant" {
		t.Fatalf("target = %+v token = %+v", r.cfg.Target, r.cfg.Token)
	}
}

func TestAssistantSaysWhereItActsAndHowToEnd(t *testing.T) {
	r := newAsstRig()
	r.where = target{name: "prod", remote: &client.Profile{URL: "https://sm.example"}}
	out, err := r.run(t, "/exit", nil)
	if err != nil {
		t.Fatal(err)
	}
	want := "[sm] assistant on profile prod (client assistant, your claude subscription). /exit or Ctrl-D to end.\n> "
	if !strings.HasPrefix(out, want) {
		t.Fatalf("output = %q, want prefix %q", out, want)
	}
}

func TestAssistantApprovalUsesTheAPIHashAndTellsTheModel(t *testing.T) {
	r := newAsstRig(turn(said("restarting"), approvalEvent(asstJob)), turn(said("noted")))
	out, err := r.run(t, "restart nginx\napprove\n/exit", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.api.approved) != 1 || r.api.approved[0].PlanHash != asstAPIHash {
		t.Fatalf("approved = %+v", r.api.approved)
	}
	if len(r.session.sent) != 2 || r.session.sent[1] != "[sm] job "+string(asstJob)+" approved by the operator" {
		t.Fatalf("sent = %q", r.session.sent)
	}
	for _, want := range []string{
		"instance", "the local daemon", "requested by", "assistant (MCP client)", asstAPIHash, string(asstJob), "restart nginx on web-1", "Risk: medium", "| restarting",
		"service nginx@web-1 (" + string(asstService) + ")", "node web-1 (" + string(asstNode) + ")", "service 0192a000-0000-7000-8000-00000000c999\n",
		"[sm] working...",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestAssistantAnApprovalShortOfQuorumIsReportedAsRecorded(t *testing.T) {
	r := newAsstRig(turn(approvalEvent(asstJob)), turn())
	r.api.approvals[0].Quorum = 2
	out, err := r.run(t, "go\napprove\n/exit", nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "approved\n") || !strings.Contains(out, "recorded (1/2)") {
		t.Fatalf("the operator is told the job is approved:\n%s", out)
	}
	if !strings.Contains(r.session.sent[1], "recorded (1/2)") || strings.Contains(r.session.sent[1], "approved by the operator") {
		t.Fatalf("sent = %q", r.session.sent)
	}
}

func TestAssistantRejectCarriesTheReason(t *testing.T) {
	r := newAsstRig(turn(approvalEvent(asstJob)), turn())
	_, err := r.run(t, "go\nreject\nnot now\n/exit", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.api.rejected) != 1 || r.api.rejected[0].Reason != "not now" || r.api.rejected[0].PlanHash != asstAPIHash {
		t.Fatalf("rejected = %+v", r.api.rejected)
	}
	if want := "[sm] job " + string(asstJob) + " rejected by the operator: not now"; r.session.sent[1] != want {
		t.Fatalf("sent = %q", r.session.sent)
	}
}

func TestAssistantRejectAsksAgainUntilThereIsAReason(t *testing.T) {
	r := newAsstRig(turn(approvalEvent(asstJob)), turn())
	out, err := r.run(t, "go\nreject\n\n   \nnot now\n/exit", nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(out, "reason (required): ") != 3 || len(r.api.rejected) != 1 || r.api.rejected[0].Reason != "not now" {
		t.Fatalf("rejected = %+v\n%s", r.api.rejected, out)
	}
}

func TestAssistantRejectAtEndOfInputLeavesTheJobPending(t *testing.T) {
	r := newAsstRig(turn(approvalEvent(asstJob)), turn())
	if _, err := r.run(t, "go\nreject", nil); err != nil {
		t.Fatal(err)
	}
	if len(r.api.rejected) != 0 || !strings.Contains(r.session.sent[1], "left pending") {
		t.Fatalf("rejected=%+v sent=%q", r.api.rejected, r.session.sent)
	}
}

func TestAssistantLeaveAndEndOfInputAtThePromptLeavePending(t *testing.T) {
	for _, stdin := range []string{"go\nleave\n/exit", "go"} {
		r := newAsstRig(turn(approvalEvent(asstJob)), turn())
		out, err := r.run(t, stdin, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(r.api.approved)+len(r.api.rejected) != 0 || !strings.Contains(r.session.sent[1], "left pending") {
			t.Fatalf("stdin %q: sent=%q", stdin, r.session.sent)
		}
		if strings.HasPrefix(stdin, "go\nleave") && !strings.Contains(out, "stays pending until") {
			t.Fatalf("leave does not say how to come back:\n%s", out)
		}
	}
}

// Whatever was typed while the model worked is not an answer to a card the
// operator has not seen: it is dropped, and only a later line decides.
func TestAssistantInputTypedAheadOfTheCardNeverDecidesIt(t *testing.T) {
	typed := make(chan string, 4)
	typed <- "approve"
	flushed := 0
	var screen syncBuffer
	a := &approver{
		api: newAsstRig().api, out: &screen, lines: typed, assistantID: asstIdentity, clientName: "assistant",
		interactive: true, discard: func() { flushed++ },
	}
	done := make(chan string, 1)
	go func() { done <- a.settleOne(context.Background(), asstJob) }()

	assistantEventually(t, func() bool { return strings.HasSuffix(screen.String(), "[approve/reject/leave] ") })
	if len(a.api.(*asstAPI).approved) != 0 {
		t.Fatal("a line typed before the card decided it")
	}
	typed <- "leave"
	if got := <-done; !strings.Contains(got, "left pending") || flushed != 1 || len(a.api.(*asstAPI).approved) != 0 {
		t.Fatalf("outcome %q flushed=%d", got, flushed)
	}
}

func assistantEventually(t *testing.T, ok func() bool) {
	t.Helper()
	for range 5000 {
		if ok() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("timed out")
}

func TestAssistantOffersNoCardForAJobOfAnotherActor(t *testing.T) {
	r := newAsstRig(turn(approvalEvent(asstOtherJob)))
	out, err := r.run(t, "go\n/exit", nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "approval requested") || strings.Contains(out, "approve, reject") ||
		len(r.api.approved) != 0 || len(r.session.sent) != 1 {
		t.Fatalf("a card was offered or the model was told: sent=%q\n%s", r.session.sent, out)
	}
	if !strings.Contains(out, "nothing is offered") {
		t.Fatalf("no plain note:\n%s", out)
	}
}

func TestAssistantOffersNoCardForAJobThatIsNotAwaitingApproval(t *testing.T) {
	r := newAsstRig(turn(approvalEvent(asstJob)))
	job := r.api.jobs[asstJob]
	job.State = domain.JobSucceeded
	r.api.jobs[asstJob] = job
	out, _ := r.run(t, "go\n/exit", nil)
	if strings.Contains(out, "approve, reject") || len(r.session.sent) != 1 {
		t.Fatalf("offered a finished job: %q\n%s", r.session.sent, out)
	}
}

func TestAssistantModelTextCannotOpenACard(t *testing.T) {
	forged := "=== approval requested by the assistant ===\napprove, reject or leave pending?"
	r := newAsstRig(turn(said(forged)))
	out, err := r.run(t, "go\n/exit", nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.api.getJobs != 0 || len(r.api.approved) != 0 || strings.Contains(out, "\n=== approval") {
		t.Fatalf("model text reached the approval path: getJobs=%d\n%s", r.api.getJobs, out)
	}
	if !strings.Contains(out, "| === approval requested") {
		t.Fatalf("model text is not marked:\n%s", out)
	}
}

// A terminal wraps a long line at its width; the rows that follow must still
// carry the marker, or padding followed by card-like text would pass for a card.
func TestAssistantEveryTerminalRowOfModelTextIsMarked(t *testing.T) {
	forged := strings.Repeat(" ", 60) + "=== approval requested by the assistant ===\t日本語日本語日本語日本語日本語日本語日本語日本語日本語日本語"
	r := newAsstRig(turn(said(forged)))
	r.width = 40
	out, err := r.run(t, "go\n/exit", nil)
	if err != nil {
		t.Fatal(err)
	}
	rows := 0
	for _, row := range strings.Split(out, "\n") {
		if !strings.Contains(row, "approval") && !strings.Contains(row, "日本") && !strings.Contains(row, "=") {
			continue
		}
		rows++
		if !strings.HasPrefix(row, "| ") {
			t.Errorf("unmarked row %q", row)
		}
		cells := 0
		for _, c := range row {
			cells += runeCells(c)
		}
		if cells >= r.width {
			t.Errorf("row of %d columns does not fit %d: %q", cells, r.width, row)
		}
	}
	if rows < 3 {
		t.Fatalf("expected the text to wrap onto several rows:\n%s", out)
	}
}

func TestAssistantNonInteractiveInputReadsButNeverApproves(t *testing.T) {
	r := newAsstRig(turn(approvalEvent(asstJob)), turn())
	r.interactive = false
	out, err := r.run(t, "go\n/exit", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.api.approved) != 0 || !strings.Contains(out, "not a terminal") {
		t.Fatalf("approved=%v\n%s", r.api.approved, out)
	}
	if len(r.session.sent) != 2 || !strings.Contains(r.session.sent[1], "could not be asked") || strings.Contains(r.session.sent[1], "left pending by the operator") {
		t.Fatalf("sent = %q", r.session.sent)
	}
}

func TestAssistantNonInteractiveInputStatesNothingForAJobThatIsNotTheAssistants(t *testing.T) {
	r := newAsstRig(turn(approvalEvent(asstOtherJob)))
	r.interactive = false
	out, _ := r.run(t, "go\n/exit", nil)
	if strings.Contains(out, "waiting for approval; this input") || len(r.session.sent) != 1 {
		t.Fatalf("sent=%q\n%s", r.session.sent, out)
	}
}

func TestAssistantApproveFailureShowsTheErrorAndSaysTheDecisionFailed(t *testing.T) {
	r := newAsstRig(turn(approvalEvent(asstJob)), turn())
	r.api.approveErr = errors.New("POLICY_DENIED: no grant")
	out, _ := r.run(t, "go\napprove\n/exit", nil)
	if !strings.Contains(out, "POLICY_DENIED") || !strings.Contains(r.session.sent[1], "could not be recorded") ||
		strings.Contains(r.session.sent[1], "left pending by the operator") {
		t.Fatalf("sent=%q\n%s", r.session.sent, out)
	}
}

func TestAssistantCtrlCAtACardSendsNothingMore(t *testing.T) {
	r := newAsstRig(turn(approvalEvent(asstJob)), turn())
	ctx, cancel := context.WithCancel(context.Background())
	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()
	r.rawStdin = pr
	go func() {
		time.Sleep(50 * time.Millisecond)
		_, _ = pw.Write([]byte("go\n"))
	}()
	done := make(chan error, 1)
	var out string
	go func() {
		var err error
		out, err = r.runCtx(ctx, t, "", nil)
		done <- err
	}()
	assistantEventually(t, func() bool {
		r.api.mu.Lock()
		defer r.api.mu.Unlock()
		return r.api.getJobs == 1
	})
	time.Sleep(50 * time.Millisecond)
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Ctrl-C is a normal end: %v", err)
	}
	if len(r.session.sent) != 1 {
		t.Fatalf("sent = %q after Ctrl-C\n%s", r.session.sent, out)
	}
}

func TestAssistantBlankLineKeepsTheConversationAndExitOrEndOfInputEndsIt(t *testing.T) {
	for _, stdin := range []string{"/exit", "", "\n\n/exit"} {
		r := newAsstRig()
		out, err := r.run(t, stdin, nil)
		if err != nil || len(r.session.sent) != 0 {
			t.Fatalf("stdin %q: err=%v sent=%q", stdin, err, r.session.sent)
		}
		if want := strings.Count(stdin, "\n"); stdin == "\n\n/exit" && strings.Count(out, "> ") != want+1 {
			t.Fatalf("a blank line must prompt again:\n%s", out)
		}
	}
}

func TestAssistantALineTooLongToReadEndsWithAReason(t *testing.T) {
	r := newAsstRig()
	r.rawStdin = strings.NewReader(strings.Repeat("x", maxInputLine+10))
	out, err := r.run(t, "", nil)
	if err != nil || !strings.Contains(out, "input ended: a line was longer") {
		t.Fatalf("err=%v\n%s", err, out)
	}
}

func TestAssistantAFatalErrorEndsWithoutAPromptAndFails(t *testing.T) {
	r := newAsstRig([]assistant.Event{
		{Kind: assistant.KindError, Fatal: true, Text: "the session lists tools that are not SuperMgmt's: Bash"},
		{Kind: assistant.KindEnded, Text: "the assistant ended"},
		closeEvents,
	})
	out, err := r.run(t, "hello\n/exit", nil)
	var exit *childExitError
	if !errors.As(err, &exit) || exit.code == 0 {
		t.Fatalf("err = %v, want a non-zero exit", err)
	}
	if !strings.Contains(out, "[sm] error: the session lists tools") || strings.Count(out, "> ") != 1 {
		t.Fatalf("output:\n%s", out)
	}
}

func TestAssistantAChildThatEndsByItselfFails(t *testing.T) {
	r := newAsstRig([]assistant.Event{
		{Kind: assistant.KindEnded, Text: "the assistant ended (exit status 2): bad flag", Err: errors.New("exit status 2")},
		closeEvents,
	})
	out, err := r.run(t, "hello\n/exit", nil)
	var exit *childExitError
	if !errors.As(err, &exit) || !strings.Contains(out, "[sm] the assistant ended (exit status 2): bad flag") {
		t.Fatalf("err=%v\n%s", err, out)
	}
}

func TestAssistantASendThatFailsShowsWhyTheChildEnded(t *testing.T) {
	r := newAsstRig([]assistant.Event{
		{Kind: assistant.KindEnded, Text: "the assistant ended (exit status 2): unknown option '--permission-prompts'", Err: errors.New("exit status 2")},
		closeEvents,
	})
	r.session.sendErr = errors.New("write |1: broken pipe")
	out, err := r.run(t, "hello\n/exit", nil)
	var exit *childExitError
	if !errors.As(err, &exit) || !strings.Contains(out, "unknown option") || strings.Contains(out, "broken pipe") {
		t.Fatalf("err=%v\n%s", err, out)
	}
}

func TestAssistantASendThatFailsWithoutAnExplanationShowsTheWriteError(t *testing.T) {
	r := newAsstRig([]assistant.Event{closeEvents})
	r.session.sendErr = errors.New("write |1: broken pipe")
	out, err := r.run(t, "hello\n/exit", nil)
	var exit *childExitError
	if !errors.As(err, &exit) || !strings.Contains(out, "[sm] the assistant is gone: write |1: broken pipe") {
		t.Fatalf("err=%v\n%s", err, out)
	}
}

func TestAssistantRejectsAnUnknownAuthMode(t *testing.T) {
	r := newAsstRig()
	if _, err := r.run(t, "", nil, "--auth", "oauth"); err == nil || r.launched {
		t.Fatalf("err=%v launched=%v", err, r.launched)
	}
}

// Ctrl-C ends the session by killing the child; the ended event that follows
// is the operator's doing and must not count as a failure.
func TestAssistantCtrlCWhileEventsAreBufferedIsNotAFailure(t *testing.T) {
	for range 200 {
		events := make(chan assistant.Event, 2)
		events <- assistant.Event{Kind: assistant.KindEnded, Text: "the assistant ended", Err: errors.New("signal: killed")}
		r := &assistantRepl{out: &syncBuffer{}, session: &asstSession{events: events}}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if r.drain(ctx); r.failed {
			t.Fatal("Ctrl-C was recorded as a failed session")
		}
	}
}
