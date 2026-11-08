package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"slices"
	"sort"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

const (
	serverPlanID domain.ID = "0190a5c3-7b1e-7c3a-9d2e-1a2b3c4d5e11"
	serverJobID  domain.ID = "0190a5c3-7b1e-7c3a-9d2e-1a2b3c4d5e12"
	serverHash             = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	allGoldenPath   = "testdata/tools.all.golden.json"
	allGoldenUpdate = "MCP_UPDATE_ALL_GOLDEN"
)

var (
	planToolName = "infra_plan_action"

	writeToolNames = []string{
		"infra_cancel_job", "infra_create_backup", "infra_disable_tunnel", "infra_expose_port",
		"infra_power_guest", "infra_probe_node", "infra_reboot_node", "infra_refresh_provider",
		"infra_restart_service", "infra_rotate_cloudflare_access_token", "infra_shutdown_node",
		"infra_snapshot_guest", "infra_start_service", "infra_stop_service", "infra_submit_plan",
		"infra_unexpose_port",
	}
)

// submitCall is one SubmitPlan call seen by serverFakeAPI.
type submitCall struct {
	plan domain.ID
	hash string
}

// serverFakeAPI adds the plan and write calls to fakeAPI and records them.
type serverFakeAPI struct {
	fakeAPI

	plan       wire.CreatedPlan
	submission wire.Submission
	planErr    error
	submitErr  error

	planRequests    []wire.CreatePlanRequest
	submits         []submitCall
	exposes         []exposeCall
	unexposes       []unexposeCall
	routeSubmission wire.NodeRouteSubmission
	cancelJob       wire.Job

	probes        []domain.ID
	backupCreates int
	cancels       []submitCall
	refreshes     []domain.ID
	refreshed     *wire.Provider
}

// exposeCall is one ExposeNodeRoute call seen by serverFakeAPI.
type exposeCall struct {
	node    domain.ID
	request wire.ExposeNodeRouteRequest
}

// unexposeCall is one UnexposeNodeRoute call seen by serverFakeAPI.
type unexposeCall struct {
	node     domain.ID
	hostname string
}

func (f *serverFakeAPI) CreatePlan(_ context.Context, r wire.CreatePlanRequest) (wire.CreatedPlan, error) {
	f.planRequests = append(f.planRequests, r)
	return f.plan, f.planErr
}

func (f *serverFakeAPI) SubmitPlan(_ context.Context, plan domain.ID, hash string) (wire.Submission, error) {
	f.submits = append(f.submits, submitCall{plan, hash})
	return f.submission, f.submitErr
}

func (f *serverFakeAPI) ExposeNodeRoute(_ context.Context, node domain.ID, r wire.ExposeNodeRouteRequest) (wire.NodeRouteSubmission, error) {
	f.exposes = append(f.exposes, exposeCall{node, r})
	return f.routeSubmission, f.submitErr
}

func (f *serverFakeAPI) UnexposeNodeRoute(_ context.Context, node domain.ID, hostname string) (wire.NodeRouteSubmission, error) {
	f.unexposes = append(f.unexposes, unexposeCall{node, hostname})
	return f.routeSubmission, f.submitErr
}

func (f *serverFakeAPI) ProbeNode(_ context.Context, id domain.ID) (wire.Submission, error) {
	f.probes = append(f.probes, id)
	return f.submission, f.submitErr
}

func (f *serverFakeAPI) CreateBackup(context.Context) (wire.Submission, error) {
	f.backupCreates++
	return f.submission, f.submitErr
}

func (f *serverFakeAPI) CancelJob(_ context.Context, id domain.ID, hash string) (wire.Job, error) {
	f.cancels = append(f.cancels, submitCall{id, hash})
	return f.cancelJob, f.submitErr
}

func (f *serverFakeAPI) RefreshProvider(_ context.Context, id domain.ID) (wire.Provider, error) {
	f.refreshes = append(f.refreshes, id)
	if f.refreshed != nil {
		return *f.refreshed, f.submitErr
	}
	return wire.Provider{ID: id, Status: "error", LastError: viewHostile}, f.submitErr
}

func (f *serverFakeAPI) wrote() bool {
	return len(f.planRequests)+len(f.submits)+len(f.exposes)+len(f.unexposes)+
		len(f.probes)+f.backupCreates+len(f.cancels)+len(f.refreshes) > 0
}

// newServerFakeAPI serves the nodes and services of readTestAPI and a
// plan whose hash is serverHash, allowed, with a queued submission.
func newServerFakeAPI() *serverFakeAPI {
	api := &serverFakeAPI{fakeAPI: *readTestAPI()}
	api.plan = wire.CreatedPlan{
		PlanID:    serverPlanID,
		Plan:      json.RawMessage(`{"action":"service.restart","risk":"operational"}`),
		PlanHash:  serverHash,
		ExpiresAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		Policy:    wire.Policy{Decision: "allow", ApprovalRequired: true, Quorum: 1},
	}
	api.submission = wire.Submission{
		Job: wire.Job{
			ID: serverJobID, Type: "service.restart", State: domain.JobAwaitingApproval, Risk: domain.RiskOperational,
			Resource: wire.ResourceRef{Type: domain.ResourceService, ID: readServiceID}, PlanHash: serverHash,
		},
		Policy: api.plan.Policy,
	}
	api.routeSubmission = wire.NodeRouteSubmission{Submission: wire.Submission{
		Job: wire.Job{
			ID: serverJobID, Type: "control_plane.apply", State: domain.JobAwaitingApproval, Risk: domain.RiskHigh,
			Resource: wire.ResourceRef{Type: domain.ResourceNode, ID: readNodeID}, PlanHash: serverHash,
		},
		Policy: api.plan.Policy,
	}}
	return api
}

// serverSession serves NewServer over the SDK's in-memory transport.
func serverSession(t *testing.T, api API, writeTools bool) *sdk.ClientSession {
	t.Helper()
	ctx := context.Background()
	server := NewServer(api, Options{WriteTools: writeTools, Version: "9.9.9"})
	serverEnd, clientEnd := sdk.NewInMemoryTransports()
	serverSession, err := server.Connect(ctx, serverEnd, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { _ = serverSession.Close() })
	client := sdk.NewClient(&sdk.Implementation{Name: "test-client", Version: "0"}, nil)
	session, err := client.Connect(ctx, clientEnd, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func listedTools(t *testing.T, session *sdk.ClientSession) []*sdk.Tool {
	t.Helper()
	listed, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(listed.Tools, func(i, j int) bool { return listed.Tools[i].Name < listed.Tools[j].Name })
	return listed.Tools
}

func toolNames(tools []*sdk.Tool) []string {
	names := make([]string, len(tools))
	for i, tool := range tools {
		names[i] = tool.Name
	}
	return names
}

func TestNewServer_WritesDisabledListsReadToolsAndPlanOnly(t *testing.T) {
	names := toolNames(listedTools(t, serverSession(t, newServerFakeAPI(), false)))
	want := append(slices.Clone(readToolNames), planToolName)
	slices.Sort(want)
	if !slices.Equal(names, want) {
		t.Errorf("tools = %v, want %v", names, want)
	}
}

func TestNewServer_WritesDisabledRefusesWriteToolsByName(t *testing.T) {
	api := newServerFakeAPI()
	session := serverSession(t, api, false)
	for _, name := range writeToolNames {
		_, err := session.CallTool(context.Background(), &sdk.CallToolParams{Name: name, Arguments: map[string]any{}})
		if err == nil {
			t.Errorf("%s: call succeeded with write tools disabled", name)
		}
	}
	if api.wrote() {
		t.Error("a disabled write tool reached the API")
	}
}

func TestNewServer_WritesEnabledListsEveryToolOfTheSpec(t *testing.T) {
	tools := listedTools(t, serverSession(t, newServerFakeAPI(), true))
	want := append(slices.Clone(readToolNames), planToolName)
	want = append(want, writeToolNames...)
	slices.Sort(want)
	if got := toolNames(tools); !slices.Equal(got, want) {
		t.Fatalf("tools = %v, want %v", got, want)
	}
	for _, tool := range tools {
		if got := tool.Meta[SchemaVersionMetaKey]; got != float64(SchemaVersion) {
			t.Errorf("%s schema version = %v, want %d", tool.Name, got, SchemaVersion)
		}
		readOnly := tool.Annotations != nil && tool.Annotations.ReadOnlyHint
		if wantReadOnly := slices.Contains(readToolNames, tool.Name); readOnly != wantReadOnly {
			t.Errorf("%s readOnlyHint = %v, want %v", tool.Name, readOnly, wantReadOnly)
		}
	}
}

func TestNewServer_ReportsItsVersion(t *testing.T) {
	session := serverSession(t, newServerFakeAPI(), false)
	info := session.InitializeResult().ServerInfo
	if info.Name != "supermgmt" || info.Version != "9.9.9" {
		t.Errorf("server info = %+v", info)
	}
}

func TestNewServer_AllToolsGolden(t *testing.T) {
	got, err := json.MarshalIndent(listedTools(t, serverSession(t, newServerFakeAPI(), true)), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	if os.Getenv(allGoldenUpdate) != "" {
		if err := os.WriteFile(allGoldenPath, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(allGoldenPath)
	if err != nil {
		t.Fatalf("%v (set %s=1 to write it)", err, allGoldenUpdate)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("tools/list differs from %s (set %s=1 to rewrite after review)", allGoldenPath, allGoldenUpdate)
	}
}

func TestNewServer_AllGoldenKeepsTheReadToolsUnchanged(t *testing.T) {
	var all, read []map[string]any
	for path, into := range map[string]*[]map[string]any{allGoldenPath: &all, readGoldenPath: &read} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, into); err != nil {
			t.Fatal(err)
		}
	}
	byName := map[any]map[string]any{}
	for _, tool := range all {
		byName[tool["name"]] = tool
	}
	for _, tool := range read {
		got, _ := json.Marshal(byName[tool["name"]])
		want, _ := json.Marshal(tool)
		if !bytes.Equal(got, want) {
			t.Errorf("%v differs between %s and %s", tool["name"], allGoldenPath, readGoldenPath)
		}
	}
}
