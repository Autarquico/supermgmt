package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/daemon"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	mcpsrv "github.com/autarquico/supermgmt/internal/mcp"
)

// The MCP security suite (spec §11.1, §24, App. E): the real database, app
// services and API server, reached by the MCP server of internal/mcp over the
// SDK's in-memory transport, and by a real daemon. Only the SSH boundary of a
// node is faked.

// mcpSecFailure is the error JSON of a failed tool call.
type mcpSecFailure struct {
	Code   smerr.Code   `json:"code"`
	Reason smerr.Reason `json:"reason"`
}

// mcpSecSession is an MCP client of the MCP server whose API calls reach the
// given API client. writeTools is what mcp.write_tools_enabled would register.
func mcpSecSession(t *testing.T, api mcpsrv.API, writeTools bool) *sdk.ClientSession {
	t.Helper()
	ctx := context.Background()
	serverEnd, clientEnd := sdk.NewInMemoryTransports()
	serverSession, err := mcpsrv.NewServer(api, mcpsrv.Options{WriteTools: writeTools, Version: "test"}).Connect(ctx, serverEnd, nil)
	mcpRigMust(t, err)
	t.Cleanup(func() { _ = serverSession.Close() })
	session, err := sdk.NewClient(&sdk.Implementation{Name: "security-suite", Version: "0"}, nil).Connect(ctx, clientEnd, nil)
	mcpRigMust(t, err)
	t.Cleanup(func() { _ = session.Close() })
	return session
}

// mcpSecRigSession is a session of the rig's mcp caller, in process.
func mcpSecRigSession(t *testing.T, rig *mcpRig, writeTools bool) *sdk.ClientSession {
	t.Helper()
	return mcpSecSession(t, client.New(client.Options{Transport: rig.server.InProcess(rig.mcp)}), writeTools)
}

// mcpSecCall calls a tool and returns its structured result, or its failure.
func mcpSecCall(t *testing.T, session *sdk.ClientSession, tool string, arguments map[string]any) (map[string]any, *mcpSecFailure) {
	t.Helper()
	result, err := session.CallTool(context.Background(), &sdk.CallToolParams{Name: tool, Arguments: arguments})
	mcpRigMust(t, err)
	if result.IsError {
		text, ok := result.Content[0].(*sdk.TextContent)
		if !ok {
			t.Fatalf("%s failed with %T content", tool, result.Content[0])
		}
		var failure mcpSecFailure
		mcpRigMust(t, json.Unmarshal([]byte(text.Text), &failure))
		return nil, &failure
	}
	raw, err := json.Marshal(result.StructuredContent)
	mcpRigMust(t, err)
	var out map[string]any
	mcpRigMust(t, json.Unmarshal(raw, &out))
	return out, nil
}

func mcpSecWantFailure(t *testing.T, failure *mcpSecFailure, reason smerr.Reason) {
	t.Helper()
	if failure == nil {
		t.Fatalf("the call succeeded, want a failure with reason %s", reason)
	}
	if failure.Reason != reason {
		t.Errorf("failure = %+v, want reason %s", failure, reason)
	}
}

func mcpSecToolNames(t *testing.T, session *sdk.ClientSession) []string {
	t.Helper()
	listed, err := session.ListTools(context.Background(), nil)
	mcpRigMust(t, err)
	var names []string
	for _, tool := range listed.Tools {
		names = append(names, tool.Name)
	}
	slices.Sort(names)
	return names
}

// ---- plans and submission --------------------------------------------------

func TestSubmittingAPlanTheMCPClientDidNotCreateIsRefusedAsNotThePlanActor(t *testing.T) {
	rig := newMCPRig(t, true)
	var humans wire.CreatedPlan
	rig.fixture(http.MethodPost, wire.PathPlans, `{"action":"service.restart","targets":[{"type":"service","id":"`+rig.fixtures["service"]+`"}]}`).data(t, &humans)
	jobs := rig.count("jobs")

	_, failure := mcpSecCall(t, mcpSecRigSession(t, rig, true), "infra_submit_plan",
		map[string]any{"plan_id": humans.PlanID.String(), "plan_hash": humans.PlanHash})

	mcpSecWantFailure(t, failure, smerr.ReasonNotPlanActor)
	if after := rig.count("jobs"); after != jobs {
		t.Errorf("jobs went from %d to %d: a human's plan was submitted by an MCP client", jobs, after)
	}
}

func TestSubmittingAFabricatedHashFailsAsStaleAndCreatesNoJob(t *testing.T) {
	rig := newMCPRig(t, true)
	jobs := rig.count("jobs")

	_, failure := mcpSecCall(t, mcpSecRigSession(t, rig, true), "infra_submit_plan",
		map[string]any{"plan_id": rig.fixtures["plan"], "plan_hash": strings.Repeat("0", len(rig.fixtures["plan_hash"]))})

	mcpSecWantFailure(t, failure, smerr.ReasonPlanStale)
	if after := rig.count("jobs"); after != jobs {
		t.Errorf("jobs went from %d to %d on a fabricated hash", jobs, after)
	}
}

func TestAProductionRestartThroughTheToolsWaitsForApprovalAndSendsNoCommand(t *testing.T) {
	rig := newMCPRig(t, true)

	out, failure := mcpSecCall(t, mcpSecRigSession(t, rig, true), "infra_restart_service", map[string]any{"ref": "api@web-1"})

	if failure != nil {
		t.Fatalf("restart failed: %+v", failure)
	}
	if out["status"] != "approval_required" {
		t.Fatalf("status = %v, want approval_required: %v", out["status"], out)
	}
	var state, hash string
	mcpRigMust(t, rig.db.Reader().QueryRowContext(context.Background(),
		`SELECT state, plan_hash FROM jobs WHERE id = ?`, out["job_id"]).Scan(&state, &hash))
	if state != string(domain.JobAwaitingApproval) || hash != out["plan_hash"] {
		t.Errorf("job = %s with hash %s, want awaiting_approval with the hash the tool returned (%v)", state, hash, out["plan_hash"])
	}
	if commands := rig.runtime.commands.Load(); commands != 0 {
		t.Errorf("%d commands reached a node before anyone approved", commands)
	}
}

// ---- credentials -----------------------------------------------------------

func TestAnMCPClientCannotRegisterClientsIssueTokensOrMintAPITokensEvenWithAFullGrant(t *testing.T) {
	requests := []struct {
		name, method, path, body string
		keyed                    bool
		watched                  string
	}{
		{"register a client", http.MethodPost, wire.PathMCPClients, `{"name":"second","origin":"local"}`, true, "mcp_clients"},
		{"issue a client token", http.MethodPost, wire.PathMCPClients + "/{mcp_client}/token", `{"expires_at":"{expires_at}"}`, false, "mcp_clients WHERE token_hash IS NOT NULL"},
		{"delete a client", http.MethodDelete, wire.PathMCPClients + "/{mcp_client}", "", true, "mcp_clients WHERE state = 'deleted'"},
		{"create an API token", http.MethodPost, wire.PathTokens, `{"name":"mine","expires_at":"{expires_at}"}`, false, "api_tokens"},
	}
	for _, via := range mcpMatrixTransports {
		t.Run(string(via), func(t *testing.T) {
			rig := newMCPRig(t, true)
			for _, request := range requests {
				var headers []string
				if request.keyed {
					headers = rig.keyed()
				}
				before, jobs := rig.count(request.watched), rig.count("jobs")

				reply := rig.send(via, request.method, rig.expand(request.path), rig.expand(request.body), headers...)

				if reply.status != http.StatusForbidden || reply.reason(t) != smerr.ReasonMCPActionForbidden {
					t.Errorf("%s: status %d reason %q, want 403 MCP_ACTION_FORBIDDEN", request.name, reply.status, reply.reason(t))
				}
				if after := rig.count(request.watched); after != before {
					t.Errorf("%s changed %s from %d to %d", request.name, request.watched, before, after)
				}
				if after := rig.count("jobs"); after != jobs {
					t.Errorf("%s left a job behind", request.name)
				}
			}
		})
	}
}

// ---- write_tools_enabled: false, through the daemon --------------------------

// mcpDaemon is a local-mode daemon running in this process.
type mcpDaemon struct {
	t      *testing.T
	cfg    *config.Config
	socket string
	stop   context.CancelFunc
	done   chan error
}

// startMCPDaemon starts the real daemon on a temp data dir; extra is appended
// to its configuration.
func startMCPDaemon(t *testing.T, extra string) *mcpDaemon {
	t.Helper()
	root, err := os.MkdirTemp("", "smd")
	mcpRigMust(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	file := filepath.Join(root, "config.yaml")
	yaml := "version: 1\ninstance:\n  mode: local\n  data_dir: " + filepath.Join(root, "data") + "\nsecurity:\n  allow_self_approval: true\n" + extra
	mcpRigMust(t, os.WriteFile(file, []byte(yaml), 0o600))
	loaded, err := config.Load(file, []string{"HOME=" + root})
	mcpRigMust(t, err)

	d := &mcpDaemon{t: t, cfg: loaded.Config, socket: filepath.Join(root, "run", "s"), done: make(chan error, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	d.stop = cancel
	listening := make(chan struct{})
	go func() {
		d.done <- daemon.Run(ctx, daemon.Options{
			Config: d.cfg, Socket: d.socket, IdleCheck: 10 * time.Millisecond, OnListening: func(string) { close(listening) },
		})
	}()
	select {
	case <-listening:
	case err := <-d.done:
		t.Fatalf("the daemon exited before listening: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("the daemon did not start")
	}
	t.Cleanup(func() {
		cancel()
		select {
		case <-d.done:
		case <-time.After(30 * time.Second):
			t.Error("the daemon did not stop")
		}
	})
	return d
}

func (d *mcpDaemon) human() *client.Client { return client.New(client.Options{Socket: d.socket}) }

func (d *mcpDaemon) withToken(token string) *client.Client {
	return client.New(client.Options{Socket: d.socket, Token: audit.Secret(token)})
}

// seedNode adds a development node that can be rebooted, straight to the
// daemon's database, and returns its name.
func (d *mcpDaemon) seedNode() string {
	d.t.Helper()
	ctx := context.Background()
	db, err := database.Open(ctx, d.cfg.Storage.SQLite.Path, database.Options{})
	mcpRigMust(d.t, err)
	defer func() { _ = db.Close() }()
	ids, now := domain.UUIDv7Generator{}, domain.SystemClock{}.Now()
	mcpRigMust(d.t, db.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		provider, err := database.CreateProvider(ctx, tx, domain.Provider{
			ID: ids.NewID(), Type: "ssh", Name: "ssh-hosts", Origin: domain.ProviderStatic, CreatedAt: now, UpdatedAt: now,
		})
		if err != nil {
			return err
		}
		env, err := database.CreateEnvironment(ctx, tx, domain.Environment{ID: ids.NewID(), Name: "dev", RiskLevel: domain.EnvironmentDevelopment})
		if err != nil {
			return err
		}
		node, err := database.CreateNode(ctx, tx, domain.Node{
			ID: ids.NewID(), ProviderID: provider.ID, NativeID: "dev-1", Name: "dev-1", Kind: "ssh", EnvironmentID: &env.ID,
			ManagementState: domain.ManagementManaged, Reachability: domain.ReachabilityUnknown, CreatedAt: now, UpdatedAt: now,
		})
		if err != nil {
			return err
		}
		return database.SetNodeCapability(ctx, tx, node.ID, database.NodeCapability{Capability: "node.reboot", Available: true, CheckedAt: now})
	}))
	return "dev-1"
}

// issueToken registers a local MCP client as the daemon's user, approves it
// and takes its one token.
func (d *mcpDaemon) issueToken(name string) (wire.MCPClient, string) {
	d.t.Helper()
	ctx := context.Background()
	registered, err := d.human().RegisterMCPClient(ctx, wire.RegisterMCPClientRequest{Name: name, Origin: wire.MCPOriginLocal})
	mcpRigMust(d.t, err)
	if registered.Pending == nil {
		d.t.Fatalf("the registration was applied without the approval a high-risk action needs: %+v", registered)
	}
	_, err = d.human().Approve(ctx, registered.Pending.Job.ID, wire.DecisionRequest{PlanHash: registered.Pending.Job.PlanHash})
	mcpRigMust(d.t, err)
	id := d.waitForClient(name)
	issued, err := d.human().IssueMCPToken(ctx, id, wire.IssueMCPTokenRequest{ExpiresAt: domain.SystemClock{}.Now().Add(24 * time.Hour)})
	mcpRigMust(d.t, err)
	return issued.Client, issued.Token
}

// waitForClient waits for the applied registration of name.
func (d *mcpDaemon) waitForClient(name string) domain.ID {
	d.t.Helper()
	for range 1500 {
		page, err := d.human().ListMCPClients(context.Background())
		mcpRigMust(d.t, err)
		for _, listed := range page.Items {
			if listed.Name == name && listed.State != wire.MCPClientDeleted {
				return listed.ID
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	d.t.Fatalf("the approved registration of %q never produced a client", name)
	return ""
}

func (d *mcpDaemon) jobCount() int {
	d.t.Helper()
	page, err := d.human().ListJobs(context.Background(), wire.JobQuery{})
	mcpRigMust(d.t, err)
	return len(page.Items)
}

func TestWithWritesDisabledAnMCPWriteIsDeniedEndToEndThroughTheDaemon(t *testing.T) {
	d := startMCPDaemon(t, "mcp:\n  write_tools_enabled: false\n")
	node := d.seedNode()
	_, token := d.issueToken("assistant")
	mcpClient := d.withToken(token)
	ctx := context.Background()
	jobs := d.jobCount()

	// The plan is stored, with the denial as its verdict ...
	plan, err := mcpClient.CreatePlan(ctx, wire.CreatePlanRequest{
		Action: "node.reboot", Targets: []wire.ResourceRef{{Type: domain.ResourceNode, ID: d.nodeID(node)}},
	})
	if err != nil {
		t.Fatalf("create plan: %v", err)
	}
	if plan.Policy.Decision != "deny" || plan.Policy.Reason != smerr.ReasonMCPWritesDisabled {
		t.Errorf("verdict = %+v, want deny MCP_WRITES_DISABLED", plan.Policy)
	}
	// ... submitting it fails and enqueues nothing ...
	if _, err := mcpClient.SubmitPlan(ctx, plan.PlanID, plan.PlanHash); mcpSecReasonOf(err) != smerr.ReasonMCPWritesDisabled {
		t.Errorf("submit = %v, want MCP_WRITES_DISABLED", err)
	}
	// ... and so does a write tool that was registered against the flag.
	forced := mcpSecSession(t, mcpClient, true)
	out, failure := mcpSecCall(t, forced, "infra_reboot_node", map[string]any{"ref": node})
	if failure != nil || out["status"] != "denied" {
		t.Errorf("reboot tool = %v, %+v, want the denied status", out, failure)
	}
	if after := d.jobCount(); after != jobs {
		t.Errorf("jobs went from %d to %d: an MCP write got past write_tools_enabled: false", jobs, after)
	}

	// With the flag off the server does not offer the write tools at all.
	for _, name := range mcpSecToolNames(t, mcpSecSession(t, mcpClient, false)) {
		if slices.Contains([]string{"infra_submit_plan", "infra_restart_service", "infra_reboot_node", "infra_create_deployment", "infra_rollback_deployment"}, name) {
			t.Errorf("tool %s is offered with writes disabled", name)
		}
	}
}

func (d *mcpDaemon) nodeID(name string) domain.ID {
	d.t.Helper()
	page, err := d.human().ListNodes(context.Background(), wire.NodeQuery{})
	mcpRigMust(d.t, err)
	for _, node := range page.Items {
		if node.Name == name {
			return node.ID
		}
	}
	d.t.Fatalf("node %q is not listed", name)
	return ""
}

// mcpSecReasonOf is the reason of an API error, "" for any other error.
func mcpSecReasonOf(err error) smerr.Reason {
	var apiErr *smerr.Error
	if errors.As(err, &apiErr) {
		return apiErr.Reason
	}
	return ""
}
