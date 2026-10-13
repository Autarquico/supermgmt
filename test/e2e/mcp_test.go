//go:build e2e && fixtures

package e2e_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/mcp"
	"github.com/autarquico/supermgmt/test/e2e/harness"
)

// The shapes the tools return, decoded from the structured result an MCP client receives.
type (
	m5Nodes struct {
		Items []mcp.NodeView `json:"items"`
	}
	m5Services struct {
		Items []mcp.ServiceView `json:"items"`
	}
	m5Deployments struct {
		Items []mcp.DeploymentView `json:"items"`
	}
)

// TestE2E_MCPStdioReadsGraph
//
// Spec scenario "lectura sin shell" (M5): a registered MCP client launches `sm mcp`, inspects
// nodes, services and deployments, and has no shell tool to do it with. Log text from the node
// reaches the client scrubbed of credentials, and the client's token appears nowhere it should not.
func TestE2E_MCPStdioReadsGraph(t *testing.T) {
	w := newM5LocalWorld(t, true)
	tokenFile := w.addMCPClient("graph-reader")
	session, bridgeStderr := w.bridge(tokenFile)
	var outputs mcpOutputs

	t.Run("no tool runs commands, opens a shell, reads secrets or deletes", func(t *testing.T) {
		for _, name := range m5ToolNames(t, session) {
			for _, forbidden := range []string{"shell", "exec", "command", "connect", "secret", "delete", "ssh"} {
				if strings.Contains(name, forbidden) {
					t.Errorf("tool %q looks like a %s tool; MCP must not have one", name, forbidden)
				}
			}
		}
	})

	var node mcp.NodeView
	t.Run("lists the node with its environment", func(t *testing.T) {
		var nodes m5Nodes
		if failure := m5Call(t, &outputs, session, "infra_list_nodes", nil, &nodes); failure != "" {
			t.Fatalf("infra_list_nodes failed: %s", failure)
		}
		i := slices.IndexFunc(nodes.Items, func(n mcp.NodeView) bool { return n.Name == m5NodeName })
		if i < 0 {
			t.Fatalf("node %s not listed: %+v", m5NodeName, nodes.Items)
		}
		node = nodes.Items[i]
		if node.Environment != m5EnvName {
			t.Errorf("node environment = %q, want %q", node.Environment, m5EnvName)
		}
	})

	t.Run("lists the node's services and gets one by name@node", func(t *testing.T) {
		var services m5Services
		m5Call(t, &outputs, session, "infra_list_services", map[string]any{"node": m5NodeName}, &services)
		if !slices.ContainsFunc(services.Items, func(s mcp.ServiceView) bool { return s.Remote.Name == m5DemoUnit }) {
			t.Fatalf("%s not among the services: %+v", m5DemoUnit, services.Items)
		}
		var service mcp.ServiceView
		if failure := m5Call(t, &outputs, session, "infra_get_service", map[string]any{"ref": m5DemoUnit + "@" + m5NodeName}, &service); failure != "" {
			t.Fatalf("infra_get_service failed: %s", failure)
		}
		if service.NodeID != node.ID {
			t.Errorf("service node = %s, want %s", service.NodeID, node.ID)
		}
	})

	t.Run("lists deployments (none exist yet)", func(t *testing.T) {
		var deployments m5Deployments
		if failure := m5Call(t, &outputs, session, "infra_list_deployments", nil, &deployments); failure != "" {
			t.Fatalf("infra_list_deployments failed: %s", failure)
		}
		if len(deployments.Items) != 0 {
			t.Errorf("listed %d deployments in a world without apps", len(deployments.Items))
		}
	})

	t.Run("service logs reach the client flagged untrusted and scrubbed of the bearer credential", func(t *testing.T) {
		var logs mcp.LogView
		failure := m5Call(t, &outputs, session, "infra_get_service_logs", map[string]any{"ref": m5LeakUnit + "@" + m5NodeName}, &logs)
		if failure != "" {
			t.Fatalf("infra_get_service_logs failed: %s", failure)
		}
		if !logs.Log.Untrusted {
			t.Error("log text is not flagged untrusted")
		}
		if !strings.Contains(logs.Log.Text, "sm-leak.sh") || !strings.Contains(logs.Log.Text, audit.Redacted) {
			t.Fatalf("the planted log line did not reach the client with its credential masked: %q", logs.Log.Text)
		}
	})

	t.Run("no secret reaches the MCP outputs, the bridge's stderr, the daemon log or the database", func(t *testing.T) {
		evidence := w.dataFiles()
		evidence["MCP tool outputs"] = outputs.text
		evidence["sm mcp stderr"] = []byte(bridgeStderr.String())
		evidence["daemon stderr"] = []byte(w.daemon.Stderr())
		secrets := map[string]string{"the planted bearer credential": m5LeakSecret, "the MCP client token": w.readToken(tokenFile)}
		harness.AssertNoPlaintext(t, evidence, secrets)
	})
}

// TestE2E_MCPProductionRestartRequiresApproval
//
// Spec scenario "escritura en producción requiere aprobación exacta" (M5): an MCP client submits a
// restart of a production service; the job waits, the service does not restart, and only the
// approval of that exact plan lets it run.
func TestE2E_MCPProductionRestartRequiresApproval(t *testing.T) {
	w := newM5LocalWorld(t, true)
	session, _ := w.bridge(w.addMCPClient("restarter"))
	var outputs mcpOutputs
	before := w.invocationID(m5DemoUnit)

	var write mcp.WriteResult
	if failure := m5Call(t, &outputs, session, "infra_restart_service", map[string]any{"ref": m5DemoUnit + "@" + m5NodeName}, &write); failure != "" {
		t.Fatalf("infra_restart_service failed: %s", failure)
	}

	t.Run("the result says approval is required and names the plan hash", func(t *testing.T) {
		if write.Status != mcp.WriteApprovalRequired || write.JobID == nil || write.PlanHash == nil {
			t.Fatalf("restart result = %+v, want approval_required with a job and a plan hash", write)
		}
	})

	t.Run("the job waits and the service is not restarted", func(t *testing.T) {
		job := w.waitJobState(*write.JobID, 30*time.Second, domain.JobAwaitingApproval, false)
		if job.Job.PlanHash != *write.PlanHash {
			t.Errorf("job plan hash = %s, the tool returned %s", job.Job.PlanHash, *write.PlanHash)
		}
		time.Sleep(10 * time.Second) // long enough for a wrongly started job to have run
		if after := w.invocationID(m5DemoUnit); after != before {
			t.Fatalf("%s restarted without approval: invocation %s -> %s", m5DemoUnit, before, after)
		}
	})

	t.Run("approving a different plan hash does not release it", func(t *testing.T) {
		_, err := w.human.Approve(w.ctx(), *write.JobID, wire.DecisionRequest{PlanHash: "sha256:" + strings.Repeat("0", 64)})
		if err == nil {
			t.Fatal("approval of a plan hash that is not the job's was accepted")
		}
		if got := w.invocationID(m5DemoUnit); got != before {
			t.Fatalf("%s restarted after a wrong-hash approval", m5DemoUnit)
		}
	})

	t.Run("approving the exact plan runs it", func(t *testing.T) {
		harness.ApproveJob(w.ctx(), t, w.human, *write.JobID)
		w.waitJobState(*write.JobID, m5JobTimeout, domain.JobSucceeded, false)
		if after := w.invocationID(m5DemoUnit); after == before {
			t.Errorf("%s did not restart after its plan was approved", m5DemoUnit)
		}
	})
}

// TestE2E_MCPCannotApprove
//
// Spec scenario "MCP no puede aprobar" (M5): even when the policy file grants approval.grant to
// type:mcp, an MCP identity cannot approve, reject or resolve, and the job stays waiting.
func TestE2E_MCPCannotApprove(t *testing.T) {
	w := newM5LocalWorld(t, true)
	tokenFile := w.addMCPClient("would-be-approver")
	session, _ := w.bridge(tokenFile)
	var outputs mcpOutputs
	var write mcp.WriteResult
	if failure := m5Call(t, &outputs, session, "infra_restart_service", map[string]any{"ref": m5DemoUnit + "@" + m5NodeName}, &write); failure != "" {
		t.Fatalf("infra_restart_service failed: %s", failure)
	}
	if write.JobID == nil {
		t.Fatalf("no job: %+v", write)
	}
	job := *write.JobID
	asMCP := w.mcpAPI(w.readToken(tokenFile))
	hash := *write.PlanHash

	t.Run("the MCP client's approval is denied", func(t *testing.T) {
		_, err := asMCP.Approve(w.ctx(), job, wire.DecisionRequest{PlanHash: hash, Reason: "i approve my own plan"})
		wantDenied(t, "approve", err)
	})
	t.Run("the MCP client's rejection is denied", func(t *testing.T) {
		_, err := asMCP.Reject(w.ctx(), job, wire.DecisionRequest{PlanHash: hash, Reason: "no"})
		wantDenied(t, "reject", err)
	})
	t.Run("the job still waits for a human", func(t *testing.T) {
		w.waitJobState(job, 10*time.Second, domain.JobAwaitingApproval, false)
	})
	t.Run("the MCP surface offers no approval tool", func(t *testing.T) {
		for _, name := range m5ToolNames(t, session) {
			if strings.Contains(name, "approv") || strings.Contains(name, "reject") || strings.Contains(name, "resolve") {
				t.Errorf("tool %q lets an MCP client decide approvals", name)
			}
		}
	})
}

func wantDenied(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s by an MCP identity succeeded", what)
	}
	if code := smerr.CodeOf(err); code != smerr.CodePolicyDenied {
		t.Fatalf("%s by an MCP identity failed with %q (%v), want %s", what, code, err, smerr.CodePolicyDenied)
	}
}

// invocationID is the systemd InvocationID of a unit on the node: it changes when the unit restarts.
func (w *m5World) invocationID(unit string) string {
	w.t.Helper()
	res := w.node.c.Exec(w.ctx(), "", "systemctl", "show", "-p", "InvocationID", "--value", unit)
	if res.Code != 0 {
		w.t.Fatalf("systemctl show %s: %s", unit, res.Output())
	}
	return strings.TrimSpace(res.Stdout)
}

// TestE2E_MCPClientsAddFlow
//
// Spec §24 and ADR-0032: `sm mcp clients add` registers a local client, stores its one-time token
// in a 0600 file without ever printing it, never issues it twice, and `remove` revokes it. The
// token is not found in the database, the command outputs or the daemon's log.
func TestE2E_MCPClientsAddFlow(t *testing.T) {
	w := newM5LocalWorld(t, false)
	const name = "flow-agent"
	tokenFile := w.addMCPClient(name)
	token := w.readToken(tokenFile)
	if token == "" {
		t.Fatal("the token file is empty")
	}
	var seen []string // everything the commands printed

	t.Run("the client is listed active and the listing carries no token", func(t *testing.T) {
		res := w.laptop.Must(w.ctx(), "", "mcp", "clients", "list", "--config", w.configFile)
		seen = append(seen, res.Output())
		if !strings.Contains(res.Stdout, name) || !strings.Contains(res.Stdout, string(wire.MCPClientActive)) {
			t.Errorf("listing does not show %s as active:\n%s", name, res.Stdout)
		}
	})

	t.Run("adding it again is refused: the token is issued once", func(t *testing.T) {
		res := w.laptop.Run(w.ctx(), "", "mcp", "clients", "add", name, "--token-file", tokenFile+".again", "--config", w.configFile)
		seen = append(seen, res.Output())
		if res.Code == 0 || !strings.Contains(res.Output(), "already active") {
			t.Fatalf("second add exited %d: %s", res.Code, res.Output())
		}
		if _, err := os.Stat(tokenFile + ".again"); err == nil {
			t.Error("a second token file was written")
		}
	})

	t.Run("the stored token opens the stdio bridge", func(t *testing.T) {
		session, stderr := w.bridge(tokenFile)
		var outputs mcpOutputs
		var nodes m5Nodes
		if failure := m5Call(t, &outputs, session, "infra_list_nodes", nil, &nodes); failure != "" {
			t.Fatalf("infra_list_nodes failed: %s", failure)
		}
		seen = append(seen, string(outputs.text), stderr.String())
	})

	t.Run("a destination that already exists is refused before a token is issued, and the client can still receive it elsewhere", func(t *testing.T) {
		existing := harness.WriteHostFile(t, w.dir, "occupied.token", []byte("keep"), 0o600)
		add := func(file string) harness.Result {
			res := w.laptop.Run(w.ctx(), "", "mcp", "clients", "add", "second-agent", "--token-file", file, "--config", w.configFile)
			seen = append(seen, res.Output())
			return res
		}
		registered := add(existing) // registration waits for approval: nothing is stored yet
		if m := approveHint.FindStringSubmatch(registered.Stdout); m != nil {
			w.settle(domain.ID(m[1]))
		}
		if refused := add(existing); refused.Code == 0 {
			t.Fatalf("add into an existing file exited 0: %s", refused.Output())
		}
		if raw, _ := os.ReadFile(existing); string(raw) != "keep" {
			t.Errorf("the existing file was overwritten: %q", raw)
		}
		fresh := filepath.Join(w.dir, "second-agent.token")
		if stored := add(fresh); stored.Code != 0 {
			t.Fatalf("the token could not be issued after the refusal (exit %d): %s", stored.Code, stored.Output())
		}
		w.requireStored(fresh, harness.Result{})
	})

	t.Run("removing the client revokes its token", func(t *testing.T) {
		before := w.laptop.Run(w.ctx(), "", "mcp", "--token-file", tokenFile, "--config", w.configFile)
		if before.Code != 0 {
			t.Fatalf("the bridge refused a live token (exit %d): %s", before.Code, before.Output())
		}
		seen = append(seen, w.laptop.Must(w.ctx(), "", "mcp", "clients", "remove", name, "--config", w.configFile).Output())
		after := w.laptop.Run(w.ctx(), "", "mcp", "--token-file", tokenFile, "--config", w.configFile)
		seen = append(seen, after.Output())
		if after.Code == 0 {
			t.Fatalf("the bridge accepted a revoked token: %s", after.Output())
		}
		if _, err := w.mcpAPI(token).Me(w.ctx()); err == nil {
			t.Fatal("the daemon accepted a revoked MCP token on its socket")
		}
	})

	t.Run("the token appears nowhere but its file", func(t *testing.T) {
		evidence := w.dataFiles()
		evidence["command output"] = []byte(strings.Join(seen, "\n"))
		evidence["daemon stderr"] = []byte(w.daemon.Stderr())
		harness.AssertNoPlaintext(t, evidence, map[string]string{"the MCP client token": token})
	})
}
