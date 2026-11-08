package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	cryptossh "golang.org/x/crypto/ssh"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/secrets"
	sshtransport "github.com/autarquico/supermgmt/internal/transport/ssh"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// The scenarios of mcp-node-tools, end to end: the real database, services and
// API server under a policy that grants node.add and node.setup to MCP, reached
// through the MCP server. The host key scan dials a real SSH listener on
// loopback; nothing else of a node is faked. Argument shapes and the per-value
// setup refusals are unit tests (internal/mcp/tools_node_test.go,
// internal/app/mcp_node_test.go).

const mcpNodeGrant = `
  - name: rig-mcp-nodes
    subjects: ["type:mcp"]
    allow: ["node.add", "node.setup", "sudoers.write"]
`

// mcpNodeHost is an SSH listener that presents one host key and authenticates
// nobody: enough for the daemon to scan its key.
type mcpNodeHost struct {
	host        string
	port        int
	authorized  string
	fingerprint string
}

func startMCPNodeHost(t *testing.T) mcpNodeHost {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	mcpRigMust(t, err)
	signer, err := cryptossh.NewSignerFromKey(private)
	mcpRigMust(t, err)
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	mcpRigMust(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				cfg := &cryptossh.ServerConfig{PasswordCallback: func(cryptossh.ConnMetadata, []byte) (*cryptossh.Permissions, error) {
					return nil, net.ErrClosed
				}}
				cfg.AddHostKey(signer)
				if _, _, _, err := cryptossh.NewServerConn(conn, cfg); err == nil {
					return
				}
			}()
		}
	}()
	return mcpNodeHost{
		host: "127.0.0.1", port: listener.Addr().(*net.TCPAddr).Port,
		authorized:  strings.TrimSpace(string(cryptossh.MarshalAuthorizedKey(signer.PublicKey()))),
		fingerprint: cryptossh.FingerprintSHA256(signer.PublicKey()),
	}
}

// planOf is the plan document of the one approval a job waits on, as `sm
// approvals --plan` and the TUI approval view receive it.
func (rig *mcpRig) planOf(jobID any) (steps []string, plan string) {
	rig.t.Helper()
	reply := rig.send(mcpRigLocalUser, http.MethodGet, wire.PathApprovals, "")
	var page wire.Page[wire.Approval]
	reply.data(rig.t, &page)
	for _, approval := range page.Items {
		if string(approval.Job.ID) != jobID {
			continue
		}
		var doc struct {
			Steps []string `json:"steps"`
		}
		mcpRigMust(rig.t, json.Unmarshal(approval.Plan, &doc))
		return doc.Steps, string(approval.Plan)
	}
	rig.t.Fatalf("job %v has no approval", jobID)
	return nil, ""
}

func TestAnAddedNodeWaitsForApprovalAndThePlanShowsHostUsersReferencesAndFingerprint(t *testing.T) {
	rig := newMCPRigGranting(t, true, mcpNodeGrant)
	host := startMCPNodeHost(t)
	nodes := rig.count("nodes")

	out, failure := mcpSecCall(t, mcpSecRigSession(t, rig, true), "infra_add_node", map[string]any{
		"name": "edge-1", "host": host.host, "port": host.port, "admin_user": "admin",
	})

	if failure != nil {
		t.Fatalf("infra_add_node failed: %+v", failure)
	}
	if out["status"] != "approval_required" {
		t.Fatalf("status = %v, want approval_required: %v", out["status"], out)
	}
	if after := rig.count("nodes"); after != nodes {
		t.Errorf("nodes went from %d to %d before anyone approved", nodes, after)
	}
	steps, _ := rig.planOf(out["job_id"])
	shown := strings.Join(steps, "\n")
	for _, want := range []string{host.host + ":" + strconv.Itoa(host.port), "admin", "supermgmt", "secret://ssh/default", host.fingerprint} {
		if !strings.Contains(shown, want) {
			t.Errorf("the approval steps lack %q:\n%s", want, shown)
		}
	}
}

func TestTheKeyPinnedByAnAddIsTheOneTheDaemonScannedNotOneTheModelNamed(t *testing.T) {
	rig := newMCPRigGranting(t, true, mcpNodeGrant)
	real, imposter := startMCPNodeHost(t), startMCPNodeHost(t)

	session := mcpSecRigSession(t, rig, true)

	refused, err := session.CallTool(t.Context(), &sdk.CallToolParams{Name: "infra_add_node", Arguments: map[string]any{
		"name": "edge-1", "host": real.host, "port": real.port, "admin_user": "admin",
		"host_public_key": imposter.authorized, "fingerprint": imposter.fingerprint,
	}})
	mcpRigMust(t, err)
	if !refused.IsError {
		t.Error("a host key and fingerprint were accepted as arguments")
	}
	out, failure := mcpSecCall(t, session, "infra_add_node", map[string]any{
		"name": "edge-1", "host": real.host, "port": real.port, "admin_user": "admin",
	})
	if failure != nil {
		t.Fatalf("infra_add_node failed: %+v", failure)
	}
	steps, _ := rig.planOf(out["job_id"])
	shown := strings.Join(steps, "\n")
	if !strings.Contains(shown, real.fingerprint) || strings.Contains(shown, imposter.fingerprint) {
		t.Errorf("the plan pins the wrong key:\n%s\nwant %s, not %s", shown, real.fingerprint, imposter.fingerprint)
	}
}

func TestAKeyThatChangedAfterApprovalFailsOnTheFirstDialWithAHostKeyMismatch(t *testing.T) {
	rig := newMCPRigGranting(t, true, mcpNodeGrant)
	original, changed := startMCPNodeHost(t), startMCPNodeHost(t)
	out, failure := mcpSecCall(t, mcpSecRigSession(t, rig, true), "infra_add_node", map[string]any{
		"name": "edge-1", "host": original.host, "port": original.port, "admin_user": "admin",
	})
	if failure != nil {
		t.Fatalf("infra_add_node failed: %+v", failure)
	}
	steps, plan := rig.planOf(out["job_id"])
	if !strings.Contains(strings.Join(steps, "\n"), original.fingerprint) {
		t.Fatalf("the plan does not pin the scanned key: %q", steps)
	}
	var doc struct {
		Parameters struct {
			HostPublicKey string `json:"host_public_key"`
		} `json:"parameters"`
	}
	mcpRigMust(t, json.Unmarshal([]byte(plan), &doc))
	if doc.Parameters.HostPublicKey == "" {
		t.Fatalf("the plan carries no host_public_key to pin: %s", plan)
	}

	// The node now presents `changed`; the pool dials with the key the plan pinned.
	pool := sshtransport.NewPool(
		sshtransport.PoolConfig{
			ConnectTimeout: 10 * time.Second, CommandTimeout: 30 * time.Second, KeepaliveInterval: 15 * time.Second,
			MaxDialsInFlight: 4, MaxConnections: 8, MaxSessionsPerConnection: 10, IdleConnectionTTL: time.Minute,
		},
		sshtransport.NewCredentials(mcpNodeSigner{t: t}), domaintest.NewFakeClock(epoch))
	t.Cleanup(pool.Close)
	command, err := templates.Render("setup.verify_id", nil)
	mcpRigMust(t, err)

	_, err = pool.For(sshtransport.Target{
		NodeID: domain.ID("edge-1"), Host: changed.host, Port: changed.port, User: "admin",
		HostKey: doc.Parameters.HostPublicKey, CredentialRef: "secret://ssh/default",
	}).Run(t.Context(), command)

	if smerr.CodeOf(err) != smerr.CodeSSHHostKeyMismatch {
		t.Fatalf("dial = %v, want SSH_HOST_KEY_MISMATCH", err)
	}
}

func TestARawAddNamingAFileOrANonDefaultCredentialIsRefusedWithNoPlan(t *testing.T) {
	rig := newMCPRigGranting(t, true, mcpNodeGrant)
	host := startMCPNodeHost(t)
	body := func(extra string) string {
		return `{"name":"edge-1","host":"` + host.host + `","port":` + strconv.Itoa(host.port) +
			`,"admin_user":"admin","host_public_key":"` + host.authorized + `"` + extra + `}`
	}
	for name, extra := range map[string]string{
		"file admin credential":  `,"admin_credential_ref":"file:///root/.ssh/id_ed25519"`,
		"other credential_ref":   `,"credential_ref":"secret://ssh/other"`,
		"agent admin credential": `,"admin_credential_ref":"ssh-agent://default"`,
	} {
		t.Run(name, func(t *testing.T) {
			plans, jobs := rig.count("plans"), rig.count("jobs")

			reply := rig.send(mcpRigSocket, http.MethodPost, wire.PathNodesSSH, body(extra), rig.keyed()...)

			if reply.status < 400 || reply.status >= 500 {
				t.Errorf("status = %d, want a 4xx: %s", reply.status, reply.body)
			}
			if rig.count("plans") != plans || rig.count("jobs") != jobs {
				t.Errorf("a refused add left a plan or job behind")
			}
		})
	}
}

func TestSetupByMCPRefusesWhatGrantsRootThroughPlanActionAndTheRawAPIAndStoresNoPlan(t *testing.T) {
	rig := newMCPRigGranting(t, true, mcpNodeGrant)
	rig.seedBareNode("bare-1")
	session := mcpSecRigSession(t, rig, true)
	unsafe := map[string]map[string]any{
		"docker_access": {"docker_access": "true"},
		"grants":        {"docker_access": "false", "grants": []any{"restart app.service"}},
		"deploy_root":   {"docker_access": "false", "deploy_root": "/srv/x"},
		"proxmox":       {"docker_access": "false", "proxmox": "true"},
		"logs_mode":     {"docker_access": "false", "logs_mode": "broker"},
	}
	for name, params := range unsafe {
		t.Run(name, func(t *testing.T) {
			plans := rig.count("plans")

			_, failure := mcpSecCall(t, session, "infra_plan_action", map[string]any{
				"action": "node.setup", "targets": []map[string]any{{"type": "node", "ref": "bare-1"}}, "parameters": params,
			})
			if failure == nil {
				t.Error("infra_plan_action accepted an unsafe node.setup")
			}

			raw, err := json.Marshal(wire.CreatePlanRequest{
				Action: "node.setup", Targets: []wire.ResourceRef{{Type: domain.ResourceNode, ID: domain.ID(rig.fixtures["node_bare"])}}, Parameters: params,
			})
			mcpRigMust(t, err)
			reply := rig.send(mcpRigSocket, http.MethodPost, wire.PathPlans, string(raw), rig.keyed()...)
			if reply.status < 400 || reply.status >= 500 {
				t.Errorf("raw plan status = %d, want a 4xx: %s", reply.status, reply.body)
			}
			if after := rig.count("plans"); after != plans {
				t.Errorf("plans went from %d to %d: a refused setup was stored", plans, after)
			}
		})
	}
}

func TestAPersonPlanningTheSameUnsafeSetupIsUnaffected(t *testing.T) {
	rig := newMCPRigGranting(t, true, mcpNodeGrant)
	raw, err := json.Marshal(wire.CreatePlanRequest{
		Action:     "node.setup",
		Targets:    []wire.ResourceRef{{Type: domain.ResourceNode, ID: domain.ID(rig.fixtures["node"])}},
		Parameters: map[string]any{"docker_access": "true", "logs_mode": "broker"},
	})
	mcpRigMust(t, err)

	reply := rig.send(mcpRigLocalUser, http.MethodPost, wire.PathPlans, string(raw), rig.keyed()...)

	if reply.status >= 400 {
		t.Errorf("a person's plan was refused: %d %s", reply.status, reply.body)
	}
}

func TestSetupByMCPIsRefusedOnANodeThatAlreadyHasASetup(t *testing.T) {
	rig := newMCPRigGranting(t, true, mcpNodeGrant)
	plans := rig.count("plans")

	_, failure := mcpSecCall(t, mcpSecRigSession(t, rig, true), "infra_setup_node", map[string]any{"node": "dev-1"})

	if failure == nil || failure.Code != smerr.CodeInvalidArgument {
		t.Errorf("failure = %+v, want INVALID_ARGUMENT", failure)
	}
	if after := rig.count("plans"); after != plans {
		t.Errorf("plans went from %d to %d: a refused setup was stored", plans, after)
	}
}

func TestSafeSetupByMCPWaitsForApproval(t *testing.T) {
	rig := newMCPRigGranting(t, true, mcpNodeGrant)
	rig.seedBareNode("bare-1")

	out, failure := mcpSecCall(t, mcpSecRigSession(t, rig, true), "infra_setup_node", map[string]any{"node": "bare-1"})

	if failure != nil {
		t.Fatalf("infra_setup_node failed: %+v", failure)
	}
	if out["status"] != "approval_required" {
		t.Errorf("status = %v, want approval_required: %v", out["status"], out)
	}
	if commands := rig.runtime.commands.Load(); commands != 0 {
		t.Errorf("%d commands reached a node before anyone approved", commands)
	}
}

func TestNodeToolsAreDeniedByDefaultNamingThePolicyReason(t *testing.T) {
	rig := newMCPRigGranting(t, true, "")
	rig.seedBareNode("bare-1")
	host := startMCPNodeHost(t)
	session := mcpSecRigSession(t, rig, true)
	nodes := rig.count("nodes")

	add, addFailure := mcpSecCall(t, session, "infra_add_node", map[string]any{
		"name": "edge-1", "host": host.host, "port": host.port, "admin_user": "admin",
	})
	setup, setupFailure := mcpSecCall(t, session, "infra_setup_node", map[string]any{"node": "bare-1"})
	setUp, setUpFailure := mcpSecCall(t, session, "infra_setup_node", map[string]any{"node": "dev-1"}) // has a setup: still the denial

	for name, result := range map[string]struct {
		out     map[string]any
		failure *mcpSecFailure
	}{"infra_add_node": {add, addFailure}, "infra_setup_node": {setup, setupFailure}, "infra_setup_node on a set-up node": {setUp, setUpFailure}} {
		if result.failure != nil || result.out["status"] != "denied" {
			t.Errorf("%s = %v / %+v, want the denied status", name, result.out, result.failure)
			continue
		}
		if summary, _ := result.out["summary"].(string); !strings.Contains(summary, string(smerr.ReasonDefaultDeny)) {
			t.Errorf("%s summary = %q, want it to name %s", name, summary, smerr.ReasonDefaultDeny)
		}
	}
	if after := rig.count("nodes"); after != nodes {
		t.Errorf("nodes went from %d to %d", nodes, after)
	}
}

func TestSetupByMCPWithoutReadOnTheNodeLearnsNothingOfItsSetup(t *testing.T) {
	rig := newMCPRigGranting(t, true, mcpNodeGrant+`
  - name: rig-mcp-blind
    subjects: ["type:mcp"]
    resources: ["node:dev-1"]
    deny: ["node.read"]
`)
	plans := rig.count("plans")

	out, failure := mcpSecCall(t, mcpSecRigSession(t, rig, true), "infra_setup_node", map[string]any{"node": "dev-1"})

	if failure != nil && failure.Code == smerr.CodeInvalidArgument {
		t.Errorf("failure = %+v, want nothing about the node's setup state", failure)
	}
	if failure == nil && out["status"] != "denied" {
		t.Errorf("out = %v, want the denied status", out)
	}
	if after := rig.count("plans"); after != plans {
		t.Errorf("plans went from %d to %d", plans, after)
	}
}

// mcpNodeSigner hands one generated identity to the credential resolver, for
// any reference.
type mcpNodeSigner struct{ t *testing.T }

func (s mcpNodeSigner) Signer(context.Context, secrets.Ref) (cryptossh.Signer, error) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	mcpRigMust(s.t, err)
	return cryptossh.NewSignerFromKey(private)
}
