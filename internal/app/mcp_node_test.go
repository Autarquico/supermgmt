package app

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/policy"
	sshnode "github.com/autarquico/supermgmt/internal/providers/ssh"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/transport/ssh"
)

func TestNodeAddPlan_StepsShowWhatThePersonTrustsAndAreStableAcrossRebuilds(t *testing.T) {
	n := newNodeFixture(t)
	req := n.addRequest("web-2", "")
	p, err := n.inv.addParams(context.Background(), n.db.Reader(), req)
	mustf(t, err, "addParams")
	params, err := toParams(p)
	mustf(t, err, "toParams")
	ref := domain.ResourceRef{Type: domain.ResourceNode, ID: p.NodeID}
	ctx := context.Background()

	first, err := build(ctx, n.db.Reader(), actionNodeAdd, n.admin, ref, params)
	mustf(t, err, "build")
	again, err := build(ctx, n.db.Reader(), actionNodeAdd, n.admin, ref, params)
	mustf(t, err, "build again")

	key, err := sshnode.ParseHostKey(req.HostKey)
	mustf(t, err, "ParseHostKey")
	want := []string{
		"trust host key (compare with the host): ssh-ed25519 " + cryptossh.FingerprintSHA256(key),
		"name: web-2", "host: 10.0.0.9:22", "admin user: admin", "automation user: supermgmt",
		"admin credential: ssh-agent://default", "automation credential: secret://ssh/default",
	}
	if !slices.Equal(first.plan.Steps, want) {
		t.Errorf("steps = %q, want %q", first.plan.Steps, want)
	}
	if !slices.Equal(first.plan.Steps, again.plan.Steps) {
		t.Error("rebuilding the plan changed its steps")
	}
}

func TestAddSSHNode_AnMCPActorMayNotNameAFileOrANonDefaultCredential(t *testing.T) {
	n := newNodeFixture(t)
	var assistant domain.ID
	n.inTx(func(ctx context.Context, tx *database.Tx) error {
		assistant = n.identity(ctx, tx, "assistant-1", domain.ActorMCP, "")
		return nil
	})
	for name, mutate := range map[string]func(*AddSSHNode){
		"file admin credential":  func(r *AddSSHNode) { r.AdminCredentialRef = "file:///root/.ssh/id_ed25519" },
		"agent admin credential": func(r *AddSSHNode) { r.AdminCredentialRef = "ssh-agent://default" },
		"other credential_ref":   func(r *AddSSHNode) { r.CredentialRef = "secret://ssh/other" },
		"space in reference":     func(r *AddSSHNode) { r.AdminCredentialRef = "secret://ssh/admin fake step" },
		"bidi override":          func(r *AddSSHNode) { r.AdminCredentialRef = "secret://ssh/admin\u202e" },
		"C1 control":             func(r *AddSSHNode) { r.AdminCredentialRef = "secret://ssh/admin\u009b" },
	} {
		t.Run(name, func(t *testing.T) {
			req := n.addRequest("web-2", "")
			mutate(&req)
			_, err := n.inv.AddSSHNode(context.Background(), n.caller(assistant), req)
			wantError(t, err, smerr.CodeInvalidArgument, "")
		})
	}
	if got := n.count("SELECT COUNT(*) FROM plans"); got != 0 {
		t.Errorf("plans = %d: a refused add stored a plan", got)
	}
}

func TestAddSSHNode_AnMCPActorWithASecretReferenceReachesPolicy(t *testing.T) {
	n := newNodeFixture(t)
	var assistant domain.ID
	n.inTx(func(ctx context.Context, tx *database.Tx) error {
		assistant = n.identity(ctx, tx, "assistant-1", domain.ActorMCP, "")
		return nil
	})
	req := n.addRequest("web-2", "")
	req.AdminCredentialRef = "secret://ssh/admin"
	req.CredentialRef = "secret://ssh/default"
	n.inv.scan = scanning(req.HostKey)

	_, err := n.inv.AddSSHNode(context.Background(), n.caller(assistant), req)

	wantError(t, err, smerr.CodePolicyDenied, smerr.ReasonMCPWritesDisabled)
}

func scanning(authorized string) func(context.Context, string, int) (ssh.HostKey, error) {
	return func(context.Context, string, int) (ssh.HostKey, error) {
		return ssh.HostKey{Authorized: authorized}, nil
	}
}

func TestAddSSHNode_AnMCPActorCannotPinAKeyTheDaemonDidNotScan(t *testing.T) {
	n := newNodeFixture(t, func(c *Config) {
		c.MCPWritesEnabled = true
		c.Policy = everythingAllowed(t)
	})
	var assistant domain.ID
	n.inTx(func(ctx context.Context, tx *database.Tx) error {
		assistant = n.identity(ctx, tx, "assistant-1", domain.ActorMCP, "")
		return nil
	})
	req := n.addRequest("web-2", "")
	n.inv.scan = scanning(newAuthorizedKey())

	_, err := n.inv.AddSSHNode(context.Background(), n.caller(assistant), req)

	wantError(t, err, smerr.CodeInvalidArgument, "")
	if got := n.count("SELECT COUNT(*) FROM plans"); got != 0 {
		t.Errorf("plans = %d: a refused add stored a plan", got)
	}
	n.inv.scan = scanning(req.HostKey)
	if _, err := n.inv.AddSSHNode(context.Background(), n.caller(assistant), req); err != nil {
		t.Errorf("the scanned key was refused: %v", err)
	}
}

func TestUpdateNode_AnMCPActorCannotRepinOrNameAFile(t *testing.T) {
	n := newNodeFixture(t, func(c *Config) {
		c.MCPWritesEnabled = true
		c.Policy = everythingAllowed(t)
	})
	var assistant domain.ID
	n.inTx(func(ctx context.Context, tx *database.Tx) error {
		assistant = n.identity(ctx, tx, "assistant-1", domain.ActorMCP, "")
		return nil
	})
	file, key, secret := "file:///root/.ssh/id_ed25519", newAuthorizedKey(), "secret://ssh/admin"
	for name, patch := range map[string]NodePatch{
		"host key":        {HostPublicKey: &key},
		"file credential": {AdminCredentialRef: &file},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := n.inv.UpdateNode(context.Background(), n.caller(assistant), n.node.ID, n.node.SpecRevision, patch)
			wantError(t, err, smerr.CodeInvalidArgument, "")
		})
	}
	if got := n.count("SELECT COUNT(*) FROM plans"); got != 0 {
		t.Errorf("plans = %d: a refused update stored a plan", got)
	}
	if err := requireMCPPatch(domain.Actor{Type: domain.ActorMCP}, NodePatch{AdminCredentialRef: &secret}); err != nil {
		t.Errorf("a secret reference was refused: %v", err)
	}
}

func TestPlansCreate_NodeSetupByMCPRefusesWhatGrantsRootByValue(t *testing.T) {
	f, assistant, _ := newMCPOperateFixture(t, true)
	safe := map[string]any{policy.ParamDockerAccess: "false"}
	with := func(k string, v any) map[string]any {
		params := map[string]any{policy.ParamDockerAccess: "false"}
		params[k] = v
		return params
	}
	cases := map[string]map[string]any{
		"docker_access":  {policy.ParamDockerAccess: "true"},
		"grants":         with(policy.ParamGrants, []any{"restart app.service"}),
		"deploy_root":    with(policy.ParamDeployRoot, "/srv/x"),
		"proxmox":        with(policy.ParamProxmox, "true"),
		"logs_mode":      with(policy.ParamLogsMode, "broker"),
		"docker_access2": {policy.ParamDockerAccess: "yes"},
	}
	before := f.count("SELECT COUNT(*) FROM plans")
	for name, params := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := f.plans.Create(context.Background(), f.caller(assistant), PlanRequest{
				Action: policy.ActionNodeSetup, Target: domain.ResourceRef{Type: domain.ResourceNode, ID: f.node.ID}, Parameters: params,
			})
			wantError(t, err, smerr.CodeInvalidArgument, "")
			if !strings.Contains(err.Error(), "MCP client") {
				t.Errorf("err = %v, want it to say a person must plan this", err)
			}
		})
	}
	if after := f.count("SELECT COUNT(*) FROM plans"); after != before {
		t.Errorf("plans = %d, want %d: a refused plan was stored", after, before)
	}
	safeReq := PlanRequest{Action: policy.ActionNodeSetup, Target: domain.ResourceRef{Type: domain.ResourceNode, ID: f.node.ID}, Parameters: safe}
	if err := requireMCPSafeSetup(domain.Actor{Type: domain.ActorMCP}, safeReq); err != nil {
		t.Errorf("safe parameters refused: %v", err)
	}
}

func TestPlansCreate_NodeSetupByMCPRefusesTheBrokerTheInstanceDefaultWouldFill(t *testing.T) {
	f, assistant, _ := newMCPOperateFixture(t, true)
	f.plans.cfg.DefaultLogsMode = runtimes.LogsBroker

	_, err := f.plans.Create(context.Background(), f.caller(assistant), PlanRequest{
		Action: policy.ActionNodeSetup, Target: domain.ResourceRef{Type: domain.ResourceNode, ID: f.node.ID},
		Parameters: map[string]any{policy.ParamDockerAccess: "false"},
	})

	wantError(t, err, smerr.CodeInvalidArgument, "")
	if got := f.count("SELECT COUNT(*) FROM plans"); got != 0 {
		t.Errorf("plans = %d: a refused plan was stored", got)
	}
}

func TestPlansCreate_NodeSetupByMCPRefusesARerunAndATunnelNode(t *testing.T) {
	for name, prepare := range map[string]func(*fixture){
		"already set up": func(f *fixture) { f.grantSetup() },
		"tunnel node": func(f *fixture) {
			f.inTx(func(ctx context.Context, tx *database.Tx) error {
				f.node.Endpoint.Transport, f.node.Endpoint.TunnelHostname = domain.TransportCloudflare, "ssh-web-1.example.test"
				_, err := database.UpdateNodeSpec(ctx, tx, f.node, f.node.SpecRevision)
				return err
			})
		},
	} {
		t.Run(name, func(t *testing.T) {
			f, assistant, _ := newMCPOperateFixture(t, true)
			f.plans.cfg.Policy = everythingAllowed(t)
			prepare(f)

			_, err := f.plans.Create(context.Background(), f.caller(assistant), PlanRequest{
				Action: policy.ActionNodeSetup, Target: domain.ResourceRef{Type: domain.ResourceNode, ID: f.node.ID},
				Parameters: map[string]any{policy.ParamDockerAccess: "false", policy.ParamLogsMode: "journal-group"},
			})

			wantError(t, err, smerr.CodeInvalidArgument, "")
			if !strings.Contains(err.Error(), "sm nodes setup") {
				t.Errorf("err = %v, want it to say a person re-runs it with sm nodes setup", err)
			}
			if got := f.count("SELECT COUNT(*) FROM plans"); got != 0 {
				t.Errorf("plans = %d: a refused plan was stored", got)
			}
		})
	}
}

func TestRequireMCPSafeSetup_APersonIsUnaffected(t *testing.T) {
	req := PlanRequest{Action: policy.ActionNodeSetup, Parameters: map[string]any{
		policy.ParamDockerAccess: "true", policy.ParamDeployRoot: "/srv/x", policy.ParamLogsMode: "broker",
	}}
	if err := requireMCPSafeSetup(domain.Actor{Type: domain.ActorHuman}, req); err != nil {
		t.Errorf("a person's setup was refused: %v", err)
	}
}

func TestPlansCreate_NodeSetupByMCPLearnsNothingOfASetupNodeWhenPolicyDenies(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.MCPWritesEnabled = true })
	var assistant domain.ID
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		assistant = f.identity(ctx, tx, "assistant-1", domain.ActorMCP, "")
		return nil
	})
	f.grantSetup()

	_, err := f.plans.Create(context.Background(), f.caller(assistant), PlanRequest{
		Action: policy.ActionNodeSetup, Target: domain.ResourceRef{Type: domain.ResourceNode, ID: f.node.ID},
		Parameters: map[string]any{policy.ParamDockerAccess: "false", policy.ParamLogsMode: "journal-group"},
	})

	if smerr.CodeOf(err) == smerr.CodeInvalidArgument || (err != nil && strings.Contains(err.Error(), f.node.Name)) {
		t.Errorf("err = %v, want the policy outcome without the node's setup state", err)
	}
}

func TestSetupJob_AnMCPActorNeverRunsOnANodeThatAlreadyHasASetup(t *testing.T) {
	s := newSetting(t, func(c *Config) {
		c.MCPWritesEnabled = true
		c.Policy = everythingAllowed(t)
	})
	var assistant domain.ID
	s.inTx(func(ctx context.Context, tx *database.Tx) error {
		assistant = s.fixture.identity(ctx, tx, "assistant-1", domain.ActorMCP, "")
		return nil
	})
	ctx, by := context.Background(), s.caller(assistant)
	created, err := s.plans.Create(ctx, by, PlanRequest{
		Action: policy.ActionNodeSetup, Target: domain.ResourceRef{Type: domain.ResourceNode, ID: s.node.ID},
		Parameters: map[string]any{"docker_access": "false", "logs_mode": "journal-group"},
	})
	mustf(t, err, "Create")
	sub, err := s.plans.Submit(ctx, by, created.Record.ID, created.Record.PlanHash)
	mustf(t, err, "Submit")
	s.approveToQuorum(sub.Job)
	s.grantSetup("app.service")
	before, _ := s.setupCapability()

	err = s.run()

	wantError(t, err, smerr.CodeInvalidArgument, "")
	if after, _ := s.setupCapability(); !reflect.DeepEqual(after, before) {
		t.Errorf("setup = %+v, want it unchanged: %+v", after, before)
	}
}

func TestSetupJob_AnMCPActorRunsOnANodeWithoutASetup(t *testing.T) {
	s := newSetting(t, func(c *Config) {
		c.MCPWritesEnabled = true
		c.Policy = everythingAllowed(t)
	})
	var assistant domain.ID
	s.inTx(func(ctx context.Context, tx *database.Tx) error {
		assistant = s.fixture.identity(ctx, tx, "assistant-1", domain.ActorMCP, "")
		return nil
	})
	ctx, by := context.Background(), s.caller(assistant)
	created, err := s.plans.Create(ctx, by, PlanRequest{
		Action: policy.ActionNodeSetup, Target: domain.ResourceRef{Type: domain.ResourceNode, ID: s.node.ID},
		Parameters: map[string]any{"docker_access": "false", "logs_mode": "journal-group"},
	})
	mustf(t, err, "Create")
	sub, err := s.plans.Submit(ctx, by, created.Record.ID, created.Record.PlanHash)
	mustf(t, err, "Submit")
	s.approveToQuorum(sub.Job)

	if err := s.run(); err != nil {
		t.Fatalf("a setup the mcp client planned on a bare node: %v", err)
	}
	if _, ok := s.setupCapability(); !ok {
		t.Error("setup not recorded")
	}
}

func TestAddSSHNode_AnMCPActorCannotStoreTextBesideTheScannedKey(t *testing.T) {
	n := newNodeFixture(t, func(c *Config) {
		c.MCPWritesEnabled = true
		c.Policy = everythingAllowed(t)
	})
	var assistant domain.ID
	n.inTx(func(ctx context.Context, tx *database.Tx) error {
		assistant = n.identity(ctx, tx, "assistant-1", domain.ActorMCP, "")
		return nil
	})
	req := n.addRequest("web-2", "")
	n.inv.scan = scanning(req.HostKey)
	for name, text := range map[string]string{
		"comment":  req.HostKey + " APPROVED BY SECURITY",
		"options":  `command="id" ` + req.HostKey,
		"preceded": "# verified\n" + req.HostKey,
	} {
		t.Run(name, func(t *testing.T) {
			r := req
			r.HostKey = text
			_, err := n.inv.AddSSHNode(context.Background(), n.caller(assistant), r)
			wantError(t, err, smerr.CodeInvalidArgument, "")
		})
	}
	if got := n.count("SELECT COUNT(*) FROM plans"); got != 0 {
		t.Errorf("plans = %d: a refused add stored a plan", got)
	}
}
