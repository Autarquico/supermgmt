package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/secrets"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// rootChain is `stat` output of a systemctl whose whole path is root-owned and not writable by others.
const rootChain = "0 755 /usr/bin/systemctl\n0 755 /usr/bin\n0 755 /usr\n0 755 /\n0 755 /usr/bin/systemctl\n0 755 /usr/bin\n0 755 /usr\n0 755 /\n"

// onATrustedNode answers the questions setup asks about the systemctl chain and the account's primary group.
func onATrustedNode(n *fakeNode) *fakeNode {
	return n.reply("systemd.path_chain", rootChain).reply("setup.user_primary_group", "supermgmt\n").
		reply("setup.user_groups", "supermgmt systemd-journal\n").reply("setup.verify_groups", "supermgmt systemd-journal\n")
}

const passwdEntry = "supermgmt:x:998:998::/var/lib/supermgmt:/bin/sh\n"

// setting is a node fixture ready for node.setup: an instance row, a scripted
// admin session that behaves like a fresh Debian node, and a dedicated-user
// session that passes verification.
type setting struct {
	*nodeFixture
	identity secrets.Identity
	handler  setupHandler
	lease    jobs.Lease
}

func newSetting(t *testing.T) *setting {
	t.Helper()
	s := &setting{nodeFixture: newNodeFixture(t)}
	s.inTx(func(ctx context.Context, tx *database.Tx) error {
		return database.CreateInstance(ctx, tx, database.Instance{ID: s.ids.NewID(), Name: "test", CreatedAt: s.clock.Now()})
	})
	s.identity = secrets.Identity{
		Ref: secrets.Ref{Name: secrets.SSHIdentityName, Version: 1}, AuthorizedKey: newAuthorizedKey(), FingerprintSHA256: "SHA256:identity",
	}

	users := 0
	admin := s.dialer.as("admin")
	admin.fallback = func(templates.Command) (transport.Result, error) { return transport.Result{}, nil }
	admin.reply("setup.systemctl_path", "/usr/bin/systemctl\n")
	admin.on("setup.user_entry", func(templates.Command) (transport.Result, error) {
		users++
		if users == 1 {
			return transport.Result{ExitStatus: 2}, nil // absent: create it
		}
		return transport.Result{Stdout: []byte(passwdEntry)}, nil
	})
	admin.reply("setup.user_groups", "supermgmt systemd-journal\n")
	onATrustedNode(admin)

	dedicated := s.dialer.as("supermgmt")
	onATrustedNode(dedicated)
	dedicated.reply("setup.verify_id", "supermgmt\n")
	dedicated.reply("setup.verify_markers", "writable\n")
	dedicated.exit("setup.verify_sudo", 1) // sudo -n -l fails: no sudo rights at all

	prober, err := NewProber(s.cfg, s.conn, fakeAdapters(newFakeAdapter(domain.RuntimeSystemd), newFakeAdapter(domain.RuntimeDocker)))
	mustf(t, err, "NewProber")
	core, err := newCore(s.cfg)
	mustf(t, err, "newCore")
	s.handler = setupHandler{
		core: core, store: s.store, conn: s.conn, prober: prober,
		identity: func(context.Context) (secrets.Identity, error) { return s.identity, nil },
	}
	return s
}

// setupPlan submits and approves a node.setup of the fixture node as admin.
func (s *setting) setupPlan(params map[string]any) jobs.Job {
	s.t.Helper()
	ctx, by := context.Background(), s.caller(s.admin)
	created, err := s.plans.Create(ctx, by, PlanRequest{
		Action: "node.setup", Target: domain.ResourceRef{Type: domain.ResourceNode, ID: s.node.ID}, Parameters: params,
	})
	mustf(s.t, err, "Create")
	sub, err := s.plans.Submit(ctx, by, created.Record.ID, created.Record.PlanHash)
	mustf(s.t, err, "Submit")
	return s.approveToQuorum(sub.Job)
}

func defaultSetup() map[string]any {
	return map[string]any{"docker_access": "false", "logs_mode": "journal-group", "grants": []any{}}
}

func (s *setting) run() error {
	s.t.Helper()
	claimed, ok := s.claim()
	if !ok {
		s.t.Fatal("no job to claim")
	}
	s.lease = claimed.Lease
	err := s.handler.Run(context.Background(), claimed.Lease)
	if err == nil {
		mustf(s.t, s.store.Succeed(context.Background(), claimed.Lease), "Succeed")
	}
	return err
}

func (s *setting) setupCapability() (runtimes.SetupMeta, bool) {
	s.t.Helper()
	meta, err := loadSetup(context.Background(), s.db.Reader(), s.node.ID)
	mustf(s.t, err, "loadSetup")
	if meta == nil {
		return runtimes.SetupMeta{}, false
	}
	return *meta, true
}

func TestSetupProvisionsVerifiesAndOnlyThenRecordsTheCapability(t *testing.T) {
	s := newSetting(t)
	s.setupPlan(map[string]any{"docker_access": "false", "logs_mode": "journal-group", "grants": []any{}})

	if err := s.run(); err != nil {
		t.Fatalf("setup: %v", err)
	}

	meta, ok := s.setupCapability()
	if !ok {
		t.Fatal("node.setup capability not recorded")
	}
	want := runtimes.SetupMeta{
		SetupVersion: runtimes.SetupVersion, SystemctlPath: "/usr/bin/systemctl", LogsMode: runtimes.LogsJournalGroup, DeployRoot: "/srv/supermgmt",
		KeyRef: "secret://ssh/default", KeyVersion: 1, KeyFingerprint: "SHA256:identity",
	}
	if meta.SetupVersion != want.SetupVersion || meta.SystemctlPath != want.SystemctlPath || meta.LogsMode != want.LogsMode ||
		meta.KeyRef != want.KeyRef || meta.KeyVersion != 1 || meta.KeyFingerprint != want.KeyFingerprint || meta.DockerAccess || meta.DeployRoot != want.DeployRoot {
		t.Errorf("metadata = %+v, want %+v", meta, want)
	}
	admin := s.dialer.as("admin")
	if admin.count("setup.user_add.sudo") != 1 || admin.count("setup.user_add") != 0 {
		t.Errorf("admin_user is not root, every privileged step must go through sudo: %v", admin.ran())
	}
	for _, target := range s.dialer.targets()[:1] {
		if target.User != "admin" || target.CredentialRef != "ssh-agent://default" {
			t.Errorf("bootstrap session = %s with %s", target.User, target.CredentialRef)
		}
	}
	verified := false
	for _, target := range s.dialer.targets() {
		verified = verified || (target.User == "supermgmt" && target.CredentialRef == "secret://ssh/default@1")
	}
	if !verified {
		t.Errorf("targets = %+v; verification must use a session as the dedicated user with the key just authorized", s.dialer.targets())
	}
	if len(s.events("node.setup.completed")) != 1 {
		t.Error("completion was not audited")
	}
}

func TestSetupV2CreatesDeployRootAndRequiresJQ(t *testing.T) {
	t.Run("deploy_root is created through sudo", func(t *testing.T) {
		s := newSetting(t)
		s.setupPlan(defaultSetup())

		mustf(t, s.run(), "setup")

		admin := s.dialer.as("admin")
		if admin.count("setup.deploy_root.sudo") != 1 || admin.count("setup.deploy_root") != 0 || admin.count("setup.jq_path") != 1 {
			t.Errorf("admin ran %v", admin.ran())
		}
	})
	t.Run("a node without jq is refused before anything changes", func(t *testing.T) {
		s := newSetting(t)
		s.dialer.as("admin").exit("setup.jq_path", 1)
		s.setupPlan(defaultSetup())

		err := s.run()

		wantError(t, err, smerr.CodeCapabilityUnavailable, "")
		if !strings.Contains(err.Error(), "jq is required") {
			t.Errorf("error = %v", err)
		}
		if got := s.dialer.as("admin").count("setup.user_add.sudo"); got != 0 {
			t.Errorf("%d privileged steps ran on a node without jq", got)
		}
		if _, ok := s.setupCapability(); ok {
			t.Error("capability recorded for a node without jq")
		}
	})
	t.Run("a deploy_root that cannot be created fails the setup", func(t *testing.T) {
		s := newSetting(t)
		s.dialer.as("admin").exit("setup.deploy_root.sudo", 1)
		s.setupPlan(defaultSetup())

		wantError(t, s.run(), smerr.CodeCapabilityUnavailable, "")
		if _, ok := s.setupCapability(); ok {
			t.Error("capability recorded although deploy_root is missing")
		}
		if ends := s.events("node.setup.privileged_session"); len(ends) != 2 || ends[1].Result != domain.ResultFailed {
			t.Errorf("the failed session must be closed in the audit trail: %+v", ends)
		}
	})
}

func TestRerunningSetupUpgradesAVersion1Node(t *testing.T) {
	s := newSetting(t)
	v1 := runtimes.SetupMeta{SetupVersion: 1, SystemctlPath: "/usr/bin/systemctl", LogsMode: runtimes.LogsJournalGroup, KeyRef: "secret://ssh/default", KeyVersion: 1}
	capability, err := setupCapability(v1, s.clock.Now())
	mustf(t, err, "setupCapability")
	s.inTx(func(ctx context.Context, tx *database.Tx) error {
		return database.SetNodeCapability(ctx, tx, s.node.ID, capability)
	})
	s.setupPlan(defaultSetup())

	mustf(t, s.run(), "setup")

	meta, ok := s.setupCapability()
	if !ok || meta.SetupVersion != runtimes.SetupVersion || meta.DeployRoot != "/srv/supermgmt" {
		t.Errorf("metadata = %+v, want the current setup_version with the default deploy_root", meta)
	}
}

func TestDeployRootOfTheSetupParameters(t *testing.T) {
	tests := []struct {
		name   string
		params map[string]any
		want   string
		bad    bool
	}{
		{"absent means the default", map[string]any{}, "/srv/supermgmt", false},
		{"explicit", map[string]any{"deploy_root": "/opt/deploy"}, "/opt/deploy", false},
		{"relative", map[string]any{"deploy_root": "opt/deploy"}, "", true},
		{"not clean", map[string]any{"deploy_root": "/opt/../etc"}, "", true},
		{"empty", map[string]any{"deploy_root": ""}, "", true},
		{"not a string", map[string]any{"deploy_root": 7}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := deployRootOf(tt.params)
			if tt.bad {
				wantError(t, err, smerr.CodeInvalidArgument, "")
				return
			}
			if err != nil || got != tt.want {
				t.Errorf("deployRootOf = %q, %v; want %q", got, err, tt.want)
			}
		})
	}
}

func TestSetupAuditsTheBootstrapSession(t *testing.T) {
	s := newSetting(t)
	s.setupPlan(defaultSetup())

	mustf(t, s.run(), "setup")

	events := s.events("node.setup.privileged_session")
	if len(events) != 2 || events[0].Data["phase"] != "start" || events[1].Data["phase"] != "end" ||
		events[0].Data["via"] != "sudo" || events[0].Data["admin_user"] != "admin" {
		t.Errorf("events = %+v", events)
	}
	if events[1].Result != domain.ResultSucceeded {
		t.Errorf("end result = %s", events[1].Result)
	}
}

func TestSetupAsRootRunsTheStepsDirectly(t *testing.T) {
	s := newSetting(t)
	s.inTx(func(ctx context.Context, tx *database.Tx) error {
		node, _ := database.GetNode(ctx, tx, s.node.ID)
		node.Endpoint.AdminUser = "root"
		_, err := database.UpdateNodeSpec(ctx, tx, node, node.SpecRevision)
		return err
	})
	s.dialer.as("root").fallback = s.dialer.as("admin").fallback
	root := s.dialer.as("root")
	root.reply("setup.systemctl_path", "/usr/bin/systemctl\n")
	root.reply("setup.user_entry", passwdEntry)
	root.reply("setup.user_groups", "supermgmt systemd-journal\n")
	onATrustedNode(root)
	s.setupPlan(defaultSetup())

	mustf(t, s.run(), "setup")

	if root.count("setup.user_add.sudo") != 0 || root.count("setup.dir") == 0 {
		t.Errorf("root session ran %v; root needs no sudo variants", root.ran())
	}
	if got := s.events("node.setup.privileged_session")[0].Data["via"]; got != "root" {
		t.Errorf("via = %v", got)
	}
}

func TestSetupRefusesAnAdminWithoutPasswordlessSudo(t *testing.T) {
	s := newSetting(t)
	s.dialer.as("admin").reply("probe", strings.Replace(linuxProbe, "@@sudo\nyes", "@@sudo\nno", 1))
	s.setupPlan(defaultSetup())

	err := s.run()

	wantError(t, err, smerr.CodeCapabilityUnavailable, "")
	if !strings.Contains(err.Error(), "admin_user needs root or passwordless sudo for setup") {
		t.Errorf("error = %v", err)
	}
	if got := s.dialer.as("admin").count("setup.user_add.sudo"); got != 0 {
		t.Errorf("%d privileged steps ran after the preflight failed", got)
	}
	if _, ok := s.setupCapability(); ok {
		t.Error("capability recorded for a failed setup")
	}
}

func TestSetupRefusesANodeThatIsNotLinux(t *testing.T) {
	s := newSetting(t)
	s.dialer.as("admin").reply("probe", strings.Replace(linuxProbe, "Linux 6.12.43-amd64 x86_64", "Darwin 25.0.0 arm64", 1))
	s.setupPlan(defaultSetup())

	err := s.run()

	wantError(t, err, smerr.CodeCapabilityUnavailable, "")
	if !strings.Contains(err.Error(), "setup needs a Linux node; this one runs Darwin") {
		t.Errorf("error = %v", err)
	}
	if got := len(s.dialer.as("admin").ran()); got != 1 {
		t.Errorf("ran %v; nothing may run after the preflight refused", s.dialer.as("admin").ran())
	}
}

func TestSetupNeverAdoptsAForeignAccount(t *testing.T) {
	s := newSetting(t)
	s.dialer.as("admin").reply("setup.user_entry", "supermgmt:x:1000:1000::/home/supermgmt:/bin/bash\n")
	s.setupPlan(defaultSetup())

	err := s.run()

	if smerr.CodeOf(err) != smerr.CodeConflict {
		t.Fatalf("error = %v, want CONFLICT", err)
	}
	if _, ok := s.setupCapability(); ok {
		t.Error("capability recorded although an existing account was not ours")
	}
	if ends := s.events("node.setup.privileged_session"); len(ends) != 2 || ends[1].Result != domain.ResultFailed {
		t.Errorf("the failed bootstrap session must still be closed in the audit trail: %+v", ends)
	}
}

func TestAFailedVerificationLeavesTheNodeOnTheAdminAccount(t *testing.T) {
	s := newSetting(t)
	s.dialer.as("supermgmt").reply("setup.verify_markers", "")
	s.setupPlan(defaultSetup())

	err := s.run()

	wantError(t, err, smerr.CodeCapabilityUnavailable, "")
	if _, ok := s.setupCapability(); ok {
		t.Fatal("capability recorded although verification failed")
	}
	if s.dialer.as("supermgmt").count("probe") != 0 {
		t.Error("the node was probed as the dedicated user although setup failed")
	}
}

func TestARerunOfSetupKeepsTheAccountAndRewritesTheCapability(t *testing.T) {
	s := newSetting(t)
	s.setupPlan(defaultSetup())
	mustf(t, s.run(), "first setup")
	s.setupPlan(defaultSetup())

	mustf(t, s.run(), "second setup")

	if got := s.dialer.as("admin").count("setup.user_add.sudo"); got != 1 {
		t.Errorf("the account was created %d times, want 1", got)
	}
	if _, ok := s.setupCapability(); !ok {
		t.Error("capability missing after a rerun")
	}
}

func TestAWorkerThatLostItsLeaseRecordsNothing(t *testing.T) {
	s := newSetting(t)
	s.dialer.as("admin").on("setup.tmpfiles_apply.sudo", func(templates.Command) (transport.Result, error) {
		s.clock.Advance(time.Minute) // the lease (30s) expires while setup is still working
		return transport.Result{}, nil
	})
	s.setupPlan(defaultSetup())

	err := s.run()

	if !errors.Is(err, jobs.ErrLeaseLost) {
		t.Errorf("error = %v, want ErrLeaseLost", err)
	}
	if _, ok := s.setupCapability(); ok {
		t.Error("a fenced-out worker recorded the capability")
	}
}

func TestSetupOfTheLocalProviderIsRefused(t *testing.T) {
	s := newSetting(t)
	s.setupPlan(defaultSetup())
	s.inTx(func(ctx context.Context, tx *database.Tx) error {
		// The node becomes local after the plan was approved: the handler still refuses.
		_, err := tx.ExecContext(ctx, `UPDATE nodes SET kind = 'local' WHERE id = ?`, s.node.ID)
		return err
	})

	err := s.run()

	wantError(t, err, smerr.CodeCapabilityUnavailable, "")
}

func TestASetupPlanIsCompositeAndHighRisk(t *testing.T) {
	s := newSetting(t)
	params := map[string]any{"docker_access": "true", "logs_mode": "broker", "grants": []any{"restart nginx.service", "stop nginx.service"}}

	created, err := s.plans.Create(context.Background(), s.caller(s.admin), PlanRequest{
		Action: "node.setup", Target: domain.ResourceRef{Type: domain.ResourceNode, ID: s.node.ID}, Parameters: params,
	})

	mustf(t, err, "Create")
	var actions []string
	for _, sub := range created.Plan.SubActions {
		actions = append(actions, sub.Action)
	}
	if len(actions) != 2 || actions[0] != "log_broker.install" || actions[1] != "sudoers.write" {
		t.Errorf("sub-actions = %v; broker mode adds log_broker.install to sudoers.write", actions)
	}
	if created.Plan.Risk != domain.RiskHigh || !created.Policy.ApprovalRequired || created.Policy.Quorum != 2 {
		t.Errorf("risk %s policy %+v", created.Plan.Risk, created.Policy)
	}
}

func TestASetupPlanNeedsEverySubActionAllowed(t *testing.T) {
	s := newSetting(t)

	created, err := s.plans.Create(context.Background(), s.caller(s.alice), PlanRequest{ // an operator
		Action: "node.setup", Target: domain.ResourceRef{Type: domain.ResourceNode, ID: s.node.ID}, Parameters: defaultSetup(),
	})

	mustf(t, err, "Create")
	if created.Policy.Decision == "allow" {
		t.Error("an operator may not set up a node, which writes sudoers")
	}
}

func TestSetupParametersAreValidatedWhenPlanning(t *testing.T) {
	s := newSetting(t)
	for name, params := range map[string]map[string]any{
		"grant that is not verb unit":  {"docker_access": "false", "logs_mode": "journal-group", "grants": []any{"restart"}},
		"unknown verb":                 {"docker_access": "false", "logs_mode": "journal-group", "grants": []any{"reload nginx.service"}},
		"unit with a shell character":  {"docker_access": "false", "logs_mode": "journal-group", "grants": []any{"restart x;rm.service"}},
		"docker access has no default": {"logs_mode": "journal-group"},
		"unknown parameter":            {"docker_access": "false", "logs_mode": "journal-group", "user": "root"},
	} {
		_, err := s.plans.Create(context.Background(), s.caller(s.admin), PlanRequest{
			Action: "node.setup", Target: domain.ResourceRef{Type: domain.ResourceNode, ID: s.node.ID}, Parameters: params,
		})
		if smerr.CodeOf(err) != smerr.CodeInvalidArgument {
			t.Errorf("%s: error = %v, want INVALID_ARGUMENT", name, err)
		}
	}
}

func TestGrantsAreMergedPerUnitInCanonicalOrder(t *testing.T) {
	grants, err := parseGrants([]any{"restart a.service", "start b.service", "start a.service", "restart a.service"})

	if err != nil || len(grants) != 2 || grants[0].Unit != "a.service" || grants[1].Unit != "b.service" {
		t.Fatalf("grants = %+v, %v", grants, err)
	}
	if got := grants[0].Verbs; len(got) != 2 || got[0] != domain.VerbStart || got[1] != domain.VerbRestart {
		t.Errorf("verbs = %v, want canonical start, restart", got)
	}
}

func TestSetupDropsTheDedicatedConnectionBeforeVerifying(t *testing.T) {
	s := newSetting(t)
	s.setupPlan(defaultSetup())

	mustf(t, s.run(), "setup")

	if want := s.node.ID.String() + "/supermgmt"; len(s.dialer.invalidated) != 1 || s.dialer.invalidated[0] != want {
		t.Errorf("invalidated = %v, want [%s]: verification needs a fresh session that sees the new groups", s.dialer.invalidated, want)
	}
}

func TestSetupVerifiesTheEffectiveGroupsOfTheFreshSession(t *testing.T) {
	for name, groups := range map[string]string{
		"docker that was not requested": "supermgmt systemd-journal docker\n",
		"a privileged group":            "supermgmt systemd-journal sudo\n",
		"no journal group":              "supermgmt\n",
	} {
		s := newSetting(t)
		s.dialer.as("supermgmt").reply("setup.verify_groups", groups)
		s.setupPlan(defaultSetup())

		err := s.run()

		wantError(t, err, smerr.CodeCapabilityUnavailable, "")
		if _, ok := s.setupCapability(); ok {
			t.Errorf("%s: capability recorded", name)
		}
	}
}

func TestSetupWithDockerAccessRequiresTheDockerGroupInTheSession(t *testing.T) {
	s := newSetting(t)
	s.dialer.as("admin").reply("setup.user_groups", "supermgmt systemd-journal docker\n").reply("setup.verify_groups", "supermgmt systemd-journal docker\n")
	s.setupPlan(map[string]any{"docker_access": "true", "logs_mode": "journal-group", "grants": []any{}})

	err := s.run() // the fresh session lacks docker

	wantError(t, err, smerr.CodeCapabilityUnavailable, "")
}

func TestASetupPlanTakesTheConfiguredLogsModeWhenNoneIsGiven(t *testing.T) {
	broker := newSetting(t)
	broker.cfg.DefaultLogsMode = "broker"
	plans, err := NewPlans(broker.cfg, broker.store)
	mustf(t, err, "NewPlans")
	created, err := plans.Create(context.Background(), broker.caller(broker.admin), PlanRequest{
		Action: "node.setup", Target: domain.ResourceRef{Type: domain.ResourceNode, ID: broker.node.ID},
		Parameters: map[string]any{"docker_access": "false"},
	})
	mustf(t, err, "Create")
	plain, err := broker.plans.Create(context.Background(), broker.caller(broker.admin), PlanRequest{
		Action: "node.setup", Target: domain.ResourceRef{Type: domain.ResourceNode, ID: broker.node.ID},
		Parameters: map[string]any{"docker_access": "false"},
	})
	mustf(t, err, "Create")

	if created.Plan.Parameters["logs_mode"] != "broker" || plain.Plan.Parameters["logs_mode"] != "journal-group" {
		t.Errorf("logs_mode = %v and %v; the plan must state the mode that will run", created.Plan.Parameters["logs_mode"], plain.Plan.Parameters["logs_mode"])
	}
	if len(created.Plan.SubActions) != 2 {
		t.Errorf("sub-actions = %+v; the defaulted broker mode is composite", created.Plan.SubActions)
	}
}
