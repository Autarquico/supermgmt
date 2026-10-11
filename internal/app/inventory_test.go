package app

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/policy"
	localprovider "github.com/autarquico/supermgmt/internal/providers/local"
	sshnode "github.com/autarquico/supermgmt/internal/providers/ssh"
	"github.com/autarquico/supermgmt/internal/transport/ssh"
)

// withStaging adds a staging environment, where an operational change needs no approval.
func (n *nodeFixture) withStaging() string {
	n.t.Helper()
	n.inTx(func(ctx context.Context, tx *database.Tx) error {
		_, err := database.CreateEnvironment(ctx, tx, domain.Environment{
			ID: n.ids.NewID(), Name: "staging", RiskLevel: domain.EnvironmentStaging, ApprovalsRequired: 1,
		})
		return err
	})
	return "staging"
}

func (n *nodeFixture) addRequest(name, environment string) AddSSHNode {
	return AddSSHNode{
		Name: name, Host: "10.0.0.9", AdminUser: "admin", HostKey: newAuthorizedKey(),
		Environment: environment, Tags: []string{"web", "api", "web"},
	}
}

// addApplied adds a node as admin and returns its view.
func (n *nodeFixture) addApplied(name, environment string) wire.Node {
	n.t.Helper()
	res, err := n.inv.AddSSHNode(context.Background(), n.caller(n.admin), n.addRequest(name, environment))
	if err != nil || res.Applied == nil {
		n.t.Fatalf("AddSSHNode: %v / %+v", err, res)
	}
	return *res.Applied
}

func TestAddSSHNodeAppliesInsideTheRequest(t *testing.T) {
	n := newNodeFixture(t)
	staging := n.withStaging()
	req := n.addRequest("web-2", staging)

	res, err := n.inv.AddSSHNode(context.Background(), n.caller(n.admin), req)

	if err != nil || res.Applied == nil || res.Pending != nil {
		t.Fatalf("AddSSHNode = %+v, %v; want it applied", res, err)
	}
	node := *res.Applied
	if node.Name != "web-2" || node.Kind != "ssh" || node.Provider != "web-2" || node.Origin != domain.ProviderAPI ||
		node.Environment != "staging" || node.ManagementState != domain.ManagementManaged || node.Reachability != domain.ReachabilityUnknown {
		t.Errorf("view = %+v", node)
	}
	if !slices.Equal(node.Tags, []string{"api", "web"}) {
		t.Errorf("tags = %v, want sorted and deduplicated", node.Tags)
	}
	if e := node.Endpoint; e.Port != 22 || e.User != "supermgmt" || e.AdminUser != "admin" || e.HostPublicKey != req.HostKey ||
		!strings.HasPrefix(e.HostKeyFingerprintSHA256, "SHA256:") {
		t.Errorf("endpoint = %+v", e)
	}
	if node.CredentialRef != "secret://ssh/default" || node.AdminCredentialRef != "ssh-agent://default" {
		t.Errorf("credential refs = %q / %q, want the local-mode defaults", node.CredentialRef, node.AdminCredentialRef)
	}
	if len(n.dialer.targets()) != 0 {
		t.Errorf("adding a node dialed %v; first trust is the confirmed key, not a connection", n.dialer.targets())
	}
	if len(n.events("node.add")) != 1 {
		t.Errorf("want one node.add event, got %d", len(n.events("node.add")))
	}
}

func TestAddSSHNodeRejectsWhatTheAllowlistsRefuse(t *testing.T) {
	n := newNodeFixture(t)
	n.addApplied("taken", "")
	tests := []struct {
		name   string
		mutate func(*AddSSHNode)
		want   smerr.Code
	}{
		{"name with a space", func(r *AddSSHNode) { r.Name = "web 2" }, smerr.CodeInvalidArgument},
		{"host that looks like an option", func(r *AddSSHNode) { r.Host = "-oProxyCommand=x" }, smerr.CodeInvalidArgument},
		{"user@host", func(r *AddSSHNode) { r.Host = "root@10.0.0.9" }, smerr.CodeInvalidArgument},
		{"no host key", func(r *AddSSHNode) { r.HostKey = "" }, smerr.CodeInvalidArgument},
		{"garbage host key", func(r *AddSSHNode) { r.HostKey = "ssh-ed25519 AAAA" }, smerr.CodeInvalidArgument},
		{"uppercase admin user", func(r *AddSSHNode) { r.AdminUser = "Root" }, smerr.CodeInvalidArgument},
		{"credential that is not a reference", func(r *AddSSHNode) { r.CredentialRef = "-----BEGIN KEY" }, smerr.CodeInvalidArgument},
		{"unknown environment", func(r *AddSSHNode) { r.Environment = "nowhere" }, smerr.CodeInvalidArgument},
		{"tag with a space", func(r *AddSSHNode) { r.Tags = []string{"a b"} }, smerr.CodeInvalidArgument},
		{"duplicate name", func(r *AddSSHNode) { r.Name = "taken" }, smerr.CodeConflict},
	}
	before := len(mustNodes(t, n.fixture))
	for _, tt := range tests {
		req := n.addRequest("fresh", "")
		tt.mutate(&req)

		_, err := n.inv.AddSSHNode(context.Background(), n.caller(n.admin), req)

		if smerr.CodeOf(err) != tt.want {
			t.Errorf("%s: error = %v, want %s", tt.name, err, tt.want)
		}
	}
	if after := len(mustNodes(t, n.fixture)); after != before {
		t.Errorf("rejected requests left %d new nodes", after-before)
	}
}

func mustNodes(t *testing.T, f *fixture) []domain.Node {
	t.Helper()
	nodes, err := database.ListNodes(context.Background(), f.db.Reader())
	if err != nil {
		t.Fatalf("ListNodes: %v", err)
	}
	return nodes
}

func TestAddSSHNodeNeedsThePermission(t *testing.T) {
	n := newNodeFixture(t)

	_, err := n.inv.AddSSHNode(context.Background(), n.caller(n.alice), n.addRequest("web-2", ""))

	wantError(t, err, smerr.CodePolicyDenied, smerr.ReasonDefaultDeny)
	if len(n.events("policy.deny")) == 0 {
		t.Error("the refusal was not audited")
	}
}

func TestAddSSHNodeToProductionWaitsForApprovalAndIsAppliedByTheJob(t *testing.T) {
	n := newNodeFixture(t)

	res, err := n.inv.AddSSHNode(context.Background(), n.caller(n.admin), n.addRequest("web-2", "prod"))

	if err != nil || res.Pending == nil || res.Applied != nil {
		t.Fatalf("AddSSHNode = %+v, %v; want a pending job", res, err)
	}
	job := res.Pending.Job
	if job.Type != JobControlPlaneApply || job.State != domain.JobAwaitingApproval || res.Pending.Policy.Quorum != 2 {
		t.Errorf("job = %s %s quorum %d", job.Type, job.State, res.Pending.Policy.Quorum)
	}
	if len(mustNodes(t, n.fixture)) != 1 {
		t.Fatal("the node exists before approval")
	}

	n.approveToQuorum(job)
	claimed, ok := n.claim()
	if !ok {
		t.Fatal("the approved job was not claimable")
	}
	if err := (applyHandler{inv: n.inv}).Run(context.Background(), claimed.Lease); err != nil {
		t.Fatalf("apply: %v", err)
	}

	nodes := mustNodes(t, n.fixture)
	if len(nodes) != 2 {
		t.Fatalf("want the new node, have %d nodes", len(nodes))
	}
	added := slices.IndexFunc(nodes, func(x domain.Node) bool { return x.Name == "web-2" })
	if added < 0 || nodes[added].EnvironmentID == nil || *nodes[added].EnvironmentID != n.env.ID {
		t.Errorf("nodes = %+v", nodes)
	}
}

func TestApplyingAnAddTwiceConverges(t *testing.T) {
	n := newNodeFixture(t)
	res, err := n.inv.AddSSHNode(context.Background(), n.caller(n.admin), n.addRequest("web-2", "prod"))
	if err != nil {
		t.Fatalf("AddSSHNode: %v", err)
	}
	n.approveToQuorum(res.Pending.Job)
	claimed, _ := n.claim()

	for range 2 {
		if err := (applyHandler{inv: n.inv}).Run(context.Background(), claimed.Lease); err != nil {
			t.Fatalf("apply: %v", err)
		}
	}

	if len(mustNodes(t, n.fixture)) != 2 || len(n.events("node.add")) != 1 {
		t.Errorf("nodes %d, node.add events %d; a repeated apply must change nothing", len(mustNodes(t, n.fixture)), len(n.events("node.add")))
	}
}

func TestUpdateNodeBumpsTheRevisionOnlyWhenSomethingChanges(t *testing.T) {
	n := newNodeFixture(t)
	node := n.addApplied("web-2", n.withStaging())
	tags := []string{"db"}
	admin := "ops"

	res, err := n.inv.UpdateNode(context.Background(), n.caller(n.admin), node.ID, node.SpecRevision, NodePatch{Tags: &tags, AdminUser: &admin})
	if err != nil || res.Applied == nil {
		t.Fatalf("UpdateNode = %+v, %v", res, err)
	}
	updated := *res.Applied
	if updated.SpecRevision != node.SpecRevision+1 || !slices.Equal(updated.Tags, tags) || updated.Endpoint.AdminUser != "ops" {
		t.Errorf("updated = rev %d tags %v admin %q", updated.SpecRevision, updated.Tags, updated.Endpoint.AdminUser)
	}

	same, err := n.inv.UpdateNode(context.Background(), n.caller(n.admin), node.ID, updated.SpecRevision, NodePatch{Tags: &tags})
	if err != nil || same.Applied.SpecRevision != updated.SpecRevision {
		t.Errorf("a patch that changes nothing moved the revision: %+v, %v", same.Applied, err)
	}
}

func TestUpdateNodeWithAStaleRevisionIsAConflict(t *testing.T) {
	n := newNodeFixture(t)
	node := n.addApplied("web-2", n.withStaging())
	name := "renamed"

	_, err := n.inv.UpdateNode(context.Background(), n.caller(n.admin), node.ID, node.SpecRevision+5, NodePatch{Name: &name})

	var typed *smerr.Error
	if !errors.As(err, &typed) || typed.Code != smerr.CodeConflict || typed.Details["current_spec_revision"] != node.SpecRevision {
		t.Errorf("error = %v (%+v), want CONFLICT carrying the current revision", err, typed)
	}
}

func requireErrorCode(t *testing.T, err error, want smerr.Code) {
	t.Helper()
	if smerr.CodeOf(err) != want {
		t.Fatalf("error = %v, want %s", err, want)
	}
}

func (n *nodeFixture) storedHostKey(id domain.ID) string {
	n.t.Helper()
	var key string
	n.inTx(func(ctx context.Context, tx *database.Tx) error {
		node, err := database.GetNode(ctx, tx, id)
		key = node.Endpoint.HostPublicKey
		return err
	})
	return key
}

func TestRepinReplacesThePinDropsTheConnectionsAndAuditsBothFingerprints(t *testing.T) {
	n := newNodeFixture(t)
	node := n.addApplied("web-3", n.withStaging())
	newKey := newAuthorizedKey()
	oldFingerprint, _ := sshnode.Fingerprint(node.Endpoint.HostPublicKey)
	newFingerprint, _ := sshnode.Fingerprint(newKey)

	res, err := n.inv.UpdateNode(context.Background(), n.caller(n.admin), node.ID, node.SpecRevision, NodePatch{HostPublicKey: &newKey})

	if err != nil || res.Applied == nil {
		t.Fatalf("UpdateNode = %+v, %v", res, err)
	}
	if got := n.storedHostKey(node.ID); got != newKey || res.Applied.SpecRevision != node.SpecRevision+1 {
		t.Errorf("stored pin %q, revision %d; want the new key at revision %d", got, res.Applied.SpecRevision, node.SpecRevision+1)
	}
	events := n.events("node.host_key.repinned")
	if len(events) != 1 || events[0].Data["old_fingerprint"] != oldFingerprint || events[0].Data["new_fingerprint"] != newFingerprint {
		t.Fatalf("events = %+v, want one carrying both fingerprints", events)
	}
	if strings.Contains(fmt.Sprint(events[0].Data), newKey) {
		t.Error("the event carries the key itself, not just its fingerprint")
	}
	for _, user := range []string{"supermgmt", "admin"} {
		if !slices.Contains(n.dialer.invalidated, node.ID.String()+"/"+user) {
			t.Errorf("the pooled connection of %s was not dropped: %v", user, n.dialer.invalidated)
		}
	}
}

func TestRepinTogetherWithOtherFieldsAppliesBoth(t *testing.T) {
	n := newNodeFixture(t)
	node := n.addApplied("web-3", n.withStaging())
	newKey, tags := newAuthorizedKey(), []string{"edge"}

	res, err := n.inv.UpdateNode(context.Background(), n.caller(n.admin), node.ID, node.SpecRevision, NodePatch{HostPublicKey: &newKey, Tags: &tags})

	if err != nil || res.Applied == nil {
		t.Fatalf("UpdateNode = %+v, %v", res, err)
	}
	if n.storedHostKey(node.ID) != newKey || !slices.Equal(res.Applied.Tags, tags) {
		t.Errorf("pin %q tags %v; want both changes", n.storedHostKey(node.ID), res.Applied.Tags)
	}
}

func TestRepinToTheCurrentKeyChangesNothing(t *testing.T) {
	n := newNodeFixture(t)
	node := n.addApplied("web-3", n.withStaging())
	same := node.Endpoint.HostPublicKey

	res, err := n.inv.UpdateNode(context.Background(), n.caller(n.admin), node.ID, node.SpecRevision, NodePatch{HostPublicKey: &same})

	if err != nil || res.Applied.SpecRevision != node.SpecRevision || len(n.events("node.host_key.repinned")) != 0 || len(n.dialer.invalidated) != 0 {
		t.Errorf("revision %d, events %d, drops %v; a re-pin to the same key must be a no-op", res.Applied.SpecRevision, len(n.events("node.host_key.repinned")), n.dialer.invalidated)
	}
}

func TestRepinRefusals(t *testing.T) {
	validKey := newAuthorizedKey()
	cases := map[string]struct {
		key  string
		want smerr.Code
	}{
		"not a key":      {"definitely not a key", smerr.CodeInvalidArgument},
		"two keys":       {validKey + "\n" + newAuthorizedKey(), smerr.CodeInvalidArgument},
		"an empty value": {"", smerr.CodeInvalidArgument},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			n := newNodeFixture(t)
			node := n.addApplied("web-3", n.withStaging())
			_, err := n.inv.UpdateNode(context.Background(), n.caller(n.admin), node.ID, node.SpecRevision, NodePatch{HostPublicKey: &c.key})
			requireErrorCode(t, err, c.want)
			if n.storedHostKey(node.ID) != node.Endpoint.HostPublicKey {
				t.Error("a refused re-pin changed the pin")
			}
		})
	}

	t.Run("a stale revision", func(t *testing.T) {
		n := newNodeFixture(t)
		node := n.addApplied("web-3", n.withStaging())
		_, err := n.inv.UpdateNode(context.Background(), n.caller(n.admin), node.ID, node.SpecRevision+1, NodePatch{HostPublicKey: &validKey})
		requireErrorCode(t, err, smerr.CodeConflict)
		if n.storedHostKey(node.ID) != node.Endpoint.HostPublicKey {
			t.Error("a re-pin with a stale If-Match changed the pin")
		}
	})
	t.Run("a caller without node.update", func(t *testing.T) {
		n := newNodeFixture(t)
		node := n.addApplied("web-3", n.withStaging())
		_, err := n.inv.UpdateNode(context.Background(), n.caller(n.dave), node.ID, node.SpecRevision, NodePatch{HostPublicKey: &validKey})
		requireErrorCode(t, err, smerr.CodePolicyDenied)
		if n.storedHostKey(node.ID) != node.Endpoint.HostPublicKey {
			t.Error("a denied re-pin changed the pin")
		}
	})
	t.Run("the local node", func(t *testing.T) {
		n := newNodeFixture(t)
		var local domain.Node
		n.inTx(func(ctx context.Context, tx *database.Tx) error {
			now := n.clock.Now()
			provider, err := database.CreateProvider(ctx, tx, domain.Provider{
				ID: n.ids.NewID(), Type: localprovider.ProviderType, Name: "local", Origin: domain.ProviderAPI, CreatedAt: now, UpdatedAt: now,
			})
			if err != nil {
				return err
			}
			local, err = database.CreateNode(ctx, tx, domain.Node{
				ID: n.ids.NewID(), ProviderID: provider.ID, NativeID: localprovider.NativeID, Name: "local", Kind: localprovider.NodeKind,
				ManagementState: domain.ManagementManaged, Reachability: domain.ReachabilityUnknown, CreatedAt: now, UpdatedAt: now,
			})
			return err
		})
		var err error
		_, err = n.inv.UpdateNode(context.Background(), n.caller(n.admin), local.ID, local.SpecRevision, NodePatch{HostPublicKey: &validKey})
		requireErrorCode(t, err, smerr.CodeInvalidArgument)
	})
}

func TestRepinThatNeedsApprovalChangesNothingUntilTheJobAppliesTheKey(t *testing.T) {
	n := newNodeFixture(t) // the fixture node is in production: two approvals
	newKey, tags := newAuthorizedKey(), []string{"edge"}
	oldFingerprint, _ := sshnode.Fingerprint(n.node.Endpoint.HostPublicKey)
	newFingerprint, _ := sshnode.Fingerprint(newKey)

	res, err := n.inv.UpdateNode(context.Background(), n.caller(n.admin), n.node.ID, n.node.SpecRevision, NodePatch{HostPublicKey: &newKey, Tags: &tags})

	if err != nil || res.Pending == nil || res.Applied != nil {
		t.Fatalf("UpdateNode = %+v, %v; want a pending job", res, err)
	}
	if n.storedHostKey(n.node.ID) != n.node.Endpoint.HostPublicKey || len(n.dialer.invalidated) != 0 || len(n.events("node.host_key.repinned")) != 0 {
		t.Fatal("the pin changed before the approval")
	}

	n.approveToQuorum(res.Pending.Job)
	claimed, ok := n.claim()
	if !ok {
		t.Fatal("the approved job was not claimable")
	}
	for range 2 { // a retried job converges
		if err := (applyHandler{inv: n.inv}).Run(context.Background(), claimed.Lease); err != nil {
			t.Fatalf("apply: %v", err)
		}
	}

	if got := n.storedHostKey(n.node.ID); got != newKey {
		t.Errorf("stored pin %q, want the approved key", got)
	}
	node := mustNodeByID(t, n.fixture, n.node.ID)
	if !slices.Equal(node.Tags, tags) || node.SpecRevision != n.node.SpecRevision+2 {
		t.Errorf("tags %v revision %d; want the other fields applied after the re-pin", node.Tags, node.SpecRevision)
	}
	events := n.events("node.host_key.repinned")
	if len(events) != 1 || events[0].Data["old_fingerprint"] != oldFingerprint || events[0].Data["new_fingerprint"] != newFingerprint {
		t.Errorf("events = %+v, want one carrying both fingerprints", events)
	}
	if !slices.Contains(n.dialer.invalidated, n.node.ID.String()+"/admin") {
		t.Errorf("the pooled connection was not dropped: %v", n.dialer.invalidated)
	}
}

func mustNodeByID(t *testing.T, f *fixture, id domain.ID) domain.Node {
	t.Helper()
	var node domain.Node
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		var err error
		node, err = database.GetNode(ctx, tx, id)
		return err
	})
	return node
}

func TestUpdateAndRemoveRefuseNodesDefinedInTheConfigurationFile(t *testing.T) {
	n := newNodeFixture(t)
	n.inTx(func(ctx context.Context, tx *database.Tx) error {
		provider, err := database.CreateProvider(ctx, tx, domain.Provider{
			ID: n.ids.NewID(), Type: "ssh", Name: "from-file", Origin: domain.ProviderStatic, CreatedAt: n.clock.Now(), UpdatedAt: n.clock.Now(),
		})
		if err != nil {
			return err
		}
		_, err = database.CreateNode(ctx, tx, domain.Node{
			ID: n.ids.NewID(), ProviderID: provider.ID, NativeID: "from-file", Name: "from-file", Kind: "ssh",
			ManagementState: domain.ManagementManaged, Reachability: domain.ReachabilityUnknown,
			CreatedAt: n.clock.Now(), UpdatedAt: n.clock.Now(),
		})
		return err
	})
	var fromFile domain.Node
	for _, node := range mustNodes(t, n.fixture) {
		if node.Name == "from-file" {
			fromFile = node
		}
	}
	name := "x"

	_, updateErr := n.inv.UpdateNode(context.Background(), n.caller(n.admin), fromFile.ID, fromFile.SpecRevision, NodePatch{Name: &name})
	_, removeErr := n.inv.RemoveNode(context.Background(), n.caller(n.admin), fromFile.ID, fromFile.SpecRevision)

	if smerr.CodeOf(updateErr) != smerr.CodeConflict || smerr.CodeOf(removeErr) != smerr.CodeConflict {
		t.Errorf("update %v, remove %v; want CONFLICT for both", updateErr, removeErr)
	}
}

func TestUpdateIsRefusedWhileAJobHoldsTheNode(t *testing.T) {
	n := newNodeFixture(t)
	sub, _ := n.submitReboot()
	n.approveToQuorum(sub.Job)
	if _, ok := n.claim(); !ok {
		t.Fatal("job not claimed")
	}
	tags := []string{"x"}
	current, err := n.inv.GetNode(context.Background(), n.caller(n.admin), n.node.ID, false)
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}

	_, err = n.inv.UpdateNode(context.Background(), n.caller(n.admin), n.node.ID, current.SpecRevision, NodePatch{Tags: &tags})

	wantError(t, err, smerr.CodeConflict, smerr.ReasonResourceLocked)
}

func TestUpdateInProductionBecomesAJobAndStalePlansFail(t *testing.T) {
	n := newNodeFixture(t)
	tags := []string{"edge"}

	res, err := n.inv.UpdateNode(context.Background(), n.caller(n.admin), n.node.ID, n.node.SpecRevision, NodePatch{Tags: &tags})
	if err != nil || res.Pending == nil {
		t.Fatalf("UpdateNode = %+v, %v; want a pending job", res, err)
	}
	n.bumpNodeRevision() // someone else edits the node before approval
	n.approveToQuorum(res.Pending.Job)

	if _, ok := n.claim(); ok {
		t.Error("a job whose node changed after the plan was claimed")
	}
	if got := n.job(res.Pending.Job.ID); got.State != domain.JobFailed || got.Error == nil || got.Error.Reason != smerr.ReasonPlanStale {
		t.Errorf("job = %s %+v, want failed with PLAN_STALE", got.State, got.Error)
	}
}

// destructiveAdmins lets admins remove nodes: node.remove is destructive, and
// the built-in policy deliberately grants nobody that gate.
func destructiveAdmins(c *Config) {
	text := string(policy.DefaultYAML()) + `  - name: test-destructive
    subjects: ["role:admin"]
    allow: ["node.remove"]
    allow_destructive: true
`
	p, err := policy.Parse([]byte(text))
	if err != nil {
		panic(err)
	}
	c.Policy = p
}

func TestRemoveNodeIsGatedByTheDestructiveRule(t *testing.T) {
	n := newNodeFixture(t)
	node := n.addApplied("web-2", n.withStaging())

	_, err := n.inv.RemoveNode(context.Background(), n.caller(n.admin), node.ID, node.SpecRevision)

	wantError(t, err, smerr.CodePolicyDenied, smerr.ReasonDestructiveGate)
}

func TestRemoveNodeRetiresItAfterApproval(t *testing.T) {
	n := newNodeFixture(t, destructiveAdmins)
	node := n.addApplied("web-2", n.withStaging())

	res, err := n.inv.RemoveNode(context.Background(), n.caller(n.admin), node.ID, node.SpecRevision)
	if err != nil || res.Pending == nil {
		t.Fatalf("RemoveNode = %+v, %v; a destructive action is always approval-gated", res, err)
	}
	if _, err := n.approve(n.bob, res.Pending.Job); err != nil {
		t.Fatalf("approve: %v", err)
	}
	claimed, ok := n.claim()
	if !ok {
		t.Fatal("not claimable")
	}
	if err := (applyHandler{inv: n.inv}).Run(context.Background(), claimed.Lease); err != nil {
		t.Fatalf("apply: %v", err)
	}

	got, err := database.GetNode(context.Background(), n.db.Reader(), node.ID)
	if err != nil || got.ManagementState != domain.ManagementRetired {
		t.Errorf("node = %+v, %v; want retired", got, err)
	}
	if len(n.events("node.remove")) != 1 {
		t.Error("the removal was not audited")
	}
}

func TestRegisterLocalCreatesTheLocalProviderAndItsNodeAfterApproval(t *testing.T) {
	n := newNodeFixture(t)

	res, err := n.inv.RegisterLocal(context.Background(), n.caller(n.admin))
	if err != nil || res.Pending == nil {
		t.Fatalf("RegisterLocal = %+v, %v; provider.write is high risk and waits for approval", res, err)
	}
	approved, err := n.approve(n.bob, res.Pending.Job)
	if err != nil || approved.State != domain.JobQueued {
		t.Fatalf("approve: %v, %s", err, approved.State)
	}
	claimed, _ := n.claim()
	if err := (applyHandler{inv: n.inv}).Run(context.Background(), claimed.Lease); err != nil {
		t.Fatalf("apply: %v", err)
	}

	again, err := n.inv.RegisterLocal(context.Background(), n.caller(n.admin))
	if err != nil || again.Applied == nil || again.Applied.Type != "local" {
		t.Fatalf("second RegisterLocal = %+v, %v; want the existing provider", again, err)
	}
	var local domain.Node
	for _, node := range mustNodes(t, n.fixture) {
		if node.Kind == "local" {
			local = node
		}
	}
	if local.ID == "" || local.Name != "local" || local.ManagementState != domain.ManagementManaged {
		t.Errorf("local node = %+v", local)
	}
}

func TestListNodesAnswersFromTheDatabaseWithoutDialing(t *testing.T) {
	n := newNodeFixture(t)
	n.addApplied("web-2", n.withStaging())
	n.dialer.states[n.node.ID] = ssh.ConnState{Status: ssh.ConnBackoff, LastError: errors.New("connection refused\x1b[31m")}

	page, err := n.inv.ListNodes(context.Background(), n.caller(n.alice), wire.NodeQuery{})

	if err != nil || len(page.Items) != 2 {
		t.Fatalf("ListNodes = %d items, %v", len(page.Items), err)
	}
	if got := len(n.dialer.targets()); got != 0 {
		t.Errorf("listing dialed %d times", got)
	}
	var seeded wire.Node
	for _, node := range page.Items {
		if node.ID == n.node.ID {
			seeded = node
		}
	}
	if seeded.Connection.State != wire.ConnBackoff || strings.ContainsRune(seeded.Connection.LastError, 0x1b) {
		t.Errorf("connection = %+v, want the pool state with its error sanitized", seeded.Connection)
	}
	if !seeded.Stale {
		t.Error("a node that was never probed must be stale")
	}
}

func TestListNodesFiltersAndPaginates(t *testing.T) {
	n := newNodeFixture(t)
	staging := n.withStaging()
	for _, name := range []string{"a-1", "a-2", "a-3"} {
		n.addApplied(name, staging)
	}
	ctx, by := context.Background(), n.caller(n.alice)

	first, err := n.inv.ListNodes(ctx, by, wire.NodeQuery{PageQuery: wire.PageQuery{Limit: 2}, Environment: "staging"})
	if err != nil || len(first.Items) != 2 || first.NextCursor == "" {
		t.Fatalf("first page = %d items, cursor %q, %v", len(first.Items), first.NextCursor, err)
	}
	second, err := n.inv.ListNodes(ctx, by, wire.NodeQuery{PageQuery: wire.PageQuery{Limit: 2, Cursor: first.NextCursor}, Environment: "staging"})
	if err != nil || len(second.Items) != 1 || second.NextCursor != "" {
		t.Fatalf("second page = %d items, cursor %q, %v", len(second.Items), second.NextCursor, err)
	}
	byTag, _ := n.inv.ListNodes(ctx, by, wire.NodeQuery{Tag: "web"})
	if len(byTag.Items) != 4 { // the seeded node and the three added ones carry the web tag
		t.Errorf("tag filter returned %d nodes", len(byTag.Items))
	}
	if _, err := n.inv.ListNodes(ctx, by, wire.NodeQuery{PageQuery: wire.PageQuery{Cursor: "no-such-id"}}); smerr.CodeOf(err) != smerr.CodeInvalidArgument {
		t.Errorf("bad cursor: %v", err)
	}
}

func TestListNodesShowsOnlyWhatTheCallerMayRead(t *testing.T) {
	n := newNodeFixture(t)

	page, err := n.inv.ListNodes(context.Background(), n.caller(n.dave), wire.NodeQuery{}) // no role

	if err != nil || len(page.Items) != 0 {
		t.Errorf("a caller without node.read saw %d nodes, err %v", len(page.Items), err)
	}
}

func TestGetNodeWithFocusRenewsTheLease(t *testing.T) {
	n := newNodeFixture(t)
	n.inv.focus = NewFocus(n.clock, 10)

	if _, err := n.inv.GetNode(context.Background(), n.caller(n.alice), n.node.ID, false); err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	if n.inv.focus.Active(n.node.ID) {
		t.Error("a read without focus took a lease")
	}
	if _, err := n.inv.GetNode(context.Background(), n.caller(n.alice), n.node.ID, true); err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	if !n.inv.focus.Active(n.node.ID) {
		t.Error("focus=true did not take a lease")
	}
}

func TestScanHostKeyNeedsNodeAddAndValidatesTheEndpoint(t *testing.T) {
	n := newNodeFixture(t)
	scanned := 0
	n.inv.scan = func(_ context.Context, host string, port int) (ssh.HostKey, error) {
		scanned++
		return ssh.HostKey{Authorized: testHostKey, Type: "ssh-ed25519", FingerprintSHA256: "SHA256:x"}, nil
	}
	ctx := context.Background()

	key, err := n.inv.ScanHostKey(ctx, n.caller(n.admin), "10.0.0.9", 0)
	if err != nil || key.FingerprintSHA256 != "SHA256:x" || scanned != 1 {
		t.Fatalf("admin scan = %+v, %v", key, err)
	}
	if _, err := n.inv.ScanHostKey(ctx, n.caller(n.alice), "10.0.0.9", 22); smerr.CodeOf(err) != smerr.CodePolicyDenied {
		t.Errorf("operator scan: %v, want POLICY_DENIED", err)
	}
	if _, err := n.inv.ScanHostKey(ctx, n.caller(n.admin), "-oProxyCommand=x", 22); smerr.CodeOf(err) != smerr.CodeInvalidArgument {
		t.Errorf("hostile host: %v, want INVALID_ARGUMENT", err)
	}
	if scanned != 1 {
		t.Errorf("a refused or invalid scan still dialed (%d scans)", scanned)
	}
}

func TestConnectInfoNamesTheAdminAccountAndIsAudited(t *testing.T) {
	n := newNodeFixture(t)

	info, err := n.inv.ConnectInfo(context.Background(), n.caller(n.alice), n.node.ID)
	if err != nil {
		t.Fatalf("ConnectInfo: %v", err)
	}
	if info.User != "admin" || info.Host != "10.0.0.5" || info.Port != 22 || info.HostPublicKey != testHostKey || info.HostKeyAlias != "sm-"+n.node.ID.String() {
		t.Errorf("info = %+v; interactive sessions use admin_user, never the dedicated account", info)
	}
	if len(n.events("node.connect")) != 1 {
		t.Error("node.connect was not audited")
	}
}

func TestConnectInfoIsUnavailableWithoutSSH(t *testing.T) {
	n := newNodeFixture(t)
	n.inTx(func(ctx context.Context, tx *database.Tx) error {
		return database.SetNodeCapability(ctx, tx, n.node.ID, database.NodeCapability{Capability: "node.ssh", Available: false, CheckedAt: n.clock.Now()})
	})

	_, err := n.inv.ConnectInfo(context.Background(), n.caller(n.alice), n.node.ID)

	if smerr.CodeOf(err) != smerr.CodeCapabilityUnavailable {
		t.Errorf("error = %v, want CAPABILITY_UNAVAILABLE", err)
	}
}

func TestListingServicesAndReadingLogs(t *testing.T) {
	n := newNodeFixture(t)
	n.grantSetup("nginx.service")
	ctx, by := context.Background(), n.caller(n.alice)

	page, err := n.inv.ListServices(ctx, by, n.node.ID, wire.PageQuery{})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("ListServices = %d, %v", len(page.Items), err)
	}
	svc := page.Items[0]
	if svc.Node != "web-1" || svc.Kind != domain.ServiceSystemdUnit || svc.RuntimeType != domain.RuntimeSystemd ||
		!slices.Equal(svc.Actions, domain.AllServiceVerbs()) {
		t.Errorf("service = %+v", svc)
	}

	n.dialer.as("supermgmt").reply("systemd.logs_group", "2026-10-10T12:00:00+0000 host nginx[1]: ready\x1b[31m red\n")
	chunk, err := n.inv.ServiceLogs(ctx, by, n.service.ID, 50)
	if err != nil || len(chunk.Lines) != 1 || strings.Contains(chunk.Lines[0], "\x1b") || !strings.Contains(chunk.Lines[0], "ready") {
		t.Errorf("logs = %+v, %v", chunk, err)
	}
	if _, err := n.inv.ServiceLogs(ctx, by, n.service.ID, 100000); smerr.CodeOf(err) != smerr.CodeInvalidArgument {
		t.Errorf("too many lines: %v", err)
	}
}

func TestServicesOfANodeWithoutSetupAdvertiseNoActions(t *testing.T) {
	n := newNodeFixture(t)

	svc, err := n.inv.GetService(context.Background(), n.caller(n.alice), n.service.ID)

	if err != nil || len(svc.Actions) != 0 {
		t.Errorf("service = %+v, %v; actions need node.setup (ADR-0009 g)", svc, err)
	}
}

func TestLogsAreReadAsTheAdminAccountBeforeSetupAndTheDedicatedOneAfter(t *testing.T) {
	n := newNodeFixture(t)
	n.dialer.as("admin").reply("systemd.logs_group", "before\n")
	n.dialer.as("supermgmt").reply("systemd.logs_group", "after\n")

	before, err := n.inv.ServiceLogs(context.Background(), n.caller(n.alice), n.service.ID, 10)
	mustf(t, err, "logs before setup")
	n.grantSetup("nginx.service")
	after, err := n.inv.ServiceLogs(context.Background(), n.caller(n.alice), n.service.ID, 10)
	mustf(t, err, "logs after setup")

	if before.Lines[0] != "before" || after.Lines[0] != "after" {
		t.Errorf("logs = %v then %v; the connection user must follow node.setup", before.Lines, after.Lines)
	}
	targets := n.dialer.targets()
	if targets[0].User != "admin" || targets[0].CredentialRef != "ssh-agent://default" ||
		targets[1].User != "supermgmt" || targets[1].CredentialRef != "secret://ssh/default@1" {
		t.Errorf("targets = %+v", targets)
	}
}

func TestLogsAreRedactedAsAWholeUnlessTurnedOff(t *testing.T) {
	pem := "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk=\n-----END OPENSSH PRIVATE KEY-----"
	text := "starting\n" + pem + "\nAuthorization: Bearer abc.def.ghi\ndone\n"
	for _, raw := range []bool{false, true} {
		n := newNodeFixture(t)
		n.inv.redactLogs = !raw
		n.dialer.as("admin").reply("systemd.logs_group", text)

		chunk, err := n.inv.ServiceLogs(context.Background(), n.caller(n.alice), n.service.ID, 50)

		mustf(t, err, "ServiceLogs")
		joined := strings.Join(chunk.Lines, "\n")
		leaks := strings.Contains(joined, "b3BlbnNzaC1rZXk=") || strings.Contains(joined, "abc.def.ghi")
		if leaks == !raw || !strings.Contains(joined, "starting") || !strings.Contains(joined, "done") {
			t.Errorf("raw=%v: leaks=%v in %q", raw, leaks, joined)
		}
	}
}

func TestANewNodeCanBeProbedAtOnce(t *testing.T) {
	n := newNodeFixture(t)
	node := n.addApplied("web-2", n.withStaging())

	created, err := n.plans.Create(context.Background(), n.caller(n.alice), PlanRequest{
		Action: "node.probe", Target: domain.ResourceRef{Type: domain.ResourceNode, ID: node.ID},
	})

	mustf(t, err, "Create")
	if created.Policy.Decision != "allow" {
		t.Errorf("policy = %+v; a node that was just added must accept a probe before the first refresh", created.Policy)
	}
}
