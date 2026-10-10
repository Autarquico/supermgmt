package app

import (
	"context"
	"slices"
	"testing"

	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
)

func (f *fixture) reconciler(t *testing.T) *StaticReconciler {
	t.Helper()
	r, err := NewStaticReconciler(f.cfg, config.ModeLocal)
	mustf(t, err, "NewStaticReconciler")
	return r
}

func fileEnvs() []config.Environment {
	return []config.Environment{{Name: "lab", RiskLevel: "staging", ApprovalsRequired: 1}}
}

func fileNode(name, host string) config.Provider {
	return config.Provider{SSH: &config.SSHProvider{
		Type: "ssh", Name: name, Environment: "lab", Tags: []string{"web", "edge"},
		CredentialRef: "secret://ssh/default",
		Endpoint:      config.SSHEndpoint{Host: host, Port: 22, User: "supermgmt", AdminUser: "alex", HostPublicKey: testHostKey},
	}}
}

func (f *fixture) nodeNamed(name string) (domain.Node, bool) {
	f.t.Helper()
	for _, n := range mustNodes(f.t, f) {
		if n.Name == name {
			return n, true
		}
	}
	return domain.Node{}, false
}

func TestReconcileCreatesTheEnvironmentsAndNodesOfTheFile(t *testing.T) {
	f := newFixture(t)

	err := f.reconciler(t).Reconcile(context.Background(), fileEnvs(), []config.Provider{fileNode("edge-1", "10.1.0.1")})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	node, ok := f.nodeNamed("edge-1")
	if !ok {
		t.Fatal("node not created")
	}
	if node.Kind != "ssh" || node.ManagementState != domain.ManagementManaged || node.Endpoint.Host != "10.1.0.1" ||
		node.Endpoint.AdminUser != "alex" || node.Endpoint.AdminCredentialRef != "ssh-agent://default" ||
		!slices.Equal(node.Tags, []string{"edge", "web"}) || node.EnvironmentID == nil {
		t.Errorf("node = %+v", node)
	}
	provider, _ := database.GetProvider(context.Background(), f.db.Reader(), node.ProviderID)
	if provider.Origin != domain.ProviderStatic {
		t.Errorf("provider origin = %s, want static", provider.Origin)
	}
	for _, e := range f.events("node.add", "environment.write") {
		if e.Source != "config" || e.ActorType != domain.ActorSystem {
			t.Errorf("event %s: source %q actor %s", e.Action, e.Source, e.ActorType)
		}
	}
}

func TestReconcileIsQuietWhenNothingChanged(t *testing.T) {
	f := newFixture(t)
	r := f.reconciler(t)
	providers := []config.Provider{fileNode("edge-1", "10.1.0.1")}
	mustf(t, r.Reconcile(context.Background(), fileEnvs(), providers), "first")
	before, _ := f.nodeNamed("edge-1")
	events := len(f.events())

	mustf(t, r.Reconcile(context.Background(), fileEnvs(), providers), "second")

	after, _ := f.nodeNamed("edge-1")
	if after.SpecRevision != before.SpecRevision || len(f.events()) != events {
		t.Errorf("revision %d -> %d, events %d -> %d; an unchanged file must change nothing", before.SpecRevision, after.SpecRevision, events, len(f.events()))
	}
}

func TestAChangedEndpointBumpsTheRevisionAndStalesPlans(t *testing.T) {
	f := newFixture(t)
	r := f.reconciler(t)
	mustf(t, r.Reconcile(context.Background(), fileEnvs(), []config.Provider{fileNode("edge-1", "10.1.0.1")}), "first")
	before, _ := f.nodeNamed("edge-1")

	mustf(t, r.Reconcile(context.Background(), fileEnvs(), []config.Provider{fileNode("edge-1", "10.1.0.2")}), "second")

	after, _ := f.nodeNamed("edge-1")
	if after.SpecRevision != before.SpecRevision+1 || after.Endpoint.Host != "10.1.0.2" {
		t.Errorf("revision %d -> %d, host %s", before.SpecRevision, after.SpecRevision, after.Endpoint.Host)
	}
	updates := f.events("node.update")
	if len(updates) != 1 || updates[0].Data["fields"].([]any)[0] != "endpoint" {
		t.Errorf("update events = %+v", updates)
	}
}

func TestAChangedEnvironmentRiskBumpsItsRevision(t *testing.T) {
	f := newFixture(t)
	r := f.reconciler(t)
	mustf(t, r.Reconcile(context.Background(), fileEnvs(), nil), "first")
	before, _ := environmentNamed(context.Background(), f.db.Reader(), "lab")

	promoted := []config.Environment{{Name: "lab", RiskLevel: "production", ApprovalsRequired: 2}}
	mustf(t, r.Reconcile(context.Background(), promoted, nil), "second")

	after, _ := environmentNamed(context.Background(), f.db.Reader(), "lab")
	if after.RiskLevel != domain.EnvironmentProduction || after.ApprovalsRequired != 2 || after.SpecRevision != before.SpecRevision+1 {
		t.Errorf("environment = %+v after %+v", after, before)
	}
}

func TestANodeThatLeftTheFileIsRetiredAndAPINodesAreUntouched(t *testing.T) {
	f := newFixture(t)
	r := f.reconciler(t)
	providers := []config.Provider{fileNode("edge-1", "10.1.0.1"), fileNode("edge-2", "10.1.0.2")}
	mustf(t, r.Reconcile(context.Background(), fileEnvs(), providers), "first")

	mustf(t, r.Reconcile(context.Background(), fileEnvs(), providers[:1]), "second")

	gone, _ := f.nodeNamed("edge-2")
	kept, _ := f.nodeNamed("edge-1")
	fixtureNode, _ := f.nodeNamed("web-1") // created through the API in the fixture
	if gone.ManagementState != domain.ManagementRetired || kept.ManagementState != domain.ManagementManaged ||
		fixtureNode.ManagementState != domain.ManagementManaged {
		t.Errorf("states: edge-2 %s, edge-1 %s, web-1 %s", gone.ManagementState, kept.ManagementState, fixtureNode.ManagementState)
	}
	if len(f.events("node.remove")) != 1 {
		t.Error("the retirement was not audited")
	}
}

func TestANodeThatReturnsToTheFileIsManagedAgain(t *testing.T) {
	f := newFixture(t)
	r := f.reconciler(t)
	providers := []config.Provider{fileNode("edge-1", "10.1.0.1")}
	mustf(t, r.Reconcile(context.Background(), fileEnvs(), providers), "first")
	mustf(t, r.Reconcile(context.Background(), fileEnvs(), nil), "removed")

	mustf(t, r.Reconcile(context.Background(), fileEnvs(), providers), "returned")

	if node, _ := f.nodeNamed("edge-1"); node.ManagementState != domain.ManagementManaged {
		t.Errorf("state = %s", node.ManagementState)
	}
}

func TestAFileCannotTakeOverANodeCreatedThroughTheAPI(t *testing.T) {
	f := newFixture(t)

	err := f.reconciler(t).Reconcile(context.Background(), fileEnvs(), []config.Provider{fileNode("ssh-hosts", "10.1.0.9")})

	if err == nil {
		t.Error("the file claimed a provider that the API created")
	}
}

func TestAnErrorLeavesTheDatabaseUntouched(t *testing.T) {
	f := newFixture(t)
	bad := fileNode("edge-1", "10.1.0.1")
	bad.SSH.Environment = "nonexistent"

	err := f.reconciler(t).Reconcile(context.Background(), fileEnvs(), []config.Provider{fileNode("edge-0", "10.1.0.0"), bad})

	if err == nil {
		t.Fatal("want an error for the unknown environment")
	}
	if _, ok := f.nodeNamed("edge-0"); ok {
		t.Error("a failed reconcile left a partial result")
	}
}
