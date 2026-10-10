package app

import (
	"context"
	"errors"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/runtimes"
)

// probing is a node fixture whose prober uses scripted runtime adapters.
type probing struct {
	*nodeFixture
	systemd, docker *fakeAdapter
}

func newProbing(t *testing.T) *probing {
	t.Helper()
	p := &probing{nodeFixture: newNodeFixture(t), systemd: newFakeAdapter(domain.RuntimeSystemd), docker: newFakeAdapter(domain.RuntimeDocker)}
	var err error
	p.probe, err = NewProber(p.cfg, p.conn, fakeAdapters(p.systemd, p.docker))
	mustf(t, err, "NewProber")
	p.systemd.discovered = runtimes.Discovered{
		Runtime:  runtimes.DiscoveredRuntime{Type: domain.RuntimeSystemd, NativeID: "systemd", Version: "257", Status: "running"},
		Services: []runtimes.DiscoveredService{unit("nginx.service"), unit("cron.service")},
	}
	p.docker.discovered = runtimes.Discovered{
		Runtime: runtimes.DiscoveredRuntime{Type: domain.RuntimeDocker, NativeID: "docker", Version: "26.1.5", Status: "running"},
		Services: []runtimes.DiscoveredService{
			{Kind: domain.ServiceDockerContainer, NativeID: "abc123", Name: "web", Status: "running"},
		},
	}
	return p
}

func (p *probing) run(scope ProbeScope) error {
	return p.probe.Probe(context.Background(), p.node.ID, scope, nil)
}

func (p *probing) node_(t *testing.T) wire.Node {
	t.Helper()
	view, err := p.inv.GetNode(context.Background(), p.caller(p.alice), p.node.ID, false)
	mustf(t, err, "GetNode")
	return view
}

func (p *probing) serviceNames(t *testing.T) map[string]string {
	t.Helper()
	services, err := database.ListServices(context.Background(), p.db.Reader(), p.node.ID)
	mustf(t, err, "ListServices")
	out := map[string]string{}
	for _, s := range services {
		out[s.NativeID] = s.Status
	}
	return out
}

func TestProbeRecordsTheNodeAsObservations(t *testing.T) {
	p := newProbing(t)

	if err := p.run(ProbeFull); err != nil {
		t.Fatalf("Probe: %v", err)
	}

	view := p.node_(t)
	if view.Reachability != domain.ReachabilityReachable || view.Stale || view.LastSeenAt == nil {
		t.Errorf("reachability %s stale %v seen %v", view.Reachability, view.Stale, view.LastSeenAt)
	}
	if view.OS != "Debian GNU/Linux 13 (trixie)" || view.Arch != "x86_64" {
		t.Errorf("os %q arch %q", view.OS, view.Arch)
	}
	if m := view.Metrics; m == nil || m.MemoryTotalBytes != 8000000*1024 || m.MemoryUsedBytes != 3000000*1024 || m.UptimeSeconds != 12345 || m.CPUPercent <= 0 {
		t.Errorf("metrics = %+v", view.Metrics)
	}
	if len(view.Addresses) != 2 || !view.Addresses[0].Preferred {
		t.Errorf("addresses = %+v", view.Addresses)
	}
	names := map[string]bool{}
	for _, c := range view.Capabilities {
		names[c.Name] = c.Available
	}
	if !names["service.read"] || !names["docker.read"] || !names["tool.tmux"] || names["tool.lazydocker"] {
		t.Errorf("capabilities = %v", names)
	}
	if got := p.serviceNames(t); len(got) != 3 || got["abc123"] != "running" {
		t.Errorf("services = %v", got)
	}
	if view.SpecRevision != p.node.SpecRevision {
		t.Errorf("a probe moved spec_revision %d -> %d; observations never do (spec §6.4)", p.node.SpecRevision, view.SpecRevision)
	}
}

func TestProbeBeforeSetupConnectsAsTheAdminAccountAndAfterAsTheDedicatedOne(t *testing.T) {
	p := newProbing(t)
	p.dialer.as("supermgmt")

	mustf(t, p.run(ProbeStatus), "probe before setup")
	p.grantSetup("nginx.service")
	mustf(t, p.run(ProbeStatus), "probe after setup")

	targets := p.dialer.targets()
	if len(targets) != 2 || targets[0].User != "admin" || targets[1].User != "supermgmt" || targets[1].CredentialRef != "secret://ssh/default@1" {
		t.Errorf("targets = %+v", targets)
	}
}

func TestProbeAdvertisesMutatingCapabilitiesOnlyAfterSetup(t *testing.T) {
	p := newProbing(t)
	p.dialer.as("supermgmt")

	mustf(t, p.run(ProbeStatus), "probe")
	before := capabilityMap(t, p, "service.restart")
	p.grantSetup("nginx.service")
	mustf(t, p.run(ProbeStatus), "probe after setup")
	after := capabilityMap(t, p, "service.restart")

	if before.Available {
		t.Error("service.restart is advertised on a node without node.setup")
	}
	if !after.Available || after.Metadata["units"] == nil {
		t.Errorf("after setup: %+v; the probe must load the setup metadata into the snapshot", after)
	}
}

func capabilityMap(t *testing.T, p *probing, name string) database.NodeCapability {
	t.Helper()
	c, err := database.GetNodeCapability(context.Background(), p.db.Reader(), p.node.ID, name)
	mustf(t, err, "capability %s", name)
	return c
}

func TestProbeRetiresServicesThatDisappeared(t *testing.T) {
	p := newProbing(t)
	mustf(t, p.run(ProbeFull), "first probe")
	p.systemd.discovered.Services = p.systemd.discovered.Services[:1]

	mustf(t, p.run(ProbeFull), "second probe")

	got := p.serviceNames(t)
	if got["nginx.service"] != "running" || got["cron.service"] != database.StatusGone {
		t.Errorf("services = %v; a vanished service is kept as gone", got)
	}
}

func TestAFailedDiscoveryKeepsWhatIsKnown(t *testing.T) {
	p := newProbing(t)
	mustf(t, p.run(ProbeFull), "first probe")
	p.docker.discoverErr = errors.New("docker.ps exploded")
	p.systemd.discovered.Services = nil

	mustf(t, p.run(ProbeFull), "second probe")

	got := p.serviceNames(t)
	if got["abc123"] != "running" {
		t.Errorf("services = %v; a failed Docker discovery must not retire its containers", got)
	}
	if got["nginx.service"] != database.StatusGone {
		t.Errorf("services = %v; a successful discovery that found no units retires them", got)
	}
}

func TestAStatusProbeLeavesServicesAlone(t *testing.T) {
	p := newProbing(t)
	mustf(t, p.run(ProbeFull), "full probe")
	p.systemd.discovered.Services = nil

	mustf(t, p.run(ProbeStatus), "status probe")

	if got := p.serviceNames(t); got["nginx.service"] != "running" {
		t.Errorf("services = %v; only the discovery pass changes services", got)
	}
}

func TestAnUnreachableNodeIsMarkedOnceAndRecovers(t *testing.T) {
	p := newProbing(t)
	node := p.dialer.as("admin")
	node.down("probe", smerr.New(smerr.CodeNodeUnreachable, "", "connection refused"))

	for range 2 {
		if err := p.run(ProbeFull); smerr.CodeOf(err) != smerr.CodeNodeUnreachable {
			t.Fatalf("Probe error = %v, want NODE_UNREACHABLE", err)
		}
	}
	if got := p.node_(t).Reachability; got != domain.ReachabilityUnreachable {
		t.Errorf("reachability = %s", got)
	}
	if len(p.events("node.reachability")) != 1 {
		t.Errorf("%d reachability events; only the change is audited", len(p.events("node.reachability")))
	}

	node.reply("probe", linuxProbe)
	mustf(t, p.run(ProbeFull), "recovery")
	if p.node_(t).Reachability != domain.ReachabilityReachable || len(p.events("node.reachability")) != 2 {
		t.Errorf("reachability %s, %d events", p.node_(t).Reachability, len(p.events("node.reachability")))
	}
}

func TestAHostKeyMismatchMakesTheNodeUnreachable(t *testing.T) {
	p := newProbing(t)
	p.dialer.as("admin").down("probe", smerr.New(smerr.CodeSSHHostKeyMismatch, "", "host key changed"))

	err := p.run(ProbeFull)

	if smerr.CodeOf(err) != smerr.CodeSSHHostKeyMismatch || p.node_(t).Reachability != domain.ReachabilityUnreachable {
		t.Errorf("error %v, reachability %s", err, p.node_(t).Reachability)
	}
}

func TestOnlyConnectivityFailuresChangeReachability(t *testing.T) {
	p := newProbing(t)
	mustf(t, p.run(ProbeStatus), "first probe")
	p.dialer.as("admin").reply("probe", "garbage that is not a probe")

	err := p.run(ProbeStatus)

	if err == nil {
		t.Fatal("want a parse error")
	}
	if got := p.node_(t).Reachability; got != domain.ReachabilityReachable {
		t.Errorf("reachability = %s; an unparsable probe says nothing about connectivity", got)
	}
}

func TestACancelledProbeDoesNotMarkTheNodeUnreachable(t *testing.T) {
	p := newProbing(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p.dialer.as("admin").down("probe", smerr.New(smerr.CodeNodeUnreachable, "", "dial aborted"))

	err := p.probe.Probe(ctx, p.node.ID, ProbeStatus, nil)

	if err == nil || p.node_(t).Reachability == domain.ReachabilityUnreachable {
		t.Errorf("error %v, reachability %s", err, p.node_(t).Reachability)
	}
}

func TestAJobHandlerProbeWritesNothingOnceTheLeaseIsLost(t *testing.T) {
	p := newProbing(t)
	fence := func(context.Context, database.Querier) error { return jobs.ErrLeaseLost }

	err := p.probe.Probe(context.Background(), p.node.ID, ProbeFull, fence)

	if !errors.Is(err, jobs.ErrLeaseLost) {
		t.Fatalf("error = %v, want ErrLeaseLost", err)
	}
	if view := p.node_(t); view.LastSeenAt != nil || len(p.serviceNames(t)) != 1 {
		t.Errorf("a fenced probe recorded last_seen=%v services=%v", view.LastSeenAt, p.serviceNames(t))
	}
}

func TestRetiredNodesAreNotProbed(t *testing.T) {
	p := newProbing(t)
	p.inTx(func(ctx context.Context, tx *database.Tx) error {
		node, err := database.GetNode(ctx, tx, p.node.ID)
		if err != nil {
			return err
		}
		node.ManagementState = domain.ManagementRetired
		_, err = database.UpdateNodeSpec(ctx, tx, node, node.SpecRevision)
		return err
	})

	err := p.run(ProbeFull)

	if smerr.CodeOf(err) != smerr.CodeConflict || len(p.dialer.targets()) != 0 {
		t.Errorf("error %v, dialed %v", err, p.dialer.targets())
	}
}

func TestTheLocalNodeIsProbedThroughTheLocalExecutor(t *testing.T) {
	p := newProbing(t)
	localNode := newFakeNode(t).reply("probe", linuxProbe)
	p.probe, _ = NewProber(p.cfg, Connector{Remote: p.dialer, Local: localNode}, fakeAdapters(p.systemd, p.docker))
	var id domain.ID
	p.inTx(func(ctx context.Context, tx *database.Tx) error {
		provider, err := database.CreateProvider(ctx, tx, domain.Provider{
			ID: p.ids.NewID(), Type: "local", Name: "local", Origin: domain.ProviderAPI, CreatedAt: p.clock.Now(), UpdatedAt: p.clock.Now(),
		})
		if err != nil {
			return err
		}
		node, err := database.CreateNode(ctx, tx, domain.Node{
			ID: p.ids.NewID(), ProviderID: provider.ID, NativeID: "local", Name: "local", Kind: "local",
			ManagementState: domain.ManagementManaged, Reachability: domain.ReachabilityUnknown, CreatedAt: p.clock.Now(), UpdatedAt: p.clock.Now(),
		})
		id = node.ID
		return err
	})

	mustf(t, p.probe.Probe(context.Background(), id, ProbeFull, nil), "probe local")

	if localNode.count("probe") != 1 || len(p.dialer.targets()) != 0 {
		t.Errorf("local probes %d, ssh dials %v", localNode.count("probe"), p.dialer.targets())
	}
	ssh, err := database.GetNodeCapability(context.Background(), p.db.Reader(), id, "node.ssh")
	if err != nil || ssh.Available {
		t.Errorf("node.ssh = %+v, %v; the local provider has no SSH", ssh, err)
	}
	restart, _ := database.GetNodeCapability(context.Background(), p.db.Reader(), id, "service.restart")
	if restart.Available {
		t.Error("the local provider must not advertise mutating capabilities (plan Q10)")
	}
}

func TestTheProbeJobHandlerRunsAFullProbeUnderItsLease(t *testing.T) {
	p := newProbing(t)
	req := PlanRequest{Action: "node.probe", Target: domain.ResourceRef{Type: domain.ResourceNode, ID: p.node.ID}}
	created, err := p.plans.Create(context.Background(), p.caller(p.alice), req)
	mustf(t, err, "Create")
	sub, err := p.plans.Submit(context.Background(), p.caller(p.alice), created.Record.ID, created.Record.PlanHash)
	mustf(t, err, "Submit")
	if sub.Job.State != domain.JobQueued {
		t.Fatalf("a read-risk probe should not need approval, job is %s", sub.Job.State)
	}
	claimed, ok := p.claim()
	if !ok {
		t.Fatal("probe job not claimable")
	}

	err = probeHandler{prober: p.probe, store: p.store}.Run(context.Background(), claimed.Lease)

	if err != nil || len(p.serviceNames(t)) != 3 {
		t.Errorf("handler: %v, services %v", err, p.serviceNames(t))
	}
}
