package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/providers/local"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// interruptAndRequeue lets the worker of a claimed job die: its lease expires,
// the reconciler takes the job over and, the job being idempotent, requeues it.
func interruptAndRequeue(t *testing.T, f *fixture, job domain.ID) {
	t.Helper()
	f.clock.Advance(31 * time.Second)
	taken, err := f.store.Takeover(context.Background(), "test")
	if err != nil || len(taken) != 1 {
		t.Fatalf("Takeover = %v, %v", taken, err)
	}
	resolutions, err := f.store.Reconcile(context.Background(), nil)
	if err != nil || len(resolutions) != 1 || resolutions[0].Action != jobs.ReconcileRequeued {
		t.Fatalf("Reconcile = %+v, %v; an idempotent job is requeued, never resumed or failed", resolutions, err)
	}
	if got := f.job(job).State; got != domain.JobQueued {
		t.Fatalf("job = %s, want queued", got)
	}
}

func TestAnInterruptedProbeIsRequeuedAndConverges(t *testing.T) {
	p := newProbing(t)
	gate := make(chan struct{})
	p.dialer.route(p.node.ID, newFakeNode(t).on("probe", func(templates.Command) (transport.Result, error) {
		<-gate
		return transport.Result{}, errors.New("daemon killed")
	}))
	req := PlanRequest{Action: "node.probe", Target: domain.ResourceRef{Type: domain.ResourceNode, ID: p.node.ID}}
	created, err := p.plans.Create(context.Background(), p.caller(p.alice), req)
	mustf(t, err, "Create")
	sub, err := p.plans.Submit(context.Background(), p.caller(p.alice), created.Record.ID, created.Record.PlanHash)
	mustf(t, err, "Submit")
	claimed, _ := p.claim()
	ctx, kill := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- (probeHandler{prober: p.probe, store: p.store}).Run(ctx, claimed.Lease) }()
	kill()
	close(gate)
	<-done

	interruptAndRequeue(t, p.fixture, sub.Job.ID)
	p.dialer.route(p.node.ID, newFakeNode(t).reply("probe", linuxProbe))
	again, ok := p.claim()
	if !ok {
		t.Fatal("the requeued probe was not claimable")
	}
	err = probeHandler{prober: p.probe, store: p.store}.Run(context.Background(), again.Lease)

	if err != nil || p.node_(t).Reachability != domain.ReachabilityReachable {
		t.Errorf("rerun: %v, reachability %s", err, p.node_(t).Reachability)
	}
}

func TestAnInterruptedSetupIsRequeuedAndConverges(t *testing.T) {
	s := newSetting(t)
	s.setupPlan(defaultSetup())
	crashed := true
	s.dialer.as("admin").on("setup.tmpfiles_apply.sudo", func(templates.Command) (transport.Result, error) {
		if crashed {
			return transport.Result{}, context.Canceled // the daemon dies in the middle of setup
		}
		return transport.Result{}, nil
	})
	claimed, _ := s.claim()
	ctx, kill := context.WithCancel(context.Background())
	kill()
	if err := s.handler.Run(ctx, claimed.Lease); err == nil {
		t.Fatal("a killed setup must not succeed")
	}
	if _, ok := s.setupCapability(); ok {
		t.Fatal("capability recorded by an unfinished setup")
	}

	interruptAndRequeue(t, s.fixture, claimed.Lease.JobID)
	crashed = false
	if err := s.run(); err != nil {
		t.Fatalf("setup after requeue: %v", err)
	}

	if _, ok := s.setupCapability(); !ok {
		t.Error("the requeued setup did not converge")
	}
	if got := s.dialer.as("admin").count("setup.user_add.sudo"); got > 1 {
		t.Errorf("the account was created %d times across the retry", got)
	}
}

func TestAnInterruptedApplyIsRequeuedAndConverges(t *testing.T) {
	n := newNodeFixture(t)
	res, err := n.inv.AddSSHNode(context.Background(), n.caller(n.admin), n.addRequest("web-9", "prod"))
	mustf(t, err, "AddSSHNode")
	n.approveToQuorum(res.Pending.Job)
	claimed, _ := n.claim()
	// The worker applied the change but died before it could finish the job.
	mustf(t, applyHandler{inv: n.inv}.Run(context.Background(), claimed.Lease), "first apply")

	interruptAndRequeue(t, n.fixture, res.Pending.Job.ID)
	again, ok := n.claim()
	if !ok {
		t.Fatal("the requeued apply was not claimable")
	}
	err = applyHandler{inv: n.inv}.Run(context.Background(), again.Lease)

	nodes := 0
	for _, node := range mustNodes(t, n.fixture) {
		if node.Name == "web-9" {
			nodes++
		}
	}
	if err != nil || nodes != 1 || len(n.events("node.add")) != 1 {
		t.Errorf("rerun: %v; %d nodes named web-9, %d node.add events; want one of each", err, nodes, len(n.events("node.add")))
	}
}

func TestTheLocalMachineIsDiscoveredThroughTheLocalExecutor(t *testing.T) {
	p := newProbing(t)
	conn := Connector{Remote: p.dialer, Local: local.Executor{}}
	prober, err := NewProber(p.cfg, conn, fakeAdapters(p.systemd, p.docker))
	mustf(t, err, "NewProber")
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

	// This runs the real probe script on the machine running the tests: Linux in
	// CI, macOS on a developer machine (spec §14).
	mustf(t, prober.Probe(context.Background(), id, ProbeStatus, nil), "probe the local machine")

	view, err := p.inv.GetNode(context.Background(), p.caller(p.alice), id, false)
	mustf(t, err, "GetNode")
	if view.Reachability != domain.ReachabilityReachable || view.OS == "" || view.Arch == "" {
		t.Errorf("view = reachability %s os %q arch %q", view.Reachability, view.OS, view.Arch)
	}
	if view.Metrics == nil || view.Metrics.MemoryTotalBytes <= 0 || view.Metrics.DiskTotalBytes <= 0 {
		t.Errorf("metrics = %+v; the local probe must read memory and disk", view.Metrics)
	}
	if len(p.dialer.targets()) != 0 {
		t.Error("the local node was reached over SSH")
	}
}
