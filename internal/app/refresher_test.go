package app

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

var testRefresh = config.Refresh{
	FocusedInterval: 5 * time.Second, InventoryInterval: 60 * time.Second,
	MetricsInterval: 30 * time.Second, DiscoveryInterval: 5 * time.Minute,
}

func (p *probing) refresher(t *testing.T, tweak ...func(*RefresherOptions)) *Refresher {
	t.Helper()
	o := RefresherOptions{Prober: p.probe, Focus: NewFocus(p.clock, 10*time.Second), Refresh: testRefresh}
	for _, fn := range tweak {
		fn(&o)
	}
	r, err := NewRefresher(p.cfg, o)
	mustf(t, err, "NewRefresher")
	return r
}

// probesOf counts the probes the fixture's shared admin fake has served.
func (p *probing) probesOf() int { return p.dialer.as("admin").count("probe") }

func TestTheRefresherProbesEveryNodeOnItsFirstPassAndThenOnSchedule(t *testing.T) {
	p := newProbing(t)
	r := p.refresher(t)
	ctx := context.Background()

	mustf(t, r.Pass(ctx), "pass 1")
	r.Wait()
	mustf(t, r.Pass(ctx), "pass 2 (nothing is due)")
	r.Wait()
	if got := p.probesOf(); got != 1 {
		t.Fatalf("probes = %d after two immediate passes, want 1", got)
	}

	p.clock.Advance(31 * time.Second) // metrics_interval: a status probe, no discovery
	p.systemd.discovered.Services = nil
	mustf(t, r.Pass(ctx), "pass 3")
	r.Wait()
	if p.probesOf() != 2 || p.serviceNames(t)["nginx.service"] != "running" {
		t.Errorf("probes %d, services %v; the status tier must not rediscover services", p.probesOf(), p.serviceNames(t))
	}

	p.clock.Advance(5 * time.Minute) // discovery_interval
	mustf(t, r.Pass(ctx), "pass 4")
	r.Wait()
	if p.serviceNames(t)["nginx.service"] != database.StatusGone {
		t.Errorf("services = %v; the discovery tier must retire what vanished", p.serviceNames(t))
	}
}

func TestNodesInFocusAreRefreshedAtTheFocusedInterval(t *testing.T) {
	p := newProbing(t)
	focus := NewFocus(p.clock, time.Minute)
	r := p.refresher(t, func(o *RefresherOptions) { o.Focus = focus })
	ctx := context.Background()
	mustf(t, r.Pass(ctx), "pass 1")
	r.Wait()

	p.clock.Advance(6 * time.Second)
	mustf(t, r.Pass(ctx), "unfocused pass")
	r.Wait()
	if p.probesOf() != 1 {
		t.Fatalf("probes = %d; an unfocused node waits for metrics_interval", p.probesOf())
	}

	focus.Touch(p.node.ID)
	mustf(t, r.Pass(ctx), "focused pass")
	r.Wait()
	if p.probesOf() != 2 {
		t.Errorf("probes = %d; a focused node is due after focused_interval", p.probesOf())
	}
}

func TestARetiredNodeIsNotRefreshed(t *testing.T) {
	p := newProbing(t)
	p.inTx(func(ctx context.Context, tx *database.Tx) error {
		node, _ := database.GetNode(ctx, tx, p.node.ID)
		node.ManagementState = domain.ManagementRetired
		_, err := database.UpdateNodeSpec(ctx, tx, node, node.SpecRevision)
		return err
	})
	r := p.refresher(t)

	mustf(t, r.Pass(context.Background()), "pass")
	r.Wait()

	if p.probesOf() != 0 {
		t.Errorf("a retired node was probed %d times", p.probesOf())
	}
}

// hung makes a node whose probe blocks until released, and counts the probes.
func hung(t *testing.T) (node *fakeNode, release func(), started *atomic.Int32) {
	t.Helper()
	gate := make(chan struct{})
	started = new(atomic.Int32)
	node = newFakeNode(t).on("probe", func(templates.Command) (transport.Result, error) {
		started.Add(1)
		<-gate
		return transport.Result{Stdout: []byte(linuxProbe)}, nil
	})
	return node, func() { close(gate) }, started
}

func TestAHungNodeDoesNotDelayTheOthersOrStackUpProbes(t *testing.T) {
	p := newProbing(t)
	slow, release, started := hung(t)
	p.dialer.route(p.node.ID, slow)
	staging := p.withStaging()
	fast := p.addApplied("fast-1", staging)
	r := p.refresher(t)
	ctx := context.Background()

	mustf(t, r.Pass(ctx), "pass 1") // returns without waiting for the hung probe
	eventually(t, "the healthy node to be probed", func() bool {
		view, err := p.inv.GetNode(ctx, p.caller(p.alice), fast.ID, false)
		return err == nil && view.Reachability == domain.ReachabilityReachable
	})
	eventually(t, "the hung probe to start", func() bool { return started.Load() == 1 })
	p.clock.Advance(time.Hour)
	mustf(t, r.Pass(ctx), "pass 2 while the first probe still hangs")
	if got := started.Load(); got != 1 {
		t.Errorf("hung node was probed %d times concurrently, want 1", got)
	}

	release()
	r.Wait()
}

func TestTheRefresherBoundsTheProbesInFlight(t *testing.T) {
	p := newProbing(t)
	staging := p.withStaging()
	var running, peak atomic.Int32
	gate := make(chan struct{})
	slow := newFakeNode(t).on("probe", func(templates.Command) (transport.Result, error) {
		n := running.Add(1)
		for {
			if old := peak.Load(); n <= old || peak.CompareAndSwap(old, n) {
				break
			}
		}
		<-gate
		running.Add(-1)
		return transport.Result{Stdout: []byte(linuxProbe)}, nil
	})
	for _, name := range []string{"a-1", "a-2", "a-3", "a-4", "a-5"} {
		p.dialer.route(p.addApplied(name, staging).ID, slow)
	}
	p.dialer.route(p.node.ID, slow)
	r := p.refresher(t, func(o *RefresherOptions) { o.Workers = 2 })

	mustf(t, r.Pass(context.Background()), "pass")
	eventually(t, "two probes in flight", func() bool { return running.Load() == 2 })
	close(gate)
	r.Wait()

	if peak.Load() != 2 {
		t.Errorf("peak concurrent probes = %d, want 2 (Workers)", peak.Load())
	}
}

func TestRunStopsWhenItsContextEndsAndWaitsForProbes(t *testing.T) {
	p := newProbing(t)
	r := p.refresher(t, func(o *RefresherOptions) { o.Tick = time.Millisecond })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()

	eventually(t, "the first probe", func() bool { return p.probesOf() >= 1 })
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after its context ended")
	}
}

func TestFocusLeasesExpire(t *testing.T) {
	p := newProbing(t)
	focus := NewFocus(p.clock, 10*time.Second)

	focus.Touch(p.node.ID)
	if !focus.Active(p.node.ID) {
		t.Fatal("a fresh lease is active")
	}
	p.clock.Advance(11 * time.Second)

	if focus.Active(p.node.ID) {
		t.Error("an expired lease is still active")
	}
	var none *Focus
	none.Touch(p.node.ID)
	if none.Active(p.node.ID) {
		t.Error("a nil Focus must hold no leases")
	}
}
