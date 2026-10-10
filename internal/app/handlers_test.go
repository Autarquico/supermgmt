package app

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/secrets"
)

func (n *nodeFixture) handlers(t *testing.T, systemd, docker *fakeAdapter) *Handlers {
	t.Helper()
	adapters := fakeAdapters(systemd, docker)
	prober, err := NewProber(n.cfg, n.conn, adapters)
	mustf(t, err, "NewProber")
	h, err := NewHandlers(n.cfg, HandlersOptions{
		Store: n.store, Connector: n.conn, Adapters: adapters, Inventory: n.inv, Prober: prober,
		Identity: func(context.Context) (secrets.Identity, error) { return secrets.Identity{}, nil },
	})
	mustf(t, err, "NewHandlers")
	return h
}

func TestTheHandlerTableCoversEveryJobTypeM1Adds(t *testing.T) {
	n := newNodeFixture(t)

	table := n.handlers(t, newFakeAdapter(domain.RuntimeSystemd), newFakeAdapter(domain.RuntimeDocker)).Map()

	var types []string
	for jobType := range table {
		types = append(types, jobType)
	}
	sort.Strings(types)
	want := []string{"control_plane.apply", "node.probe", "node.setup", "service.restart", "service.start", "service.stop"}
	if len(types) != len(want) {
		t.Fatalf("handler types = %v, want %v", types, want)
	}
	for i := range want {
		if types[i] != want[i] {
			t.Errorf("handler types = %v, want %v", types, want)
		}
	}
}

func TestNewHandlersRequiresItsCollaborators(t *testing.T) {
	n := newNodeFixture(t)
	good := HandlersOptions{
		Store: n.store, Inventory: n.inv, Prober: n.probe, Identity: func(context.Context) (secrets.Identity, error) { return secrets.Identity{}, nil },
	}
	for name, mutate := range map[string]func(*HandlersOptions){
		"store":     func(o *HandlersOptions) { o.Store = nil },
		"inventory": func(o *HandlersOptions) { o.Inventory = nil },
		"prober":    func(o *HandlersOptions) { o.Prober = nil },
		"identity":  func(o *HandlersOptions) { o.Identity = nil },
	} {
		o := good
		mutate(&o)
		if _, err := NewHandlers(n.cfg, o); err == nil {
			t.Errorf("accepted options without %s", name)
		}
	}
}

// engine runs the real job engine over the handlers until stop is called.
func (n *nodeFixture) engine(t *testing.T, h *Handlers, router *EvidenceRouter) (stop func()) {
	t.Helper()
	engine, err := jobs.NewEngine(jobs.EngineConfig{
		Store: n.store, Handlers: h.Map(), Evidence: router, Workers: 2,
		PollInterval: time.Millisecond, ReconcileInterval: time.Hour,
		OnError: func(err error) { t.Errorf("engine: %v", err) },
	})
	mustf(t, err, "NewEngine")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = engine.Run(ctx); close(done) }()
	return func() { cancel(); <-done }
}

func TestTheEngineRunsAProbeJobEndToEnd(t *testing.T) {
	p := newProbing(t)
	h := p.handlers(t, p.systemd, p.docker)
	stop := p.engine(t, h, nil)
	defer stop()
	req := PlanRequest{Action: "node.probe", Target: domain.ResourceRef{Type: domain.ResourceNode, ID: p.node.ID}}
	created, err := p.plans.Create(context.Background(), p.caller(p.alice), req)
	mustf(t, err, "Create")
	sub, err := p.plans.Submit(context.Background(), p.caller(p.alice), created.Record.ID, created.Record.PlanHash)
	mustf(t, err, "Submit")

	eventually(t, "the probe job to succeed", func() bool { return p.job(sub.Job.ID).State == domain.JobSucceeded })

	if p.node_(t).Reachability != domain.ReachabilityReachable || len(p.serviceNames(t)) != 3 {
		t.Errorf("reachability %s, services %v", p.node_(t).Reachability, p.serviceNames(t))
	}
}

func TestTheEngineRunsAServiceRestartEndToEnd(t *testing.T) {
	a := newAction(t)
	a.adapter.observe = func(int) (jobs.Evidence, error) { return complete(jobs.ClassComplete), nil }
	router, err := NewEvidenceRouter(a.cfg, a.conn, fakeAdapters(a.adapter, newFakeAdapter(domain.RuntimeDocker)))
	mustf(t, err, "NewEvidenceRouter")
	job := a.restartApproved()
	stop := a.engine(t, a.handlersWith(t), router)
	defer stop()

	eventually(t, "the restart to succeed", func() bool { return a.job(job.ID).State == domain.JobSucceeded })

	if got := len(a.adapter.dispatches()); got != 1 {
		t.Errorf("%d dispatches, want 1", got)
	}
}

func (a *action) handlersWith(t *testing.T) *Handlers {
	t.Helper()
	return a.handlers(t, a.adapter, newFakeAdapter(domain.RuntimeDocker))
}

func TestTheEngineAppliesAnApprovedNodeAdd(t *testing.T) {
	n := newNodeFixture(t)
	res, err := n.inv.AddSSHNode(context.Background(), n.caller(n.admin), n.addRequest("web-9", "prod"))
	mustf(t, err, "AddSSHNode")
	n.approveToQuorum(res.Pending.Job)
	stop := n.engine(t, n.handlers(t, newFakeAdapter(domain.RuntimeSystemd), newFakeAdapter(domain.RuntimeDocker)), nil)
	defer stop()

	eventually(t, "the add to be applied", func() bool { return n.job(res.Pending.Job.ID).State == domain.JobSucceeded })

	if _, ok := n.nodeNamed("web-9"); !ok {
		t.Error("the approved node does not exist")
	}
}
