package app

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/netguard"
	"github.com/autarquico/supermgmt/internal/policy"
	"github.com/autarquico/supermgmt/internal/providers/proxmox"
	"github.com/autarquico/supermgmt/internal/providers/proxmox/pvefake"
)

const (
	pveHTTPTimeout = 2 * time.Second
	pvePollEvery   = 10 * time.Second
	pveTokenID     = pveTokenUser + "!sm"
)

type approvedRevalidator struct{}

func (approvedRevalidator) Revalidate(context.Context, database.Querier, jobs.Job) error { return nil }

// powerRig is a fake PVE cluster with a discovered tree, the power handler,
// the Proxmox evidence source and a job store that accepts every job.
type powerRig struct {
	*fixture
	fake     *pvefake.Fake
	pve      domain.Provider
	store    *jobs.Store
	handler  *proxmoxPowerHandler
	evidence *EvidenceRouter
	lease    jobs.Lease
	onSleep  func() // runs inside every poll sleep
	slept    time.Duration
}

func newPowerRig(t *testing.T, fakeOpts ...pvefake.Option) *powerRig {
	t.Helper()
	f := newFixture(t)
	fake := pvefake.New(t, append([]pvefake.Option{pvefake.WithClock(f.clock.Now)}, fakeOpts...)...)
	fake.AddNode("pve1")
	fake.AddNode("pve2")
	fake.AddGuest(pvefake.Guest{Node: "pve1", Type: "qemu", VMID: 100, Name: "web", Status: "running", Pool: "prod"})
	fake.AddGuest(pvefake.Guest{Node: "pve2", Type: "lxc", VMID: 200, Name: "db", Status: "stopped"})
	fake.SetRole(pveRole, "VM.Audit", "Sys.Audit", "Datastore.Audit", "Pool.Audit", "VM.PowerMgmt")
	token := fake.AddToken(pveTokenUser, "sm", false)
	fake.Grant(pveTokenUser, "/", pveRole, true)

	caFile := filepath.Join(t.TempDir(), "pve-root-ca.pem")
	mustf(t, os.WriteFile(caFile, fake.CAPEM(), 0o600), "write the CA")
	pve := config.Provider{Proxmox: &config.ProxmoxProvider{
		Type: "proxmox", Name: "pve", Endpoint: fake.Endpoint(), CredentialRef: pveTokenRef,
		VerifyTLS: true, CAFile: caFile, SyncInterval: 30 * time.Second,
	}}
	mustf(t, f.reconciler(t).Reconcile(context.Background(), nil, []config.Provider{pve}), "configure the provider")
	sync, err := NewProxmoxSync(f.cfg, ProxmoxSyncOptions{
		Token:  func(context.Context, string) (audit.Secret, error) { return audit.Secret(token), nil },
		Client: []proxmox.Option{proxmox.WithHTTPTimeout(pveHTTPTimeout), proxmox.WithNetguardOptions(netguard.WithTestDialer(fake.Dial))},
	})
	mustf(t, err, "NewProxmoxSync")

	r := &powerRig{fixture: f, fake: fake}
	r.store, err = jobs.NewStore(jobs.Config{DB: f.db, Clock: f.clock, IDs: f.ids, Revalidator: approvedRevalidator{}, LockPlanner: LockPlanner{}})
	mustf(t, err, "NewStore")
	r.handler = &proxmoxPowerHandler{
		core: mustCore(t, f.cfg), store: r.store, sync: sync, httpTimeout: pveHTTPTimeout,
		settle: Settle{Interval: pvePollEvery, Sleep: func(ctx context.Context, d time.Duration) {
			f.clock.Advance(d)
			r.slept += d
			if r.onSleep != nil {
				r.onSleep()
			}
			_ = r.store.Heartbeat(ctx, r.lease)
		}}.withDefaults(),
	}
	pveEvidence, err := NewProxmoxEvidence(f.cfg, sync, pveHTTPTimeout)
	mustf(t, err, "NewProxmoxEvidence")
	r.evidence, err = NewEvidenceRouter(f.cfg, Connector{}, nil, WithProxmoxEvidence(pveEvidence))
	mustf(t, err, "NewEvidenceRouter")

	mustf(t, sync.Sync(context.Background(), r.providerRow().ID), "first discovery")
	r.pve = r.providerRow()
	return r
}

func mustCore(t *testing.T, cfg Config) core {
	t.Helper()
	c, err := newCore(cfg)
	mustf(t, err, "newCore")
	return c
}

func (r *powerRig) providerRow() domain.Provider {
	r.t.Helper()
	providers, err := database.ListProviders(context.Background(), r.db.Reader())
	mustf(r.t, err, "ListProviders")
	for _, p := range providers {
		if p.Name == "pve" {
			return p
		}
	}
	r.t.Fatal("no provider named pve")
	return domain.Provider{}
}

func (r *powerRig) guest(native string) domain.Node {
	r.t.Helper()
	for _, n := range mustNodes(r.t, r.fixture) {
		if n.ProviderID == r.pve.ID && n.NativeID == native {
			return n
		}
	}
	r.t.Fatalf("no discovered object %s", native)
	return domain.Node{}
}

// submit enqueues a power job on the guest.
func (r *powerRig) submit(native, verb string) jobs.Job {
	r.t.Helper()
	var job jobs.Job
	target := nodeRef(r.guest(native).ID)
	r.inTx(func(ctx context.Context, tx *database.Tx) error {
		var err error
		job, err = r.store.Enqueue(ctx, tx, jobs.NewJob{
			Type: policy.ActionProxmoxVMPower, Resource: target, ActorID: r.alice,
			Credential: domain.CredentialContext{Kind: domain.CredentialAPIToken, ID: "token", Scopes: []string{}},
			Risk:       domain.RiskOperational, RetryClass: domain.RetryNonRetryable,
			Payload: json.RawMessage(`{"verb":"` + verb + `"}`),
		})
		return err
	})
	return job
}

// run submits a power job and executes it.
func (r *powerRig) run(native, verb string) (jobs.Job, error) {
	r.t.Helper()
	submitted := r.submit(native, verb)
	err := r.execute(context.Background())
	return r.job(submitted.ID), err
}

// execute claims the queued job and runs it the way the engine does: the
// handler, then the write its error calls for.
func (r *powerRig) execute(ctx context.Context) error {
	r.t.Helper()
	claimed, ok, err := r.store.Claim(ctx, "worker")
	if err != nil || !ok {
		r.t.Fatalf("Claim = %v, %v", ok, err)
	}
	r.lease = claimed.Lease
	runErr := r.handler.Run(ctx, claimed.Lease)
	finish := context.WithoutCancel(ctx)
	switch {
	case runErr == nil:
		mustf(r.t, r.store.Succeed(finish, r.lease), "Succeed")
	case errors.Is(runErr, jobs.ErrOutcomeUnknown):
		mustf(r.t, r.store.Interrupt(finish, r.lease, runErr), "Interrupt")
	default:
		mustf(r.t, r.store.Fail(finish, r.lease, runErr), "Fail")
	}
	return runErr
}

func (r *powerRig) intent(job jobs.Job) jobs.Intent {
	r.t.Helper()
	intents, err := r.store.Intents(context.Background(), r.db.Reader(), job.ID)
	mustf(r.t, err, "Intents")
	if len(intents) != 1 {
		r.t.Fatalf("job has %d intents, want 1", len(intents))
	}
	return intents[0]
}

func (r *powerRig) state(job jobs.Job) domain.JobState { return r.fixture.job(job.ID).State }

// reconcileTwice runs the reconciler on two samples SampleGap apart, after the
// dead worker's lease expired.
func (r *powerRig) reconcileTwice() {
	r.t.Helper()
	r.clock.Advance(31 * time.Second)
	for i := 0; i < 2; i++ {
		if _, err := r.store.Reconcile(context.Background(), r.evidence); err != nil {
			r.t.Fatalf("Reconcile: %v", err)
		}
		r.clock.Advance(31 * time.Second)
	}
}

func (r *powerRig) posts(verb string) int { return r.fake.Count("POST", "/status/"+verb) }

func evidenceOf(t *testing.T, in jobs.Intent) (jobs.Evidence, taskFingerprint) {
	t.Helper()
	var ev jobs.Evidence
	mustf(t, json.Unmarshal(in.Evidence, &ev), "decode evidence")
	var fp taskFingerprint
	mustf(t, json.Unmarshal(ev.Fingerprint, &fp), "decode fingerprint")
	return ev, fp
}

func TestPowerDeadlinesAreHandlerConstants(t *testing.T) {
	for verb, want := range map[string]time.Duration{
		"start": 5 * time.Minute, "shutdown": 5 * time.Minute, "reboot": 5 * time.Minute, "stop": 2 * time.Minute,
	} {
		if got, err := powerDeadline(verb); err != nil || got != want {
			t.Errorf("powerDeadline(%s) = %v, %v; want %v", verb, got, err, want)
		}
	}
	if _, err := powerDeadline("poweroff"); smerr.CodeOf(err) != smerr.CodeInvalidArgument {
		t.Errorf("powerDeadline(poweroff) = %v, want INVALID_ARGUMENT", err)
	}
}

func TestPowerStartRecordsTheIntentThenTheTaskAndSucceeds(t *testing.T) {
	r := newPowerRig(t)

	job, err := r.run("lxc/200", "start")

	if err != nil || job.State != domain.JobSucceeded {
		t.Fatalf("job = %s, err %v; want succeeded", job.State, err)
	}
	if got := r.fake.GuestStatus(200); got != "running" {
		t.Errorf("guest = %s, want running", got)
	}
	if n := r.posts("start"); n != 1 {
		t.Errorf("POSTs = %d, want exactly 1", n)
	}
	in := r.intent(job)
	task := r.fake.Tasks()[0].UPID
	if in.Operation != "proxmox.vm.power.start" || in.TargetID != r.guest("lxc/200").ID.String() || in.Marker != in.ID.String() {
		t.Errorf("intent = %+v", in)
	}
	if in.State != jobs.IntentCompleted || in.Outcome != jobs.OutcomeSucceeded || in.ExternalRef != task || in.DispatchedAt == nil {
		t.Errorf("intent state %s outcome %s ref %q dispatched %v; want completed/succeeded with the UPID %s", in.State, in.Outcome, in.ExternalRef, in.DispatchedAt, task)
	}
	if want := in.DispatchedAt.Add(proxmox.DeadlineStart); !in.DeadlineAt.Equal(want) {
		t.Errorf("deadline = %v, want dispatched + 5m = %v", in.DeadlineAt, want)
	}
	var pre powerPreState
	mustf(t, json.Unmarshal(in.PreState, &pre), "decode pre-state")
	if want := (powerPreState{Type: "lxc", VMID: 200, PVENode: "pve2", TokenUser: pveTokenID, Status: "stopped"}); pre != want {
		t.Errorf("pre-state = %+v, want %+v", pre, want)
	}
	ev, fp := evidenceOf(t, in)
	if !ev.Done || ev.ExitStatus != 0 || ev.Proof != jobs.ProofPVETask || ev.Classification != jobs.ClassComplete ||
		fp != (taskFingerprint{UPID: task, Status: "stopped", ExitStatus: "OK"}) || string(ev.Pre) != string(in.PreState) {
		t.Errorf("evidence = %+v fingerprint %+v", ev, fp)
	}
}

func TestPowerUPIDIsPersistedBeforeThePollingStarts(t *testing.T) {
	r := newPowerRig(t, pvefake.WithManualTasks())
	r.fake.Inject(pvefake.Rule{Method: "GET", PathSuffix: "/status", Fault: pvefake.Hang()}) // the first poll never answers
	ctx, kill := context.WithCancel(context.Background())
	defer kill()
	done := make(chan error, 1)
	r.submit("lxc/200", "start")
	go func() { done <- r.execute(ctx) }()

	waitFor(t, "the first poll", func() bool { return r.fake.Count("GET", "/status") == 1 })
	killedDuringFirstPoll := r.fake.Tasks()[0].UPID
	intents, err := r.store.Intents(context.Background(), r.db.Reader(), r.onlyJob().ID)
	mustf(t, err, "Intents")
	kill() // the daemon dies while the first poll is in flight

	if got := <-done; !errors.Is(got, jobs.ErrOutcomeUnknown) {
		t.Errorf("handler = %v, want outcome unknown", got)
	}
	if len(intents) != 1 || intents[0].ExternalRef != killedDuringFirstPoll || intents[0].State != jobs.IntentRecorded {
		t.Errorf("intents at the first poll = %+v; want one recorded intent holding UPID %s", intents, killedDuringFirstPoll)
	}
}

func (r *powerRig) onlyJob() jobs.Job {
	r.t.Helper()
	all, err := r.store.List(context.Background(), r.db.Reader(), jobs.ListFilter{Limit: 10})
	mustf(r.t, err, "List")
	if len(all) != 1 {
		r.t.Fatalf("%d jobs, want 1", len(all))
	}
	return all[0]
}

func TestPowerUncertainPostIsNeverRetried(t *testing.T) {
	for name, fault := range map[string]pvefake.Fault{
		"connection dropped after the work": pvefake.DropAfter(),
		"connection dropped before":         pvefake.DropBefore(),
		"gateway error without a body":      pvefake.Respond(502, ""),
		"success with an unreadable body":   pvefake.Respond(200, "not json"),
	} {
		t.Run(name, func(t *testing.T) {
			r := newPowerRig(t)
			r.fake.Inject(pvefake.Rule{Method: "POST", PathSuffix: "/status/start", Fault: fault})

			job, err := r.run("lxc/200", "start")

			if !errors.Is(err, jobs.ErrOutcomeUnknown) || job.State != domain.JobInterrupted {
				t.Fatalf("job = %s, err %v; want interrupted with outcome unknown", job.State, err)
			}
			if n := r.posts("start"); n != 1 {
				t.Errorf("POSTs = %d, want exactly 1", n)
			}
			if in := r.intent(job); in.State != jobs.IntentRecorded || in.ExternalRef != "" || in.DispatchedAt == nil {
				t.Errorf("intent = %+v; want recorded, dispatched, without a UPID", in)
			}
			r.reconcileTwice()
			if n := r.posts("start"); n != 1 {
				t.Errorf("POSTs after reconciling = %d, want still 1: nothing is ever re-dispatched", n)
			}
		})
	}
}

func TestReconcileProxmoxCorrelationOne(t *testing.T) {
	r := newPowerRig(t)
	r.fake.Inject(pvefake.Rule{Method: "POST", PathSuffix: "/status/start", Fault: pvefake.DropAfter()})
	job, _ := r.run("lxc/200", "start")

	r.reconcileTwice()

	if r.state(job) != domain.JobSucceeded {
		t.Fatalf("job = %s, want succeeded: the one matching task ended OK", r.state(job))
	}
	in := r.intent(job)
	_, fp := evidenceOf(t, in)
	if in.Outcome != jobs.OutcomeSucceeded || fp.UPID != r.fake.Tasks()[0].UPID || fp.ExitStatus != "OK" {
		t.Errorf("intent %s, fingerprint %+v; want succeeded from the correlated task", in.Outcome, fp)
	}
	if n := r.posts("start"); n != 1 {
		t.Errorf("POSTs = %d, want 1", n)
	}
}

func TestReconcileProxmoxFailedTaskFailsTheJob(t *testing.T) {
	r := newPowerRig(t, pvefake.WithManualTasks())
	r.fake.Inject(pvefake.Rule{Method: "POST", PathSuffix: "/status/start", Fault: pvefake.DropAfter()})
	job, _ := r.run("lxc/200", "start")
	r.fake.FinishTask(r.fake.Tasks()[0].UPID, "command 'lxc-start' failed")

	r.reconcileTwice()

	if r.state(job) != domain.JobFailed {
		t.Fatalf("job = %s, want failed", r.state(job))
	}
	if got := r.fake.GuestStatus(200); got != "stopped" {
		t.Errorf("guest = %s, want stopped", got)
	}
}

func TestReconcileProxmoxCorrelationNoneHoldsTheJob(t *testing.T) {
	r := newPowerRig(t)
	r.fake.Inject(pvefake.Rule{Method: "POST", PathSuffix: "/status/start", Fault: pvefake.DropBefore()})
	job, _ := r.run("lxc/200", "start")

	r.reconcileTwice()

	if r.state(job) != domain.JobInterrupted {
		t.Errorf("job = %s: no task proves nothing, the job is held for a human", r.state(job))
	}
	if n := r.posts("start"); n != 1 {
		t.Errorf("POSTs = %d, want 1", n)
	}
}

func TestReconcileProxmoxCorrelationManyHoldsTheJob(t *testing.T) {
	r := newPowerRig(t, pvefake.WithManualTasks())
	other, err := proxmox.New(r.fake.Endpoint(), r.fake.CAPEM(), audit.Secret(r.tokenValue(t)),
		proxmox.WithNetguardOptions(netguard.WithTestDialer(r.fake.Dial)))
	mustf(t, err, "second client")
	_, outcome, err := other.Power(context.Background(), proxmox.GuestRef{Node: "pve2", Type: proxmox.GuestLXC, VMID: 200}, "start")
	if outcome != proxmox.PowerAccepted {
		t.Fatalf("seed task = %v, %v", outcome, err)
	}
	r.fake.Inject(pvefake.Rule{Method: "POST", PathSuffix: "/status/start", Fault: pvefake.DropAfter()})
	job, _ := r.run("lxc/200", "start")
	for _, tk := range r.fake.Tasks() {
		r.fake.FinishTask(tk.UPID, "OK")
	}

	r.reconcileTwice()

	if r.state(job) != domain.JobInterrupted {
		t.Errorf("job = %s: two matching tasks cannot be told apart, the job is held", r.state(job))
	}
}

// tokenValue is the API token the rig's provider uses.
func (r *powerRig) tokenValue(t *testing.T) string {
	t.Helper()
	token, err := r.handler.sync.opts.Token(context.Background(), pveTokenRef)
	mustf(t, err, "token")
	return token.Reveal()
}

func TestReconcileProxmoxRunningTaskPastDeadlineIsNeitherReconciledNorResolvable(t *testing.T) {
	r := newPowerRig(t, pvefake.WithManualTasks())
	r.fake.Inject(pvefake.Rule{Method: "POST", PathSuffix: "/status/start", Fault: pvefake.DropAfter()})
	job, _ := r.run("lxc/200", "start")

	r.clock.Advance(6 * time.Minute) // past deadline + reconcile grace, inside the evidence window
	r.reconcileTwice()
	req := jobs.ResolveRequest{JobID: job.ID, Outcome: jobs.ResolveFailed, Note: "looked", By: domain.Actor{ID: r.alice, Type: domain.ActorHuman}}
	_, resolveErr := r.resolve(req)

	if r.state(job) != domain.JobInterrupted {
		t.Errorf("job = %s, want interrupted while the task runs", r.state(job))
	}
	if smerr.CodeOf(resolveErr) != smerr.CodeConflict {
		t.Errorf("Resolve = %v, want CONFLICT: the task may still run", resolveErr)
	}
	r.fake.FinishTask(r.fake.Tasks()[0].UPID, "OK")
	r.reconcileTwice()
	if r.state(job) != domain.JobSucceeded {
		t.Errorf("job = %s, want succeeded once the task stopped", r.state(job))
	}
}

func (r *powerRig) resolve(req jobs.ResolveRequest) (jobs.Job, error) {
	var (
		job jobs.Job
		err error
	)
	txErr := r.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		job, err = r.store.Resolve(ctx, tx, req)
		return err
	})
	if txErr != nil && err == nil {
		r.t.Fatalf("transaction: %v", txErr)
	}
	return job, err
}

func TestPowerDefiniteRejectionFailsTheJobAndSettlesTheIntent(t *testing.T) {
	r := newPowerRig(t)
	r.fake.Inject(pvefake.Rule{
		Method: "POST", PathSuffix: "/status/start",
		Fault: pvefake.Respond(403, `{"data":null,"message":"Permission check failed (/vms/200, VM.PowerMgmt)"}`),
	})

	job, err := r.run("lxc/200", "start")

	if job.State != domain.JobFailed || smerr.CodeOf(err) != smerr.CodeProviderError || errors.Is(err, jobs.ErrOutcomeUnknown) {
		t.Fatalf("job = %s, err %v; want failed with PROVIDER_ERROR", job.State, err)
	}
	in := r.intent(job)
	ev, fp := evidenceOf(t, in)
	if in.State != jobs.IntentCompleted || in.Outcome != jobs.OutcomeFailed || in.ExternalRef != "" ||
		ev.Proof != jobs.ProofPVETask || ev.Classification != jobs.ClassNotStarted || !ev.Done || fp.Status != "rejected" || fp.UPID != "" {
		t.Errorf("intent %+v evidence %+v fingerprint %+v", in, ev, fp)
	}
	if n := r.posts("start"); n != 1 {
		t.Errorf("POSTs = %d, want 1", n)
	}
}

func TestPowerOnAGuestThatMigratedSinceDiscoveryIsADefiniteRejection(t *testing.T) {
	r := newPowerRig(t)
	r.fake.MigrateGuest(100, "pve2") // discovery still says pve1

	job, err := r.run("qemu/100", "stop")

	if job.State != domain.JobFailed || errors.Is(err, jobs.ErrOutcomeUnknown) {
		t.Fatalf("job = %s, err %v; want failed: PVE answered that the guest is not on that node", job.State, err)
	}
	if in := r.intent(job); in.Outcome != jobs.OutcomeFailed || in.State != jobs.IntentCompleted {
		t.Errorf("intent = %+v, want completed/failed", in)
	}
	if got := r.fake.GuestStatus(100); got != "running" {
		t.Errorf("guest = %s, want untouched", got)
	}
}

func TestPowerUncertainOnAGuestThatMigratedIsCorrelatedAcrossTheCluster(t *testing.T) {
	r := newPowerRig(t)
	r.fake.Inject(pvefake.Rule{Method: "POST", PathSuffix: "/status/stop", Fault: pvefake.DropAfter()})
	job, _ := r.run("qemu/100", "stop")
	r.fake.MigrateGuest(100, "pve2") // the guest moved after the dispatch; the task is on pve1

	r.reconcileTwice()

	if r.state(job) != domain.JobSucceeded {
		t.Fatalf("job = %s, want succeeded: the task was found on another node than the guest's", r.state(job))
	}
	if _, fp := evidenceOf(t, r.intent(job)); fp.UPID != r.fake.Tasks()[0].UPID {
		t.Errorf("fingerprint = %+v", fp)
	}
	if n := r.posts("stop"); n != 1 {
		t.Errorf("POSTs = %d, want 1", n)
	}
}

func TestPowerRechecksThePermissionBeforeDispatching(t *testing.T) {
	r := newPowerRig(t)
	r.fake.Revoke(pveTokenUser, "/", pveRole) // after discovery advertised the capability

	job, err := r.run("lxc/200", "start")

	if job.State != domain.JobFailed || smerr.CodeOf(err) != smerr.CodeCapabilityUnavailable {
		t.Fatalf("job = %s, err %v; want failed with CAPABILITY_UNAVAILABLE", job.State, err)
	}
	if n := r.posts("start"); n != 0 {
		t.Errorf("POSTs = %d, want none", n)
	}
	intents, _ := r.store.Intents(context.Background(), r.db.Reader(), job.ID)
	if len(intents) != 0 {
		t.Errorf("%d intents recorded for a dispatch that never happened", len(intents))
	}
}

func TestPowerPermissionRecheckUsesTheNearestListedAncestor(t *testing.T) {
	r := newPowerRig(t)
	r.fake.Revoke(pveTokenUser, "/", pveRole)
	r.fake.Grant(pveTokenUser, "/vms/200", pveRole, true) // only the guest, not /vms

	job, err := r.run("lxc/200", "start")

	if err != nil || job.State != domain.JobSucceeded {
		t.Errorf("job = %s, err %v; want succeeded: VM.PowerMgmt is effective on /vms/200", job.State, err)
	}
}

func TestPowerTaskThatEndsWithAnErrorFailsTheJobFromTheHandler(t *testing.T) {
	r := newPowerRig(t, pvefake.WithManualTasks())
	r.onSleep = func() { r.fake.FinishTask(r.fake.Tasks()[0].UPID, "start failed: exit code 255") }

	job, err := r.run("lxc/200", "start")

	if job.State != domain.JobFailed || smerr.CodeOf(err) != smerr.CodeProviderError || errors.Is(err, jobs.ErrOutcomeUnknown) {
		t.Fatalf("job = %s, err %v", job.State, err)
	}
	in := r.intent(job)
	ev, fp := evidenceOf(t, in)
	if in.Outcome != jobs.OutcomeFailed || ev.Classification != jobs.ClassNotStarted || fp.Status != "stopped" || fp.ExitStatus != "start failed: exit code 255" {
		t.Errorf("intent %s evidence %+v fingerprint %+v", in.Outcome, ev, fp)
	}
}

func TestPowerWaitsForARunningTaskUntilItStops(t *testing.T) {
	r := newPowerRig(t, pvefake.WithManualTasks())
	sleeps := 0
	r.onSleep = func() {
		if sleeps++; sleeps == 3 {
			r.fake.FinishTask(r.fake.Tasks()[0].UPID, "OK")
		}
	}

	job, err := r.run("lxc/200", "start")

	if err != nil || job.State != domain.JobSucceeded || sleeps != 3 {
		t.Errorf("job = %s, err %v, sleeps %d; want succeeded after 3 polls", job.State, err, sleeps)
	}
}

func TestPowerGivesUpAtTheVerbsDeadlineAndLeavesTheTaskTracked(t *testing.T) {
	for _, c := range []struct {
		native, verb string
		deadline     time.Duration
	}{
		{"lxc/200", "start", 5 * time.Minute},
		{"qemu/100", "shutdown", 5 * time.Minute},
		{"qemu/100", "reboot", 5 * time.Minute},
		{"qemu/100", "stop", 2 * time.Minute},
	} {
		t.Run(c.verb, func(t *testing.T) {
			r := newPowerRig(t, pvefake.WithManualTasks())

			job, err := r.run(c.native, c.verb)

			if !errors.Is(err, jobs.ErrOutcomeUnknown) || job.State != domain.JobInterrupted {
				t.Fatalf("job = %s, err %v; want interrupted", job.State, err)
			}
			if r.slept < c.deadline || r.slept >= c.deadline+pvePollEvery {
				t.Errorf("waited %v, want the %v deadline", r.slept, c.deadline)
			}
			in := r.intent(job)
			if in.State != jobs.IntentRecorded || in.ExternalRef != r.fake.Tasks()[0].UPID {
				t.Errorf("intent = %+v; want it recorded with the running task's UPID", in)
			}
		})
	}
}

func TestPowerShutdownTimeoutIsBelowTheDeadline(t *testing.T) {
	for _, verb := range []string{"shutdown", "reboot"} {
		r := newPowerRig(t)
		if _, err := r.run("qemu/100", verb); err != nil {
			t.Fatalf("%s: %v", verb, err)
		}
		var timeout int
		for _, req := range r.fake.Requests() {
			if req.Method == "POST" {
				timeout, _ = strconv.Atoi(req.Form.Get("timeout"))
			}
		}
		if limit := int(proxmox.DeadlineShutdown / time.Second); timeout <= 0 || timeout >= limit {
			t.Errorf("%s timeout = %ds, want 0 < t < %d", verb, timeout, limit)
		}
	}
}

func TestPowerRefusesAnUnknownVerb(t *testing.T) {
	r := newPowerRig(t)

	job, err := r.run("lxc/200", "poweroff")

	if job.State != domain.JobFailed || smerr.CodeOf(err) != smerr.CodeInvalidArgument || len(r.fake.Requests()) > 3 {
		t.Errorf("job = %s, err %v; want failed with INVALID_ARGUMENT before any dispatch", job.State, err)
	}
	if n := r.posts("poweroff"); n != 0 {
		t.Errorf("POSTs = %d", n)
	}
}

func TestHandlersRegisterProxmoxPowerOnlyWhenConfigured(t *testing.T) {
	if _, ok := (&Handlers{}).Map()[policy.ActionProxmoxVMPower]; ok {
		t.Error("proxmox.vm.power has a handler without a Proxmox sync")
	}
	if _, ok := (&Handlers{power: &proxmoxPowerHandler{}}).Map()[policy.ActionProxmoxVMPower]; !ok {
		t.Error("proxmox.vm.power has no handler")
	}
}

func TestEvidenceRouterRefusesProxmoxIntentsWithoutASource(t *testing.T) {
	f := newFixture(t)
	router, err := NewEvidenceRouter(f.cfg, Connector{}, nil)
	mustf(t, err, "NewEvidenceRouter")
	at := epoch

	_, err = router.Collect(context.Background(), jobs.Intent{Operation: "proxmox.vm.power.start", DispatchedAt: &at})

	if err == nil {
		t.Error("a Proxmox intent was answered by a router with no Proxmox source")
	}
}

func TestTaskEvidenceEncoding(t *testing.T) {
	upid := "UPID:pve1:0000000A:0000000A:6A2E1B00:qmstart:100:sm@pve!sm:"
	parsed, err := proxmox.ParseUPID(upid)
	mustf(t, err, "ParseUPID")
	pre := json.RawMessage(`{"vmid":100}`)

	if _, err := taskEvidence(proxmox.TaskStatus{UPID: parsed, Status: "running"}, pre); err == nil {
		t.Error("a running task yielded evidence")
	}
	for exit, class := range map[string]jobs.Classification{"OK": jobs.ClassComplete, "ERROR: boom": jobs.ClassNotStarted, "": jobs.ClassNotStarted} {
		ev, err := taskEvidence(proxmox.TaskStatus{UPID: parsed, Status: "stopped", ExitStatus: exit}, pre)
		if err != nil {
			t.Fatalf("exit %q: %v", exit, err)
		}
		want := `{"upid":"` + upid + `","status":"stopped","exitstatus":"` + exit + `"}`
		if !ev.Done || ev.ExitStatus != 0 || ev.Proof != jobs.ProofPVETask || ev.Classification != class || string(ev.Fingerprint) != want || string(ev.Pre) != string(pre) {
			t.Errorf("exit %q: evidence %+v, want %s fingerprint %s", exit, ev, class, want)
		}
	}
}
