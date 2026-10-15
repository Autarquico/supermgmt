package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare/cffake"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/secrets"
	"github.com/autarquico/supermgmt/internal/transport/ssh"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

func TestTunnelSetupProvisionsEverythingProvesTheTunnelAndOnlyThenSwitches(t *testing.T) {
	ts := newTunnelSetting(t)
	ts.plan()

	mustf(t, ts.attempt(), "tunnel setup")

	ts.wantOneOfEach()
	ts.wantRecorded()
	node := ts.currentNode()
	if node.Endpoint.Transport != domain.TransportCloudflare || node.Endpoint.TunnelHostname != ts.hostname() {
		t.Errorf("endpoint = %q %q, want cloudflare %q", node.Endpoint.Transport, node.Endpoint.TunnelHostname, ts.hostname())
	}
	if node.SpecRevision != ts.node.SpecRevision+1 {
		t.Errorf("spec revision = %d, want %d: one conditional update", node.SpecRevision, ts.node.SpecRevision+1)
	}
	meta, ok := ts.setupCapability()
	if !ok || meta.Tunnel == nil || meta.Tunnel.Hostname != ts.hostname() || meta.SetupVersion != runtimes.SetupVersion {
		t.Errorf("capability = %+v, want tunnel state for %s", meta, ts.hostname())
	}
	if ops := ts.operations(); len(ops) != 1 || ops[0].Phase != database.PhaseCommitted || ops[0].Kind != database.TunnelEnable {
		t.Errorf("operations = %+v, want one committed enable", ops)
	}
	app := ts.cf.Apps()[0]
	if app.Domain != ts.hostname() || len(app.PolicyIDs) != 2 || len(app.AllowedIdPs) != 1 {
		t.Errorf("Access application = %+v: want the hostname, both policies and the configured IdP", app)
	}
	stored, err := ts.secrets.Get(context.Background(), secrets.Ref{Name: "cloudflare/access-service-token"})
	mustf(t, err, "service token secret")
	token := ts.cf.ServiceTokens()[0]
	if stored.Reveal() != token.ClientID+":"+token.ClientSecret {
		t.Error("the stored runtime secret is not client_id:client_secret of the created token")
	}
	if got := ts.files[templates.CloudflaredTokenPath]; !strings.HasSuffix(got, "\n") || len(got) < 20 {
		t.Errorf("the tunnel token file on the node = %q", got)
	}
	if got := ts.dialer.invalidated[len(ts.dialer.invalidated)-1]; got != ts.node.ID.String()+"/*" {
		t.Errorf("last invalidation = %q: the pooled connections of the old transport must be retired after the switch", got)
	}
	for _, action := range []string{
		"cloudflare.service_token.created", "cloudflare.access_policy.created", "cloudflare.tunnel.created",
		"cloudflare.tunnel.ingress_set", "cloudflare.access_app.created", "cloudflare.dns_record.created", "node.tunnel.enabled",
	} {
		if len(ts.events(action)) == 0 {
			t.Errorf("no %s event", action)
		}
	}
}

func TestTheTunnelPathIsVerifiedOverAFreshCloudflareConnectionWithThePinnedKey(t *testing.T) {
	ts := newTunnelSetting(t)
	ts.plan()

	mustf(t, ts.attempt(), "tunnel setup")

	var viaTunnel []ssh.Target
	for _, target := range ts.dialer.targets() {
		if target.Transport == domain.TransportCloudflare {
			viaTunnel = append(viaTunnel, target)
		}
	}
	if len(viaTunnel) == 0 {
		t.Fatal("nothing was verified through the cloudflare transport")
	}
	for _, target := range viaTunnel {
		if target.TunnelHostname != ts.hostname() || target.HostKey != ts.node.Endpoint.HostPublicKey || target.User != "supermgmt" {
			t.Errorf("tunnel target %+v: want the hostname, the pinned host key and the dedicated account", target)
		}
	}
	if ts.dialer.through("supermgmt").count("setup.verify_id") == 0 {
		t.Error("the dedicated-account verification did not run over the tunnel path")
	}
	direct := ts.dialer.as("supermgmt")
	if direct.count("setup.verify_id") != 1 {
		t.Errorf("the direct path was verified %d times, want once (the tunnel verification is separate)", direct.count("setup.verify_id"))
	}
}

func TestAFailedTunnelVerificationLeavesTheNodeDirectAndTheOperationResumable(t *testing.T) {
	ts := newTunnelSetting(t)
	ts.dialer.mu.Lock()
	delete(ts.dialer.tunnel, "supermgmt") // Access denies the service token: nothing answers
	ts.dialer.mu.Unlock()
	ts.plan()

	err := ts.attempt()

	if err == nil || !strings.Contains(err.Error(), "verification over the tunnel") {
		t.Fatalf("error = %v, want one naming the verification step", err)
	}
	if node := ts.currentNode(); node.Endpoint.Transport != "" && node.Endpoint.Transport != domain.TransportDirect {
		t.Errorf("transport = %q after a failed verification", node.Endpoint.Transport)
	}
	if _, ok := ts.setupCapability(); ok {
		t.Error("the capability was recorded although the tunnel was not proven")
	}
	if ops := ts.operations(); len(ops) != 1 || ops[0].Phase != database.PhaseInstalled {
		t.Fatalf("operations = %+v, want one at phase installed", ops)
	}

	ts.dialer.through("supermgmt")
	scriptDedicated(ts.dialer.through("supermgmt"))
	interruptAndRequeue(t, ts.fixture, ts.queued.ID)
	mustf(t, ts.attempt(), "retry")

	ts.wantOneOfEach()
	if got := ts.currentNode().Endpoint.Transport; got != domain.TransportCloudflare {
		t.Errorf("transport = %q after the tunnel was proven", got)
	}
}

func TestADedicatedAccountThatFailsOverTheTunnelKeepsTheTransportDirect(t *testing.T) {
	ts := newTunnelSetting(t)
	ts.dialer.through("supermgmt").reply("setup.verify_id", "someone-else\n")
	ts.plan()

	err := ts.attempt()

	if err == nil || !strings.Contains(err.Error(), "verification over the tunnel") {
		t.Fatalf("error = %v", err)
	}
	if got := ts.currentNode().Endpoint.Transport; got == domain.TransportCloudflare {
		t.Error("switched although the dedicated account failed its verification over the tunnel")
	}
}

func TestEveryFaultAfterEveryMutationConvergesWithEachObjectOnce(t *testing.T) {
	clean := newTunnelSetting(t)
	clean.plan()
	mustf(t, clean.attempt(), "clean run")
	total := len(clean.cf.Mutations())
	if total < 7 {
		t.Fatalf("a clean run made %d mutations, want at least 7 (token, 2 policies, tunnel, ingress, app, DNS)", total)
	}

	for _, mode := range []string{"lost response", "refused before", "crash", "lease loss"} {
		for k := 1; k <= total; k++ {
			t.Run(fmt.Sprintf("%s at mutation %d", mode, k), func(t *testing.T) {
				ts := newTunnelSetting(t)
				ts.inject(mode, k)
				ts.plan()

				failures := ts.converge(4)

				if len(failures) == 0 && (mode == "crash" || mode == "lease loss") {
					t.Fatal("the fault changed nothing")
				}
				ts.wantOneOfEach()
				ts.wantRecorded()
				if got := ts.currentNode().Endpoint.Transport; got != domain.TransportCloudflare {
					t.Errorf("transport = %q after convergence", got)
				}
				if ts.secrets.versions("cloudflare/access-service-token") != 1 {
					t.Errorf("the service token secret has %d versions, want 1", ts.secrets.versions("cloudflare/access-service-token"))
				}
				if mode == "lease loss" && !errors.Is(failures[0], jobs.ErrLeaseLost) {
					t.Errorf("first failure = %v, want the lease loss", failures[0])
				}
			})
		}
	}
}

// inject arms one fault at the k-th Cloudflare mutation of the first attempt.
func (ts *tunnelSetting) inject(mode string, k int) {
	switch mode {
	case "lost response", "refused before":
		fault := cffake.LostResponse
		if mode == "refused before" {
			fault = cffake.FailBefore
		}
		ts.cf.Plan(func(m cffake.Mutation) cffake.Fault {
			if m.Seq == k {
				return fault
			}
			return cffake.NoFault
		})
	default:
		ts.chaos.k, ts.chaos.mode = k, mode
	}
}

func TestAWorkerThatLostItsLeaseMakesNoFurtherMutation(t *testing.T) {
	ts := newTunnelSetting(t)
	ts.inject("lease loss", 3)
	ts.plan()

	err := ts.attempt()

	if !errors.Is(err, jobs.ErrLeaseLost) {
		t.Fatalf("error = %v, want ErrLeaseLost", err)
	}
	if got := len(ts.cf.Mutations()); got != 3 {
		t.Errorf("%d Cloudflare mutations, want 3: nothing after the lease was lost", got)
	}
	if got := ts.currentNode().Endpoint.Transport; got == domain.TransportCloudflare {
		t.Error("a fenced-out worker switched the transport")
	}
}

func TestALostAnswerWhoseObjectIsNotVisibleYetIsFoundOnTheSecondLookup(t *testing.T) {
	ts := newTunnelSetting(t, cffake.WithPropagationDelay(1))
	ts.cf.Plan(func(m cffake.Mutation) cffake.Fault {
		if m.Op == cffake.OpTunnelCreate {
			return cffake.LostResponse
		}
		return cffake.NoFault
	})
	ts.plan()

	ts.converge(3)

	ts.wantOneOfEach()
}

func TestARerunReusesTheRecordedObjectsAndChangesNothing(t *testing.T) {
	ts := newTunnelSetting(t)
	ts.plan()
	mustf(t, ts.attempt(), "first run")
	mutations, revision := len(ts.cf.Mutations()), ts.currentNode().SpecRevision

	ts.plan()
	mustf(t, ts.attempt(), "rerun")

	if got := len(ts.cf.Mutations()); got != mutations {
		t.Errorf("the rerun made %d Cloudflare mutations, want none", got-mutations)
	}
	ts.wantOneOfEach()
	if got := ts.currentNode().SpecRevision; got != revision {
		t.Errorf("spec revision %d -> %d: the endpoint did not change", revision, got)
	}
	ops := ts.operations()
	if len(ops) != 2 || ops[0].Generation != 2 || ops[0].Phase != database.PhaseCommitted || ops[0].Objects != ops[1].Objects {
		t.Errorf("operations = %+v, want generation 2 committed with the same objects", ops)
	}
}

func TestAnObjectWithTheExpectedNameButAnotherOwnerIsAConflictNeverAdopted(t *testing.T) {
	ids := func(ts *tunnelSetting) (instance, node string) {
		inst, err := database.GetInstance(context.Background(), ts.db.Reader())
		mustf(t, err, "GetInstance")
		return inst.ID.String(), ts.node.ID.String()
	}
	tests := []struct {
		name string
		seed func(ts *tunnelSetting)
		kept func(ts *tunnelSetting) bool
	}{
		{"tunnel", func(ts *tunnelSetting) {
			instance, node := ids(ts)
			ts.cf.SeedTunnel("sm-" + instance + "-" + node)
		}, func(ts *tunnelSetting) bool { return len(ts.cf.Apps()) == 0 && len(ts.cf.DNSRecords()) == 0 }},
		{"owners policy", func(ts *tunnelSetting) {
			instance, _ := ids(ts)
			ts.cf.SeedPolicy("supermgmt owners "+instance, "someone@else.test")
		}, func(ts *tunnelSetting) bool { return len(ts.cf.Tunnels()) == 0 }},
		{"Access application", func(ts *tunnelSetting) {
			instance, node := ids(ts)
			ts.cf.SeedApp("supermgmt "+instance+" "+node, ts.hostname())
		}, func(ts *tunnelSetting) bool { return len(ts.cf.DNSRecords()) == 0 }},
		{"DNS record", func(ts *tunnelSetting) {
			ts.cf.SeedDNSRecord(ts.hostname(), "elsewhere.example.test", "someone else's")
		}, func(ts *tunnelSetting) bool {
			return len(ts.cf.DNSRecords()) == 1 && ts.cf.DNSRecords()[0].Comment == "someone else's"
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ts := newTunnelSetting(t)
			tc.seed(ts)
			ts.clock.Advance(time.Hour) // the foreign object predates the operation
			ts.plan()

			err := ts.attempt()

			wantError(t, err, smerr.CodeConflict, "")
			if !tc.kept(ts) {
				t.Error("the job went past the foreign object or touched it")
			}
			if ops := ts.operations(); len(ops) != 1 || ops[0].Phase != database.PhaseConflict {
				t.Errorf("operations = %+v, want the operation halted as conflict", ops)
			}
			if got := ts.currentNode().Endpoint.Transport; got == domain.TransportCloudflare {
				t.Error("switched on a conflict")
			}
			if routable := ts.cf.EverRoutableWithoutAccess(); len(routable) != 0 {
				t.Errorf("routable without Access: %v", routable)
			}
			interruptAndRequeue(t, ts.fixture, ts.queued.ID)
			wantError(t, ts.attempt(), smerr.CodeConflict, "") // an automatic retry does not undo the halt
			if ops := ts.operations(); ops[0].Phase != database.PhaseConflict {
				t.Errorf("phase after an automatic retry = %s, want conflict", ops[0].Phase)
			}
		})
	}
}

func TestTheDNSRecordIsNeverCreatedBeforeTheAccessApplication(t *testing.T) {
	ts := newTunnelSetting(t)
	ts.plan()
	mustf(t, ts.attempt(), "tunnel setup")

	var order []cffake.Op
	for _, m := range ts.cf.Mutations() {
		order = append(order, m.Op)
	}
	appAt, dnsAt := indexOf(order, cffake.OpAppCreate), indexOf(order, cffake.OpDNSCreate)
	if appAt < 0 || dnsAt < 0 || dnsAt < appAt {
		t.Errorf("mutation order %v: DNS must come after the Access application", order)
	}
	if routable := ts.cf.EverRoutableWithoutAccess(); len(routable) != 0 {
		t.Errorf("routable without Access: %v", routable)
	}
}

func indexOf(ops []cffake.Op, op cffake.Op) int {
	for i, o := range ops {
		if o == op {
			return i
		}
	}
	return -1
}

func TestAnOrphanedServiceTokenIsDeletedAndReplaced(t *testing.T) {
	ts := newTunnelSetting(t)
	inst, err := database.GetInstance(context.Background(), ts.db.Reader())
	mustf(t, err, "GetInstance")
	orphan := ts.cf.SeedServiceToken("supermgmt-" + inst.ID.String()) // created, secret lost
	ts.plan()

	mustf(t, ts.attempt(), "tunnel setup")

	tokens := ts.cf.ServiceTokens()
	if len(tokens) != 1 || tokens[0].ID == orphan.ID {
		t.Errorf("tokens = %+v, want only a new one", tokens)
	}
	if len(ts.events("cloudflare.service_token.deleted")) != 1 {
		t.Error("deleting the orphan was not audited")
	}
}

func TestARecordedTokenWhoseSecretIsMissingIsReplaced(t *testing.T) {
	ts := newTunnelSetting(t)
	ts.plan()
	mustf(t, ts.attempt(), "first run")
	first := ts.cf.ServiceTokens()[0]
	ts.secrets.mu.Lock()
	delete(ts.secrets.vals, "cloudflare/access-service-token")
	ts.secrets.mu.Unlock()

	ts.plan()
	mustf(t, ts.attempt(), "rerun")

	tokens := ts.cf.ServiceTokens()
	if len(tokens) != 1 || tokens[0].ID == first.ID {
		t.Fatalf("tokens = %+v, want the recorded token replaced", tokens)
	}
	state, err := database.GetCloudflareState(context.Background(), ts.db.Reader())
	mustf(t, err, "state")
	if state.Token.ID != tokens[0].ID || len(ts.cf.Policies()) != 2 {
		t.Errorf("state token %s, %d policies: want the new token recorded and the policies kept", state.Token.ID, len(ts.cf.Policies()))
	}
	if svc := serviceToken(ts); len(svc.ServiceTokenIDs) != 1 || svc.ServiceTokenIDs[0] != tokens[0].ID {
		t.Errorf("service policy admits %v, want only the new token", svc.ServiceTokenIDs)
	}
}

func serviceToken(ts *tunnelSetting) cffake.Policy {
	for _, p := range ts.cf.Policies() {
		if p.Decision == "non_identity" {
			return p
		}
	}
	ts.t.Fatal("no service auth policy")
	return cffake.Policy{}
}

func TestTunnelIsRefusedWithoutACloudflareConnection(t *testing.T) {
	s := newSetting(t)
	params := defaultSetup()
	params["tunnel"] = "true"

	_, err := s.plans.Create(context.Background(), s.caller(s.admin), PlanRequest{
		Action: "node.setup", Target: domain.ResourceRef{Type: domain.ResourceNode, ID: s.node.ID}, Parameters: params,
	})

	wantError(t, err, smerr.CodeInvalidArgument, "")
	if !strings.Contains(err.Error(), "cloudflare") {
		t.Errorf("error %q does not say the connection is not configured", err)
	}
	if err := s.handler.Run(context.Background(), s.leaseFor(t, params)); err == nil {
		t.Error("the handler ran a tunnel setup without a connection")
	}
}

// leaseFor submits an approved setup with params that skips plan-time checks
// (the plan exists only to obtain a claimable job) and returns its lease.
func (s *setting) leaseFor(t *testing.T, params map[string]any) jobs.Lease {
	t.Helper()
	plain := defaultSetup()
	job := s.setupPlan(plain)
	claimed, ok := s.claim()
	if !ok {
		t.Fatal("no job to claim")
	}
	s.inTx(func(ctx context.Context, tx *database.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE jobs SET payload_json = ? WHERE id = ?`, string(mustJSON(t, params)), job.ID)
		return err
	})
	return claimed.Lease
}

func TestTunnelIsRefusedForANodeThatIsNotAnSSHNode(t *testing.T) {
	ts := newTunnelSetting(t)
	ts.inTx(func(ctx context.Context, tx *database.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE nodes SET kind = 'vm' WHERE id = ?`, ts.node.ID)
		return err
	})
	params := defaultSetup()
	params["tunnel"] = "true"

	_, err := ts.plans.Create(context.Background(), ts.caller(ts.admin), PlanRequest{
		Action: "node.setup", Target: domain.ResourceRef{Type: domain.ResourceNode, ID: ts.node.ID}, Parameters: params,
	})

	wantError(t, err, smerr.CodeInvalidArgument, "")
	if got := len(ts.cf.Mutations()); got != 0 {
		t.Errorf("%d Cloudflare mutations for a refused plan", got)
	}
}

func TestTheTunnelParameterIsClosed(t *testing.T) {
	for _, value := range []any{"yes", "TRUE", true, 1} {
		params := defaultSetup()
		params["tunnel"] = value
		if err := validateParameters("node.setup", params); err == nil {
			t.Errorf("tunnel=%v accepted", value)
		}
	}
	for _, value := range []any{nil, "true", "false"} {
		params := defaultSetup()
		if value != nil {
			params["tunnel"] = value
		}
		if err := validateParameters("node.setup", params); err != nil {
			t.Errorf("tunnel=%v refused: %v", value, err)
		}
	}
}

func TestSetupWithoutTunnelNeverCallsCloudflare(t *testing.T) {
	ts := newTunnelSetting(t)
	ts.setupPlan(defaultSetup())

	mustf(t, ts.run(), "plain setup")

	if got := len(ts.cf.Requests()); got != 0 {
		t.Errorf("%d Cloudflare requests during a setup without tunnel", got)
	}
	if got := ts.currentNode().Endpoint.Transport; got == domain.TransportCloudflare {
		t.Error("a setup without tunnel switched the transport")
	}
	if _, err := database.ActiveTunnelOperation(context.Background(), ts.db.Reader(), ts.node.ID); smerr.CodeOf(err) != smerr.CodeNotFound {
		t.Errorf("an operation record exists for a setup without tunnel: %v", err)
	}
}

func TestTunnelSetupHoldsTheInstanceWideCloudflareLock(t *testing.T) {
	ts := newTunnelSetting(t)
	job := ts.plan()

	specs, err := LockPlanner{}.PlanLocks(context.Background(), ts.db.Reader(), job)

	mustf(t, err, "PlanLocks")
	found := false
	for _, spec := range specs {
		found = found || (spec.Key == cloudflareInstanceLock.Key && spec.Mode == domain.LockExclusive)
	}
	if !found {
		t.Errorf("locks = %+v, want the exclusive instance-wide Cloudflare lock", specs)
	}
	plain := newSetting(t)
	plainJob := plain.setupPlan(defaultSetup())
	specs, err = LockPlanner{}.PlanLocks(context.Background(), plain.db.Reader(), plainJob)
	mustf(t, err, "PlanLocks plain")
	for _, spec := range specs {
		if spec.Key == cloudflareInstanceLock.Key {
			t.Error("a setup without tunnel takes the Cloudflare lock")
		}
	}
}

func TestNoCredentialLeaksIntoPlansPayloadsEventsErrorsOrCommands(t *testing.T) {
	ts := newTunnelSetting(t)
	ts.dialer.mu.Lock()
	delete(ts.dialer.tunnel, "supermgmt") // a failure first: errors are scanned too
	ts.dialer.mu.Unlock()
	job := ts.plan()
	failure := ts.attempt()
	scriptDedicated(ts.dialer.through("supermgmt"))
	interruptAndRequeue(t, ts.fixture, job.ID)
	mustf(t, ts.attempt(), "retry")

	token := ts.cf.ServiceTokens()[0]
	tunnelToken := strings.TrimSpace(ts.files[templates.CloudflaredTokenPath])
	secretsToHide := map[string]string{
		"API token": ts.cf.Token(), "service token secret": token.ClientSecret, "tunnel token": tunnelToken,
	}
	if tunnelToken == "" || token.ClientSecret == "" {
		t.Fatal("the scan has nothing to look for")
	}
	haystacks := map[string]string{"failure": fmt.Sprint(failure)}
	for _, e := range ts.events() {
		haystacks["event "+e.Action] = fmt.Sprint(e.Data) + e.Action
	}
	for _, op := range ts.operations() {
		haystacks["operation record"] = fmt.Sprintf("%+v", op)
	}
	var row string
	ts.inTx(func(ctx context.Context, tx *database.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT payload_json FROM jobs WHERE id = ?`, job.ID).Scan(&row)
	})
	haystacks["job payload"] = row
	haystacks["job"] = fmt.Sprintf("%+v", ts.job(job.ID))
	for _, user := range []string{"admin", "supermgmt"} {
		for _, c := range ts.dialer.as(user).calls {
			haystacks["command "+c.Template] = c.Line
			if len(c.Stdin) > 0 && !strings.Contains(string(c.Stdin), tunnelToken) {
				continue
			}
			if len(c.Stdin) > 0 && !c.Sensitive {
				t.Errorf("%s carries the tunnel token on stdin but is not marked sensitive", c.Template)
			}
		}
	}
	record, err := database.GetPlan(context.Background(), ts.db.Reader(), ts.jobPlan(job))
	mustf(t, err, "plan")
	haystacks["plan"] = string(record.PlanJSON)
	for what, secret := range secretsToHide {
		for where, text := range haystacks {
			if strings.Contains(text, secret) {
				t.Errorf("the %s appears in %s", what, where)
			}
		}
	}
}

func (ts *tunnelSetting) jobPlan(job jobs.Job) domain.ID {
	if job.PlanID == nil {
		ts.t.Fatal("job has no plan")
	}
	return *job.PlanID
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	mustf(t, err, "marshal")
	return raw
}
