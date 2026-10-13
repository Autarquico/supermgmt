package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/deployments/compose"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/health"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

var (
	healthvLoopback = netip.MustParseAddr("127.0.0.1")
	healthvPrivate  = netip.MustParseAddr("10.0.0.5")
)

func healthvPorts(addr netip.Addr) []compose.HostPort {
	return []compose.HostPort{{Service: "web", Addr: addr, Port: 8080, Proto: "tcp"}}
}

func healthvManifestHTTP() health.Check {
	return health.Check{
		Origin: health.OriginManifest, Type: health.TypeHTTP, Scope: health.ScopeNode,
		Port: 8080, Path: "/health", Timeout: 3 * time.Second, Interval: 5 * time.Second, Attempts: 3,
	}
}

// healthvSequence answers each call with the next result; the last repeats.
func healthvSequence(results ...transport.Result) func(templates.Command) (transport.Result, error) {
	var n atomic.Int64
	return func(templates.Command) (transport.Result, error) {
		i := min(int(n.Add(1))-1, len(results)-1)
		return results[i], nil
	}
}

func healthvStatus(code string) transport.Result { return transport.Result{Stdout: []byte(code)} }

// healthvSleeps is a Sleep that records the waits instead of waiting.
type healthvSleeps struct{ waits []time.Duration }

func (s *healthvSleeps) sleep(_ context.Context, d time.Duration) { s.waits = append(s.waits, d) }

func healthvVerifier(node transport.Executor, s *healthvSleeps) healthVerifier {
	return healthVerifier{Node: node, Sleep: s.sleep}
}

func TestDeployHealth_NodeHTTPRetriesUntilHealthy(t *testing.T) {
	node := newFakeNode(t).on("health.http", healthvSequence(healthvStatus("503"), healthvStatus("503"), healthvStatus("200")))
	sleeps := &healthvSleeps{}
	run := healthRun{Checks: []health.Check{healthvManifestHTTP()}, Ports: healthvPorts(healthvLoopback)}

	verdict, err := healthvVerifier(node, sleeps).verify(context.Background(), run)

	if err != nil || !verdict.Healthy {
		t.Fatalf("verdict = %+v, %v", verdict, err)
	}
	if got := node.count("health.http"); got != 3 {
		t.Fatalf("attempts = %d, want 3", got)
	}
	if len(sleeps.waits) != 2 || sleeps.waits[0] != 5*time.Second {
		t.Fatalf("waits = %v, want two intervals of 5s", sleeps.waits)
	}
}

func TestDeployHealth_UnhealthyAfterAllAttempts(t *testing.T) {
	node := newFakeNode(t).reply("health.http", "503")
	run := healthRun{Checks: []health.Check{healthvManifestHTTP()}, Ports: healthvPorts(healthvLoopback)}

	verdict, err := healthvVerifier(node, &healthvSleeps{}).verify(context.Background(), run)

	if err != nil || verdict.Healthy {
		t.Fatalf("verdict = %+v, %v", verdict, err)
	}
	for _, want := range []string{"check 1 (http)", "HTTP status 503", "after 3 attempts"} {
		if !strings.Contains(verdict.Failure, want) {
			t.Fatalf("failure %q lacks %q", verdict.Failure, want)
		}
	}
	if got := node.count("health.http"); got != 3 {
		t.Fatalf("attempts = %d, want 3", got)
	}
}

func TestDeployHealth_NodeCheckTypes(t *testing.T) {
	tcp := health.Check{Origin: health.OriginManifest, Type: health.TypeTCP, Scope: health.ScopeNode, Port: 8080, Timeout: time.Second, Attempts: 1}
	docker := health.Check{Origin: health.OriginControlPlane, Type: health.TypeDockerHealth, Scope: health.ScopeNode, Timeout: time.Second, Attempts: 1}
	tests := []struct {
		name        string
		check       health.Check
		template    string
		result      transport.Result
		wantHealthy bool
		wantFailure string
	}{
		{"tcp connects", tcp, "health.tcp", transport.Result{}, true, ""},
		{"tcp refused", tcp, "health.tcp", transport.Result{ExitStatus: 1}, false, "exited with status 1"},
		{"docker healthy", docker, "health.docker", transport.Result{Stdout: []byte("healthy\n")}, true, ""},
		{"docker starting", docker, "health.docker", transport.Result{Stdout: []byte("starting\n")}, false, "container health is starting"},
		{"docker without a health check", docker, "health.docker", transport.Result{Stdout: []byte("none\n")}, false, "container health is none"},
		{"docker output is not repeated", docker, "health.docker", transport.Result{Stdout: []byte("pwned-by-node\n")}, false, "not recognized"},
		{"http status is not a number", healthvManifestHTTP(), "health.http", healthvStatus("<html>"), false, "was not recognized"},
		{"http 301 is not healthy", healthvManifestHTTP(), "health.http", healthvStatus("301"), false, "HTTP status 301"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := newFakeNode(t).on(tt.template, healthvSequence(tt.result))
			tt.check.Attempts = 1
			run := healthRun{Checks: []health.Check{tt.check}, Ports: healthvPorts(healthvLoopback), Container: "web-1"}

			verdict, err := healthvVerifier(node, &healthvSleeps{}).verify(context.Background(), run)

			if err != nil || verdict.Healthy != tt.wantHealthy {
				t.Fatalf("verdict = %+v, %v; want healthy=%v", verdict, err, tt.wantHealthy)
			}
			if !tt.wantHealthy && !strings.Contains(verdict.Failure, tt.wantFailure) {
				t.Fatalf("failure %q lacks %q", verdict.Failure, tt.wantFailure)
			}
		})
	}
}

func TestDeployHealth_InvalidChecksNeverReachTheNode(t *testing.T) {
	docker := health.Check{Origin: health.OriginControlPlane, Type: health.TypeDockerHealth, Scope: health.ScopeNode, Timeout: time.Second, Attempts: 1}
	tests := []struct {
		name  string
		check health.Check
		run   healthRun
	}{
		{"manifest port published off loopback", healthvManifestHTTP(), healthRun{Ports: healthvPorts(healthvPrivate)}},
		{"manifest port the model does not publish", func() health.Check { c := healthvManifestHTTP(); c.Port = 9999; return c }(), healthRun{Ports: healthvPorts(healthvLoopback)}},
		{"manifest check carrying a URL", func() health.Check { c := healthvManifestHTTP(); c.URL = "http://169.254.169.254/"; return c }(), healthRun{Ports: healthvPorts(healthvLoopback)}},
		{"control-plane port on an address that is not approved", func() health.Check { c := healthvManifestHTTP(); c.Origin = health.OriginControlPlane; return c }(), healthRun{Ports: healthvPorts(healthvPrivate)}},
		{"unknown origin", func() health.Check { c := healthvManifestHTTP(); c.Origin = "user"; return c }(), healthRun{Ports: healthvPorts(healthvLoopback)}},
		{"docker-health without a container", docker, healthRun{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := newFakeNode(t)
			tt.run.Checks = []health.Check{tt.check}

			verdict, err := healthvVerifier(node, &healthvSleeps{}).verify(context.Background(), tt.run)

			if err != nil || verdict.Healthy || !strings.HasPrefix(verdict.Failure, "check 1") {
				t.Fatalf("verdict = %+v, %v", verdict, err)
			}
			if len(node.ran()) != 0 {
				t.Fatalf("the node was reached: %v", node.ran())
			}
		})
	}
}

func TestDeployHealth_ControlPlaneOriginMayCheckAnApprovedAddress(t *testing.T) {
	node := newFakeNode(t).on("health.http", healthvSequence(healthvStatus("200")))
	check := healthvManifestHTTP()
	check.Origin = health.OriginControlPlane
	run := healthRun{Checks: []health.Check{check}, Ports: healthvPorts(healthvPrivate), AllowedBind: []netip.Addr{healthvPrivate}}

	verdict, err := healthvVerifier(node, &healthvSleeps{}).verify(context.Background(), run)

	if err != nil || !verdict.Healthy {
		t.Fatalf("verdict = %+v, %v", verdict, err)
	}
	if line := node.calls[0].Line; !strings.Contains(line, "10.0.0.5") {
		t.Fatalf("command %q does not target the approved address", line)
	}
}

func TestDeployHealth_EveryCheckMustPass(t *testing.T) {
	node := newFakeNode(t).reply("health.http", "200").exit("health.tcp", 1)
	tcp := health.Check{Origin: health.OriginManifest, Type: health.TypeTCP, Scope: health.ScopeNode, Port: 8080, Timeout: time.Second, Attempts: 1}
	run := healthRun{Checks: []health.Check{healthvManifestHTTP(), tcp}, Ports: healthvPorts(healthvLoopback)}

	verdict, err := healthvVerifier(node, &healthvSleeps{}).verify(context.Background(), run)

	if err != nil || verdict.Healthy || !strings.HasPrefix(verdict.Failure, "check 2 (tcp)") {
		t.Fatalf("verdict = %+v, %v", verdict, err)
	}
}

func TestDeployHealth_NoCheckIsUnhealthy(t *testing.T) {
	verdict, err := healthvVerifier(newFakeNode(t), &healthvSleeps{}).verify(context.Background(), healthRun{})
	if err != nil || verdict.Healthy || verdict.Failure == "" {
		t.Fatalf("verdict = %+v, %v; a deployment nothing verifies must not become known-good", verdict, err)
	}
}

func TestDeployHealth_TransportFailureIsAFailedAttempt(t *testing.T) {
	var calls atomic.Int64
	node := newFakeNode(t).on("health.http", func(templates.Command) (transport.Result, error) {
		if calls.Add(1) == 1 {
			return transport.Result{}, smerr.New(smerr.CodeNodeUnreachable, "", "ssh: connection lost to 10.9.9.9")
		}
		return healthvStatus("200"), nil
	})
	run := healthRun{Checks: []health.Check{healthvManifestHTTP()}, Ports: healthvPorts(healthvLoopback)}

	verdict, err := healthvVerifier(node, &healthvSleeps{}).verify(context.Background(), run)

	if err != nil || !verdict.Healthy {
		t.Fatalf("verdict = %+v, %v", verdict, err)
	}
}

func TestDeployHealth_TransportFailureDetailHidesTheCause(t *testing.T) {
	node := newFakeNode(t).down("health.http", errors.New("ssh: dial 10.9.9.9: connection refused"))
	run := healthRun{Checks: []health.Check{healthvManifestHTTP()}, Ports: healthvPorts(healthvLoopback)}

	verdict, _ := healthvVerifier(node, &healthvSleeps{}).verify(context.Background(), run)

	if verdict.Healthy || strings.Contains(verdict.Failure, "10.9.9.9") {
		t.Fatalf("failure = %q", verdict.Failure)
	}
}

func TestDeployHealth_CancelledContextEndsTheVerification(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	node := newFakeNode(t).reply("health.http", "503")
	v := healthVerifier{Node: node, Sleep: func(context.Context, time.Duration) { cancel() }}
	run := healthRun{Checks: []health.Check{healthvManifestHTTP()}, Ports: healthvPorts(healthvLoopback)}

	_, err := v.verify(ctx, run)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if got := node.count("health.http"); got != 1 {
		t.Fatalf("attempts after cancel = %d, want 1", got)
	}
}

func TestDeployHealth_ControlPlaneScope(t *testing.T) {
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte("secret-body-must-not-surface"))
	}))
	t.Cleanup(srv.Close)
	check := health.Check{
		Origin: health.OriginControlPlane, Type: health.TypeHTTP, Scope: health.ScopeControlPlane,
		URL: srv.URL + "/health", Timeout: time.Second, Attempts: 1,
	}
	v := healthVerifier{HTTP: srv.Client(), Sleep: (&healthvSleeps{}).sleep}

	healthy, err := v.verify(context.Background(), healthRun{Checks: []health.Check{check}})
	if err != nil || !healthy.Healthy {
		t.Fatalf("200: %+v, %v", healthy, err)
	}
	status = http.StatusInternalServerError
	unhealthy, err := v.verify(context.Background(), healthRun{Checks: []health.Check{check}})
	if err != nil || unhealthy.Healthy || strings.Contains(unhealthy.Failure, "secret-body") {
		t.Fatalf("500: %+v, %v", unhealthy, err)
	}
}

// healthvSeedDeployment inserts a deployment of the fixture's node and walks it
// to state, returning its id.
func healthvSeedDeployment(f *fixture, kind string, state deployments.State) domain.ID {
	f.t.Helper()
	path := []deployments.State{
		deployments.StateQueued, deployments.StatePreparing, deployments.StateStaging,
		deployments.StateDeploying, deployments.StateVerifying, deployments.StateRollingBack,
	}
	app, target, id := f.ids.NewID(), f.ids.NewID(), f.ids.NewID()
	now := f.clock.Now()
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		for _, stmt := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO apps (id, name, deployed_service, image_policy_json, compose_source, created_at, updated_at)
				VALUES (?, ?, 'web', '{}', 'control-plane', 1, 1)`, []any{app, "app-" + app.String()}},
			{`INSERT INTO app_targets (id, app_id, environment_id, node_id, compose_project, deployment_policy_json, created_at, updated_at)
				VALUES (?, ?, ?, ?, 'web-prod', '{}', 1, 1)`, []any{target, app, f.env.ID, f.node.ID}},
		} {
			if _, err := tx.ExecContext(ctx, stmt.sql, stmt.args...); err != nil {
				return err
			}
		}
		err := database.InsertDeployment(ctx, tx, database.Deployment{
			ID: id, Kind: kind, AppID: app, AppTargetID: target, EnvironmentID: f.env.ID, NodeID: f.node.ID,
			State: deployments.StateCreated, RequestedBy: f.alice, CommitSha: "abc", RequestedRaw: json.RawMessage(`{"images":[]}`),
			Credential: domain.CredentialContext{Kind: domain.CredentialSession, ID: "sess", Scopes: []string{"deployment.create"}},
			CreatedAt:  now, UpdatedAt: now,
		})
		if err != nil {
			return err
		}
		for _, next := range path {
			if state == deployments.StateCreated {
				break
			}
			if err := database.TransitionDeployment(ctx, tx, id, next, database.StateFailure{}, now); err != nil {
				return err
			}
			if next == state {
				break
			}
		}
		return nil
	})
	return id
}

func healthvGet(f *fixture, id domain.ID) database.Deployment {
	f.t.Helper()
	d, err := database.GetDeployment(context.Background(), f.db.Reader(), id)
	if err != nil {
		f.t.Fatalf("GetDeployment: %v", err)
	}
	return d
}

func healthvSettle(f *fixture, id domain.ID, v healthVerdict, in deployments.RollbackInputs) deployments.State {
	f.t.Helper()
	var got deployments.State
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		var err error
		got, err = settleVerification(ctx, tx, id, v, in, f.clock.Now())
		return err
	})
	return got
}

func healthvRollbackable() deployments.RollbackInputs {
	return deployments.RollbackInputs{
		Mode: deployments.RollbackAutomatic, EnvAllows: true, HasKnownGood: true, Kind: deployments.KindDeploy,
	}
}

func TestSettleVerification_HealthyDeploymentBecomesKnownGood(t *testing.T) {
	for _, kind := range []string{deployments.KindDeploy, deployments.KindRollback} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			id := healthvSeedDeployment(f, kind, deployments.StateVerifying)

			state := healthvSettle(f, id, healthVerdict{Healthy: true}, healthvRollbackable())

			d := healthvGet(f, id)
			if state != deployments.StateSucceeded || d.State != deployments.StateSucceeded || !d.KnownGood || d.FinishedAt == nil {
				t.Fatalf("state = %s, deployment = %+v", state, d)
			}
		})
	}
}

func TestSettleVerification_UnhealthyWithRollbackAvailableRollsBack(t *testing.T) {
	f := newFixture(t)
	id := healthvSeedDeployment(f, deployments.KindDeploy, deployments.StateVerifying)

	state := healthvSettle(f, id, healthVerdict{Failure: "check 1 (http): HTTP status 503"}, healthvRollbackable())

	d := healthvGet(f, id)
	if state != deployments.StateRollingBack || d.State != deployments.StateRollingBack || d.KnownGood || d.FinishedAt != nil {
		t.Fatalf("state = %s, deployment = %+v", state, d)
	}
}

func TestSettleVerification_UnhealthyWithoutRollbackFailsWithItsCause(t *testing.T) {
	tests := []struct {
		name  string
		tweak func(*deployments.RollbackInputs)
		cause string
	}{
		{"manual rollback mode", func(in *deployments.RollbackInputs) { in.Mode = deployments.RollbackManual }, deployments.CauseManualMode},
		{"manifest downgrades to manual", func(in *deployments.RollbackInputs) { in.ManifestMode = deployments.RollbackManual }, deployments.CauseManualMode},
		{"stateful target", func(in *deployments.RollbackInputs) { in.Stateful = true }, deployments.CauseStateful},
		{"environment forbids automatic rollback", func(in *deployments.RollbackInputs) { in.EnvAllows = false }, deployments.CauseEnvironmentForbids},
		{"first deployment of the target", func(in *deployments.RollbackInputs) { in.HasKnownGood = false }, deployments.CauseNoKnownGood},
		{"a rollback never rolls back", func(in *deployments.RollbackInputs) { in.Kind = deployments.KindRollback }, deployments.CauseRollbackKind},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			id := healthvSeedDeployment(f, deployments.KindDeploy, deployments.StateVerifying)
			in := healthvRollbackable()
			tt.tweak(&in)

			state := healthvSettle(f, id, healthVerdict{Failure: "check 1 (http): HTTP status 503"}, in)

			d := healthvGet(f, id)
			want := database.StateFailure{
				Code: string(smerr.CodeDeploymentFailed), Reason: string(smerr.ReasonRollbackUnavailable), Cause: tt.cause,
			}
			if state != deployments.StateFailed || d.State != deployments.StateFailed || d.Failure != want || d.KnownGood {
				t.Fatalf("state = %s, failure = %+v, want %+v", state, d.Failure, want)
			}
		})
	}
}

func TestSettleVerification_OnlyAVerifyingDeploymentSettles(t *testing.T) {
	f := newFixture(t)
	id := healthvSeedDeployment(f, deployments.KindDeploy, deployments.StateStaging)

	err := f.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		_, err := settleVerification(ctx, tx, id, healthVerdict{Healthy: true}, healthvRollbackable(), f.clock.Now())
		return err
	})

	if smerr.CodeOf(err) != smerr.CodeConflict {
		t.Fatalf("err = %v, want INVALID_TRANSITION", err)
	}
	if d := healthvGet(f, id); d.State != deployments.StateStaging || d.KnownGood {
		t.Fatalf("deployment = %+v", d)
	}
}
