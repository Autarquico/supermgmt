package app

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/deployments/manifest"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/plan"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/health"
	"github.com/autarquico/supermgmt/internal/jobs"
)

// moveWorld is a target with a known-good deployment on a node (A) and a second managed node (B) in the same
// environment, with the app moves service on top.
type moveWorld struct {
	*finFixture
	svc      *AppMoves
	reval    *Revalidator
	dest     domain.Node
	otherJob domain.ID
}

func newMoveWorld(t *testing.T) *moveWorld {
	t.Helper()
	f := newFinFixture(t, finOptions{pinned: true})
	svc, err := NewAppMoves(f.cfg, f.plans)
	mustf(t, err, "NewAppMoves")
	reval, err := NewRevalidator(f.cfg)
	mustf(t, err, "NewRevalidator")
	w := &moveWorld{finFixture: f, svc: svc, reval: reval}
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		now := f.clock.Now()
		var err error
		w.dest, err = database.CreateNode(ctx, tx, domain.Node{
			ID: f.ids.NewID(), ProviderID: f.provider.ID, NativeID: "web-2", Name: "web-2", Kind: "ssh",
			EnvironmentID: &f.env.ID, ManagementState: domain.ManagementManaged, Reachability: domain.ReachabilityUnknown,
			Endpoint: domain.NodeEndpoint{
				Host: "10.0.0.6", Port: 22, User: "supermgmt", AdminUser: "admin",
				AdminCredentialRef: "ssh-agent://default", HostPublicKey: testHostKey,
			},
			CredentialRef: "secret://ssh/default", Tags: []string{"web"}, CreatedAt: now, UpdatedAt: now,
		})
		if err != nil {
			return err
		}
		return database.SetNodeCapability(ctx, tx, w.dest.ID, database.NodeCapability{
			Capability: capabilityComposeDeploy, Available: true, CheckedAt: now,
		})
	})
	return w
}

// ---- frozen models ----------------------------------------------------------------------------------

const (
	modelStateless    = `{"services":{"web":{"image":"web"}}}`
	modelSharedVolume = `{"services":{
		"web":{"volumes":[{"type":"volume","source":"data","target":"/data"},{"type":"tmpfs","target":"/tmp"}]},
		"worker":{"volumes":[{"type":"volume","source":"data","target":"/data","read_only":true}]}},
		"volumes":{"data":{"name":"PROJECT_data"}}}`
	modelReadOnlyVolume = `{"services":{"web":{"volumes":[{"type":"volume","source":"data","target":"/data","read_only":true}]}}}`
)

// goodModel describes the known-good deployment a world seeds.
type goodModel struct {
	effective string
	ports     []snapshotPort
	stateful  bool
	check     *health.Check
}

func nodeHealth() *health.Check {
	return &health.Check{
		Origin: health.OriginManifest, Type: health.TypeHTTP, Scope: health.ScopeNode, Port: 8080, Path: "/health",
		Timeout: time.Second, Interval: time.Second, Attempts: 3,
	}
}

func (w *moveWorld) project() string {
	w.t.Helper()
	target, err := database.GetAppTarget(context.Background(), w.db.Reader(), w.target.ID)
	mustf(w.t, err, "GetAppTarget")
	return target.ComposeProject
}

// seedGood records a succeeded, known-good deployment of the target whose snapshots hold m.
func (w *moveWorld) seedGood(m goodModel) database.Deployment {
	w.t.Helper()
	if m.effective == "" {
		m.effective = modelStateless
	}
	if m.check == nil {
		m.check = nodeHealth()
	}
	if m.ports == nil {
		m.ports = []snapshotPort{tcpPort("web", "127.0.0.1", 8080)}
	}
	effective := strings.ReplaceAll(m.effective, "PROJECT", w.project())
	var dep database.Deployment
	w.inTx(func(ctx context.Context, tx *database.Tx) error {
		now := w.clock.Now()
		set, err := newSnapshotSet(now, composeSnapshot{
			Public: "services: {}", Effective: json.RawMessage(effective), Images: []snapshotImage{}, Secrets: []snapshotSecret{},
			HostPorts: m.ports,
		}, wire.ComposeExceptions{}, manifest.EffectivePolicy{Rollback: "automatic", Stateful: m.stateful, Health: m.check})
		if err != nil {
			return err
		}
		if err := set.store(ctx, tx); err != nil {
			return err
		}
		var hostPorts []string
		for _, p := range m.ports {
			hostPorts = append(hostPorts, p.Addr+":"+itoa(int(p.Port)))
		}
		raw, err := plan.Canonical(&plan.Plan{
			Version: plan.Version, Action: deploymentCreateAction, Actor: "identity/" + w.admin.String(),
			Targets: []plan.Target{{Type: string(domain.ResourceAppTarget), ID: w.target.ID.String()}},
			Content: plan.Content{
				ComposeHash: &set.compose, ExceptionsHash: &set.exceptions, HealthHash: &set.health,
				DeploymentPolicyHash: &set.deployPol, HostPorts: hostPorts,
			},
			Risk: domain.RiskOperational,
		})
		if err != nil {
			return err
		}
		rec := database.PlanRecord{
			ID: w.ids.NewID(), Action: deploymentCreateAction, ActorID: w.admin, Credential: w.caller(w.admin).Credential,
			PlanJSON: raw, PlanHash: "hash-" + set.compose, FinalizedAt: now, CreatedAt: now, ExpiresAt: now.Add(24 * time.Hour),
		}
		if err := database.InsertPlan(ctx, tx, rec); err != nil {
			return err
		}
		dep = database.Deployment{
			ID: w.ids.NewID(), Kind: deployments.KindDeploy, AppID: w.target.AppID, AppTargetID: w.target.ID,
			EnvironmentID: w.target.EnvironmentID, NodeID: w.node.ID, State: deployments.StateCreated, RequestedBy: w.admin,
			Credential: w.caller(w.admin).Credential, CommitSha: "abc", RequestedRaw: json.RawMessage(`[]`),
			CreatedAt: now, UpdatedAt: now,
		}
		if err := database.InsertDeployment(ctx, tx, dep); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE deployments SET plan_id = ?, compose_hash = ?, state = 'succeeded', known_good = 1, finished_at = ? WHERE id = ?`,
			rec.ID, set.compose, domain.UnixMillis(now), dep.ID)
		return err
	})
	return w.row(dep.ID)
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// ---- requests -------------------------------------------------------------------------------------

func (w *moveWorld) move() (AppMoveResult, error) {
	return w.svc.Move(context.Background(), w.caller(w.admin), w.target.ID, w.dest.ID)
}

func (w *moveWorld) mustMove() AppMoveResult {
	w.t.Helper()
	res, err := w.move()
	mustf(w.t, err, "Move")
	return res
}

func (w *moveWorld) planOfJob(job jobs.Job) plan.Plan {
	w.t.Helper()
	rec, err := database.GetPlan(context.Background(), w.db.Reader(), *job.PlanID)
	mustf(w.t, err, "GetPlan")
	parsed, err := plan.Parse(rec.PlanJSON)
	mustf(w.t, err, "plan.Parse")
	return *parsed
}

func (w *moveWorld) openMove() database.AppMove {
	w.t.Helper()
	m, err := database.GetOpenAppMoveByTarget(context.Background(), w.db.Reader(), w.target.ID)
	mustf(w.t, err, "GetOpenAppMoveByTarget")
	return m
}

func (w *moveWorld) approved(res AppMoveResult) jobs.Job {
	w.t.Helper()
	job, err := w.approve(w.bob, res.Submission.Job)
	mustf(w.t, err, "approve")
	return job
}

func wantRefusal(t *testing.T, err error, code smerr.Code, contains string) {
	t.Helper()
	if smerr.CodeOf(err) != code || !strings.Contains(err.Error(), contains) {
		t.Fatalf("error = %v, want code %s mentioning %q", err, code, contains)
	}
}

// ---- catalog and plan --------------------------------------------------------------------------------

func TestMove_PlanFreezesBothNodesTheKnownGoodDeploymentAndTheDestination(t *testing.T) {
	w := newMoveWorld(t)
	good := w.seedGood(goodModel{effective: modelSharedVolume})

	res := w.mustMove()

	job := res.Submission.Job
	if job.Type != appMoveAction || job.State != domain.JobAwaitingApproval || job.Risk != domain.RiskHigh || job.MaxAttempts != 3 {
		t.Fatalf("job = %+v, want a high-risk app_target.move awaiting approval with 3 attempts", job)
	}
	p := w.planOfJob(job)
	if p.Action != appMoveAction || p.Parameters["to_node"] != w.dest.ID.String() || p.Risk != domain.RiskHigh {
		t.Errorf("plan header = %+v", p)
	}
	if rt := p.Content.RollbackTarget; rt == nil || rt.DeploymentID != good.ID.String() || rt.ComposeHash != good.ComposeHash {
		t.Errorf("rollback_target = %+v, want the known-good deployment and its hash", rt)
	}
	pinned := map[string]plan.Input{}
	for _, in := range p.Inputs {
		pinned[in.Type+":"+in.ID] = in
	}
	for _, node := range []domain.Node{w.node, w.dest} {
		in, ok := pinned["node:"+node.ID.String()]
		if !ok || in.Endpoint == nil || in.Endpoint.Address != node.Endpoint.Host || in.HostPublicKeySHA256 == nil {
			t.Errorf("node %s is not pinned with its endpoint and host key: %+v", node.Name, in)
		}
	}
	if len(p.SubActions) != 1 || p.SubActions[0].Target.ID != w.dest.ID.String() {
		t.Errorf("sub-actions = %+v, want the destination evaluated by policy", p.SubActions)
	}
	wantSteps := []string{"preflight", "staged", "source_stopped", "data_copied", "started", "verified", "committed", "source_parked"}
	if !slices.Equal(p.Steps, wantSteps) {
		t.Errorf("steps = %v, want %v", p.Steps, wantSteps)
	}

	m := w.openMove()
	if m.SourceNodeID != w.node.ID || m.DestNodeID != w.dest.ID || m.PlanID != *job.PlanID || m.JobID != job.ID ||
		m.KnownGoodDeploymentID != good.ID || !m.Stateful || m.Phase != database.AppMovePreflight {
		t.Errorf("move = %+v", m)
	}
	if len(res.Volumes) != 1 || res.Volumes[0].VolumeName != w.project()+"_data" || res.Volumes[0].Service != "web" {
		t.Errorf("volumes = %+v", res.Volumes)
	}
}

func TestMove_AStatelessPlanHasNoDataSteps(t *testing.T) {
	w := newMoveWorld(t)
	w.seedGood(goodModel{})

	res := w.mustMove()

	if p := w.planOfJob(res.Submission.Job); slices.Contains(p.Steps, "source_stopped") || slices.Contains(p.Steps, "data_copied") {
		t.Errorf("steps = %v, a stateless move does not stop the source or copy data", p.Steps)
	}
	if res.Move.Stateful || len(res.Volumes) != 0 {
		t.Errorf("move = %+v volumes = %+v, want stateless", res.Move, res.Volumes)
	}
}

func TestMove_APlanForTheSameStateIsTheSamePlan(t *testing.T) {
	w := newMoveWorld(t)
	w.seedGood(goodModel{effective: modelSharedVolume})
	first := w.mustMove()
	w.exec(`UPDATE jobs SET state = 'failed', started_at = created_at WHERE id = ?`, first.Submission.Job.ID)

	second, err := w.move()

	mustf(t, err, "second Move")
	if !second.Resumed || second.Move.ID != first.Move.ID {
		t.Fatalf("second = %+v, want the first move resumed", second)
	}
	a, b := w.planOfJob(first.Submission.Job), w.planOfJob(second.Submission.Job)
	a.Actor, b.Actor = "", ""
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if string(ja) != string(jb) {
		t.Errorf("the resumed plan differs from the first:\n%s\n%s", ja, jb)
	}
}

func TestMove_PolicyDecidesWhoMayMoveAndBothNodesNeedTheCapability(t *testing.T) {
	w := newMoveWorld(t)
	w.seedGood(goodModel{})

	_, err := w.svc.Move(context.Background(), w.caller(w.deployer), w.target.ID, w.dest.ID)
	wantAppsCode(t, err, smerr.CodePolicyDenied)

	w.inTx(func(ctx context.Context, tx *database.Tx) error {
		return database.SetNodeCapability(ctx, tx, w.dest.ID, database.NodeCapability{
			Capability: capabilityComposeDeploy, Available: false, CheckedAt: w.clock.Now(),
		})
	})
	_, err = w.move()
	wantAppsCode(t, err, smerr.CodeCapabilityUnavailable)
	if w.rowCount("app_moves") != 0 {
		t.Error("a refused request wrote a move")
	}
}

func TestMove_ThePlansEndpointDoesNotCreateMovePlans(t *testing.T) {
	w := newMoveWorld(t)

	for _, action := range []string{appMoveAction, appMoveCleanupAction, appMoveAbandonAction} {
		_, err := w.plans.Create(context.Background(), w.caller(w.admin), PlanRequest{
			Action: action, Target: appTargetRef(w.target.ID), Parameters: map[string]any{"to_node": w.dest.ID.String(), "move_id": "m"},
		})
		wantAppsCode(t, err, smerr.CodeInvalidArgument)
	}
}

// ---- the volume map ---------------------------------------------------------------------------------

func TestVolumeMap(t *testing.T) {
	tests := []struct {
		name    string
		model   string
		want    []database.AppMoveVolume
		wantErr string
	}{
		{name: "no volumes", model: modelStateless},
		{name: "tmpfs is not data", model: `{"services":{"web":{"volumes":[{"type":"tmpfs","target":"/tmp"}]}}}`},
		{
			name:  "a shared volume is exported once, through its first read-write service",
			model: modelSharedVolume,
			want:  []database.AppMoveVolume{{VolumeName: "p_data", Service: "web", MountTarget: "/data", OtherServices: []string{"worker"}}},
		},
		{
			name: "the first read-write service in name order wins",
			model: `{"services":{
				"zeta":{"volumes":[{"type":"volume","source":"data","target":"/z"}]},
				"alpha":{"volumes":[{"type":"volume","source":"data","target":"/a","read_only":true}]},
				"beta":{"volumes":[{"type":"volume","source":"data","target":"/b"}]}}}`,
			want: []database.AppMoveVolume{{VolumeName: "p_data", Service: "beta", MountTarget: "/b", OtherServices: []string{"alpha", "zeta"}}},
		},
		{
			name: "one entry per distinct volume, sorted, the lowest target of a service that mounts it twice",
			model: `{"services":{"web":{"volumes":[
				{"type":"volume","source":"logs","target":"/logs"},
				{"type":"volume","source":"data","target":"/z"},
				{"type":"volume","source":"data","target":"/a"}]}}}`,
			want: []database.AppMoveVolume{
				{VolumeName: "p_data", Service: "web", MountTarget: "/a", OtherServices: []string{}},
				{VolumeName: "p_logs", Service: "web", MountTarget: "/logs", OtherServices: []string{}},
			},
		},
		{name: "read-only everywhere is refused", model: modelReadOnlyVolume, wantErr: "read-write"},
		{name: "a bind mount is not carried", model: `{"services":{"web":{"volumes":[{"type":"bind","source":"/x","target":"/x"}]}}}`, wantErr: "named volumes only"},
		{name: "unreadable model", model: `[1]`, wantErr: "unreadable"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			model := strings.ReplaceAll(tc.model, "PROJECT", "p")
			got, err := volumeMapOf("p", json.RawMessage(model))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want one mentioning %q", err, tc.wantErr)
				}
				return
			}
			mustf(t, err, "volumeMapOf")
			if len(got) != len(tc.want) {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
			for i := range got {
				w := tc.want[i]
				if got[i].VolumeName != w.VolumeName || got[i].Service != w.Service || got[i].MountTarget != w.MountTarget ||
					!slices.Equal(got[i].OtherServices, w.OtherServices) {
					t.Errorf("entry %d = %+v, want %+v", i, got[i], w)
				}
			}
		})
	}
}

func TestStatefulIsThePolicyFlagOrAnyNamedVolume(t *testing.T) {
	tests := []struct {
		name  string
		model goodModel
		want  bool
	}{
		{"neither", goodModel{}, false},
		{"the policy flag alone", goodModel{stateful: true}, true},
		{"a named volume alone", goodModel{effective: modelSharedVolume}, true},
		{"tmpfs alone", goodModel{effective: `{"services":{"web":{"volumes":[{"type":"tmpfs","target":"/tmp"}]}}}`}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := newMoveWorld(t)
			w.seedGood(tc.model)

			res := w.mustMove()

			if res.Move.Stateful != tc.want {
				t.Errorf("stateful = %v, want %v", res.Move.Stateful, tc.want)
			}
		})
	}
}

// ---- request-time refusals -----------------------------------------------------------------------------

func TestMove_RefusesAtRequestTimeAndWritesNothing(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(w *moveWorld) domain.ID // returns the destination; zero means w.dest
		model    goodModel
		noGood   bool
		code     smerr.Code
		contains string
	}{
		{name: "the destination is the source", setup: func(w *moveWorld) domain.ID { return w.node.ID }, code: smerr.CodeInvalidArgument, contains: "already runs on"},
		{
			name: "the destination is not managed", code: smerr.CodeInvalidArgument, contains: "not managed",
			setup: func(w *moveWorld) domain.ID {
				w.exec(`UPDATE nodes SET management_state = 'discovered' WHERE id = ?`, w.dest.ID)
				return ""
			},
		},
		{
			name: "the destination is in another environment", code: smerr.CodeInvalidArgument, contains: "another environment",
			setup: func(w *moveWorld) domain.ID {
				w.exec(`UPDATE nodes SET environment_id = ? WHERE id = ?`, w.staging.ID, w.dest.ID)
				return ""
			},
		},
		{name: "the destination does not exist", setup: func(*moveWorld) domain.ID { return "nowhere" }, code: smerr.CodeNotFound, contains: "not found"},
		{name: "no known-good deployment", noGood: true, code: smerr.CodeInvalidArgument, contains: "no known-good deployment"},
		{
			name: "an open deployment", code: smerr.CodeConflict, contains: "deploy",
			setup: func(w *moveWorld) domain.ID {
				w.create()
				return ""
			},
		},
		{
			name: "an open rollback", code: smerr.CodeConflict, contains: "rollback",
			setup: func(w *moveWorld) domain.ID {
				w.insertDeployment(deployments.KindRollback, deployments.StateQueued, w.node.ID)
				return ""
			},
		},
		{
			name: "another target uses the project on the destination", code: smerr.CodeConflict, contains: "compose project",
			setup: func(w *moveWorld) domain.ID {
				project := w.project()
				w.inTx(func(ctx context.Context, tx *database.Tx) error {
					_, err := database.CreateAppTarget(ctx, tx, database.AppTarget{
						ID: w.ids.NewID(), AppID: w.target.AppID, EnvironmentID: w.staging.ID, NodeID: w.dest.ID,
						ComposeProject: project, DeploymentPolicyJSON: []byte(`{}`), CreatedAt: w.clock.Now(), UpdatedAt: w.clock.Now(),
					})
					return err
				})
				return ""
			},
		},
		{
			name: "a route that is still provisioning", code: smerr.CodeConflict, contains: "provisioning",
			setup: func(w *moveWorld) domain.ID {
				w.insertRoute()
				w.exec(`UPDATE app_routes SET phase = 'provisioning'`)
				return ""
			},
		},
		{
			name: "a port bound to another address", code: smerr.CodeInvalidArgument, contains: "127.0.0.1 or 0.0.0.0",
			model: goodModel{ports: []snapshotPort{tcpPort("web", "192.168.1.5", 8080)}},
		},
		{
			name: "a volume no service mounts read-write", code: smerr.CodeInvalidArgument, contains: "read-write",
			model: goodModel{effective: modelReadOnlyVolume},
		},
		{
			name: "a control-plane health check", code: smerr.CodeInvalidArgument, contains: "control plane",
			model: goodModel{check: &health.Check{
				Origin: health.OriginControlPlane, Type: health.TypeHTTPS, Scope: health.ScopeControlPlane, URL: "https://app.example.com/health",
				Timeout: time.Second, Interval: time.Second, Attempts: 3,
			}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := newMoveWorld(t)
			if !tc.noGood {
				w.seedGood(tc.model)
			}
			to := w.dest.ID
			if tc.setup != nil {
				if other := tc.setup(w); other != "" {
					to = other
				}
			}
			plans, jobs, moves := w.rowCount("plans"), w.rowCount("jobs"), w.rowCount("app_moves")

			_, err := w.svc.Move(context.Background(), w.caller(w.admin), w.target.ID, to)

			wantRefusal(t, err, tc.code, tc.contains)
			if w.rowCount("plans") != plans || w.rowCount("jobs") != jobs || w.rowCount("app_moves") != moves {
				t.Error("a refused request left a plan, a job or a move")
			}
		})
	}
}

func (w *moveWorld) insertDeployment(kind string, state deployments.State, node domain.ID) database.Deployment {
	w.t.Helper()
	now := w.clock.Now()
	dep := database.Deployment{
		ID: w.ids.NewID(), Kind: kind, AppID: w.target.AppID, AppTargetID: w.target.ID, EnvironmentID: w.target.EnvironmentID,
		NodeID: node, State: state, RequestedBy: w.admin, Credential: w.caller(w.admin).Credential, CommitSha: "abc",
		RequestedRaw: json.RawMessage(`[]`), CreatedAt: now, UpdatedAt: now,
	}
	w.inTx(func(ctx context.Context, tx *database.Tx) error { return database.InsertDeployment(ctx, tx, dep) })
	return dep
}

func (w *moveWorld) insertRoute() {
	w.t.Helper()
	w.inTx(func(ctx context.Context, tx *database.Tx) error {
		_, err := database.InsertAppRoute(ctx, tx, database.AppRoute{
			ID: w.ids.NewID(), AppTargetID: w.target.ID, NodeID: w.node.ID, Hostname: "shop.example.com", Service: "web", Port: 8080,
			Access: "owners", AccountID: "acct", Zone: "example.com", InstanceID: "inst", TunnelID: "tun", TunnelGeneration: 1,
			CreatedBy: w.admin, CreatedAt: w.clock.Now(),
		})
		return err
	})
}

func TestMove_ARemovedRouteDoesNotBlock(t *testing.T) {
	w := newMoveWorld(t)
	w.seedGood(goodModel{})
	w.insertRoute()
	w.exec(`UPDATE app_routes SET phase = 'removed'`)

	if _, err := w.move(); err != nil {
		t.Fatalf("Move: %v", err)
	}
}

func TestMove_AnOpenMoveRefusesAnotherUnlessItsJobHasEnded(t *testing.T) {
	w := newMoveWorld(t)
	w.seedGood(goodModel{})
	first := w.mustMove()

	_, err := w.move()
	wantRefusal(t, err, smerr.CodeConflict, "in progress")

	w.exec(`UPDATE jobs SET state = 'failed', started_at = created_at WHERE id = ?`, first.Submission.Job.ID)
	resumed, err := w.move()
	mustf(t, err, "resume")
	if !resumed.Resumed || resumed.Move.ID != first.Move.ID || resumed.Move.JobID != resumed.Submission.Job.ID ||
		resumed.Move.JobID == first.Move.JobID || resumed.Move.PlanID != *resumed.Submission.Job.PlanID {
		t.Errorf("resumed = %+v, want the same move on the new job and plan", resumed.Move)
	}
	if w.rowCount("app_moves") != 1 {
		t.Errorf("%d moves, want 1", w.rowCount("app_moves"))
	}
}

func TestMove_AResumeNamesTheMovesDestination(t *testing.T) {
	w := newMoveWorld(t)
	w.seedGood(goodModel{})
	first := w.mustMove()
	w.exec(`UPDATE jobs SET state = 'cancelled', started_at = created_at WHERE id = ?`, first.Submission.Job.ID)

	_, err := w.svc.Move(context.Background(), w.caller(w.admin), w.target.ID, w.node.ID)

	wantRefusal(t, err, smerr.CodeConflict, "move to node "+w.dest.ID.String())
}

// ---- the same refusals on other paths ----------------------------------------------------------------

func TestOpenMove_RefusesDeploymentsRollbacksTargetsAndExposes(t *testing.T) {
	w := newMoveWorld(t)
	good := w.seedGood(goodModel{})
	w.mustMove()
	ctx := context.Background()

	_, err := w.deployments.Create(ctx, w.caller(w.deployer), w.request())
	wantRefusal(t, err, smerr.CodeConflict, "move")

	_, err = w.rollback(good.ID, wire.RollbackRequest{})
	wantRefusal(t, err, smerr.CodeConflict, "move")

	err = w.apps.requireFreeSlot(ctx, w.db.Reader(), appTargetCreateParams{AppID: "other-app", NodeID: w.dest.ID}, w.staging, w.project())
	wantRefusal(t, err, smerr.CodeConflict, "destination of a move")
	if err := w.apps.requireFreeSlot(ctx, w.db.Reader(), appTargetCreateParams{AppID: "other-app", NodeID: w.node.ID}, w.staging, "another-project"); err != nil {
		t.Errorf("an unrelated project was refused: %v", err)
	}

	core := w.deployments.core
	core.cfg.Cloudflare = &config.Cloudflare{AccountID: "acct", Zone: "example.com"}
	routes := &AppRoutes{core: core, plans: w.plans}
	_, _, err = routes.assess(ctx, w.db.Reader(), w.target.ID, appRouteParams{Hostname: "shop.example.com", Service: "web", Port: "8080", Access: "owners"}, true)
	wantRefusal(t, err, smerr.CodeConflict, "move")

	err = requireProjectFreeOn(ctx, w.db.Reader(), database.AppTarget{ID: "other-target", ComposeProject: w.project()}, w.dest)
	wantRefusal(t, err, smerr.CodeConflict, "being moved there")
}

func TestOpenMove_RefusesAQueuedDeploymentAtClaim(t *testing.T) {
	w := newMoveWorld(t)
	created := w.create()
	w.mustFinalize(created.ID)
	queued := w.row(created.ID)
	if queued.JobID == nil || queued.State != deployments.StateQueued {
		t.Fatalf("deployment = %+v, want queued with a job", queued)
	}
	w.openMoveRowFor(*queued.PlanID, *queued.JobID, queued.ID)

	claimed, ok := w.claim()

	if ok {
		t.Fatalf("claimed %s although the target has an open move", claimed.Job.ID)
	}
	job := w.job(*queued.JobID)
	if job.State != domain.JobFailed || job.Error == nil || job.Error.Code != smerr.CodeConflict {
		t.Errorf("job = %s %+v, want failed with CONFLICT", job.State, job.Error)
	}
}

// openMoveRowFor writes an open move whose plan and job are the given rows; they only have to exist.
func (w *moveWorld) openMoveRowFor(planID, jobID, goodID domain.ID) database.AppMove {
	w.t.Helper()
	var m database.AppMove
	w.inTx(func(ctx context.Context, tx *database.Tx) error {
		var err error
		m, err = database.InsertAppMove(ctx, tx, database.AppMove{
			ID: w.ids.NewID(), AppTargetID: w.target.ID, SourceNodeID: w.node.ID, DestNodeID: w.dest.ID, PlanID: planID, JobID: jobID,
			KnownGoodDeploymentID: goodID, CreatedBy: w.admin, CreatedAt: w.clock.Now(),
		}, nil)
		return err
	})
	return m
}

// ---- revalidation ------------------------------------------------------------------------------------

func (w *moveWorld) revalidate(job jobs.Job) error {
	return w.reval.Revalidate(context.Background(), w.db.Reader(), w.job(job.ID))
}

func TestRevalidate_BeforeTheCommitTheRebuildAgainstTheFrozenNodesMustMatch(t *testing.T) {
	w := newMoveWorld(t)
	w.seedGood(goodModel{effective: modelSharedVolume})
	res := w.mustMove()
	job := w.approved(res)

	if err := w.revalidate(job); err != nil {
		t.Fatalf("Revalidate: %v", err)
	}

	w.bumpNodeRevision() // the source node's configuration moved
	wantError(t, w.revalidate(job), smerr.CodeConflict, smerr.ReasonPlanStale)
}

func TestRevalidate_BeforeTheCommitATargetOnAnotherNodeIsStale(t *testing.T) {
	w := newMoveWorld(t)
	w.seedGood(goodModel{})
	job := w.approved(w.mustMove())
	w.exec(`UPDATE app_targets SET node_id = ? WHERE id = ?`, w.dest.ID, w.target.ID)

	wantError(t, w.revalidate(job), smerr.CodeConflict, smerr.ReasonPlanStale)
}

func TestRevalidate_ASupersededPlanIsStale(t *testing.T) {
	w := newMoveWorld(t)
	w.seedGood(goodModel{})
	first := w.mustMove()
	old := w.approved(first)
	w.exec(`UPDATE jobs SET state = 'failed', started_at = created_at WHERE id = ?`, first.Submission.Job.ID)
	w.mustMove()

	wantError(t, w.revalidate(old), smerr.CodeConflict, smerr.ReasonPlanStale)
}

// commitBySQL stands in for the commit transaction: the target runs on B at the next revision, B has its move
// deployment, and the move is committed at that revision.
func (w *moveWorld) commitBySQL(m database.AppMove) (database.Deployment, int64) {
	w.t.Helper()
	dep := w.insertDeployment(deployments.KindMove, deployments.StateSucceeded, w.dest.ID)
	target, err := database.GetAppTarget(context.Background(), w.db.Reader(), w.target.ID)
	mustf(w.t, err, "GetAppTarget")
	revision := target.SpecRevision + 1
	w.exec(`UPDATE app_targets SET node_id = ?, spec_revision = ? WHERE id = ?`, w.dest.ID, revision, w.target.ID)
	w.exec(`UPDATE app_moves SET phase = 'committed', dest_deployment_id = ?, committed_revision = ? WHERE id = ?`, dep.ID, revision, m.ID)
	return dep, revision
}

func TestRevalidate_FromTheCommitOnTheMoveRecordReplacesTheRebuild(t *testing.T) {
	w := newMoveWorld(t)
	w.seedGood(goodModel{effective: modelSharedVolume})
	res := w.mustMove()
	job := w.approved(res)
	_, revision := w.commitBySQL(res.Move)

	if err := w.revalidate(job); err != nil {
		t.Fatalf("a committed move must revalidate against its record: %v", err)
	}

	w.exec(`UPDATE app_targets SET spec_revision = ? WHERE id = ?`, revision+1, w.target.ID)
	wantError(t, w.revalidate(job), smerr.CodeConflict, smerr.ReasonPlanStale)
}

func TestRevalidate_AfterTheCommitEveryRecordedIDMustMatch(t *testing.T) {
	tests := []struct {
		name   string
		break_ func(w *moveWorld, m database.AppMove, dep database.Deployment)
	}{
		{"the target is not on the destination", func(w *moveWorld, _ database.AppMove, _ database.Deployment) {
			w.exec(`UPDATE app_targets SET node_id = ? WHERE id = ?`, w.node.ID, w.target.ID)
		}},
		{"the destination deployment is of another kind", func(w *moveWorld, _ database.AppMove, dep database.Deployment) {
			w.exec(`UPDATE deployments SET kind = 'deploy' WHERE id = ?`, dep.ID)
		}},
		{"the destination deployment is on another node", func(w *moveWorld, _ database.AppMove, dep database.Deployment) {
			w.exec(`UPDATE deployments SET node_id = ? WHERE id = ?`, w.node.ID, dep.ID)
		}},
		{"the move belongs to another job", func(w *moveWorld, m database.AppMove, _ database.Deployment) {
			w.exec(`UPDATE app_moves SET job_id = ? WHERE id = ?`, w.otherJob, m.ID)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := newMoveWorld(t)
			w.seedGood(goodModel{})
			w.otherJob = w.insertEndedDeploymentJob()
			res := w.mustMove()
			job := w.approved(res)
			dep, _ := w.commitBySQL(res.Move)
			tc.break_(w, res.Move, dep)

			wantError(t, w.revalidate(job), smerr.CodeConflict, smerr.ReasonPlanStale)
		})
	}
}

// insertEndedDeploymentJob returns the job of a deployment that has since ended, so it blocks no move.
func (w *moveWorld) insertEndedDeploymentJob() domain.ID {
	w.t.Helper()
	created := w.create()
	w.mustFinalize(created.ID)
	job := *w.row(created.ID).JobID
	w.exec(`UPDATE deployments SET state = 'failed' WHERE id = ?`, created.ID)
	return job
}

// ---- locks -------------------------------------------------------------------------------------------

func lockKeys(specs []domain.LockSpec) []string {
	out := make([]string, len(specs))
	for i, s := range specs {
		out[i] = s.Key + " " + string(s.Mode)
	}
	slices.Sort(out)
	return out
}

func (w *moveWorld) locksOf(job jobs.Job) []string {
	w.t.Helper()
	specs, err := LockPlanner{}.PlanLocks(context.Background(), w.db.Reader(), w.job(job.ID))
	mustf(w.t, err, "PlanLocks")
	return lockKeys(specs)
}

func TestMoveLocks_AreTheTargetAndTheProjectAndPortsOfBothFrozenNodes(t *testing.T) {
	w := newMoveWorld(t)
	w.seedGood(goodModel{ports: []snapshotPort{tcpPort("web", "127.0.0.1", 8080), tcpPort("web", "0.0.0.0", 9090)}})
	res := w.mustMove()
	project := w.project()
	x, s := string(domain.LockExclusive), string(domain.LockShared)
	want := []string{"app_target:" + w.target.ID.String() + " " + x, "environment:" + w.target.EnvironmentID.String() + " " + s}
	for _, node := range []domain.Node{w.node, w.dest} {
		id := node.ID.String()
		want = append(want,
			"node:"+id+" "+s,
			"compose_project:"+id+":"+project+" "+x,
			"port:"+id+":127.0.0.1:8080 "+x,
			"port:"+id+":0.0.0.0:9090 "+x)
	}
	slices.Sort(want)

	if got := w.locksOf(res.Submission.Job); !slices.Equal(got, want) {
		t.Errorf("locks = %v\nwant    %v", got, want)
	}

	w.commitBySQL(res.Move) // the target now runs on B: the locks still name both frozen nodes
	if got := w.locksOf(res.Submission.Job); !slices.Equal(got, want) {
		t.Errorf("locks after the commit = %v\nwant              %v", got, want)
	}
}

// ---- cleanup and abandon ------------------------------------------------------------------------------

func (w *moveWorld) doneMove() database.AppMove {
	w.t.Helper()
	res := w.mustMove()
	w.commitBySQL(res.Move)
	w.exec(`UPDATE app_moves SET phase = 'done' WHERE id = ?`, res.Move.ID)
	return res.Move
}

func TestCleanupSource_FreezesTheDoneMoveTheSourceAndItsDeployment(t *testing.T) {
	w := newMoveWorld(t)
	good := w.seedGood(goodModel{})
	m := w.doneMove()

	sub, err := w.svc.CleanupSource(context.Background(), w.caller(w.admin), w.target.ID)

	mustf(t, err, "CleanupSource")
	p := w.planOfJob(sub.Job)
	if sub.Job.Type != appMoveCleanupAction || sub.Job.Risk != domain.RiskHigh || p.Parameters["move_id"] != m.ID.String() {
		t.Fatalf("job %s risk %s params %v", sub.Job.Type, sub.Job.Risk, p.Parameters)
	}
	if rt := p.Content.RollbackTarget; rt == nil || rt.DeploymentID != good.ID.String() {
		t.Errorf("rollback_target = %+v, want the deployment A is left with", rt)
	}
	if nodes := plannedNodes(p); len(nodes) != 1 || nodes[0] != w.node.ID {
		t.Errorf("nodes = %v, want only the source", nodes)
	}
	x, s := string(domain.LockExclusive), string(domain.LockShared)
	want := []string{
		"app_target:" + w.target.ID.String() + " " + x, "environment:" + w.target.EnvironmentID.String() + " " + s,
		"node:" + w.node.ID.String() + " " + s, "compose_project:" + w.node.ID.String() + ":" + w.project() + " " + x,
	}
	slices.Sort(want)
	if got := w.locksOf(sub.Job); !slices.Equal(got, want) {
		t.Errorf("locks = %v\nwant    %v", got, want)
	}
	if sub.Job.State != domain.JobAwaitingApproval {
		t.Fatalf("job state %s, want awaiting approval: a cleanup is high risk, in every environment", sub.Job.State)
	}
	_, err = w.approve(w.bob, sub.Job)
	mustf(t, err, "approve the cleanup")
	mustf(t, w.revalidate(sub.Job), "Revalidate")
}

func TestCleanupSource_Refusals(t *testing.T) {
	t.Run("no completed move", func(t *testing.T) {
		w := newMoveWorld(t)
		_, err := w.svc.CleanupSource(context.Background(), w.caller(w.admin), w.target.ID)
		wantAppsCode(t, err, smerr.CodeNotFound)
	})
	t.Run("the target runs on the source again", func(t *testing.T) {
		w := newMoveWorld(t)
		w.seedGood(goodModel{})
		w.doneMove()
		w.exec(`UPDATE app_targets SET node_id = ? WHERE id = ?`, w.node.ID, w.target.ID)
		_, err := w.svc.CleanupSource(context.Background(), w.caller(w.admin), w.target.ID)
		wantRefusal(t, err, smerr.CodeConflict, "again")
	})
	t.Run("another target uses the project on the source", func(t *testing.T) {
		w := newMoveWorld(t)
		w.seedGood(goodModel{})
		w.doneMove()
		project := w.project()
		w.inTx(func(ctx context.Context, tx *database.Tx) error {
			_, err := database.CreateAppTarget(ctx, tx, database.AppTarget{
				ID: w.ids.NewID(), AppID: w.target.AppID, EnvironmentID: w.staging.ID, NodeID: w.node.ID,
				ComposeProject: project, DeploymentPolicyJSON: []byte(`{}`), CreatedAt: w.clock.Now(), UpdatedAt: w.clock.Now(),
			})
			return err
		})
		_, err := w.svc.CleanupSource(context.Background(), w.caller(w.admin), w.target.ID)
		wantRefusal(t, err, smerr.CodeConflict, "another target")
	})
	t.Run("a policy without the action", func(t *testing.T) {
		w := newMoveWorld(t)
		w.seedGood(goodModel{})
		w.doneMove()
		_, err := w.svc.CleanupSource(context.Background(), w.caller(w.deployer), w.target.ID)
		wantAppsCode(t, err, smerr.CodePolicyDenied)
	})
}

func TestAbandon_OnlyAMoveHaltedInCompensation(t *testing.T) {
	w := newMoveWorld(t)
	w.seedGood(goodModel{})
	ctx := context.Background()

	_, err := w.svc.Abandon(ctx, w.caller(w.admin), w.target.ID)
	wantRefusal(t, err, smerr.CodeInvalidArgument, "no open move")

	res := w.mustMove()
	_, err = w.svc.Abandon(ctx, w.caller(w.admin), w.target.ID)
	wantRefusal(t, err, smerr.CodeConflict, "halted in compensation")

	w.exec(`UPDATE app_moves SET phase = 'failed', halted_phase = 'started' WHERE id = ?`, res.Move.ID)
	_, err = w.svc.Abandon(ctx, w.caller(w.admin), w.target.ID)
	wantRefusal(t, err, smerr.CodeConflict, "halted in compensation")

	w.exec(`UPDATE app_moves SET halted_phase = 'compensating_source_started' WHERE id = ?`, res.Move.ID)
	sub, err := w.svc.Abandon(ctx, w.caller(w.admin), w.target.ID)
	mustf(t, err, "Abandon")
	_, err = w.approve(w.bob, sub.Job)
	mustf(t, err, "approve the abandon")
	p := w.planOfJob(sub.Job)
	if sub.Job.Type != appMoveAbandonAction || p.Parameters["move_id"] != res.Move.ID.String() || len(plannedNodes(p)) != 0 {
		t.Errorf("job %s plan %+v, want an abandon of the move that names no node", sub.Job.Type, p)
	}
	if got := w.locksOf(sub.Job); len(got) != 2 {
		t.Errorf("locks = %v, want the target and the environment", got)
	}
	if err := w.revalidate(sub.Job); err != nil {
		t.Errorf("Revalidate: %v", err)
	}
}

// ---- listing and registration -----------------------------------------------------------------------

func TestList_ShowsTheMovesWithTheirVolumesToWhoMayRead(t *testing.T) {
	w := newMoveWorld(t)
	w.seedGood(goodModel{effective: modelSharedVolume})
	res := w.mustMove()

	views, err := w.svc.List(context.Background(), w.caller(w.admin), w.target.ID)

	mustf(t, err, "List")
	if len(views) != 1 || views[0].Move.ID != res.Move.ID || len(views[0].Volumes) != 1 {
		t.Errorf("views = %+v", views)
	}
	_, err = w.svc.List(context.Background(), w.caller(w.dave), w.target.ID)
	wantAppsCode(t, err, smerr.CodePolicyDenied)
}

func TestHandlers_TheMoveTypesExistOnlyWhenDeploymentsAreConfigured(t *testing.T) {
	n := newNodeFixture(t)

	without := n.handlersWith(t, nil, nil).Map()
	with := n.handlersWith(t, nil, &DeployOptions{Secrets: dhSecrets{}, HTTP: &http.Client{}, SystemID: "system"}).Map()

	for _, jobType := range []string{appMoveAction, appMoveCleanupAction, appMoveAbandonAction} {
		if _, ok := without[jobType]; ok {
			t.Errorf("%s has a handler without deployment options", jobType)
		}
		if _, ok := with[jobType]; !ok {
			t.Errorf("%s has no handler although deployments are configured", jobType)
		}
	}
}

func TestEveryMoveActionHasALockModeAndAHandlerContract(t *testing.T) {
	for _, action := range []string{appMoveAction, appMoveCleanupAction, appMoveAbandonAction} {
		if lockModeByJobType[action] != domain.LockExclusive {
			t.Errorf("%s: lock mode %q, want exclusive on the app target", action, lockModeByJobType[action])
		}
		if !isMoveAction(action) {
			t.Errorf("%s is not recognised as a move action", action)
		}
	}
}

func TestMove_AnApprovedMoveIsClaimedThroughRevalidationAndLocks(t *testing.T) {
	w := newMoveWorld(t)
	w.seedGood(goodModel{})
	job := w.approved(w.mustMove())

	claimed, ok := w.claim()

	if !ok || claimed.Job.ID != job.ID || claimed.Job.State != domain.JobRunning {
		t.Fatalf("claimed %+v (found %v), want the approved move running", claimed.Job, ok)
	}
}

// ---- the fixes of review round 1 -----------------------------------------------------------------------

func TestMove_AMoveWhoseJobEndedBeforeItRanNeitherBlocksTheTargetNorTheNextRequest(t *testing.T) {
	t.Run("the target is free for other work", func(t *testing.T) {
		w := newMoveWorld(t)
		w.seedGood(goodModel{})
		first := w.mustMove()
		w.exec(`UPDATE jobs SET state = 'cancelled' WHERE id = ?`, first.Submission.Job.ID)

		if err := requireNoOpenMove(context.Background(), w.db.Reader(), w.target.ID); err != nil {
			t.Errorf("a move that never ran blocks the target: %v", err)
		}
		other := database.AppTarget{ID: "other-target", ComposeProject: w.project()}
		if err := requireProjectFreeOn(context.Background(), w.db.Reader(), other, w.dest); err != nil {
			t.Errorf("a move that never ran keeps the destination from a target of the same project: %v", err)
		}
		if got, err := database.OpenMoveDestinations(context.Background(), w.db.Reader(), w.project()); err != nil || len(got) != 0 {
			t.Errorf("open move destinations = %v, %v; want none", got, err)
		}
		if _, err := w.deployments.Create(context.Background(), w.caller(w.deployer), w.request()); err != nil && strings.Contains(err.Error(), "move") {
			t.Errorf("deployment refused because of the move: %v", err)
		}
	})
	t.Run("the next request settles it and starts a new move", func(t *testing.T) {
		w := newMoveWorld(t)
		w.seedGood(goodModel{})
		first := w.mustMove()
		w.exec(`UPDATE jobs SET state = 'cancelled' WHERE id = ?`, first.Submission.Job.ID)

		second, err := w.move()

		mustf(t, err, "Move")
		if second.Resumed || second.Move.ID == first.Move.ID {
			t.Errorf("second = %+v, want a new move", second.Move)
		}
		old, err := database.GetAppMove(context.Background(), w.db.Reader(), first.Move.ID)
		mustf(t, err, "GetAppMove")
		if old.Phase != database.AppMoveRolledBack {
			t.Errorf("the first move is %s, want rolled_back", old.Phase)
		}
		if got := len(w.events("app_move.rolled_back")); got != 1 {
			t.Errorf("rolled_back events = %d, want 1", got)
		}
	})
}

func TestRevalidate_AfterTheCommitTheNodesAreStillTheOnesThePlanPinned(t *testing.T) {
	w := newMoveWorld(t)
	w.seedGood(goodModel{})
	res := w.mustMove()
	job := w.approved(res)
	w.commitBySQL(res.Move)
	mustf(t, w.revalidate(job), "Revalidate before the endpoint changes")

	w.exec(`UPDATE nodes SET endpoint_json = json_set(endpoint_json, '$.host', '203.0.113.9') WHERE id = ?`, w.node.ID)

	wantError(t, w.revalidate(job), smerr.CodeConflict, smerr.ReasonPlanStale)
}

func TestAddBytes_FailsClosedWhereTheSumDoesNotFit(t *testing.T) {
	if got, err := addBytes(1, 2, 3); err != nil || got != 6 {
		t.Errorf("addBytes(1,2,3) = %d, %v", got, err)
	}
	for name, values := range map[string][]int64{
		"two large": {math.MaxInt64 / 2, math.MaxInt64/2 + 2}, "negative": {1, -1}, "the maximum plus one": {math.MaxInt64, 1},
	} {
		if _, err := addBytes(values...); err == nil {
			t.Errorf("%s: the sum was accepted", name)
		}
	}
	model := json.RawMessage(`{"services":{"a":{"mem_limit":"4611686018427387904"},"b":{"mem_limit":"4611686018427387904"}}}`)
	if _, _, err := resourceLimits(model); err == nil {
		t.Error("memory limits that overflow together were accepted")
	}
}
