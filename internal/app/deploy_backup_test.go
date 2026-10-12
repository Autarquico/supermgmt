package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/domain/plan"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

const predeployBackupArtifact = "/var/lib/supermgmt/db-backups/app-20261012T100000Z-42.dump"

// predeployBackupFixture claims a job to get a live lease and wires a backup step whose
// policy gate and node are fakes.
type predeployBackupFixture struct {
	t      *testing.T
	f      *fixture
	lease  jobs.Lease
	node   *fakeNode
	gated  []plan.SubAction
	denial error
	step   backupStep
	req    backupRequest
}

func newPredeployBackupFixture(t *testing.T) *predeployBackupFixture {
	t.Helper()
	f := newFixture(t)
	sub, _ := f.submitReboot()
	f.approveToQuorum(sub.Job)
	claimed, ok := f.claim()
	if !ok {
		t.Fatal("no job to claim")
	}
	b := &predeployBackupFixture{t: t, f: f, lease: claimed.Lease, node: newFakeNode(t)}
	b.step = backupStep{
		store: f.store, clock: f.clock, ids: f.ids,
		gate: func(_ context.Context, sub plan.SubAction) error {
			b.gated = append(b.gated, sub)
			return b.denial
		},
	}
	b.req = backupRequest{
		Deployment: f.ids.NewID(),
		Plan: plan.Plan{SubActions: []plan.SubAction{{
			Action: policy.ActionNodeBackupTemplateRun,
			Target: plan.SubTarget{Type: "node", ID: f.node.ID.String()},
		}}},
		Template: "postgres-dump",
		Args:     map[string]string{"container": "db", "database": "app"},
		Timeout:  time.Minute,
	}
	return b
}

func (b *predeployBackupFixture) run(ex transport.Executor) (string, error) {
	return b.step.run(context.Background(), ex, b.lease, b.req)
}

func (b *predeployBackupFixture) intents() []jobs.Intent {
	b.t.Helper()
	in, err := b.f.store.Intents(context.Background(), b.f.db.Reader(), b.lease.JobID)
	if err != nil {
		b.t.Fatalf("Intents: %v", err)
	}
	return in
}

func (b *predeployBackupFixture) wantNoIntent() {
	b.t.Helper()
	if in := b.intents(); len(in) != 0 {
		b.t.Fatalf("intents = %d, want none: nothing may be dispatched", len(in))
	}
}

func wantPredeployBackupFailed(t *testing.T, err error) {
	t.Helper()
	wantError(t, err, smerr.CodeDeploymentFailed, smerr.ReasonStagingFailed)
	var typed *smerr.Error
	if !errors.As(err, &typed) || typed.Details["cause"] != deployments.CauseBackupFailed {
		t.Fatalf("details = %v, want cause %s", typed.Details, deployments.CauseBackupFailed)
	}
}

func TestBackup_SuccessRecordsArtifactAndClosesIntent(t *testing.T) {
	b := newPredeployBackupFixture(t)
	b.node.on("postgres-dump", func(templates.Command) (transport.Result, error) {
		return transport.Result{Stdout: []byte("dumping app\n" + predeployBackupArtifact + "\n")}, nil
	})
	artifact, err := b.run(b.node)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if artifact != predeployBackupArtifact {
		t.Errorf("artifact = %q, want %q", artifact, predeployBackupArtifact)
	}
	if len(b.gated) != 1 || b.gated[0].Action != policy.ActionNodeBackupTemplateRun {
		t.Errorf("gate saw %v, want the backup sub-action once", b.gated)
	}
	in := b.intents()
	if len(in) != 1 {
		t.Fatalf("intents = %d, want 1", len(in))
	}
	if in[0].State != jobs.IntentCompleted || in[0].Outcome != jobs.OutcomeSucceeded || !in[0].Dispatched() {
		t.Errorf("intent = %+v, want dispatched and completed as succeeded", in[0])
	}
	if in[0].Step != deployments.StepPreDeployBackup || in[0].Operation != policy.ActionNodeBackupTemplateRun {
		t.Errorf("intent step/operation = %s/%s", in[0].Step, in[0].Operation)
	}
	if n := b.node.count("postgres-dump"); n != 1 {
		t.Errorf("postgres-dump ran %d times, want 1", n)
	}
}

func TestBackup_FailuresNeverReachComposeUp(t *testing.T) {
	reply := func(stdout string, exit int) func(*predeployBackupFixture) {
		return func(b *predeployBackupFixture) {
			b.node.on("postgres-dump", func(templates.Command) (transport.Result, error) {
				return transport.Result{Stdout: []byte(stdout), ExitStatus: exit}, nil
			})
		}
	}
	tests := []struct {
		name       string
		arrange    func(*predeployBackupFixture)
		dispatched bool // whether the node must have been reached
	}{
		{"non-zero exit", reply(predeployBackupArtifact+"\n", 3), true},
		{"no output", reply("", 0), true},
		{"relative path", reply("db-backups/app.dump\n", 0), true},
		{"path outside the backup directory", reply("/etc/shadow\n", 0), true},
		{"path escaping the backup directory", reply("/var/lib/supermgmt/db-backups/../x.dump\n", 0), true},
		{"path in a subdirectory", reply("/var/lib/supermgmt/db-backups/sub/app.dump\n", 0), true},
		{"path is not the last line", reply(predeployBackupArtifact+"\ndone\n", 0), true},
		{"output cut before the last line", func(b *predeployBackupFixture) {
			b.node.on("postgres-dump", func(templates.Command) (transport.Result, error) {
				return transport.Result{Stdout: []byte(predeployBackupArtifact + "\n"), Truncated: true}, nil
			})
		}, true},
		{"timeout", func(b *predeployBackupFixture) {
			b.req.Timeout = 20 * time.Millisecond
			b.node.on("postgres-dump", func(templates.Command) (transport.Result, error) {
				time.Sleep(200 * time.Millisecond)
				return transport.Result{}, context.DeadlineExceeded
			})
		}, true},
		{"unsupported template", func(b *predeployBackupFixture) { b.req.Template = "mysqldump" }, false},
		{"zero timeout", func(b *predeployBackupFixture) { b.req.Timeout = 0 }, false},
		{"timeout above the node cap", func(b *predeployBackupFixture) { b.req.Timeout = 2 * time.Hour }, false},
		{"arguments the template refuses", func(b *predeployBackupFixture) {
			b.req.Args = map[string]string{"container": "db;rm -rf /", "database": "app"}
		}, false},
		{"plan without the sub-action", func(b *predeployBackupFixture) { b.req.Plan.SubActions = nil }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := newPredeployBackupFixture(t)
			tt.arrange(b)
			artifact, err := b.run(b.node)
			wantPredeployBackupFailed(t, err)
			if artifact != "" {
				t.Errorf("artifact = %q on failure, want none", artifact)
			}
			if reached := b.node.count("postgres-dump") > 0; reached != tt.dispatched {
				t.Errorf("node reached = %v, want %v", reached, tt.dispatched)
			}
			if !tt.dispatched {
				b.wantNoIntent()
				return
			}
			in := b.intents()
			if len(in) != 1 || in[0].State != jobs.IntentCompleted || in[0].Outcome != jobs.OutcomeFailed {
				t.Errorf("intents = %+v, want one completed as failed", in)
			}
			for _, other := range b.node.ran() {
				if other != "postgres-dump" {
					t.Errorf("the failed backup went on to %s", other)
				}
			}
		})
	}
}

func TestBackup_DeniedSubActionDispatchesNothing(t *testing.T) {
	b := newPredeployBackupFixture(t)
	b.denial = smerr.New(smerr.CodePolicyDenied, smerr.ReasonDefaultDeny, "denied")
	artifact, err := b.run(b.node)
	wantError(t, err, smerr.CodePolicyDenied, smerr.ReasonDefaultDeny)
	if artifact != "" {
		t.Errorf("artifact = %q, want none", artifact)
	}
	if got := b.node.ran(); len(got) != 0 {
		t.Errorf("the node was reached after a denial: %v", got)
	}
	b.wantNoIntent()
}

func TestBackup_InterruptionKeepsTheIntentRecorded(t *testing.T) {
	t.Run("connection lost", func(t *testing.T) {
		b := newPredeployBackupFixture(t)
		b.node.down("postgres-dump", errors.New("connection reset"))
		artifact, err := b.run(b.node)
		if !errors.Is(err, jobs.ErrOutcomeUnknown) {
			t.Fatalf("err = %v, want jobs.ErrOutcomeUnknown", err)
		}
		if artifact != "" {
			t.Errorf("artifact = %q, want none", artifact)
		}
		in := b.intents()
		if len(in) != 1 || in[0].State != jobs.IntentRecorded || !in[0].Dispatched() {
			t.Errorf("intents = %+v, want one dispatched and still recorded", in)
		}
	})
	t.Run("run cancelled", func(t *testing.T) {
		b := newPredeployBackupFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		b.node.on("postgres-dump", func(templates.Command) (transport.Result, error) {
			cancel()
			return transport.Result{}, ctx.Err()
		})
		_, err := b.step.run(ctx, b.node, b.lease, b.req)
		if !errors.Is(err, jobs.ErrOutcomeUnknown) {
			t.Fatalf("err = %v, want jobs.ErrOutcomeUnknown", err)
		}
		if in := b.intents(); len(in) != 1 || in[0].State != jobs.IntentRecorded {
			t.Errorf("intents = %+v, want one still recorded", in)
		}
	})
}

func TestBackup_ErrorsNeverEchoNodeOutput(t *testing.T) {
	b := newPredeployBackupFixture(t)
	b.node.on("postgres-dump", func(templates.Command) (transport.Result, error) {
		return transport.Result{Stdout: []byte("password=hunter2\n"), Stderr: []byte("password=hunter2"), ExitStatus: 1}, nil
	})
	_, err := b.run(b.node)
	wantPredeployBackupFailed(t, err)
	if strings.Contains(err.Error(), "hunter2") {
		t.Errorf("error leaks node output: %v", err)
	}
}
