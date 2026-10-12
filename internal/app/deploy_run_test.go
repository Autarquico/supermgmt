package app

import (
	"context"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/deployments"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

func TestDeployRun_UpRunsComposeUpUnderTheProjectFlock(t *testing.T) {
	exec := &deployStageExec{}
	dir := deployStageDir()
	if err := (deployRun{exec: exec}).Up(context.Background(), deployments.RecoveryForward, dir, "marker-3"); err != nil {
		t.Fatalf("Up: %v", err)
	}
	c := exec.commands[0]
	if c.Template != "compose.up" || !c.Mutating || c.Sensitive {
		t.Errorf("command = %+v; want a mutating, non-sensitive compose.up", c)
	}
	for _, want := range []string{"flock", templates.LockPath(dir.Project), "marker-3", dir.Deployment.String()} {
		if !strings.Contains(c.Line, want) {
			t.Errorf("line lacks %q: %s", want, c.Line)
		}
	}
}

func TestDeployRun_UpFailures(t *testing.T) {
	cases := []struct {
		name   string
		status int
		code   smerr.Code
		reason smerr.Reason
	}{
		{"project lock held", templates.LockConflictExit, smerr.CodeConflict, smerr.ReasonResourceLocked},
		{"compose up failed", 1, smerr.CodeDeploymentFailed, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			exec := &deployStageExec{reply: deployStageReply(transport.Result{ExitStatus: tc.status, Stderr: []byte(deployStageSecretValue)})}
			err := deployRun{exec: exec}.Up(context.Background(), deployments.RecoveryForward, deployStageDir(), "marker-3")
			if smerr.CodeOf(err) != tc.code {
				t.Fatalf("code = %s; want %s", smerr.CodeOf(err), tc.code)
			}
			if tc.reason != "" {
				_ = deployStageWantError(t, err, tc.reason)
			}
			deployStageNoSecret(t, "up error", err)
		})
	}
}

func TestDeployRun_UpRefusesUnderSafetyRecovery(t *testing.T) {
	exec := &deployStageExec{}
	err := deployRun{exec: exec}.Up(context.Background(), deployments.RecoverySafetyRecovery, deployStageDir(), "marker-3")
	_ = deployStageWantError(t, err, smerr.ReasonInvalidTransition)
	if len(exec.commands) != 0 {
		t.Error("compose up reached the node under safety recovery")
	}
}

func TestDeployRun_RestoreVariantRunsUnderSafetyRecovery(t *testing.T) {
	exec := &deployStageExec{}
	if err := (deployRun{exec: exec}).runUp(context.Background(), deployStageDir(), "marker-3"); err != nil || len(exec.commands) != 1 {
		t.Errorf("runUp = %v with %d commands; want one compose up", err, len(exec.commands))
	}
}
