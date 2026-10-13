package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/deployments/compose"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

const (
	deployStageSecretValue = "s3cr3t-p@ss $word"
	deployStageImage       = "ghcr.io/acme/api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	deployStageSidecar     = "docker.io/library/redis@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// deployStageExec records every command and answers through reply.
type deployStageExec struct {
	commands []templates.Command
	reply    func(templates.Command) (transport.Result, error)
}

func (e *deployStageExec) Run(_ context.Context, c templates.Command) (transport.Result, error) {
	e.commands = append(e.commands, c)
	if e.reply == nil {
		return transport.Result{}, nil
	}
	return e.reply(c)
}

func deployStageReply(res transport.Result) func(templates.Command) (transport.Result, error) {
	return func(templates.Command) (transport.Result, error) { return res, nil }
}

func deployStageSum(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func deployStageDir() deployDir {
	return deployDir{Root: "/srv/supermgmt", Project: "sm-shop-prod", Deployment: domain.UUIDv7Generator{}.NewID()}
}

const deployStagePublic = `services:
  api:
    environment:
      GREETING: a$$b
    image: ` + deployStageImage + `
    labels:
      dev.supermgmt.owner: owner-1
      dev.supermgmt.project: sm-shop-prod
  cache:
    image: ` + deployStageSidecar + `
    labels:
      dev.supermgmt.owner: owner-1
      dev.supermgmt.project: sm-shop-prod
`

func deployStageFrozen() compose.Frozen {
	effective := fmt.Sprintf(`{"name":"sm-shop-prod","services":{`+
		`"api":{"image":%q,"environment":{"GREETING":"sha256:%s"},"labels":{"dev.supermgmt.owner":"owner-1","dev.supermgmt.project":"sm-shop-prod"}},`+
		`"cache":{"image":%q,"labels":{"dev.supermgmt.owner":"owner-1","dev.supermgmt.project":"sm-shop-prod"}}}}`,
		deployStageImage, deployStageSum("a$b"), deployStageSidecar)
	return compose.Frozen{
		Public:    []byte(deployStagePublic),
		Effective: json.RawMessage(effective),
		Images: []compose.ImageUse{
			{Service: "api", Ref: deployStageImage},
			{Service: "cache", Ref: deployStageSidecar},
			{Service: "worker", Ref: deployStageImage},
		},
		Secrets: []compose.SecretUse{{Service: "api", EnvName: "DATABASE_URL", Ref: "apps/shop/database_url", Version: 3}},
	}
}

func deployStageValues() []compose.ResolvedSecret {
	return []compose.ResolvedSecret{{Ref: "apps/shop/database_url", Version: 3, Value: audit.Secret(deployStageSecretValue)}}
}

// deployStageNodeOutput is what a faithful node prints for deployStageFrozen.
func deployStageNodeOutput(dir deployDir, secretHash string) []byte {
	return []byte(fmt.Sprintf(`{"model":{"name":"sm-shop-prod","services":{`+
		`"api":{"image":%q,"environment":{"GREETING":"sha256:%s","DATABASE_URL":"sha256:%s"},`+
		`"labels":{"dev.supermgmt.owner":"owner-1","dev.supermgmt.project":"sm-shop-prod","dev.supermgmt.deployment":%q}},`+
		`"cache":{"image":%q,"labels":{"dev.supermgmt.owner":"owner-1","dev.supermgmt.project":"sm-shop-prod","dev.supermgmt.deployment":%q}}}},`+
		`"set":[{"service":"api","env_name":"DATABASE_URL","sha256":%q},{"service":"api","env_name":"GREETING","sha256":%q}]}`,
		deployStageImage, deployStageSum("a$b"), secretHash, dir.Deployment.String(),
		deployStageSidecar, dir.Deployment.String(), secretHash, deployStageSum("a$b")))
}

func deployStageWantError(t *testing.T, err error, reason smerr.Reason) *smerr.Error {
	t.Helper()
	var got *smerr.Error
	if !errors.As(err, &got) || got.Reason != reason {
		t.Fatalf("error = %v; want reason %s", err, reason)
	}
	return got
}

func deployStageNoSecret(t *testing.T, what string, err error) {
	t.Helper()
	if err != nil && strings.Contains(err.Error(), deployStageSecretValue) {
		t.Errorf("%s leaks the secret value: %v", what, err)
	}
}

func TestDeployStage_VerifyAcceptsAFaithfulNode(t *testing.T) {
	dir := deployStageDir()
	exec := &deployStageExec{reply: deployStageReply(transport.Result{Stdout: deployStageNodeOutput(dir, deployStageSum(deployStageSecretValue))})}
	err := deployStage{exec: exec}.Verify(context.Background(), deployments.RecoveryForward, dir, deployStageFrozen(), deployStageValues())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if c := exec.commands[0]; c.Template != "compose.verify" || c.Mutating {
		t.Errorf("command = %+v; want the read-only compose.verify", c)
	}
}

func TestDeployStage_VerifyRejectsWhatTheNodeResolvedDifferently(t *testing.T) {
	dir := deployStageDir()
	good := deployStageNodeOutput(dir, deployStageSum(deployStageSecretValue))
	tampered := deployStageNodeOutput(dir, deployStageSum("another value"))
	cases := []struct {
		name  string
		out   []byte
		cause string
	}{
		{"changed secret value", tampered, deployments.CauseEnvHashMismatch},
		{"missing name", []byte(strings.Replace(string(good), `{"service":"api","env_name":"DATABASE_URL","sha256":"`+deployStageSum(deployStageSecretValue)+`"},`, "", 1)), deployments.CauseEnvHashMismatch},
		{"extra name", []byte(strings.Replace(string(good), `"set":[`, `"set":[{"service":"api","env_name":"EXTRA","sha256":"00"},`, 1)), deployments.CauseEnvHashMismatch},
		{"unresolved name", []byte(strings.Replace(string(good), `"sha256":"`+deployStageSum("a$b")+`"}]`, `"sha256":null}]`, 1)), deployments.CauseEnvHashMismatch},
		{"different image", []byte(strings.Replace(string(good), deployStageSidecar, strings.Replace(deployStageSidecar, "bbbb", "cccc", 1), 1)), deployments.CauseModelMismatch},
		{"missing deployment label", []byte(strings.Replace(string(good), `"dev.supermgmt.deployment":"`+dir.Deployment.String()+`"`, `"x":"y"`, 1)), deployments.CauseModelMismatch},
		{"extra service", []byte(strings.Replace(string(good), `"services":{`, `"services":{"rogue":{"image":"evil"},`, 1)), deployments.CauseModelMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			exec := &deployStageExec{reply: deployStageReply(transport.Result{Stdout: tc.out})}
			err := deployStage{exec: exec}.Verify(context.Background(), deployments.RecoveryForward, dir, deployStageFrozen(), deployStageValues())
			got := deployStageWantError(t, err, smerr.ReasonStagingFailed)
			if got.Details["cause"] != tc.cause {
				t.Errorf("cause = %v; want %s", got.Details["cause"], tc.cause)
			}
			deployStageNoSecret(t, "verify error", err)
		})
	}
}

func TestDeployStage_VerifyRefusesUnusableNodeOutput(t *testing.T) {
	dir := deployStageDir()
	for name, res := range map[string]transport.Result{
		"exit status": {ExitStatus: 1, Stdout: []byte("compose.verify: failed")},
		"truncated":   {Stdout: deployStageNodeOutput(dir, deployStageSum(deployStageSecretValue)), Truncated: true},
		"not json":    {Stdout: []byte("hello")},
		"no model":    {Stdout: []byte(`{"set":[]}`)},
	} {
		t.Run(name, func(t *testing.T) {
			exec := &deployStageExec{reply: deployStageReply(res)}
			err := deployStage{exec: exec}.Verify(context.Background(), deployments.RecoveryForward, dir, deployStageFrozen(), deployStageValues())
			_ = deployStageWantError(t, err, smerr.ReasonStagingFailed)
		})
	}
}

func TestDeployStage_VerifyListsAtMostTenDifferences(t *testing.T) {
	dir := deployStageDir()
	var rows []string
	for i := range 40 {
		rows = append(rows, fmt.Sprintf(`{"service":"api","env_name":"X%d","sha256":"00"}`, i))
	}
	out := strings.Replace(string(deployStageNodeOutput(dir, deployStageSum(deployStageSecretValue))), `"set":[`, `"set":[`+strings.Join(rows, ",")+",", 1)
	exec := &deployStageExec{reply: deployStageReply(transport.Result{Stdout: []byte(out)})}
	err := deployStage{exec: exec}.Verify(context.Background(), deployments.RecoveryForward, dir, deployStageFrozen(), deployStageValues())
	diffs, _ := deployStageWantError(t, err, smerr.ReasonStagingFailed).Details["diffs"].([]string)
	if len(diffs) != maxReportedDiffs+1 {
		t.Errorf("reported %d entries; want %d plus the overflow note", len(diffs), maxReportedDiffs)
	}
}

func TestDeployStage_StagingNeverTouchesRunningServices(t *testing.T) {
	dir := deployStageDir()
	exec := &deployStageExec{reply: deployStageReply(transport.Result{ExitStatus: 1})}
	stage := deployStage{exec: exec}
	_ = stage.Verify(context.Background(), deployments.RecoveryForward, dir, deployStageFrozen(), deployStageValues())
	for _, c := range exec.commands {
		switch c.Template {
		case "compose.pull", "compose.materialize", "compose.verify":
		default:
			t.Errorf("staging ran %s", c.Template)
		}
		if strings.Contains(c.Line, " up ") || strings.Contains(c.Line, " down ") {
			t.Errorf("staging command can change a service: %s", c.Line)
		}
	}
}

func TestDeployStage_ForwardStepsRefuseUnderSafetyRecovery(t *testing.T) {
	dir := deployStageDir()
	ctx, mode := context.Background(), deployments.RecoverySafetyRecovery
	exec := &deployStageExec{}
	stage := deployStage{exec: exec}
	steps := map[string]error{
		deployments.StepVerifyOnNode: stage.Verify(ctx, mode, dir, deployStageFrozen(), deployStageValues()),
	}
	for step, err := range steps {
		_ = deployStageWantError(t, err, smerr.ReasonInvalidTransition)
		if !strings.Contains(err.Error(), step) {
			t.Errorf("error %q does not name step %s", err, step)
		}
	}
	if len(exec.commands) != 0 {
		t.Errorf("%d node commands ran under safety recovery", len(exec.commands))
	}
}

func TestDeployHandler_ForwardStepsRefuseUnderSafetyRecoveryBeforeTouchingTheNode(t *testing.T) {
	j := &deployJob{mode: deployments.RecoverySafetyRecovery}
	h := deployHandler{}
	steps := map[string]func(deployments.Step) error{
		deployments.StepPull:        func(s deployments.Step) error { return h.pull(context.Background(), j, frozenDeployment{}, s) },
		deployments.StepMaterialize: func(s deployments.Step) error { return h.materialize(context.Background(), j, frozenDeployment{}, s) },
		deployments.StepDeploy:      func(s deployments.Step) error { return h.deploy(context.Background(), j, s) },
	}
	for name, run := range steps {
		err := run(deployments.Step{Name: name})
		_ = deployStageWantError(t, err, smerr.ReasonInvalidTransition)
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error %q does not name step %s", err, name)
		}
	}
}
