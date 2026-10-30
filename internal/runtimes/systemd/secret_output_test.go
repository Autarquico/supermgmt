package systemd

import (
	"context"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

var tokenAddArgs = map[string]string{"user": "sm-ab12cd34@pve", "id": "sm", "comment": "supermgmt install ab12cd34"}

func TestAFailedSecretOutputStepNeverQuotesTheNode(t *testing.T) {
	node := newFakeNode(t).on(templates.PVETokenAddStep, func(c templates.Command) transport.Result {
		if !c.SecretOutput {
			t.Error("the command lost SecretOutput")
		}
		return transport.Result{ExitStatus: 1, Stdout: []byte("SECRET-OUT"), Stderr: []byte("SECRET-ERR")}
	})
	err := stepper{ex: node}.do(context.Background(), templates.PVETokenAddStep, tokenAddArgs, nil)
	if err == nil || strings.Contains(err.Error(), "SECRET") || !strings.Contains(err.Error(), "output withheld") {
		t.Errorf("err = %v", err)
	}
}

func TestAFailedOrdinaryStepStillReportsTheNodesFirstLine(t *testing.T) {
	node := newFakeNode(t).on(templates.PVETokenRemoveStep, func(templates.Command) transport.Result {
		return transport.Result{ExitStatus: 2, Stderr: []byte("no such user\nsecond")}
	})
	err := stepper{ex: node}.do(context.Background(), templates.PVETokenRemoveStep, map[string]string{"user": "sm-ab12cd34@pve", "id": "sm"}, nil)
	if err == nil || !strings.Contains(err.Error(), "no such user") {
		t.Errorf("err = %v", err)
	}
}

func TestASecretOutputStepReturnsItsStdoutOnSuccess(t *testing.T) {
	node := newFakeNode(t).reply(templates.PVETokenAddStep+templates.SudoVariantSuffix, `{"value":"x"}`)
	res, err := stepper{ex: node, sudo: true}.run(context.Background(), templates.PVETokenAddStep, tokenAddArgs, nil)
	if err != nil || string(res.Stdout) != `{"value":"x"}` {
		t.Errorf("res = %+v, err = %v", res, err)
	}
	if node.calls[0].Template != templates.PVETokenAddStep+templates.SudoVariantSuffix || !node.calls[0].SecretOutput {
		t.Errorf("call = %+v", node.calls[0])
	}
}
