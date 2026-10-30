package join

import (
	"context"
	"strings"
	"testing"
	"time"

	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

func TestRootExecutorRunsALineAndReportsItsExitStatus(t *testing.T) {
	res, err := rootExecutor{}.Run(context.Background(), templates.Command{Line: "cat; echo err >&2; exit 3", Stdin: []byte("in")})

	if err != nil || res.ExitStatus != 3 || string(res.Stdout) != "in" || strings.TrimSpace(string(res.Stderr)) != "err" {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
}

func TestRootExecutorWithholdsSecretOutput(t *testing.T) {
	res, err := rootExecutor{}.Run(context.Background(), templates.Command{Line: "echo secret; echo secret >&2; exit 1", SecretOutput: true})

	if err != nil || len(res.Stdout) != 0 || len(res.Stderr) != 0 {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
}

func TestRootExecutorBoundsItsOutput(t *testing.T) {
	res, err := rootExecutor{}.Run(context.Background(), templates.Command{Line: "yes | head -c 100000", MaxBytes: 100})

	if err != nil || !res.Truncated || len(res.Stdout) != 100 {
		t.Fatalf("truncated=%v len=%d err=%v", res.Truncated, len(res.Stdout), err)
	}
}

func TestRootExecutorStopsAtTheDeadline(t *testing.T) {
	_, err := rootExecutor{}.Run(context.Background(), templates.Command{Line: "sleep 5", Deadline: 100 * time.Millisecond})

	if smerr.CodeOf(err) != smerr.CodeTimeout {
		t.Fatalf("err = %v", err)
	}
}
