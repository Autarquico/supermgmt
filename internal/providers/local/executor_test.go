package local

import (
	"context"
	"strings"
	"testing"
	"time"

	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

func run(t *testing.T, e Executor, c templates.Command) (string, error) {
	t.Helper()
	res, err := e.Run(context.Background(), c)
	return string(res.Stdout), err
}

func TestRunReturnsOutputAndExitStatusWithoutError(t *testing.T) {
	res, err := Executor{}.Run(context.Background(), templates.Command{Line: "echo out; echo err >&2; exit 3", MaxBytes: 1024})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if string(res.Stdout) != "out\n" || string(res.Stderr) != "err\n" || res.ExitStatus != 3 {
		t.Errorf("result = %q %q exit %d", res.Stdout, res.Stderr, res.ExitStatus)
	}
}

func TestRunRefusesMutatingCommands(t *testing.T) {
	_, err := Executor{}.Run(context.Background(), templates.Command{Line: "true", Mutating: true, MaxBytes: 16})

	if smerr.CodeOf(err) != smerr.CodeCapabilityUnavailable {
		t.Errorf("error = %v, want CAPABILITY_UNAVAILABLE", err)
	}
}

func TestRunCapsOutputAndSaysSo(t *testing.T) {
	res, err := Executor{}.Run(context.Background(), templates.Command{Line: "yes | head -n 100000", MaxBytes: 64, MaxLines: 5})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Truncated || strings.Count(string(res.Stdout), "\n") > 5 || len(res.Stdout) > 64 {
		t.Errorf("truncated=%v lines=%d bytes=%d", res.Truncated, strings.Count(string(res.Stdout), "\n"), len(res.Stdout))
	}
}

func TestRunSanitizesTerminalEscapes(t *testing.T) {
	out, err := run(t, Executor{}, templates.Command{Line: `printf '\033[31mred\033[0m\n'`, MaxBytes: 64})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out != "red\n" {
		t.Errorf("stdout = %q, want escapes removed", out)
	}
}

func TestRunEnforcesTheCommandDeadline(t *testing.T) {
	_, err := Executor{}.Run(context.Background(), templates.Command{Line: "sleep 30", MaxBytes: 16, Deadline: 100 * time.Millisecond})

	if smerr.CodeOf(err) != smerr.CodeTimeout {
		t.Errorf("error = %v, want TIMEOUT", err)
	}
}

func TestRunStopsOnContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := Executor{}.Run(ctx, templates.Command{Line: "sleep 30", MaxBytes: 16})

	if err == nil {
		t.Fatal("want an error for a cancelled context")
	}
}

func TestRunPassesStdinThrough(t *testing.T) {
	out, err := run(t, Executor{}, templates.Command{Line: "cat", Stdin: []byte("hello"), MaxBytes: 64})
	if err != nil || out != "hello" {
		t.Errorf("stdout = %q, err = %v", out, err)
	}
}

func TestTheProbeTemplateRunsLocally(t *testing.T) {
	c, err := templates.Render("probe", map[string]string{})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	res, err := Executor{}.Run(context.Background(), c)

	if err != nil || res.ExitStatus != 0 {
		t.Fatalf("probe: exit %d, err %v", res.ExitStatus, err)
	}
	if !strings.HasPrefix(string(res.Stdout), "@@probe 1") {
		t.Errorf("probe output starts %q", string(res.Stdout)[:min(20, len(res.Stdout))])
	}
}
