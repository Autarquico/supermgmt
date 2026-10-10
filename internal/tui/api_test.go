package tui

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
)

// handoffDone carries the outcome of a handoff back into the program.
type handoffDone struct{ err error }

// handoffModel starts one handoff and quits when it returns.
type handoffModel struct{ handoff Handoff }

func (m handoffModel) Init() tea.Cmd {
	return tea.ExecProcess(m.handoff.Cmd, func(err error) tea.Msg { return handoffDone{err} })
}

func (m handoffModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if done, ok := msg.(handoffDone); ok {
		m.handoff.Done(exitCode(done.err))
		return m, tea.Quit
	}
	return m, nil
}

func (handoffModel) View() tea.View { return tea.NewView("") }

// exitCode maps the ExecProcess callback error to Handoff.Done's arguments.
func exitCode(err error) (int, error) {
	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0, nil
	case errors.As(err, &exit):
		return exit.ExitCode(), nil
	}
	return -1, err
}

// TestHandoffRunsThroughExecProcess pins the integration the TUI relies on:
// a Handoff's Cmd runs via tea.ExecProcess(*exec.Cmd, func(error) tea.Msg),
// and Done sees the child's exit code or its launch failure.
func TestHandoffRunsThroughExecProcess(t *testing.T) {
	tests := []struct {
		name          string
		cmd           *exec.Cmd
		wantCode      int
		wantLaunchErr bool
	}{
		{"exit 0", exec.CommandContext(context.Background(), "/bin/sh", "-c", "exit 0"), 0, false},
		{"exit 3", exec.CommandContext(context.Background(), "/bin/sh", "-c", "exit 3"), 3, false},
		{"missing executable", exec.CommandContext(context.Background(), "/nonexistent/sm-test-tool"), -1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			var gotCode int
			var gotErr error
			h := Handoff{Cmd: tt.cmd, Done: func(code int, launchErr error) {
				calls++
				gotCode, gotErr = code, launchErr
			}}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			p := tea.NewProgram(handoffModel{h},
				tea.WithContext(ctx), tea.WithInput(bytes.NewReader(nil)), tea.WithOutput(io.Discard),
				tea.WithoutRenderer(), tea.WithoutSignals())
			if _, err := p.Run(); err != nil {
				t.Fatal(err)
			}
			if calls != 1 || gotCode != tt.wantCode || (gotErr != nil) != tt.wantLaunchErr {
				t.Errorf("Done called %d times with (%d, %v), want once with (%d, launch error %v)",
					calls, gotCode, gotErr, tt.wantCode, tt.wantLaunchErr)
			}
		})
	}
}
