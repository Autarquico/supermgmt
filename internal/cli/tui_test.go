package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func TestBareCommandOutsideATerminalPrintsHelp(t *testing.T) {
	var out bytes.Buffer
	root := &cobra.Command{Use: "sm", Short: "SuperMgmt", RunE: runBareTUI(nil)}
	root.SetIn(strings.NewReader(""))
	root.SetOut(&out)
	root.SetArgs(nil)
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Usage:") {
		t.Errorf("output = %q, want the help text", out.String())
	}
}

func TestTUICommandRefusesANonInteractiveTerminal(t *testing.T) {
	cmd := newTUICmd(nil)
	cmd.SetIn(strings.NewReader(""))
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs(nil)
	err := cmd.Execute()
	if smerr.CodeOf(err) != smerr.CodeInvalidArgument {
		t.Errorf("err = %v, want INVALID_ARGUMENT", err)
	}
}

func TestTUIAuthFlagIsValidatedBeforeTheTerminalCheck(t *testing.T) {
	tests := []struct {
		name string
		env  []string
		args []string
		want string
	}{
		{"unknown value", nil, []string{"--auth", "bogus"}, "--auth must be subscription or api-key"},
		{"api-key without the key", []string{"PATH=/bin"}, []string{"--auth", "api-key"}, "ANTHROPIC_API_KEY"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd := newTUICmd(tc.env)
			cmd.SetIn(strings.NewReader(""))
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetArgs(tc.args)
			err := cmd.Execute()
			if smerr.CodeOf(err) != smerr.CodeInvalidArgument || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want INVALID_ARGUMENT mentioning %q", err, tc.want)
			}
		})
	}
}

func TestTUIAuthFlagAcceptsBothModesAndThenNeedsATerminal(t *testing.T) {
	for _, mode := range []string{"subscription", "api-key"} {
		cmd := newTUICmd([]string{"ANTHROPIC_API_KEY=sk-test"})
		cmd.SetIn(strings.NewReader(""))
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetArgs([]string{"--auth", mode})
		err := cmd.Execute()
		if smerr.CodeOf(err) != smerr.CodeInvalidArgument || err == nil || !strings.Contains(err.Error(), "interactive terminal") {
			t.Errorf("--auth %s: err = %v, want the terminal refusal", mode, err)
		}
	}
}

func TestIsTerminal(t *testing.T) {
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = null.Close() }()
	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pipeR.Close(); _ = pipeW.Close() }()

	tests := []struct {
		name   string
		stream any
		want   bool
	}{
		{"buffer", &bytes.Buffer{}, false},
		{"/dev/null", null, false},
		{"pipe", pipeR, false},
	}
	for _, tc := range tests {
		if got := isTerminal(tc.stream); got != tc.want {
			t.Errorf("%s: isTerminal = %v, want %v", tc.name, got, tc.want)
		}
	}
}
