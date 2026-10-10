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
