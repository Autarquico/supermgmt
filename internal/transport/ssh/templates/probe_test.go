package templates

import (
	"context"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// TestProbeRunsAndEmitsEverySectionInOrder executes the real probe under
// /bin/sh on the test host: whatever the host lacks, the format holds.
func TestProbeRunsAndEmitsEverySectionInOrder(t *testing.T) {
	cmd, err := Render("probe", map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.CommandContext(context.Background(), "/bin/sh", "-c", cmd.Line).Output()
	if err != nil {
		t.Fatalf("probe failed: %v", err)
	}
	var headers []string
	for _, line := range strings.Split(string(out), "\n") {
		if name, ok := strings.CutPrefix(line, "@@"); ok {
			headers = append(headers, name)
		}
	}
	want := append([]string{"probe 1"}, ProbeSections...)
	if !slices.Equal(headers, want) {
		t.Errorf("headers = %v\nwant     %v", headers, want)
	}
	if len(out) > cmd.MaxBytes {
		t.Errorf("output %d bytes exceeds MaxBytes %d", len(out), cmd.MaxBytes)
	}
}

func TestProbeIsReadOnlyAndTakesNoArguments(t *testing.T) {
	if _, err := Render("probe", map[string]string{"x": "y"}); err == nil {
		t.Error("probe accepted an argument")
	}
	if _, err := RenderMutating("probe", "m1", nil); err == nil {
		t.Error("probe rendered as mutating")
	}
	cmd, _ := Render("probe", nil)
	if cmd.Mutating || len(cmd.Stdin) != 0 {
		t.Errorf("probe command = %+v", cmd)
	}
}

func TestProbeDoesNotDependOnTheLoginShell(t *testing.T) {
	cmd, _ := Render("probe", nil)
	if !strings.HasPrefix(cmd.Line, "sh -c ") {
		t.Errorf("line starts %q", cmd.Line[:20])
	}
}
