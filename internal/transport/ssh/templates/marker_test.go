package templates

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// runMarkerState renders marker.state and runs it under /bin/sh against dir
// instead of the production markers directory.
func runMarkerState(t *testing.T, dir, marker string) (MarkerState, error) {
	t.Helper()
	cmd, err := Render("marker.state", map[string]string{"marker": marker})
	if err != nil {
		return MarkerState{}, err
	}
	line := strings.ReplaceAll(cmd.Line, MarkerDir, dir)
	out, err := exec.CommandContext(context.Background(), "/bin/sh", "-c", line).Output()
	if err != nil {
		t.Fatalf("marker.state failed: %v", err)
	}
	return ParseMarkerState(out)
}

func TestMarkerStateReportsEachStage(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("started", "")
	write("ok", "")
	write("ok.done", "0\n")
	write("failed", "")
	write("failed.done", "3\n")
	write("garbled", "")
	write("garbled.done", "banana\n")

	tests := []struct {
		marker string
		want   MarkerState
		proof  bool
		parse  bool
	}{
		{"never", MarkerState{Kind: MarkerAbsent}, false, true},
		{"started", MarkerState{Kind: MarkerStarted}, false, true},
		{"ok", MarkerState{Kind: MarkerDone}, true, true},
		{"failed", MarkerState{Kind: MarkerDone, ExitStatus: 3}, false, true},
		{"garbled", MarkerState{}, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.marker, func(t *testing.T) {
			got, err := runMarkerState(t, dir, tt.marker)
			if (err == nil) != tt.parse {
				t.Fatalf("err = %v, want parse ok = %v", err, tt.parse)
			}
			if got != tt.want || got.CompletionProof() != tt.proof {
				t.Errorf("got %+v proof=%v, want %+v proof=%v", got, got.CompletionProof(), tt.want, tt.proof)
			}
		})
	}
}

// TestMissingMarkersDirectoryIsNeverReportedAbsent: absent is the evidence
// that a command never started, so an unreadable directory must not say it.
func TestMissingMarkersDirectoryIsNeverReportedAbsent(t *testing.T) {
	got, err := runMarkerState(t, filepath.Join(t.TempDir(), "missing"), "m1")
	if err != nil || got.Kind != MarkerUnavailable {
		t.Errorf("missing dir: %+v, %v", got, err)
	}
}

func TestUnsearchableMarkersDirectoryIsUnavailable(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root ignores directory modes")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	got, err := runMarkerState(t, dir, "m1")
	if err != nil || got.Kind != MarkerUnavailable {
		t.Errorf("unsearchable dir: %+v, %v", got, err)
	}
}

func TestMarkerStateRejectsHostileMarkerNames(t *testing.T) {
	for _, marker := range []string{"", "../x", "a/b", "-rf", "A", "a b", "a;id", "$(id)", "a'b", "x\n", strings.Repeat("a", 65)} {
		if _, err := Render("marker.state", map[string]string{"marker": marker}); smerr.CodeOf(err) != smerr.CodeInvalidArgument {
			t.Errorf("marker %q: err = %v, want INVALID_ARGUMENT", marker, err)
		}
	}
}

func TestParseMarkerStateIsStrict(t *testing.T) {
	for _, bad := range []string{"", "Absent", "absent extra", "done", "done ", "done -1", "done 256", "done 01", "done 1 2", "done 0x1", " absent", "started\nabsent"} {
		if got, err := ParseMarkerState([]byte(bad + "\n")); err == nil {
			t.Errorf("%q parsed as %+v", bad, got)
		}
	}
}

func FuzzParseMarkerState(f *testing.F) {
	for _, seed := range []string{"absent\n", "done 0\n", "done 255\n", "started", "", "done -0"} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		got, err := ParseMarkerState(in)
		if err != nil {
			return
		}
		canonical := string(got.Kind)
		if got.Kind == MarkerDone {
			canonical += " " + strconv.Itoa(got.ExitStatus)
		}
		if strings.TrimSuffix(string(in), "\n") != canonical {
			t.Errorf("%q parsed as %+v", in, got)
		}
	})
}

// FuzzMarkerStateRendering: any marker the validator accepts must be a plain
// token, and the rendered command must run without touching anything outside dir.
func FuzzMarkerStateRendering(f *testing.F) {
	for _, seed := range []string{"m1", "a-b-1", "';touch pwned;'", "$(touch pwned)", "../../pwned", "a\x00b", "`touch pwned`"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, marker string) {
		cmd, err := Render("marker.state", map[string]string{"marker": marker})
		if err != nil {
			return
		}
		if !markerPattern.MatchString(marker) {
			t.Fatalf("accepted %q", marker)
		}
		dir := t.TempDir()
		line := strings.ReplaceAll(cmd.Line, MarkerDir, dir)
		c := exec.CommandContext(context.Background(), "/bin/sh", "-c", line)
		c.Dir = t.TempDir()
		if err := c.Run(); err != nil {
			t.Fatalf("run: %v", err)
		}
		entries, _ := os.ReadDir(c.Dir)
		if len(entries) != 0 {
			t.Errorf("command created files: %v", entries)
		}
	})
}
