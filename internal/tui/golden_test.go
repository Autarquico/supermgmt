package tui

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden views in testdata")

// selectNode moves the Resources cursor to the named node.
func (h *harness) selectNode(name string) {
	h.t.Helper()
	for range h.m.nodes {
		if n, ok := h.m.selectedNode(); ok && n.Name == name {
			return
		}
		h.press("j")
	}
	h.t.Fatalf("node %q not in the list", name)
}

func (h *harness) openServicesOfWeb() {
	h.t.Helper()
	h.press("2")
	h.selectNode("web-1")
	h.press("v")
}

func (h *harness) openAPIService() {
	h.t.Helper()
	h.openServicesOfWeb()
	h.press("enter")
}

func TestGoldenViews(t *testing.T) {
	screens := []struct {
		name string
		w, h int
		to   func(*harness)
	}{
		{"dashboard_80x24", 80, 24, func(*harness) {}},
		{"dashboard_120x30", 120, 30, func(*harness) {}},
		{"resources_80x24", 80, 24, func(h *harness) { h.press("2") }},
		{"resources_120x30", 120, 30, func(h *harness) { h.press("2"); h.selectNode("web-1") }},
		{"resources_narrow_60x20", 60, 20, func(h *harness) { h.press("2") }},
		{"node_80x24", 80, 24, func(h *harness) { h.press("2"); h.selectNode("web-1"); h.press("enter") }},
		{"services_80x24", 80, 24, (*harness).openServicesOfWeb},
		{"service_80x24", 80, 24, (*harness).openAPIService},
		{"logs_80x24", 80, 24, func(h *harness) { h.openAPIService(); h.press("l") }},
		{"jobs_80x24", 80, 24, func(h *harness) { h.press("3") }},
		{"job_80x24", 80, 24, func(h *harness) { h.press("3", "enter") }},
		{"approvals_120x30", 120, 30, func(h *harness) { h.press("4") }},
		{"approvals_narrow_60x20", 60, 20, func(h *harness) { h.press("4") }},
		{"events_80x24", 80, 24, func(h *harness) { h.press("5") }},
		{"help_80x24", 80, 24, func(h *harness) { h.press("?") }},
		{"palette_80x24", 80, 24, func(h *harness) { h.press("/"); h.typeText("ssh web") }},
		{"confirm_restart_80x24", 80, 24, func(h *harness) { h.openAPIService(); h.press("R") }},
		{"too_small_30x8", 30, 8, func(*harness) {}},
	}
	for _, tc := range screens {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, newFake(), tc.w, tc.h)
			h.start()
			tc.to(h)
			assertGolden(t, tc.name, h.view(), tc.w, tc.h)
		})
	}
}

func assertGolden(t *testing.T, name, got string, w, h int) {
	t.Helper()
	if w >= minWidth && h >= minHeight {
		lines := strings.Split(got, "\n")
		if len(lines) != h {
			t.Errorf("view has %d rows, want %d", len(lines), h)
		}
		for i, l := range lines {
			if n := len([]rune(l)); n != w {
				t.Errorf("row %d is %d cells wide, want %d: %q", i, n, w, l)
			}
		}
	}
	path := filepath.Join("testdata", name+".golden")
	if *update {
		if err := os.MkdirAll("testdata", 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/tui -update)", err)
	}
	if strings.TrimSuffix(string(want), "\n") != got {
		t.Errorf("view differs from %s (run with -update to accept):\n--- got ---\n%s\n--- want ---\n%s", path, got, want)
	}
}
