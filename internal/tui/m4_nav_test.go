package tui

import (
	"strings"
	"testing"
)

func TestM4NavigationReachesAppsDeploymentsAndDetail(t *testing.T) {
	h := newHarness(t, newTimelineAPI(), 80, 24)
	h.start()

	h.press("8")
	if got := h.view(); !strings.Contains(got, "Applications") || !strings.Contains(got, "shop") {
		t.Fatalf("key 8 should show the Applications list:\n%s", got)
	}

	h.press("9")
	if got := h.view(); !strings.Contains(got, "Deployments") || !strings.Contains(got, "shop / production") {
		t.Fatalf("key 9 should show the Deployments list with app labels:\n%s", got)
	}

	h.press("j", "enter")
	if got := h.view(); !strings.Contains(got, "SuperMgmt · Deployment") || !strings.Contains(got, "STEPS") {
		t.Fatalf("enter should open the deployment detail:\n%s", got)
	}

	h.press("esc")
	if got := h.view(); !strings.Contains(got, "DEPLOYMENTS") {
		t.Fatalf("esc should return to the Deployments list:\n%s", got)
	}
}

func TestM4ScreensWithoutAppsAPISayTheDaemonDoesNotServeThem(t *testing.T) {
	h := newHarness(t, newFake(), 80, 24)
	h.start()
	h.press("8")
	if got := h.view(); !strings.Contains(got, unavailableApps) {
		t.Fatalf("Applications should say the daemon does not serve apps:\n%s", got)
	}
}

func TestM4ScreenGoldens(t *testing.T) {
	for _, tc := range []struct {
		name string
		keys []string
	}{
		{"m4_nav_apps_80x24", []string{"8"}},
		{"m4_nav_deployments_80x24", []string{"9"}},
		{"m4_nav_deployment_80x24", []string{"9", "j", "enter"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, newTimelineAPI(), 80, 24)
			h.start()
			h.press(tc.keys...)
			assertGolden(t, tc.name, h.view(), 80, 24)
		})
	}
}
