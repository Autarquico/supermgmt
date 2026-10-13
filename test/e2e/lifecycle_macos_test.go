//go:build e2e && hostlifecycle

package e2e_test

import (
	"runtime"
	"testing"

	"github.com/autarquico/supermgmt/test/e2e/harness"
)

// Spec docs/specs/m6-hardening.md and ADR-0036: the macOS half of the host lifecycle. It runs on a
// GitHub-hosted macOS runner (the guard refuses anything else); the flow is lifeResidentLifecycle
// with launchd as the user service manager: the held upgrade is a disabled launchd label.

// TestLifecycleMacOS_LocalClient
//
// Given a macOS host with no installation.
// Then: the resident daemon (launchd agent) goes through install, held upgrade, backup, restore,
// uninstall and purge with its identity intact, and a client installed beside it logs in to a server.
func TestLifecycleMacOS_LocalClient(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS only; the Linux twin is TestLifecycleVM_LocalClient")
	}
	harness.RequireHostLifecycle(t)
	lifeResidentLifecycle(t)
}
