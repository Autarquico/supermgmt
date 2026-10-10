//go:build fixtures

package integration

import (
	"testing"

	"github.com/autarquico/supermgmt/internal/runtimes/systemd"
)

// R2 N2: the sudo variants of the as-user steps need only root rights.
func TestFixturesR1_SetupWorksForAnAdminWhoMayOnlyRunAsRoot(t *testing.T) {
	n, admin, id := bareNode(t)
	n.shell(t, "printf 'admin ALL=(root) NOPASSWD: ALL\\n' > /etc/sudoers.d/admin && visudo -c")

	p := setupParams(id, nil)
	out, err := systemd.Setup(t.Context(), admin, p)
	if err != nil {
		t.Fatalf("setup with a root-only NOPASSWD admin: %v", err)
	}
	h := newHarness(t, defaultPoolConfig(), id)
	if err := systemd.Verify(t.Context(), h.pool.For(n.superTarget()), verifyParams(p, out)); err != nil {
		t.Errorf("verify: %v", err)
	}
	if got := n.shell(t, "stat -c '%U:%G %a' /var/lib/supermgmt/.ssh /var/lib/supermgmt/.ssh/authorized_keys"); got != "supermgmt:supermgmt 700\nsupermgmt:supermgmt 600" {
		t.Errorf("modes = %q", got)
	}
}
