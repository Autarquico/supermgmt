//go:build fixtures

package integration

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/autarquico/supermgmt/internal/runtimes/systemd"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
	"github.com/autarquico/supermgmt/test/fixtures/fixture"
)

// interruptAt fails every command from the first one rendered from template on,
// as if the executor's process had been killed at that point.
type interruptAt struct {
	inner    transport.Executor
	template string
	cut      bool
}

func (i *interruptAt) Run(ctx context.Context, c templates.Command) (transport.Result, error) {
	if c.Template == i.template {
		i.cut = true
	}
	if i.cut {
		return transport.Result{}, fmt.Errorf("process killed before %s: %w", c.Template, context.Canceled)
	}
	return i.inner.Run(ctx, c)
}

// TestFixturesSetup_InterruptedRunConvergesOnRerun is the Setup-step variant of
// "kill mid-setup -> requeue converges"; the job-level variant needs the T5
// handler (see Followups).
func TestFixturesSetup_InterruptedRunConvergesOnRerun(t *testing.T) {
	cuts := []struct{ name, before string }{
		{"after the user exists, before the directories", "setup.dir"},
		{"with authorized_keys staged but not committed", "setup.file_commit"},
		{"with the sudoers drop-in staged but not checked or committed", "setup.sudoers_check"},
	}
	for _, cut := range cuts {
		t.Run(cut.name, func(t *testing.T) {
			n := startNode(t, fixture.Options{})
			id := newIdentity(t)
			useAgent(t, n.ClientSigner)
			h := newHarness(t, defaultPoolConfig(), id)
			admin := h.pool.For(n.target(fixture.AdminUser))
			p := setupParams(id, nil)

			killed := &interruptAt{inner: admin, template: cut.before + templates.SudoVariantSuffix}
			_, err := systemd.Setup(t.Context(), killed, p)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("interrupted setup = %v; want the injected kill", err)
			}
			assertNoPartialFiles(t, n)

			out, err := systemd.Setup(t.Context(), admin, p)
			if err != nil {
				t.Fatalf("re-run after the interruption: %v", err)
			}
			if err := systemd.Verify(t.Context(), h.pool.For(n.superTarget()), verifyParams(p, out)); err != nil {
				t.Fatalf("verify after the re-run: %v", err)
			}
			if leftovers := n.shell(t, "ls /etc/sudoers.d /etc/tmpfiles.d /var/lib/supermgmt/.ssh | grep -F .new || true"); leftovers != "" {
				t.Errorf("staging files left behind after the re-run: %q", leftovers)
			}
			converged := n.stateSnapshot(t)
			if _, err := systemd.Setup(t.Context(), admin, p); err != nil {
				t.Fatalf("third run: %v", err)
			}
			if again := n.stateSnapshot(t); again != converged {
				t.Errorf("the converged state is not stable:\n%s\n--\n%s", converged, again)
			}
		})
	}
}

// assertNoPartialFiles checks that an interruption leaves each managed file
// absent or complete, never half-written, and that sudo still parses.
func assertNoPartialFiles(t *testing.T, n *fixtureNode) {
	t.Helper()
	n.shell(t, "visudo -c")
	if _, err := n.tryShell(t, "test -e /etc/sudoers.d/supermgmt"); err == nil {
		if got := n.shell(t, "grep -c '^supermgmt ALL=(root) NOPASSWD: ' /etc/sudoers.d/supermgmt"); got != "3" {
			t.Errorf("sudoers drop-in has %s grant lines; want all 3 or no file", got)
		}
	}
	if _, err := n.tryShell(t, "test -e /var/lib/supermgmt/.ssh/authorized_keys"); err == nil {
		if got := n.shell(t, "grep -c '^restrict ' /var/lib/supermgmt/.ssh/authorized_keys"); got != "1" {
			t.Errorf("authorized_keys has %s restricted lines; want 1 or no file", got)
		}
	}
}
