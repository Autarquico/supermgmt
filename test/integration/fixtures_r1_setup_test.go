//go:build fixtures

package integration

import (
	"context"
	"errors"
	"strings"
	"testing"

	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/runtimes/systemd"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
	"github.com/autarquico/supermgmt/test/fixtures/fixture"
)

// bareNode starts a fixture node and returns it with an admin executor and the
// identity, without running setup.
func bareNode(t *testing.T) (*fixtureNode, transport.Executor, identity) {
	t.Helper()
	n := startNode(t, fixture.Options{})
	id := newIdentity(t)
	useAgent(t, n.ClientSigner)
	h := newHarness(t, defaultPoolConfig(), id)
	return n, h.pool.For(n.target(fixture.AdminUser)), id
}

// R1 T1: the service user controls everything below its home, so setup must
// never let root follow a symlink planted there.
func TestFixturesR1_SetupDoesNotFollowSymlinksPlantedByTheServiceUser(t *testing.T) {
	plants := map[string]string{
		"ssh directory pointing at /etc":     "rm -rf /var/lib/supermgmt/.ssh && ln -s /etc /var/lib/supermgmt/.ssh",
		"markers directory pointing at /etc": "rm -rf /var/lib/supermgmt/markers && ln -s /etc /var/lib/supermgmt/markers",
	}
	for name, plant := range plants {
		t.Run(name, func(t *testing.T) {
			p := provision(t, fixture.Options{}, nil)
			before := p.shell(t, "stat -c '%U:%G %a' /etc; ls -A /etc | sha256sum")
			p.shell(t, plant)

			_, err := systemd.Setup(t.Context(), p.admin, p.params)
			if err == nil {
				t.Fatal("setup followed a symlink planted by the service user")
			}
			if after := p.shell(t, "stat -c '%U:%G %a' /etc; ls -A /etc | sha256sum"); after != before {
				t.Errorf("/etc was changed through the symlink:\nbefore %s\nafter  %s", before, after)
			}
		})
	}
}

func TestFixturesR1_SetupReplacesPlantedFileSymlinksWithoutWritingThroughThem(t *testing.T) {
	p := provision(t, fixture.Options{}, nil)
	p.shell(t, "echo keep > /etc/r1-victim && "+
		"rm -f /var/lib/supermgmt/.ssh/authorized_keys && ln -s /etc/r1-victim /var/lib/supermgmt/.ssh/authorized_keys && "+
		"ln -s /etc/r1-victim /var/lib/supermgmt/.ssh/authorized_keys.new && chown -h supermgmt:supermgmt /var/lib/supermgmt/.ssh/authorized_keys*")

	if _, err := systemd.Setup(t.Context(), p.admin, p.params); err != nil {
		t.Fatalf("setup with planted file symlinks: %v", err)
	}
	if got := p.shell(t, "cat /etc/r1-victim; stat -c '%U %a' /etc/r1-victim"); got != "keep\nroot 644" {
		t.Errorf("the symlink target was written through: %q", got)
	}
	if got := p.shell(t, "test -L /var/lib/supermgmt/.ssh/authorized_keys && echo link || cat /var/lib/supermgmt/.ssh/authorized_keys"); !strings.HasPrefix(got, "restrict ") {
		t.Errorf("authorized_keys = %q; want the restricted key line", got)
	}
}

// R1 T2: the sudo-granted systemctl must be root-owned along its whole path.
func TestFixturesR1_SetupRefusesAServiceWritableSystemctl(t *testing.T) {
	n, admin, id := bareNode(t)
	n.shell(t, "install -d -m 0755 /opt/evil && cp /bin/true /opt/evil/systemctl && chown admin /opt/evil/systemctl")

	_, err := systemd.Setup(t.Context(), admin, setupParams(id, func(p *systemd.SetupParams) { p.SystemctlPath = "/opt/evil/systemctl" }))
	if codeOf(err) != smerr.CodeCapabilityUnavailable || !strings.Contains(err.Error(), "systemctl is not trusted") {
		t.Fatalf("setup with a user-owned systemctl: %v", err)
	}
	if n.hasUser(t, dedicatedUser) {
		t.Error("the dedicated user was created before the systemctl check")
	}
	if _, statErr := n.tryShell(t, "test -e /etc/sudoers.d/supermgmt"); statErr == nil {
		t.Error("a sudoers drop-in was installed for an untrusted systemctl")
	}
}

func TestFixturesR1_VerifyRefusesAnUntrustedSystemctl(t *testing.T) {
	p := provision(t, fixture.Options{}, nil)
	p.shell(t, "chmod g+w /usr/bin/systemctl; chgrp supermgmt $(readlink -f /usr/bin/systemctl)")
	defer p.shell(t, "chmod g-w $(readlink -f /usr/bin/systemctl); chgrp root $(readlink -f /usr/bin/systemctl)")

	if err := systemd.Verify(t.Context(), p.super, verifyParams(p.params, p.outcome)); err == nil || !strings.Contains(err.Error(), "systemctl is not trusted") {
		t.Fatalf("verify with a group-writable systemctl: %v", err)
	}
}

// R1 T4: a foreign pre-existing account gets no credential.
func TestFixturesR1_SetupRefusesForeignAccountsBeforeInstallingTheKey(t *testing.T) {
	accounts := map[string]string{
		"uid 995, primary group docker, separate supermgmt group": "groupadd supermgmt && useradd --system --uid 995 --gid docker " +
			"--home-dir /var/lib/supermgmt --create-home --shell /bin/sh supermgmt",
		"uid 0": "useradd --system --non-unique --uid 0 --gid 0 --home-dir /var/lib/supermgmt --create-home --shell /bin/sh supermgmt",
		"member of sudo": "useradd --system --user-group --home-dir /var/lib/supermgmt --create-home --shell /bin/sh supermgmt && " +
			"usermod -aG sudo supermgmt",
	}
	for name, create := range accounts {
		t.Run(name, func(t *testing.T) {
			n, admin, id := bareNode(t)
			n.shell(t, create)

			_, err := systemd.Setup(t.Context(), admin, setupParams(id, nil))
			if codeOf(err) != smerr.CodeConflict {
				t.Fatalf("setup over a privileged foreign account: %v; want CONFLICT", err)
			}
			for _, path := range []string{"/var/lib/supermgmt/.ssh/authorized_keys", "/var/lib/supermgmt/.ssh/authorized_keys.new", "/etc/sudoers.d/supermgmt"} {
				if _, statErr := n.tryShell(t, "test -e "+path); statErr == nil {
					t.Errorf("%s exists although the account was refused", path)
				}
			}
		})
	}
}

// R1 T5: a run cut between useradd and usermod -p converges.
func TestFixturesR1_SetupConvergesAfterACutBeforeUserUnlock(t *testing.T) {
	n, admin, id := bareNode(t)
	p := setupParams(id, nil)

	killed := &interruptAt{inner: admin, template: "setup.user_unlock" + templates.SudoVariantSuffix}
	if _, err := systemd.Setup(t.Context(), killed, p); !errors.Is(err, context.Canceled) {
		t.Fatalf("interrupted setup = %v; want the injected kill", err)
	}
	if got := n.shell(t, "getent shadow supermgmt | cut -d: -f2"); got == "*" {
		t.Fatalf("password field = %q before the unlock step ran", got)
	}

	out, err := systemd.Setup(t.Context(), admin, p)
	if err != nil {
		t.Fatalf("re-run: %v", err)
	}
	if got := n.shell(t, "getent shadow supermgmt | cut -d: -f2"); got != "*" {
		t.Errorf("password field = %q after the re-run; want '*'", got)
	}
	h := newHarness(t, defaultPoolConfig(), id)
	if err := systemd.Verify(t.Context(), h.pool.For(n.superTarget()), verifyParams(p, out)); err != nil {
		t.Errorf("verify after the re-run: %v", err)
	}
}
