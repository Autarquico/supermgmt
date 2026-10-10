//go:build fixtures

package integration

import (
	"slices"
	"strconv"
	"strings"
	"testing"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/autarquico/supermgmt/internal/discovery"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/runtimes/systemd"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
	"github.com/autarquico/supermgmt/test/fixtures/fixture"
)

// stat returns "<owner>:<group> <octal mode>" of a path on the node.
func (n *fixtureNode) stat(t *testing.T, path string) string {
	t.Helper()
	return n.shell(t, "stat -c '%U:%G %a' "+path)
}

// groupsOf lists the groups the account belongs to.
func (n *fixtureNode) groupsOf(t *testing.T, user string) []string {
	t.Helper()
	return strings.Fields(n.shell(t, "id -nG "+user))
}

func (n *fixtureNode) hasUser(t *testing.T, user string) bool {
	_, err := n.tryShell(t, "getent passwd "+user)
	return err == nil
}

// stateSnapshot captures everything node.setup manages, so two runs can be compared.
func (n *fixtureNode) stateSnapshot(t *testing.T) string {
	t.Helper()
	return n.shell(t, strings.Join([]string{
		"getent passwd supermgmt", "getent shadow supermgmt | cut -d: -f1,2", "id -nG supermgmt",
		"for p in /var/lib/supermgmt /var/lib/supermgmt/markers /var/lib/supermgmt/.ssh " +
			"/var/lib/supermgmt/.ssh/authorized_keys /etc/sudoers.d/supermgmt /etc/tmpfiles.d/supermgmt.conf " +
			"/usr/local/libexec/supermgmt/unit-logs /etc/supermgmt/allowed-units; do " +
			"[ -e $p ] && { stat -c '%n %U:%G %a' $p; [ -f $p ] && sha256sum $p; }; done",
		"ls -A /etc/sudoers.d /etc/tmpfiles.d /var/lib/supermgmt/.ssh",
	}, "; "))
}

func TestFixturesSetup_CreatesTheDedicatedUserAndItsFiles(t *testing.T) {
	p := provision(t, fixture.Options{}, nil)

	t.Run("passwd entry is a system account with the managed home and /bin/sh", func(t *testing.T) {
		fields := strings.Split(p.shell(t, "getent passwd supermgmt"), ":")
		uid, err := strconv.Atoi(fields[2])
		if err != nil || uid >= 1000 || uid < 1 {
			t.Errorf("uid = %q; want a system uid", fields[2])
		}
		if fields[5] != "/var/lib/supermgmt" || fields[6] != "/bin/sh" {
			t.Errorf("home/shell = %q %q; want /var/lib/supermgmt /bin/sh", fields[5], fields[6])
		}
		if shadow := p.shell(t, "getent shadow supermgmt | cut -d: -f2"); shadow != "*" {
			t.Errorf("password field = %q; want '*' (no password, not locked)", shadow)
		}
	})

	t.Run("home and its subdirectories carry the ADR-0009 modes", func(t *testing.T) {
		want := map[string]string{
			"/var/lib/supermgmt":                      "supermgmt:supermgmt 750",
			"/var/lib/supermgmt/markers":              "supermgmt:supermgmt 700",
			"/var/lib/supermgmt/.ssh":                 "supermgmt:supermgmt 700",
			"/var/lib/supermgmt/.ssh/authorized_keys": "supermgmt:supermgmt 600",
			"/etc/sudoers.d/supermgmt":                "root:root 440",
		}
		for path, mode := range want {
			if got := p.stat(t, path); got != mode {
				t.Errorf("%s = %q; want %q", path, got, mode)
			}
		}
	})

	t.Run("authorized_keys holds exactly one restricted line for the instance key", func(t *testing.T) {
		got := p.shell(t, "cat /var/lib/supermgmt/.ssh/authorized_keys")
		want := "restrict " + p.identity.public + " supermgmt@" + instanceID
		if got != want {
			t.Errorf("authorized_keys = %q; want %q", got, want)
		}
	})

	t.Run("the restricted key cannot allocate a pty", func(t *testing.T) {
		c, err := cryptossh.Dial("tcp", p.Addr(), &cryptossh.ClientConfig{
			User: dedicatedUser, Auth: []cryptossh.AuthMethod{cryptossh.PublicKeys(p.identity.signer)},
			HostKeyCallback: cryptossh.FixedHostKey(p.HostKey),
		})
		if err != nil {
			t.Fatalf("dial as supermgmt: %v", err)
		}
		defer c.Close()
		s, err := c.NewSession()
		if err != nil {
			t.Fatalf("session: %v", err)
		}
		defer s.Close()
		if err := s.RequestPty("xterm", 24, 80, cryptossh.TerminalModes{}); err == nil {
			t.Error("pty request succeeded; the restrict option must refuse it")
		}
	})

	t.Run("journal-group mode adds the journal group and not docker", func(t *testing.T) {
		groups := p.groupsOf(t, dedicatedUser)
		if !slices.Contains(groups, "systemd-journal") && !slices.Contains(groups, "adm") {
			t.Errorf("groups = %v; want systemd-journal or adm", groups)
		}
		if slices.Contains(groups, "docker") {
			t.Errorf("groups = %v; docker needs docker_access", groups)
		}
	})

	t.Run("tmpfiles creates the node-side lock directory", func(t *testing.T) {
		if got := p.stat(t, "/run/supermgmt/locks"); got != "supermgmt:supermgmt 700" {
			t.Errorf("/run/supermgmt/locks = %q; want supermgmt:supermgmt 700", got)
		}
	})

	t.Run("sudo -l -U supermgmt equals the rendered sudoers lines", func(t *testing.T) {
		want, err := systemd.SudoCommands(p.outcome.SystemctlPath, p.params.Grants, p.params.LogsMode)
		if err != nil {
			t.Fatalf("render sudo commands: %v", err)
		}
		got := listedRootCommands(t, p.shell(t, "sudo -l -U supermgmt"))
		slices.Sort(want)
		slices.Sort(got)
		if !slices.Equal(got, want) {
			t.Errorf("sudo -l -U supermgmt = %v; want %v", got, want)
		}
		file := p.shell(t, "cat /etc/sudoers.d/supermgmt")
		rendered, err := systemd.Sudoers(dedicatedUser, p.outcome.SystemctlPath, p.params.Grants, p.params.LogsMode)
		if err != nil || strings.TrimSpace(file) != strings.TrimSpace(rendered) {
			t.Errorf("sudoers drop-in = %q; want the rendered file %q (%v)", file, rendered, err)
		}
		p.shell(t, "visudo -c")
	})

	t.Run("the session user is supermgmt after setup", func(t *testing.T) {
		if got := strings.TrimSpace(string(run(t, p.super, "setup.verify_id", nil).Stdout)); got != dedicatedUser {
			t.Errorf("id -un = %q; want %s", got, dedicatedUser)
		}
		snap, err := discovery.Probe(t.Context(), p.super)
		if err != nil {
			t.Fatalf("probe as supermgmt: %v", err)
		}
		if snap.Probed.User != dedicatedUser || !snap.Probed.HomeExists || !snap.Probed.MarkersWritable {
			t.Errorf("probed = %+v; want supermgmt with home and writable markers", snap.Probed)
		}
	})
}

// listedRootCommands parses `sudo -l` output into the "(root) NOPASSWD:" commands.
func listedRootCommands(t *testing.T, out string) []string {
	t.Helper()
	_, listing, found := strings.Cut(out, "may run the following commands")
	if !found {
		t.Fatalf("no command listing in sudo -l output:\n%s", out)
	}
	_, listing, _ = strings.Cut(listing, "\n")
	var commands []string
	for _, line := range strings.Split(listing, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		rest, ok := strings.CutPrefix(line, "(root) NOPASSWD: ")
		if !ok {
			t.Fatalf("unexpected sudo grant %q", line)
		}
		commands = append(commands, strings.Split(rest, ", ")...)
	}
	return commands
}

func TestFixturesSetup_RerunIsANoOp(t *testing.T) {
	p := provision(t, fixture.Options{}, nil)
	before := p.stateSnapshot(t)

	rec := &recorder{inner: p.admin}
	out, err := systemd.Setup(t.Context(), rec, p.params)
	if err != nil {
		t.Fatalf("second node.setup: %v", err)
	}
	if out != p.outcome {
		t.Errorf("outcome = %+v; want %+v", out, p.outcome)
	}
	if after := p.stateSnapshot(t); after != before {
		t.Errorf("node state changed on re-run:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	for _, creating := range []string{"setup.user_add", "setup.user_unlock", "setup.group_add", "setup.group_remove"} {
		if rec.ran(creating) {
			t.Errorf("re-run executed %s; an ensure step must skip what already holds", creating)
		}
	}
	if err := systemd.Verify(t.Context(), p.super, verifyParams(p.params, out)); err != nil {
		t.Errorf("verify after re-run: %v", err)
	}
}

func TestFixturesSetup_DockerAccessAddsTheDockerGroupOnlyWhenAsked(t *testing.T) {
	t.Run("docker_access true", func(t *testing.T) {
		p := provision(t, fixture.Options{DemoContainer: true}, func(p *systemd.SetupParams) { p.DockerAccess = true })
		if groups := p.groupsOf(t, dedicatedUser); !slices.Contains(groups, "docker") {
			t.Errorf("groups = %v; want docker", groups)
		}
		snap, err := discovery.Probe(t.Context(), p.super)
		if err != nil {
			t.Fatalf("probe: %v", err)
		}
		if !snap.Docker.Reachable() {
			t.Error("docker must be reachable for supermgmt with docker_access")
		}
		snap.Setup = &p.meta
		cap := capability(t, discovery.Capabilities(snap, false), "service.restart")
		if !cap.Available || cap.Metadata["containers"] != true {
			t.Errorf("service.restart = %+v; want available with containers", cap)
		}
	})

	t.Run("docker_access false", func(t *testing.T) {
		p := provision(t, fixture.Options{DemoContainer: true}, nil)
		if groups := p.groupsOf(t, dedicatedUser); slices.Contains(groups, "docker") {
			t.Errorf("groups = %v; docker must be absent without docker_access", groups)
		}
		snap, err := discovery.Probe(t.Context(), p.super)
		if err != nil {
			t.Fatalf("probe: %v", err)
		}
		if snap.Docker.Reachable() {
			t.Error("docker must not be reachable for supermgmt without docker_access")
		}
		snap.Setup = &p.meta
		cap := capability(t, discovery.Capabilities(snap, false), "service.restart")
		if cap.Metadata["containers"] != false {
			t.Errorf("service.restart metadata = %+v; want containers false", cap.Metadata)
		}
	})

	t.Run("turning docker_access off on re-run removes the group", func(t *testing.T) {
		p := provision(t, fixture.Options{}, func(p *systemd.SetupParams) { p.DockerAccess = true })
		off := p.params
		off.DockerAccess = false
		if _, err := systemd.Setup(t.Context(), p.admin, off); err != nil {
			t.Fatalf("setup without docker_access: %v", err)
		}
		if groups := p.groupsOf(t, dedicatedUser); slices.Contains(groups, "docker") {
			t.Errorf("groups = %v; the re-run must drop docker", groups)
		}
	})
}

func TestFixturesSetup_BrokerModeDropsTheJournalGroupAndInstallsTheBroker(t *testing.T) {
	p := provision(t, fixture.Options{}, func(p *systemd.SetupParams) { p.LogsMode = runtimes.LogsBroker })

	groups := p.groupsOf(t, dedicatedUser)
	for _, g := range []string{"systemd-journal", "adm", "docker"} {
		if slices.Contains(groups, g) {
			t.Errorf("groups = %v; broker mode must not grant %s", groups, g)
		}
	}
	if got := p.stat(t, templates.BrokerPath); got != "root:root 755" {
		t.Errorf("broker = %q; want root:root 755", got)
	}
	if units := p.shell(t, "cat "+templates.BrokerUnitsPath); units != demoUnit {
		t.Errorf("allowed-units = %q; want %s", units, demoUnit)
	}
	commands, _ := systemd.SudoCommands(p.outcome.SystemctlPath, p.params.Grants, p.params.LogsMode)
	if !slices.Contains(commands, templates.BrokerPath) {
		t.Fatalf("rendered sudo commands %v lack the broker", commands)
	}
	if got := listedRootCommands(t, p.shell(t, "sudo -l -U supermgmt")); !slices.Contains(got, templates.BrokerPath) {
		t.Errorf("sudo -l -U supermgmt = %v; want the broker line", got)
	}
}

func TestFixturesSetup_ForeignAccountIsAConflict(t *testing.T) {
	n := startNode(t, fixture.Options{})
	id := newIdentity(t)
	useAgent(t, n.ClientSigner)
	h := newHarness(t, defaultPoolConfig(), id)
	admin := h.pool.For(n.target(fixture.AdminUser))

	for name, create := range map[string]string{
		"regular login account":                      "useradd --create-home supermgmt",
		"system account with another home and shell": "useradd --system --home-dir /srv/other --shell /usr/sbin/nologin supermgmt",
	} {
		t.Run(name, func(t *testing.T) {
			n.shell(t, "userdel -r supermgmt 2>/dev/null; "+create)
			before := n.shell(t, "getent passwd supermgmt")
			_, err := systemd.Setup(t.Context(), admin, setupParams(id, nil))
			if codeOf(err) != smerr.CodeConflict {
				t.Fatalf("setup over a foreign account: %v; want CONFLICT", err)
			}
			if after := n.shell(t, "getent passwd supermgmt"); after != before {
				t.Errorf("the foreign account was modified: %q -> %q", before, after)
			}
			for _, path := range []string{"/etc/sudoers.d/supermgmt", "/var/lib/supermgmt/.ssh/authorized_keys"} {
				if _, err := n.tryShell(t, "test -e "+path); err == nil {
					t.Errorf("%s exists although setup refused the account", path)
				}
			}
		})
	}
}

func TestFixturesSetup_AdminWithoutSudoIsCapabilityUnavailable(t *testing.T) {
	n := startNode(t, fixture.Options{})
	id := newIdentity(t)
	useAgent(t, n.ClientSigner)
	n.shell(t, "useradd --create-home --shell /bin/bash plain && usermod -p '*' plain && "+
		"install -d -m 0700 -o plain -g plain /home/plain/.ssh && "+
		"printf '%s\\n' "+templates.Quote(authorizedKey(n.ClientSigner.PublicKey()))+" > /home/plain/.ssh/authorized_keys && "+
		"chown plain:plain /home/plain/.ssh/authorized_keys && chmod 0600 /home/plain/.ssh/authorized_keys")
	h := newHarness(t, defaultPoolConfig(), id)

	_, err := systemd.Setup(t.Context(), h.pool.For(n.target("plain")), setupParams(id, nil))
	if codeOf(err) != smerr.CodeCapabilityUnavailable {
		t.Fatalf("setup as a user without sudo: %v; want CAPABILITY_UNAVAILABLE", err)
	}
	if n.hasUser(t, dedicatedUser) {
		t.Error("supermgmt was created although the bootstrap identity has no privilege")
	}
}

func TestFixturesSetup_AdminRootRunsWithoutSudo(t *testing.T) {
	n := startNode(t, fixture.Options{})
	id := newIdentity(t)
	useAgent(t, n.ClientSigner)
	n.shell(t, "printf 'PermitRootLogin prohibit-password\\n' > /etc/ssh/sshd_config.d/05-root.conf && "+
		"install -d -m 0700 /root/.ssh && printf '%s\\n' "+templates.Quote(authorizedKey(n.ClientSigner.PublicKey()))+
		" > /root/.ssh/authorized_keys && chmod 0600 /root/.ssh/authorized_keys && systemctl reload ssh.service")
	h := newHarness(t, defaultPoolConfig(), id)
	rec := &recorder{inner: h.pool.For(n.target("root"))}

	p := setupParams(id, func(p *systemd.SetupParams) { p.AdminIsRoot = true })
	out, err := systemd.Setup(t.Context(), rec, p)
	if err != nil {
		t.Fatalf("setup as root: %v", err)
	}
	if rec.ran("setup.user_add") == false {
		t.Error("setup as root did not create the user")
	}
	for _, name := range rec.seen {
		if strings.HasSuffix(name, templates.SudoVariantSuffix) {
			t.Errorf("admin_user=root ran the sudo variant %s", name)
		}
	}
	if err := systemd.Verify(t.Context(), h.pool.For(n.superTarget()), verifyParams(p, out)); err != nil {
		t.Errorf("verify after root setup: %v", err)
	}
	if got := n.stat(t, "/etc/sudoers.d/supermgmt"); got != "root:root 440" {
		t.Errorf("sudoers drop-in = %q; want root:root 440", got)
	}
}

func TestFixturesSetup_VerifyFailureIsReported(t *testing.T) {
	t.Run("sshd refuses the dedicated user", func(t *testing.T) {
		n := startNode(t, fixture.Options{})
		id := newIdentity(t)
		useAgent(t, n.ClientSigner)
		h := newHarness(t, defaultPoolConfig(), id)
		p := setupParams(id, nil)

		out, err := systemd.Setup(t.Context(), h.pool.For(n.target(fixture.AdminUser)), p)
		if err != nil {
			t.Fatalf("setup: %v", err)
		}
		n.shell(t, "printf 'DenyUsers supermgmt\\n' > /etc/ssh/sshd_config.d/00-deny.conf && systemctl reload ssh.service")

		err = systemd.Verify(t.Context(), h.pool.For(n.superTarget()), verifyParams(p, out))
		if codeOf(err) != smerr.CodeCapabilityUnavailable {
			t.Fatalf("verify although sshd denies supermgmt: %v; want CAPABILITY_UNAVAILABLE (setup failed, no capability)", err)
		}
	})

	t.Run("an extra sudo grant is not the rendered set", func(t *testing.T) {
		p := provision(t, fixture.Options{}, nil)
		p.shell(t, "printf 'supermgmt ALL=(root) NOPASSWD: /usr/bin/id\\n' >> /etc/sudoers.d/supermgmt")

		h := newHarness(t, defaultPoolConfig(), p.identity)
		err := systemd.Verify(t.Context(), h.pool.For(p.superTarget()), verifyParams(p.params, p.outcome))
		if codeOf(err) != smerr.CodeCapabilityUnavailable {
			t.Fatalf("verify with an extra grant: %v; want CAPABILITY_UNAVAILABLE", err)
		}
	})

	t.Run("a missing grant is not the rendered set", func(t *testing.T) {
		p := provision(t, fixture.Options{}, nil)
		p.shell(t, "sed -i '/ stop /d' /etc/sudoers.d/supermgmt")

		h := newHarness(t, defaultPoolConfig(), p.identity)
		err := systemd.Verify(t.Context(), h.pool.For(p.superTarget()), verifyParams(p.params, p.outcome))
		if codeOf(err) != smerr.CodeCapabilityUnavailable {
			t.Fatalf("verify with a missing grant: %v; want CAPABILITY_UNAVAILABLE", err)
		}
	})
}
