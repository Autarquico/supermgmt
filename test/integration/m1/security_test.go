//go:build fixtures

package m1

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/test/fixtures/fixture"
)

// lab is one daemon managing one node, set up the way an operator would.
type lab struct {
	in   *instance
	api  *client.Client
	n    *node
	node wire.Node
}

// newProvisionedLab starts a node and a daemon, adds the node and, when grants
// is not empty, runs node.setup on it.
func newProvisionedLab(t *testing.T, o instanceOptions, grants ...string) *lab {
	t.Helper()
	n := startNodes(t, fixture.Options{})[0]
	in := newInstance(t, o)
	in.startDaemon()
	api := in.client()
	added := addNode(t, api, in, n, "lab-node", "staging")
	waitDiscovered(t, api, added.ID)
	if len(grants) > 0 {
		setup(t, api, added, false, grants...)
	}
	got, err := api.GetNode(t.Context(), added.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	return &lab{in: in, api: api, n: n, node: got}
}

// rotateHostKey replaces sshd's host key and restarts sshd.
// rotateHostKey also kills the established sessions. OpenSSH before 9.8 (Ubuntu
// 24.04) has no sshd-session binary: its sessions are titled "sshd: user@...",
// and the listener ("sshd: /usr/sbin/sshd ...") is excluded by the leading slash.
func (n *node) rotateHostKey(t *testing.T) {
	t.Helper()
	n.sh(t, "rm -f /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_ed25519_key.pub && "+
		"ssh-keygen -q -t ed25519 -N '' -f /etc/ssh/ssh_host_ed25519_key && systemctl restart ssh.service && { pkill -f '^sshd(-session)?: [^/ ]' || true; }")
}

func (n *node) acceptedLogins(t *testing.T) int {
	t.Helper()
	return strings.Count(n.sh(t, "journalctl -u ssh --no-pager"), "Accepted publickey")
}

// Security: a host key that changes between the scan the operator confirmed and
// the first authenticated probe is refused, and nothing authenticates to it.
func TestM1Security_HostKeyChangedBetweenScanAndFirstProbeIsRefused(t *testing.T) {
	n := startNodes(t, fixture.Options{})[0]
	in := newInstance(t, instanceOptions{FastRefresh: true})
	in.startDaemon()
	api := in.client()
	in.agent.hold(n.ClientSigner)

	scanned, err := api.ScanHostKey(t.Context(), wire.ScanHostKeyRequest{Host: n.Host, Port: n.Port})
	if err != nil {
		t.Fatal(err)
	}
	n.rotateHostKey(t) // an interposed or re-provisioned host after the operator confirmed

	added, err := api.AddSSHNode(t.Context(), wire.AddSSHNodeRequest{
		Name: "swapped", Host: n.Host, Port: n.Port, AdminUser: fixture.AdminUser,
		HostPublicKey: scanned.AuthorizedKey, Environment: "staging",
	})
	if err != nil {
		if codeOf(err) != smerr.CodeSSHHostKeyMismatch {
			t.Fatalf("add node after the key changed: %v, want SSH_HOST_KEY_MISMATCH or success followed by a refused probe", err)
		}
	} else {
		id := added.Applied.ID
		eventually(t, 30*time.Second, "the connection error to name the host key", func() bool {
			got, err := api.GetNode(t.Context(), id, false)
			return err == nil && strings.Contains(strings.ToLower(got.Connection.LastError), "host key")
		})
		got, _ := api.GetNode(t.Context(), id, false)
		if hasCapability(got, "node.read") {
			t.Errorf("a node whose host key changed was discovered: %v", capabilityNames(got))
		}
	}
	time.Sleep(3 * time.Second) // let the refresher retry
	if logins := n.acceptedLogins(t); logins != 0 {
		t.Errorf("sshd accepted %d login(s) from SuperMgmt on a host whose key does not match the pin", logins)
	}
}

// Security: after the pinned key changes, no new session authenticates.
func TestM1Security_PinnedHostKeyChangeStopsAuthentication(t *testing.T) {
	l := newProvisionedLab(t, instanceOptions{FastRefresh: true})
	probe(t, l.api, l.node.ID)
	before := l.n.acceptedLogins(t)
	if before == 0 {
		t.Fatal("no login recorded before the key change; the check would be vacuous")
	}
	l.n.rotateHostKey(t)
	after := l.n.acceptedLogins(t)

	eventually(t, 30*time.Second, "the connection error to name the host key", func() bool {
		got, err := l.api.GetNode(t.Context(), l.node.ID, false)
		t.Logf("node after the key change: reachability %s stale %t connection %+v", got.Reachability, got.Stale, got.Connection)
		return err == nil && strings.Contains(strings.ToLower(got.Connection.LastError), "host key")
	})
	time.Sleep(8 * time.Second) // several refresher passes
	if now := l.n.acceptedLogins(t); now != after {
		t.Errorf("sshd accepted %d new login(s) after the host key changed", now-after)
	}
	sub, err := l.api.ProbeNode(t.Context(), l.node.ID)
	if err == nil {
		job := waitFinal(t, l.api, sub.Job.ID, time.Minute)
		if job.State == domain.JobSucceeded {
			t.Errorf("an explicit probe succeeded against a changed host key")
		}
	}
}

func waitFinal(t *testing.T, api *client.Client, id domain.ID, within time.Duration) wire.Job {
	t.Helper()
	var last wire.Job
	eventually(t, within, "job "+string(id)+" to finish", func() bool {
		d, err := api.GetJob(t.Context(), id)
		if err != nil {
			return false
		}
		last = d.Job
		return isFinal(d.Job.State)
	})
	return last
}

// Security: log text from the node is hostile input end to end.
func TestM1Security_MaliciousANSILogsAreNeutralisedEndToEnd(t *testing.T) {
	l := newProvisionedLab(t, instanceOptions{}, allVerbs(demoUnit)...)
	l.n.sh(t, `cat > /usr/local/bin/sm-evil.sh <<'SCRIPT'
#!/bin/sh
printf 'visible-line\n'
printf '\033[2J\033[H\033]0;pwned-title\007\033]52;c;ZXZpbA==\007esc-text\n'
printf 'c1-\233\31m-text\n'
printf 'bad-utf8-\377\376-end\n'
printf 'nul-and-bell-\001\007\010-end\n'
exec sleep infinity
SCRIPT
chmod +x /usr/local/bin/sm-evil.sh
cat > /etc/systemd/system/sm-evil.service <<'UNIT'
[Unit]
Description=Hostile log producer
[Service]
ExecStart=/usr/local/bin/sm-evil.sh
UNIT
systemctl daemon-reload && systemctl start sm-evil.service`)
	probe(t, l.api, l.node.ID)
	svc := serviceNamed(t, l.api, l.node.ID, "sm-evil.service")

	var chunk wire.LogChunk
	eventually(t, 30*time.Second, "the hostile lines to reach the journal", func() bool {
		var err error
		chunk, err = l.api.ServiceLogs(t.Context(), svc.ID, wire.LogQuery{Lines: 100})
		return err == nil && strings.Contains(strings.Join(chunk.Lines, "\n"), "visible-line")
	})
	for _, line := range chunk.Lines {
		if !utf8.ValidString(line) {
			t.Errorf("log line is not valid UTF-8: %q", line)
		}
		for _, r := range line {
			if r == 0x1b || r == 0x7f || (r < 0x20 && r != '\t') || (r >= 0x80 && r <= 0x9f) {
				t.Errorf("control character %U survived the API in %q", r, line)
			}
		}
	}

	tui := newTUI(t, l.api, 120, 40)
	palette := func(command string) {
		tui.press("/")
		for _, r := range command {
			tui.press(string(r))
		}
		tui.press("enter")
	}
	palette("services lab-node") // loads the node's services, which the logs command resolves against
	tui.waitScreen("sm-evil.service", 15*time.Second)
	palette("logs sm-evil.service")
	tui.waitScreen("visible-line", 15*time.Second)
	frame := tui.m.View().Content
	for _, attack := range []string{"pwned-title", "\x1b]0;", "\x1b]52", "\x1b[2J", "\x9b", "\x07"} {
		if strings.Contains(frame, attack) {
			t.Errorf("the TUI frame carries the attacker's sequence %q", attack)
		}
	}
}

// Security: injection through plan parameters never reaches a node.
func TestM1Security_HostileSetupGrantsAreRefusedBeforeAnythingRuns(t *testing.T) {
	l := newProvisionedLab(t, instanceOptions{}, allVerbs(demoUnit)...)
	dropIn := l.n.sh(t, "cat /etc/sudoers.d/supermgmt")
	hostile := [][]string{
		{"restart foo.service\nattacker ALL=(ALL) NOPASSWD: ALL"},
		{"restart foo.service,/bin/sh"},
		{"restart foo.service ALL=(ALL) NOPASSWD: ALL"},
		{"restart *.service"},
		{"restart ../../bin/sh.service"},
		{"restart -f.service"},
		{"restart sm-demo.service; id"},
		{"rm -rf sm-demo.service"},
		{"restart a:b.service"},
	}
	for _, grants := range hostile {
		plan, err := l.api.CreatePlan(t.Context(), wire.CreatePlanRequest{
			Action:     "node.setup",
			Targets:    []wire.ResourceRef{{Type: domain.ResourceNode, ID: l.node.ID}},
			Parameters: map[string]any{"docker_access": "false", "logs_mode": "journal-group", "grants": grants},
		})
		if err == nil {
			t.Errorf("grants %q were accepted into plan %s (policy %s)", grants, plan.PlanID, plan.Policy.Decision)
			continue
		}
		if codeOf(err) != smerr.CodeInvalidArgument {
			t.Errorf("grants %q: %v, want INVALID_ARGUMENT", grants, err)
		}
	}
	for _, params := range []map[string]any{
		{"docker_access": "yes", "logs_mode": "journal-group"},
		{"docker_access": "false", "logs_mode": "journal-group; id"},
		{"docker_access": "false", "logs_mode": "journal-group", "extra": "x"},
	} {
		if _, err := l.api.CreatePlan(t.Context(), wire.CreatePlanRequest{
			Action: "node.setup", Targets: []wire.ResourceRef{{Type: domain.ResourceNode, ID: l.node.ID}}, Parameters: params,
		}); err == nil {
			t.Errorf("parameters %v were accepted", params)
		}
	}
	if got := l.n.sh(t, "cat /etc/sudoers.d/supermgmt"); got != dropIn {
		t.Errorf("the sudoers drop-in changed:\n%s\n--- was ---\n%s", got, dropIn)
	}
	if out := l.n.sh(t, "ls /etc/sudoers.d"); strings.Contains(out, "attacker") {
		t.Errorf("a hostile sudoers file exists: %s", out)
	}
}

// Security: the interactive handoff ignores the operator's hostile ssh
// configuration and trusts exactly the pinned host key (ADR-0015, spec §8.4).
func TestM1Security_HandoffIgnoresHostileSSHConfigAndPinsTheHostKey(t *testing.T) {
	if out, err := exec.CommandContext(t.Context(), "ssh", "-V").CombinedOutput(); err != nil {
		t.Skipf("no OpenSSH client: %v %s", err, out)
	}
	l := newProvisionedLab(t, instanceOptions{})
	home := t.TempDir()
	canaries := []string{filepath.Join(home, "proxy-ran"), filepath.Join(home, "knownhosts-ran"), filepath.Join(home, "local-ran")}
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	hostile := "Host *\n" +
		"  ProxyCommand touch " + canaries[0] + "; false\n" +
		"  KnownHostsCommand touch " + canaries[1] + "\n" +
		"  PermitLocalCommand yes\n  LocalCommand touch " + canaries[2] + "\n" +
		"  StrictHostKeyChecking no\n  UserKnownHostsFile /dev/null\n"
	if err := os.WriteFile(filepath.Join(sshDir, "config"), []byte(hostile), 0o600); err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	api := client.New(client.Options{Socket: l.in.socket, TempDir: tmp})

	run := func(script string) (string, error) {
		h, err := api.OpenSession(t.Context(), l.node.ID, string(wire.ToolShell))
		if err != nil {
			t.Fatalf("open session: %v", err)
		}
		if dirs, _ := filepath.Glob(filepath.Join(tmp, "sm-kh-*")); len(dirs) != 1 {
			t.Errorf("isolated known_hosts directories while the session is open = %d, want 1", len(dirs))
		}
		var out bytes.Buffer
		h.Cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "SSH_AUTH_SOCK=" + l.in.agentSocket}
		h.Cmd.Stdin = strings.NewReader(script)
		h.Cmd.Stdout, h.Cmd.Stderr = &out, &out
		runErr := h.Cmd.Run()
		code := 0
		var exit *exec.ExitError
		if runErr != nil {
			if !errors.As(runErr, &exit) {
				h.Done(0, runErr)
				return out.String(), runErr
			}
			code = exit.ExitCode()
		}
		h.Done(code, nil)
		return out.String(), runErr
	}

	out, err := run("echo LOGGED-IN-AS-$(id -un)\nexit\n")
	if err != nil || !strings.Contains(out, "LOGGED-IN-AS-"+fixture.AdminUser) {
		t.Fatalf("the handoff did not log in as admin_user with the pinned key: %v\n%s", err, out)
	}
	for _, c := range canaries {
		if _, statErr := os.Stat(c); statErr == nil {
			t.Errorf("the operator's hostile ssh config was honoured: %s exists", filepath.Base(c))
		}
	}
	if dirs, _ := filepath.Glob(filepath.Join(tmp, "sm-kh-*")); len(dirs) != 0 {
		t.Errorf("temporary known_hosts directories remain: %v", dirs)
	}

	l.n.rotateHostKey(t)
	out, err = run("echo SHOULD-NOT-RUN\nexit\n")
	if err == nil || strings.Contains(out, "SHOULD-NOT-RUN") {
		t.Errorf("the handoff logged in to a host whose key does not match the pin: %v\n%s", err, out)
	}
	if dirs, _ := filepath.Glob(filepath.Join(tmp, "sm-kh-*")); len(dirs) != 0 {
		t.Errorf("temporary known_hosts directories remain after the refused login: %v", dirs)
	}
}
