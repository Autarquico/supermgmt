package join

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"testing"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/autarquico/supermgmt/internal/audit"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/runtimes/systemd"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

const (
	connectorToken      = "eyJhIjoiYWNjb3VudCIsInQiOiJ0dW5uZWwtaWQiLCJzIjoic2VjcmV0LXNlbnRpbmVsLTEyMzQifQ=="
	otherConnectorToken = "eyJhIjoiYWNjb3VudCIsInQiOiJ0dW5uZWwtaWQiLCJzIjoib3RoZXItc2VjcmV0LXNlbnRpbmVsIn0="
	instanceID          = "0f6b2c1e-instance"
)

var quotedArg = regexp.MustCompile(`'([^']*)'`)

// fakeNode answers the setup steps the cloudflared install issues on a Debian 13
// node and keeps the state they change.
type fakeNode struct {
	t         *testing.T
	files     map[string]string
	os        string
	installed bool
	active    bool
	calls     []templates.Command
	restarts  int
	failing   string // template that exits 1
}

func newFakeNode(t *testing.T) *fakeNode {
	return &fakeNode{t: t, files: map[string]string{}, os: "debian trixie\n"}
}

func (n *fakeNode) args(c templates.Command) []string {
	var out []string
	for _, m := range quotedArg.FindAllStringSubmatch(c.Line, -1) {
		out = append(out, m[1])
	}
	return out
}

func (n *fakeNode) Run(_ context.Context, c templates.Command) (transport.Result, error) {
	n.calls = append(n.calls, c)
	args := n.args(c)
	last := func() string { return args[len(args)-1] }
	if c.Template == n.failing {
		return transport.Result{ExitStatus: 1, Stderr: []byte("boom " + string(c.Stdin))}, nil
	}
	switch c.Template {
	case "setup.os_release":
		return transport.Result{Stdout: []byte(n.os)}, nil
	case "setup.cloudflared_package":
		if n.installed {
			return transport.Result{Stdout: []byte("ii  2026.10.1\n")}, nil
		}
		return transport.Result{ExitStatus: 1}, nil
	case "systemd.show":
		state := "inactive"
		if n.active {
			state = "active"
		}
		return transport.Result{Stdout: []byte("ActiveState=" + state + "\n")}, nil
	case "setup.file_sha256":
		content, ok := n.files[last()]
		if !ok {
			return transport.Result{ExitStatus: 3}, nil
		}
		return transport.Result{Stdout: []byte(hashOf(content) + "  -\n")}, nil
	case "setup.file_stage":
		n.files[last()] = string(c.Stdin)
	case "setup.file_commit":
		from, to := args[len(args)-2], args[len(args)-1]
		n.files[to] = n.files[from]
		delete(n.files, from)
	case "setup.file_discard", "setup.file_remove":
		delete(n.files, last())
	case "setup.apt_install_cloudflared":
		n.installed = true
	case "setup.tunnel_enable":
		n.active = true
	case "setup.tunnel_restart":
		n.restarts++
	case "setup.dir", "setup.apt_update_cloudflared", "setup.daemon_reload":
	default:
		n.t.Errorf("unexpected step %s: %s", c.Template, c.Line)
	}
	return transport.Result{}, nil
}

// mutations are the steps that change the node.
func (n *fakeNode) mutations() []string {
	var out []string
	for _, c := range n.calls {
		switch c.Template {
		case "setup.os_release", "setup.cloudflared_package", "systemd.show", "setup.file_sha256":
		default:
			out = append(out, c.Template)
		}
	}
	return out
}

func (n *fakeNode) count(template string) int {
	count := 0
	for _, c := range n.calls {
		if c.Template == template {
			count++
		}
	}
	return count
}

func hashOf(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

type tunnelHost struct {
	*fakeHost
	node         *fakeNode
	tunnelErr    error
	hostKeyLine  string
	instanceKey  string
	hostKeyPrint string
}

func (h *tunnelHost) PreflightTunnel() error {
	h.record("preflight-tunnel")
	return h.tunnelErr
}
func (h *tunnelHost) Executor() transport.Executor { return h.node }

func newTunnelHost(t *testing.T) *tunnelHost {
	host := newFakeHost()
	hostKey := publicKey(t)
	host.files["/etc/ssh/ssh_host_ed25519_key.pub"] = []byte(hostKey + " root@edge-1\n")
	parsed, _, _, _, err := cryptossh.ParseAuthorizedKey([]byte(hostKey))
	if err != nil {
		t.Fatal(err)
	}
	return &tunnelHost{
		fakeHost: host, node: newFakeNode(t), instanceKey: publicKey(t),
		hostKeyLine: hostKey, hostKeyPrint: cryptossh.FingerprintSHA256(parsed),
	}
}

func (h *tunnelHost) run(token string) (string, error) {
	return TunnelJoiner{Host: h}.Run(context.Background(),
		TunnelRequest{InstanceID: instanceID, AuthorizedKey: h.instanceKey},
		func() (audit.Secret, error) { return audit.Secret(token), nil })
}

// untouched asserts that neither the account nor the node changed.
func (h *tunnelHost) untouched(t *testing.T) {
	t.Helper()
	if m := h.node.mutations(); len(m) != 0 {
		t.Errorf("the node was changed before the refusal: %v", m)
	}
	for _, call := range h.calls {
		if call != "preflight" && call != "preflight-tunnel" {
			t.Errorf("the account side was changed before the refusal: %v", h.calls)
			break
		}
	}
}

func TestTunnelJoinInstallsTheSharedContentAndProvisionsTheAccount(t *testing.T) {
	host := newTunnelHost(t)

	fingerprint, err := host.run(connectorToken)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint != host.hostKeyPrint || !strings.HasPrefix(fingerprint, "SHA256:") {
		t.Errorf("fingerprint %q, want %q", fingerprint, host.hostKeyPrint)
	}
	keyring, err := systemd.CloudflareKeyring()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		templates.CloudflareKeyringPath: string(keyring),
		templates.CloudflaredSourcePath: systemd.CloudflareSource(),
		templates.CloudflaredUnitPath:   systemd.CloudflaredUnit(),
		templates.CloudflaredTokenPath:  systemd.ConnectorTokenFile(connectorToken),
	}
	for path, content := range want {
		if host.node.files[path] != content {
			t.Errorf("%s differs from the content node setup writes", path)
		}
	}
	for _, c := range host.node.calls {
		if c.Template == "setup.file_stage" && strings.Contains(c.Line, templates.CloudflaredTokenPath) && !strings.Contains(c.Line, "'0600'") {
			t.Errorf("the token file is not staged 0600: %s", c.Line)
		}
	}
	if !host.node.installed || !host.node.active {
		t.Errorf("installed=%v active=%v", host.node.installed, host.node.active)
	}
	line := host.installed[templates.AuthorizedKeysPath].data
	if line != "restrict "+host.instanceKey+" supermgmt@"+instanceID+"\n" {
		t.Errorf("authorized_keys = %q", line)
	}
}

func TestTunnelJoinAptCommandsAreTheSetupTemplates(t *testing.T) {
	host := newTunnelHost(t)
	if _, err := host.run(connectorToken); err != nil {
		t.Fatal(err)
	}
	for _, c := range host.node.calls {
		switch c.Template {
		case "setup.apt_update_cloudflared":
			if !strings.Contains(c.Line, "Dir::Etc::sourcelist=sources.list.d/cloudflared.list") || !strings.Contains(c.Line, "DPkg::Lock::Timeout=60") {
				t.Errorf("update is not restricted to cloudflared.list: %s", c.Line)
			}
		case "setup.apt_install_cloudflared":
			for _, part := range []string{"DEBIAN_FRONTEND=noninteractive", "--no-install-recommends", "DPkg::Lock::Timeout=60", "cloudflared"} {
				if !strings.Contains(c.Line, part) {
					t.Errorf("install lacks %q: %s", part, c.Line)
				}
			}
		}
		if strings.Contains(c.Line, "sudo") {
			t.Errorf("join runs as root, a step uses sudo: %s", c.Line)
		}
	}
}

func TestTunnelJoinRefusesBeforeChangingAnything(t *testing.T) {
	foreignAccount := Account{UID: 1000, GID: 1000, Home: "/home/supermgmt", Shell: "/bin/bash", PrimaryGroup: "supermgmt"}
	tests := map[string]struct {
		arrange func(h *tunnelHost, r *TunnelRequest)
		code    smerr.Code
	}{
		"malformed key":         {func(_ *tunnelHost, r *TunnelRequest) { r.AuthorizedKey = "not a key; rm -rf /" }, smerr.CodeInvalidArgument},
		"malformed instance id": {func(_ *tunnelHost, r *TunnelRequest) { r.InstanceID = "id with space" }, smerr.CodeInvalidArgument},
		"not root or no systemd": {func(h *tunnelHost, _ *TunnelRequest) {
			h.tunnelErr = smerr.New(smerr.CodeCapabilityUnavailable, "", "no systemd")
		}, smerr.CodeCapabilityUnavailable},
		"no host key":            {func(h *tunnelHost, _ *TunnelRequest) { h.files = map[string][]byte{} }, smerr.CodeCapabilityUnavailable},
		"foreign account":        {func(h *tunnelHost, _ *TunnelRequest) { h.accounts["supermgmt"] = foreignAccount }, smerr.CodeConflict},
		"unsupported distro":     {func(h *tunnelHost, _ *TunnelRequest) { h.node.os = "debian bookworm\n" }, smerr.CodeCapabilityUnavailable},
		"foreign source, no pkg": {func(h *tunnelHost, _ *TunnelRequest) { h.node.files[templates.CloudflaredSourcePath] = "deb other\n" }, smerr.CodeConflict},
		"unreadable os-release":  {func(h *tunnelHost, _ *TunnelRequest) { h.node.failing = "setup.os_release" }, smerr.CodeCapabilityUnavailable},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			host := newTunnelHost(t)
			request := TunnelRequest{InstanceID: instanceID, AuthorizedKey: host.instanceKey}
			tc.arrange(host, &request)
			asked := false

			_, err := TunnelJoiner{Host: host}.Run(context.Background(), request, func() (audit.Secret, error) {
				asked = true
				return connectorToken, nil
			})

			if err == nil {
				t.Fatal("accepted")
			}
			if tc.code != "" && smerr.CodeOf(err) != tc.code {
				t.Errorf("code = %v, want %v (%v)", smerr.CodeOf(err), tc.code, err)
			}
			if asked {
				t.Error("the token was asked for before the checks passed")
			}
			host.untouched(t)
		})
	}
}

func TestTunnelJoinRefusesABadTokenBeforeWritingAnything(t *testing.T) {
	for name, token := range map[string]string{"short": "abc", "spaces": "eyJh IjoiYWNjb3VudCIsInQiOiJ0dW5uZWwtaWQ", "newline": connectorToken + "\nmore", "empty": ""} {
		t.Run(name, func(t *testing.T) {
			host := newTunnelHost(t)
			_, err := host.run(token)
			if smerr.CodeOf(err) != smerr.CodeInvalidArgument {
				t.Fatalf("err = %v", err)
			}
			if token != "" && strings.Contains(err.Error(), token) {
				t.Errorf("the error carries the token: %v", err)
			}
			host.untouched(t)
		})
	}
}

func TestTunnelJoinStopsWhenTheTokenCannotBeRead(t *testing.T) {
	host := newTunnelHost(t)
	boom := errors.New("no terminal")

	_, err := TunnelJoiner{Host: host}.Run(context.Background(),
		TunnelRequest{InstanceID: instanceID, AuthorizedKey: host.instanceKey},
		func() (audit.Secret, error) { return "", boom })

	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	host.untouched(t)
}

func TestTunnelJoinUsesAnInstalledCloudflaredBesideAForeignSource(t *testing.T) {
	host := newTunnelHost(t)
	host.node.installed = true
	host.node.files[templates.CloudflaredSourcePath] = "deb [signed-by=/x] https://pkg.cloudflare.com/cloudflared any main\n"

	if _, err := host.run(connectorToken); err != nil {
		t.Fatal(err)
	}

	if host.node.files[templates.CloudflaredSourcePath] != "deb [signed-by=/x] https://pkg.cloudflare.com/cloudflared any main\n" {
		t.Error("the foreign source was rewritten")
	}
	if _, ok := host.node.files[templates.CloudflareKeyringPath]; ok || host.node.count("setup.apt_install_cloudflared") != 0 {
		t.Error("the repository or the package was touched")
	}
	if host.node.files[templates.CloudflaredTokenPath] != systemd.ConnectorTokenFile(connectorToken) {
		t.Error("the connector was not configured")
	}
}

func TestTunnelJoinRerunChangesNothingAndPrintsTheSameFingerprint(t *testing.T) {
	host := newTunnelHost(t)
	first, err := host.run(connectorToken)
	if err != nil {
		t.Fatal(err)
	}
	before := len(host.node.calls)
	keysBefore := host.installed[templates.AuthorizedKeysPath]

	second, err := host.run(connectorToken)

	if err != nil || second != first {
		t.Fatalf("second = %q, %v; first %q", second, err, first)
	}
	for _, c := range host.node.calls[before:] {
		switch c.Template {
		case "setup.file_stage", "setup.file_commit", "setup.apt_install_cloudflared", "setup.apt_update_cloudflared", "setup.tunnel_restart":
			t.Errorf("the rerun changed the node: %s", c.Template)
		}
	}
	if host.node.restarts != 0 {
		t.Errorf("restarts = %d", host.node.restarts)
	}
	if host.installed[templates.AuthorizedKeysPath] != keysBefore {
		t.Error("the key line changed")
	}
}

func TestTunnelJoinReplacesADifferentTokenAndRestartsTheConnector(t *testing.T) {
	host := newTunnelHost(t)
	if _, err := host.run(connectorToken); err != nil {
		t.Fatal(err)
	}
	installs := host.node.count("setup.apt_install_cloudflared")

	if _, err := host.run(otherConnectorToken); err != nil {
		t.Fatal(err)
	}

	if host.node.files[templates.CloudflaredTokenPath] != systemd.ConnectorTokenFile(otherConnectorToken) {
		t.Error("the token was not replaced")
	}
	if host.node.restarts != 1 {
		t.Errorf("restarts = %d, want 1", host.node.restarts)
	}
	if _, left := host.node.files[templates.CloudflaredRestartPendingPath]; left {
		t.Error("the restart-pending marker was left behind")
	}
	if host.node.count("setup.apt_install_cloudflared") != installs {
		t.Error("cloudflared was installed again")
	}
}

func TestTunnelJoinKeepsTheTokenOutOfEveryLineAndError(t *testing.T) {
	host := newTunnelHost(t)
	host.node.failing = "setup.tunnel_enable"

	_, err := host.run(connectorToken)

	if err == nil {
		t.Fatal("the failing step was accepted")
	}
	if strings.Contains(err.Error(), connectorToken) {
		t.Errorf("the error carries the token: %v", err)
	}
	for _, c := range host.node.calls {
		if strings.Contains(c.Line, connectorToken) || strings.Contains(c.Template, connectorToken) {
			t.Errorf("the token is in the command line of %s", c.Template)
		}
		if strings.Contains(string(c.Stdin), connectorToken) && !c.Sensitive {
			t.Errorf("the token reaches %s on stdin without the sensitive mark", c.Template)
		}
	}
}

func TestTunnelJoinFailsWhenTheInstallFailsAndLeavesNoAccount(t *testing.T) {
	host := newTunnelHost(t)
	host.node.failing = "setup.apt_install_cloudflared"

	if _, err := host.run(connectorToken); err == nil {
		t.Fatal("accepted")
	}
	if host.did("add supermgmt") {
		t.Error("the account was created after a failed install")
	}
}

func FuzzReadHostKey(f *testing.F) {
	f.Add([]byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC/0rZjuLbOAYMUDGUQxdU6VZp13y6BXawIDIRfDnJPc root@edge-1\n"))
	f.Add([]byte("garbage"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, raw []byte) {
		host := newFakeHost()
		host.files["/etc/ssh/ssh_host_ed25519_key.pub"] = raw
		key, err := readHostKey(host)
		if err == nil && !strings.HasPrefix(cryptossh.FingerprintSHA256(key), "SHA256:") {
			t.Fatalf("fingerprint of %q", raw)
		}
	})
}
