package systemd

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/audit"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

const tunnelToken = "eyJhIjoiYWNjb3VudCIsInQiOiJ0dW5uZWwtaWQiLCJzIjoic2VjcmV0LXNlbnRpbmVsLTEyMzQifQ=="

// openPGPPacket frames body as an old-format packet with a two-octet length.
func openPGPPacket(tag int, body []byte) []byte {
	return append([]byte{0x80 | byte(tag)<<2 | 1, byte(len(body) >> 8), byte(len(body))}, body...)
}

// publicKeyBody is a V4 public-key packet body; salt makes keys differ.
func publicKeyBody(salt byte) []byte {
	return []byte{4, 0, 0, 0, 1, 22, 9, 0xAA, salt, 0xBB}
}

func fingerprintOf(body []byte) string {
	h := sha1.New()
	h.Write([]byte{0x99, byte(len(body) >> 8), byte(len(body))})
	h.Write(body)
	return strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
}

// testKeyring is a keyring of one primary key, a user id and a signature.
func testKeyring() []byte {
	ring := openPGPPacket(6, publicKeyBody(1))
	ring = append(ring, openPGPPacket(13, []byte("Cloudflare <test@example.com>"))...)
	return append(ring, openPGPPacket(2, []byte{4, 0x13, 1, 2, 3})...)
}

// pinTestKey replaces the build's pin for the test.
func pinTestKey(t *testing.T) []byte {
	t.Helper()
	ring := testKeyring()
	previous := cloudflarePin
	cloudflarePin = pinnedKey{fingerprint: fingerprintOf(publicKeyBody(1)), keyringBase64: base64.StdEncoding.EncodeToString(ring)}
	t.Cleanup(func() { cloudflarePin = previous })
	return ring
}

func tunnelParams() SetupParams {
	p := setupParams()
	p.Tunnel = &TunnelParams{Token: audit.Secret(tunnelToken)}
	return p
}

// tunnelNode simulates the commands the tunnel steps issue on a Debian 13 node.
type tunnelNode struct {
	*setupNode
	installed bool   // cloudflared package state
	active    string // ActiveState of the unit
	os        string
	removed   []string // paths setup.file_remove was asked for
}

func newTunnelNode(t *testing.T) *tunnelNode {
	n := &tunnelNode{setupNode: newSetupNode(t), active: "inactive", os: "debian trixie\n"}
	n.on("setup.os_release", func(templates.Command) transport.Result { return transport.Result{Stdout: []byte(n.os)} })
	n.on("setup.cloudflared_package", func(templates.Command) transport.Result {
		if n.installed {
			return transport.Result{Stdout: []byte("ii  2026.10.1\n")}
		}
		return transport.Result{ExitStatus: 1}
	})
	n.on("systemd.show", func(templates.Command) transport.Result {
		return transport.Result{Stdout: []byte("Id=" + templates.CloudflaredUnitName + "\nLoadState=loaded\nActiveState=" + n.active + "\n")}
	})
	for _, suffix := range []string{"", templates.SudoVariantSuffix} {
		n.on("setup.file_sha256"+suffix, func(c templates.Command) transport.Result {
			content, ok := n.files[argument(c.Line, -1)]
			if !ok {
				return transport.Result{ExitStatus: 3}
			}
			return transport.Result{Stdout: []byte(sha256Hex(content) + "  -\n")}
		})
		n.on("setup.file_remove"+suffix, func(c templates.Command) transport.Result {
			path := argument(c.Line, -1)
			n.removed = append(n.removed, path)
			delete(n.files, path)
			return transport.Result{}
		})
		n.on("setup.apt_install_cloudflared"+suffix, func(templates.Command) transport.Result {
			n.installed = true
			return transport.Result{}
		})
		n.on("setup.apt_remove_cloudflared"+suffix, func(templates.Command) transport.Result {
			n.installed = false
			return transport.Result{}
		})
		n.on("setup.tunnel_enable"+suffix, func(templates.Command) transport.Result {
			n.active = "active"
			return transport.Result{}
		})
		n.on("setup.tunnel_disable"+suffix, func(templates.Command) transport.Result {
			n.active = "inactive"
			return transport.Result{}
		})
		for _, base := range []string{"setup.apt_update_cloudflared", "setup.daemon_reload", "setup.tunnel_restart", "setup.dir_remove"} {
			n.on(base+suffix, ok)
		}
	}
	return n
}

// at is the index of the first call of template whose line contains substr, or -1.
func (n *tunnelNode) at(template, substr string) int {
	return slices.IndexFunc(n.calls, func(c templates.Command) bool {
		return c.Template == template && strings.Contains(c.Line, substr)
	})
}

func (n *tunnelNode) staged(path string) int {
	return n.countLines("setup.file_stage", quoted(path+templates.StagingSuffix))
}

func (n *tunnelNode) countLines(template, substr string) int {
	count := 0
	for _, c := range n.calls {
		if c.Template == template && strings.Contains(c.Line, substr) {
			count++
		}
	}
	return count
}

// quoted single-quotes s as a rendered argument.
func quoted(s string) string { return "'" + s + "'" }

func TestKeyringFingerprint(t *testing.T) {
	want := fingerprintOf(publicKeyBody(1))
	got, err := keyringFingerprint(testKeyring())
	if err != nil || got != want {
		t.Fatalf("got %q, %v; want %q", got, err, want)
	}
	newFormat := append([]byte{0xC0 | 6, byte(len(publicKeyBody(2)))}, publicKeyBody(2)...)
	if got, err := keyringFingerprint(newFormat); err != nil || got != fingerprintOf(publicKeyBody(2)) {
		t.Errorf("new-format packet: %q, %v", got, err)
	}
	subkey := append(testKeyring(), openPGPPacket(14, publicKeyBody(3))...)
	if got, err := keyringFingerprint(subkey); err != nil || got != want {
		t.Errorf("a subkey must not change the fingerprint: %q, %v", got, err)
	}
	refused := map[string][]byte{
		"two primary keys": append(testKeyring(), openPGPPacket(6, publicKeyBody(2))...),
		"no primary key":   openPGPPacket(13, []byte("id")),
		"empty":            nil,
		"truncated":        testKeyring()[:8],
		"not a packet":     {0x01, 0x02},
		"v3 key":           openPGPPacket(6, []byte{3, 0, 0, 0, 1}),
		"partial length":   {0xC0 | 6, 0xE0, 1},
		"indeterminate":    {0x80 | 6<<2 | 3, 4, 0, 0},
	}
	for name, ring := range refused {
		t.Run(name, func(t *testing.T) {
			if _, err := keyringFingerprint(ring); err == nil {
				t.Error("accepted")
			}
		})
	}
}

func TestPinnedKeyMustMatchItsFingerprint(t *testing.T) {
	ring := base64.StdEncoding.EncodeToString(testKeyring())
	good := fingerprintOf(publicKeyBody(1))
	for name, pin := range map[string]pinnedKey{
		"empty (as shipped until filled)": {},
		"no fingerprint":                  {keyringBase64: ring},
		"no keyring":                      {fingerprint: good},
		"other fingerprint":               {fingerprint: fingerprintOf(publicKeyBody(9)), keyringBase64: ring},
		"not base64":                      {fingerprint: good, keyringBase64: "%%%"},
	} {
		if _, err := pin.keyring(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	spaced := strings.ToLower(good[:20] + " " + good[20:])
	if _, err := (pinnedKey{fingerprint: spaced, keyringBase64: ring}).keyring(); err != nil {
		t.Errorf("a spaced, lower-case fingerprint must match: %v", err)
	}
}

func TestTheBuildPinsAUsableCloudflareKey(t *testing.T) {
	if _, err := cloudflarePin.keyring(); err != nil {
		t.Fatalf("the embedded pin is unusable: %v", err)
	}
}

func TestSetupWithTunnelFailsClosedWhileTheKeyIsNotPinned(t *testing.T) {
	previous := cloudflarePin
	cloudflarePin = pinnedKey{}
	t.Cleanup(func() { cloudflarePin = previous })
	node := newTunnelNode(t)
	if _, err := Setup(context.Background(), node, tunnelParams()); err == nil || !strings.Contains(err.Error(), "not pinned") {
		t.Fatalf("got %v", err)
	}
	if len(node.calls) != 0 {
		t.Errorf("node contacted: %v", node.ran())
	}
}

func TestTunnelParamsValidation(t *testing.T) {
	pinTestKey(t)
	for _, token := range []string{"", "short", tunnelToken + "\n", "has space " + tunnelToken, tunnelToken + ";id", strings.Repeat("a", 4097)} {
		p := tunnelParams()
		p.Tunnel.Token = audit.Secret(token)
		err := p.Validate()
		if err == nil {
			t.Errorf("token %q accepted", token)
		} else if token != "" && strings.Contains(err.Error(), token) {
			t.Errorf("the error repeats the token: %v", err)
		}
	}
	if err := tunnelParams().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestSetupInstallsTheTunnelBeforeTheKeyAndInTheRightOrder(t *testing.T) {
	ring := pinTestKey(t)
	node := newTunnelNode(t)
	out, err := Setup(context.Background(), node, tunnelParams())
	if err != nil {
		t.Fatal(err)
	}
	if out.Tunnel == nil || !out.Tunnel.PackageManaged {
		t.Errorf("outcome = %+v", out.Tunnel)
	}
	if node.files[templates.CloudflareKeyringPath] != string(ring) {
		t.Error("the keyring on the node is not the pinned one")
	}
	if got, want := node.files[templates.CloudflaredSourcePath], "deb [signed-by=/etc/apt/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main\n"; got != want {
		t.Errorf("source = %q", got)
	}
	if got := node.files[templates.CloudflaredTokenPath]; got != tunnelToken+"\n" {
		t.Error("the token file does not hold the token")
	}
	unit := node.files[templates.CloudflaredUnitPath]
	if !strings.Contains(unit, "\nExecStart=/usr/bin/cloudflared --no-autoupdate tunnel run --token-file /etc/supermgmt/cloudflared/token\n") {
		t.Errorf("unit = %s", unit)
	}
	if strings.Contains(unit, tunnelToken) || strings.Contains(unit, "Environment") {
		t.Error("the unit carries the token")
	}

	order := []int{
		node.at("setup.os_release", ""),
		node.at("setup.file_commit", quoted(templates.CloudflareKeyringPath)),
		node.at("setup.file_commit", quoted(templates.CloudflaredSourcePath)),
		node.at("setup.apt_update_cloudflared", ""),
		node.at("setup.apt_install_cloudflared", ""),
		node.at("setup.dir", quoted(templates.CloudflaredDir)),
		node.at("setup.file_commit", quoted(templates.CloudflaredTokenPath)),
		node.at("setup.file_commit", quoted(templates.CloudflaredUnitPath)),
		node.at("setup.daemon_reload", ""),
		node.at("setup.tunnel_enable", ""),
		node.at("setup.own_file_commit", ""),
	}
	if slices.Contains(order, -1) || !slices.IsSorted(order) {
		t.Errorf("tunnel steps out of order (indexes %v) in %v", order, node.ran())
	}
	if last := node.calls[len(node.calls)-1].Template; last != "setup.own_file_commit" {
		t.Errorf("authorized_keys must stay the last step, got %s", last)
	}
	if node.count("setup.tunnel_restart") != 0 {
		t.Error("a fresh install must not restart the unit")
	}
	if strings.Contains(node.lines(), "service install") {
		t.Error("cloudflared service install takes the token as an argument")
	}
}

func TestTunnelRepositoryRefreshesOnlyTheCloudflareSource(t *testing.T) {
	pinTestKey(t)
	node := newTunnelNode(t)
	if _, err := Setup(context.Background(), node, tunnelParams()); err != nil {
		t.Fatal(err)
	}
	update := node.calls[node.at("setup.apt_update_cloudflared", "")].Line
	for _, want := range []string{"apt-get update", "Dir::Etc::sourcelist=sources.list.d/cloudflared.list", "Dir::Etc::sourceparts=-"} {
		if !strings.Contains(update, want) {
			t.Errorf("update lacks %s: %s", want, update)
		}
	}
	if node.count("setup.apt_update_cloudflared") != 1 {
		t.Errorf("apt-get update ran %d times", node.count("setup.apt_update_cloudflared"))
	}
}

func TestTunnelSetupIsIdempotent(t *testing.T) {
	pinTestKey(t)
	node := newTunnelNode(t)
	if _, err := Setup(context.Background(), node, tunnelParams()); err != nil {
		t.Fatal(err)
	}
	node.account, node.members = ownAccount, "supermgmt systemd-journal"
	before := len(node.calls)
	out, err := Setup(context.Background(), node, tunnelParams())
	if err != nil {
		t.Fatal(err)
	}
	if out.Tunnel == nil || !out.Tunnel.PackageManaged {
		t.Errorf("a re-run must still own the package: %+v", out.Tunnel)
	}
	rerun := &tunnelNode{setupNode: &setupNode{fakeNode: &fakeNode{calls: node.calls[before:]}}}
	for _, path := range []string{templates.CloudflareKeyringPath, templates.CloudflaredSourcePath, templates.CloudflaredTokenPath, templates.CloudflaredUnitPath} {
		if rerun.countLines("setup.file_stage", quoted(path+templates.StagingSuffix)) != 0 {
			t.Errorf("%s was rewritten although its hash matched", path)
		}
	}
	for _, name := range []string{"setup.apt_update_cloudflared", "setup.apt_install_cloudflared", "setup.tunnel_restart"} {
		if rerun.count(name) != 0 {
			t.Errorf("%s ran on a converged node", name)
		}
	}
}

func TestChangedTokenRewritesOnlyTheTokenAndRestartsARunningUnit(t *testing.T) {
	pinTestKey(t)
	node := newTunnelNode(t)
	if _, err := Setup(context.Background(), node, tunnelParams()); err != nil {
		t.Fatal(err)
	}
	node.account, node.members = ownAccount, "supermgmt systemd-journal"
	before := len(node.calls)
	rotated := tunnelParams()
	rotated.Tunnel.Token = audit.Secret("ROTATED" + tunnelToken)
	if _, err := Setup(context.Background(), node, rotated); err != nil {
		t.Fatal(err)
	}
	rerun := &tunnelNode{setupNode: &setupNode{fakeNode: &fakeNode{calls: node.calls[before:]}}}
	if rerun.staged(templates.CloudflaredTokenPath) != 1 || rerun.staged(templates.CloudflaredUnitPath) != 0 || rerun.staged(templates.CloudflareKeyringPath) != 0 {
		t.Errorf("rewrote the wrong files: %v", rerun.ran())
	}
	if rerun.count("setup.tunnel_restart") != 1 {
		t.Errorf("restart ran %d times", rerun.count("setup.tunnel_restart"))
	}
	if node.files[templates.CloudflaredTokenPath] != "ROTATED"+tunnelToken+"\n" {
		t.Error("the node still holds the old token")
	}
}

func TestTheTokenReachesTheNodeOnlyAsSensitiveStdinOfTheTokenStagingStep(t *testing.T) {
	pinTestKey(t)
	node := newTunnelNode(t)
	if _, err := Setup(context.Background(), node, tunnelParams()); err != nil {
		t.Fatal(err)
	}
	carriers := 0
	for _, c := range node.calls {
		if strings.Contains(c.Line, tunnelToken) || strings.Contains(c.Template, tunnelToken) {
			t.Errorf("the token is in the command line of %s", c.Template)
		}
		if !strings.Contains(string(c.Stdin), tunnelToken) {
			continue
		}
		carriers++
		if c.Template != "setup.file_stage" || !strings.Contains(c.Line, quoted(templates.CloudflaredTokenPath+templates.StagingSuffix)) || !c.Sensitive {
			t.Errorf("token on stdin of %s (sensitive=%v)", c.Template, c.Sensitive)
		}
	}
	if carriers != 1 {
		t.Errorf("%d commands carried the token", carriers)
	}
	for _, c := range node.calls {
		if c.Sensitive && !strings.Contains(c.Line, "cloudflared") && c.Template != "setup.file_sha256" {
			t.Errorf("unexpected sensitive command %s", c.Template)
		}
	}
}

func TestTheTokenNeverReachesAnErrorOrAFormattedParameter(t *testing.T) {
	pinTestKey(t)
	t.Run("a failing token step echoing it", func(t *testing.T) {
		node := newTunnelNode(t)
		node.on("setup.file_stage", func(c templates.Command) transport.Result {
			if strings.Contains(c.Line, templates.CloudflaredTokenPath) {
				return transport.Result{ExitStatus: 1, Stderr: []byte("install: cannot write " + string(c.Stdin))}
			}
			node.staging[argument(c.Line, -1)] = string(c.Stdin)
			return transport.Result{}
		})
		_, err := Setup(context.Background(), node, tunnelParams())
		if err == nil || strings.Contains(err.Error(), tunnelToken) || !strings.Contains(err.Error(), "withheld") {
			t.Fatalf("err = %v", err)
		}
		if node.at("setup.file_discard", quoted(templates.CloudflaredTokenPath+templates.StagingSuffix)) < 0 {
			t.Error("the staged token was not discarded")
		}
	})
	t.Run("a node that stores something else", func(t *testing.T) {
		node := newTunnelNode(t)
		inner := node.handlers["setup.file_commit"]
		node.on("setup.file_commit", func(c templates.Command) transport.Result {
			res := inner(c)
			if argument(c.Line, -1) == templates.CloudflaredTokenPath {
				node.files[templates.CloudflaredTokenPath] = "tampered"
			}
			return res
		})
		_, err := Setup(context.Background(), node, tunnelParams())
		if err == nil || strings.Contains(err.Error(), tunnelToken) || !strings.Contains(err.Error(), "expected content") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("formatting the parameters", func(t *testing.T) {
		p := tunnelParams()
		for _, got := range []string{fmt.Sprintf("%v", p), fmt.Sprintf("%+v", p), fmt.Sprintf("%#v", p), fmt.Sprint(p.Tunnel)} {
			if strings.Contains(got, tunnelToken) {
				t.Errorf("formatted parameters show the token: %s", got)
			}
		}
	})
}

func TestTheKeyringOnTheNodeMustBeThePinnedOne(t *testing.T) {
	pinTestKey(t)
	node := newTunnelNode(t)
	inner := node.handlers["setup.file_commit"]
	node.on("setup.file_commit", func(c templates.Command) transport.Result {
		res := inner(c)
		if argument(c.Line, -1) == templates.CloudflareKeyringPath {
			node.files[templates.CloudflareKeyringPath] += "extra key"
		}
		return res
	})
	_, err := Setup(context.Background(), node, tunnelParams())
	if err == nil || !strings.Contains(err.Error(), templates.CloudflareKeyringPath) {
		t.Fatalf("err = %v", err)
	}
	if node.count("setup.apt_install_cloudflared") != 0 || node.at("setup.file_commit", quoted(templates.CloudflaredSourcePath)) >= 0 {
		t.Error("setup went on with a key that is not the pinned one")
	}
}

func TestTunnelSetupRefusesUnsupportedDistributionsAndForeignSources(t *testing.T) {
	pinTestKey(t)
	for name, os := range map[string]string{
		"debian 12":     "debian bookworm\n",
		"ubuntu 22.04":  "ubuntu jammy\n",
		"mismatch":      "debian noble\n",
		"other distro":  "alpine \n",
		"unreadable":    "\n",
		"ubuntu 24.04+": "ubuntu noble extra\n",
	} {
		t.Run(name, func(t *testing.T) {
			node := newTunnelNode(t)
			node.os = os
			_, err := Setup(context.Background(), node, tunnelParams())
			if smerr.CodeOf(err) != smerr.CodeCapabilityUnavailable {
				t.Fatalf("err = %v", err)
			}
			if node.count("setup.file_stage") > 3 {
				t.Error("tunnel files were written")
			}
		})
	}
	t.Run("ubuntu 24.04 is accepted with the same source", func(t *testing.T) {
		node := newTunnelNode(t)
		node.os = "ubuntu noble\n"
		if _, err := Setup(context.Background(), node, tunnelParams()); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(node.files[templates.CloudflaredSourcePath], "/cloudflared any main\n") {
			t.Errorf("source = %q", node.files[templates.CloudflaredSourcePath])
		}
	})
	t.Run("a source file with other content is never replaced", func(t *testing.T) {
		node := newTunnelNode(t)
		node.files[templates.CloudflaredSourcePath] = "deb https://pkg.cloudflare.com/cloudflared any main\n"
		_, err := Setup(context.Background(), node, tunnelParams())
		if smerr.CodeOf(err) != smerr.CodeConflict {
			t.Fatalf("err = %v", err)
		}
		if node.staged(templates.CloudflaredSourcePath) != 0 || node.staged(templates.CloudflaredTokenPath) != 0 {
			t.Error("setup wrote files after the conflict")
		}
	})
}

func TestAnInactiveUnitAfterStartFailsSetup(t *testing.T) {
	pinTestKey(t)
	node := newTunnelNode(t)
	node.on("setup.tunnel_enable", func(templates.Command) transport.Result { node.active = "activating"; return transport.Result{} })
	_, err := Setup(context.Background(), node, tunnelParams())
	if smerr.CodeOf(err) != smerr.CodeCapabilityUnavailable || !strings.Contains(err.Error(), "not active") {
		t.Fatalf("err = %v", err)
	}
	if node.count("setup.own_file_commit") != 0 {
		t.Error("the key was installed although the tunnel did not start")
	}
}

func TestTunnelStepsUseSudoWhenAdminIsNotRoot(t *testing.T) {
	pinTestKey(t)
	node := newTunnelNode(t)
	p := tunnelParams()
	p.AdminIsRoot = false
	if _, err := Setup(context.Background(), node, p); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"setup.file_sha256", "setup.apt_update_cloudflared", "setup.apt_install_cloudflared", "setup.daemon_reload", "setup.tunnel_enable"} {
		if node.count(name+templates.SudoVariantSuffix) == 0 || node.count(name) != 0 {
			t.Errorf("%s did not run through sudo: %v", name, node.ran())
		}
	}
	install := node.calls[node.at("setup.apt_install_cloudflared.sudo", "")].Line
	if !strings.HasPrefix(install, "sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y") {
		t.Errorf("install = %s", install)
	}
}

func TestAnExistingCloudflaredIsUsedAndNeverManaged(t *testing.T) {
	pinTestKey(t)
	node := newTunnelNode(t)
	node.installed = true
	out, err := Setup(context.Background(), node, tunnelParams())
	if err != nil {
		t.Fatal(err)
	}
	if out.Tunnel == nil || out.Tunnel.PackageManaged {
		t.Errorf("outcome = %+v", out.Tunnel)
	}
	for _, name := range []string{"setup.apt_update_cloudflared", "setup.apt_install_cloudflared"} {
		if node.count(name) != 0 {
			t.Errorf("%s ran against a cloudflared setup did not install", name)
		}
	}
	for _, path := range []string{templates.CloudflareKeyringPath, templates.CloudflaredSourcePath} {
		if _, written := node.files[path]; written {
			t.Errorf("%s was written for a foreign install", path)
		}
	}
	if node.files[templates.CloudflaredTokenPath] == "" || node.files[templates.CloudflaredUnitPath] == "" {
		t.Error("the service must still be installed")
	}

	if err := RemoveTunnel(context.Background(), node, RemoveTunnelParams{AdminIsRoot: true}); err != nil {
		t.Fatal(err)
	}
	if node.count("setup.apt_remove_cloudflared") != 0 || !node.installed {
		t.Error("the package setup did not install was removed")
	}
	for _, path := range node.removed {
		if path == templates.CloudflaredSourcePath || path == templates.CloudflareKeyringPath {
			t.Errorf("removed %s, which setup never wrote", path)
		}
	}
}

func TestRemoveTunnelRemovesOnlyWhatSetupInstalled(t *testing.T) {
	pinTestKey(t)
	node := newTunnelNode(t)
	if _, err := Setup(context.Background(), node, tunnelParams()); err != nil {
		t.Fatal(err)
	}
	owned := []string{templates.CloudflareKeyringPath, templates.CloudflaredSourcePath, templates.CloudflaredTokenPath, templates.CloudflaredUnitPath}
	kept := map[string]string{}
	for path, content := range node.files {
		if !slices.Contains(owned, path) {
			kept[path] = content
		}
	}
	node.calls = nil
	for run := 1; run <= 2; run++ { // the second run proves idempotence
		if err := RemoveTunnel(context.Background(), node, RemoveTunnelParams{AdminIsRoot: true}); err != nil {
			t.Fatalf("run %d: %v", run, err)
		}
	}
	for _, path := range owned {
		if _, left := node.files[path]; left {
			t.Errorf("%s was left behind", path)
		}
	}
	for path, content := range kept {
		if node.files[path] != content {
			t.Errorf("%s was touched", path)
		}
	}
	for _, path := range node.removed {
		if !slices.Contains(owned, path) {
			t.Errorf("setup.file_remove ran on %s", path)
		}
	}
	if node.installed {
		t.Error("the package setup installed is still there")
	}
	if node.at("setup.tunnel_disable", "") > node.at("setup.file_remove", quoted(templates.CloudflaredUnitPath)) {
		t.Error("the unit was removed before it was stopped")
	}
	if node.at("setup.file_remove", quoted(templates.CloudflaredTokenPath)) > node.at("setup.dir_remove", quoted(templates.CloudflaredDir)) {
		t.Error("the token directory was removed before the token")
	}
	for _, c := range node.calls {
		if strings.Contains(c.Line, "rm -rf") || strings.Contains(c.Line, "purge") {
			t.Errorf("destructive command: %s", c.Line)
		}
	}
}

func TestRemoveTunnelLeavesAForeignRepositoryAndItsPackage(t *testing.T) {
	pinTestKey(t)
	node := newTunnelNode(t)
	node.installed = true
	node.files[templates.CloudflaredSourcePath] = "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main\n"
	node.files[templates.CloudflareKeyringPath] = "their key"
	if err := RemoveTunnel(context.Background(), node, RemoveTunnelParams{AdminIsRoot: false}); err != nil {
		t.Fatal(err)
	}
	if node.count("setup.apt_remove_cloudflared.sudo")+node.count("setup.apt_remove_cloudflared") != 0 || !node.installed {
		t.Error("the package was removed")
	}
	if len(node.files) != 2 {
		t.Errorf("foreign files touched: %v", node.files)
	}
}

func TestRemoveTunnelStopsAtTheFirstFailure(t *testing.T) {
	pinTestKey(t)
	node := newTunnelNode(t)
	node.on("setup.tunnel_disable", func(templates.Command) transport.Result {
		return transport.Result{ExitStatus: 1, Stderr: []byte("Failed to disable unit")}
	})
	err := RemoveTunnel(context.Background(), node, RemoveTunnelParams{AdminIsRoot: true})
	if err == nil || !strings.Contains(err.Error(), "node.tunnel.disable step service") {
		t.Fatalf("err = %v", err)
	}
	if node.count("setup.file_remove") != 0 {
		t.Error("files were removed while the service could not be stopped")
	}
}
