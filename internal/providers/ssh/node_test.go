package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/runtimes"
)

func hostKey(t *testing.T) string {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	key, err := cryptossh.NewPublicKey(public)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	return strings.TrimSpace(string(cryptossh.MarshalAuthorizedKey(key)))
}

func testNode(t *testing.T) domain.Node {
	t.Helper()
	return domain.Node{
		ID: "n1",
		Endpoint: domain.NodeEndpoint{
			Host: "10.0.0.5", Port: 2222, User: "supermgmt", AdminUser: "alex",
			AdminCredentialRef: "ssh-agent://default", HostPublicKey: hostKey(t),
		},
	}
}

func TestAutomatedSessionsUseTheDedicatedUserOnlyAfterSetup(t *testing.T) {
	node := testNode(t)
	setup := &runtimes.SetupMeta{KeyRef: "secret://ssh/default", KeyVersion: 3}

	before := AutomatedTarget(node, nil)
	after := AutomatedTarget(node, setup)

	if before.User != "alex" || before.CredentialRef != "ssh-agent://default" {
		t.Errorf("before setup = %s with %s, want the admin account", before.User, before.CredentialRef)
	}
	if after.User != "supermgmt" || after.CredentialRef != "secret://ssh/default@3" {
		t.Errorf("after setup = %s with %s, want supermgmt with the pinned key version", after.User, after.CredentialRef)
	}
	if after.Host != "10.0.0.5" || after.Port != 2222 || after.HostKey != node.Endpoint.HostPublicKey {
		t.Errorf("target does not carry the endpoint: %+v", after)
	}
}

func TestSetupAndInteractiveSessionsAlwaysUseTheAdminAccount(t *testing.T) {
	node := testNode(t)

	target := AdminTarget(node)

	if target.User != "alex" || target.CredentialRef != "ssh-agent://default" {
		t.Errorf("admin target = %s with %s", target.User, target.CredentialRef)
	}
}

func TestPinnedRefWithoutVersionMeansLatest(t *testing.T) {
	if got := PinnedRef(runtimes.SetupMeta{KeyRef: "secret://ssh/default"}); got != "secret://ssh/default" {
		t.Errorf("PinnedRef = %q", got)
	}
}

func TestFingerprintMatchesTheKey(t *testing.T) {
	key := hostKey(t)

	got, err := Fingerprint(key)

	if err != nil || !strings.HasPrefix(got, "SHA256:") {
		t.Errorf("Fingerprint = %q, %v", got, err)
	}
}

func TestParseHostKeyRejectsAnythingButOneKey(t *testing.T) {
	key := hostKey(t)
	for name, in := range map[string]string{
		"empty":     "",
		"garbage":   "not a key",
		"two keys":  key + "\n" + key,
		"truncated": key[:len(key)/2],
	} {
		if _, err := ParseHostKey(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestValidateEndpointAcceptsNamesAndAddressesOnly(t *testing.T) {
	tests := []struct {
		host string
		port int
		ok   bool
	}{
		{"web-1.example.com", 22, true},
		{"10.0.0.5", 22, true},
		{"2001:db8::1", 22, true},
		{"-oProxyCommand=x", 22, false},
		{"user@host", 22, false},
		{"host name", 22, false},
		{"host;rm", 22, false},
		{"", 22, false},
		{"fe80::1%eth0", 22, false},
		{"host", 0, false},
		{"host", 65536, false},
	}
	for _, tt := range tests {
		if err := ValidateEndpoint(tt.host, tt.port); (err == nil) != tt.ok {
			t.Errorf("ValidateEndpoint(%q, %d) = %v, want ok=%v", tt.host, tt.port, err, tt.ok)
		}
	}
}

func TestValidateCredentialRefByMode(t *testing.T) {
	tests := []struct {
		ref  string
		mode config.Mode
		ok   bool
	}{
		{"secret://ssh/default", config.ModeLocal, true},
		{"ssh-agent://default", config.ModeLocal, true},
		{"ssh-agent://default", config.ModeServer, false},
		{"file:///home/a/.ssh/id", config.ModeLocal, true},
		{"file://relative", config.ModeLocal, false},
		{"secret://", config.ModeLocal, false},
		{"literal-key-material", config.ModeLocal, false},
	}
	for _, tt := range tests {
		if err := ValidateCredentialRef("credential_ref", tt.ref, tt.mode); (err == nil) != tt.ok {
			t.Errorf("ValidateCredentialRef(%q, %s) = %v, want ok=%v", tt.ref, tt.mode, err, tt.ok)
		}
	}
}

func TestEndpointDefaultsFollowTheMode(t *testing.T) {
	local := Endpoint{Host: "h", AdminUser: "alex"}.Defaults(config.ModeLocal)
	server := Endpoint{Host: "h", AdminUser: "alex"}.Defaults(config.ModeServer)

	if local.Port != 22 || local.User != "supermgmt" || local.CredentialRef != "secret://ssh/default" || local.AdminCredentialRef != "ssh-agent://default" {
		t.Errorf("local defaults = %+v", local)
	}
	if server.AdminCredentialRef != "" {
		t.Errorf("server mode must have no admin credential default, got %q", server.AdminCredentialRef)
	}
}

func TestEndpointValidateRequiresAHostKeyAndAdminCredential(t *testing.T) {
	good := Endpoint{Host: "h", AdminUser: "alex", HostPublicKey: hostKey(t)}.Defaults(config.ModeLocal)
	if err := good.Validate(config.ModeLocal); err != nil {
		t.Fatalf("valid endpoint: %v", err)
	}

	noKey := good
	noKey.HostPublicKey = ""
	noAdminCredential := good
	noAdminCredential.AdminCredentialRef = ""
	badUser := good
	badUser.User = "Root"
	for name, e := range map[string]Endpoint{"no host key": noKey, "no admin credential": noAdminCredential, "bad user": badUser} {
		if err := e.Validate(config.ModeLocal); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestFromConfigAppliesDefaults(t *testing.T) {
	key := hostKey(t)
	p := config.SSHProvider{
		Name:     "web",
		Endpoint: config.SSHEndpoint{Host: "h", Port: 22, User: "supermgmt", AdminUser: "alex", HostPublicKey: key + "\n"},
	}

	e := FromConfig(p, config.ModeLocal)

	if e.HostPublicKey != key || e.AdminCredentialRef != "ssh-agent://default" || e.CredentialRef != "secret://ssh/default" {
		t.Errorf("FromConfig = %+v", e)
	}
	if got := e.NodeEndpoint(); got.AdminUser != "alex" || got.AdminCredentialRef != "ssh-agent://default" {
		t.Errorf("NodeEndpoint = %+v", got)
	}
}

func TestValidateNameIsAnAllowlist(t *testing.T) {
	for name, ok := range map[string]bool{"web-1": true, "a.b_c": true, "": false, "-x": false, "a b": false, strings.Repeat("a", 64): false} {
		if err := ValidateName(name); (err == nil) != ok {
			t.Errorf("ValidateName(%q) = %v, want ok=%v", name, err, ok)
		}
	}
}

func TestAJoinedNodeIsProbedAsTheDedicatedUserBeforeSetup(t *testing.T) {
	node := testNode(t)
	node.Endpoint.AdminUser, node.Endpoint.AdminCredentialRef = "", ""
	node.CredentialRef = "secret://ssh/default@2"

	target := AutomatedTarget(node, nil)

	if target.User != "supermgmt" || target.CredentialRef != "secret://ssh/default@2" {
		t.Errorf("joined node = %s with %s, want supermgmt with the key enrollment pinned", target.User, target.CredentialRef)
	}
}
