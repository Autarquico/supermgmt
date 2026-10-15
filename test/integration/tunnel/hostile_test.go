package tunnel

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	sshtransport "github.com/autarquico/supermgmt/internal/transport/ssh"
)

// Scenario "hostile hostnames and paths are refused": shell syntax, % sequences,
// whitespace and option-like text are rejected before any process starts. The
// unit suites cover each validator; these tests cross the real boundaries
// (HTTP-shaped API over the daemon socket, configuration loading, the job
// engine and the pool) and prove that no carrier process was ever started.

var hostileText = []string{
	"web1;id",
	"web1 && id",
	"$(id)",
	"`id`",
	"web%h",
	"%%",
	"web 1",
	"web\t1",
	"web\n1",
	"-oProxyCommand=id",
	"--hostname=x",
	"web1'",
	`web1"`,
	"web1|id",
	"web1>/tmp/x",
	"../web1",
}

func TestTheAPIRefusesHostileNodeNamesAndHostsBeforeAnyTunnelWork(t *testing.T) {
	d := startDaemon(t, cloudflareBlock)
	for _, hostile := range hostileText {
		if _, err := d.addNode(hostile, "192.0.2.10"); codeOf(err) != smerr.CodeInvalidArgument {
			t.Errorf("node named %q: err = %v, want INVALID_ARGUMENT", hostile, err)
		}
		if _, err := d.addNode("web1", hostile); codeOf(err) != smerr.CodeInvalidArgument {
			t.Errorf("node host %q: err = %v, want INVALID_ARGUMENT", hostile, err)
		}
	}
	if nodes := d.nodes(); len(nodes) != 0 {
		t.Errorf("hostile requests stored %d nodes, want none", len(nodes))
	}
}

func TestTheAPIKeepsATunnelHostnameOutOfAnyRequest(t *testing.T) {
	// tunnel_hostname is derived by the tunnel jobs from the node name and the
	// configured zone; no request field carries it (ADR-0037, endpoint ownership).
	d := startDaemon(t, cloudflareBlock)
	added, err := d.addNode("web1", "192.0.2.10")
	must(t, err)
	if added.Applied == nil {
		t.Fatalf("node.add in a staging environment was parked for approval: %+v", added)
	}
	nodes := d.nodes()
	if len(nodes) != 1 || nodes[0].Endpoint.Transport.Effective() != domain.TransportDirect || nodes[0].Endpoint.TunnelHostname != "" {
		t.Errorf("a new node = %+v, want a direct node with no tunnel hostname", nodes)
	}
}

func TestAHostileCloudflareZoneKeepsTheDaemonFromStarting(t *testing.T) {
	for _, zone := range []string{
		"example.com;id", "ex ample.com", "%h.example.com", "-oProxyCommand=x.com", "example.com/../x", "$(id).example.com",
		"example..com", "*.example.com", "",
	} {
		block := "cloudflare:\n  account_id: 0123456789abcdef0123456789abcdef\n  zone: \"" + zone + "\"\n  owner_emails: [owner@example.test]\n"
		_, err := loadConfig(t, t.TempDir(), block)
		if err == nil {
			t.Errorf("zone %q was accepted", zone)
			continue
		}
		if !strings.Contains(err.Error(), "cloudflare.zone") {
			t.Errorf("zone %q: error %q does not name cloudflare.zone", zone, err)
		}
	}
}

func TestHostileOwnerEmailsAndReferencesKeepTheDaemonFromStarting(t *testing.T) {
	for name, block := range map[string]string{
		"wildcard owner": "cloudflare:\n  account_id: 0123456789abcdef0123456789abcdef\n  zone: example.test\n  owner_emails: ['*@example.test']\n",
		"empty owners":   "cloudflare:\n  account_id: 0123456789abcdef0123456789abcdef\n  zone: example.test\n  owner_emails: []\n",
		"plaintext token ref": "cloudflare:\n  account_id: 0123456789abcdef0123456789abcdef\n  zone: example.test\n" +
			"  api_token_ref: cf-api-token-in-the-clear\n  owner_emails: [owner@example.test]\n",
		"account id with shell syntax": "cloudflare:\n  account_id: 'abc;id'\n  zone: example.test\n  owner_emails: [owner@example.test]\n",
	} {
		if _, err := loadConfig(t, t.TempDir(), block); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestATunnelHostnameThatIsNotStrictDNSNeverStartsACarrier(t *testing.T) {
	s := newStack(t, stackOptions{})
	for i, hostile := range append([]string{"-oProxyCommand=id.example.test", "ssh-web1.example.test.", "UPPER.example.test", "a..b.test", "web1"}, hostileText...) {
		node := s.addNode("hostile"+strconv.Itoa(i), unreachable(t), "secret://ssh/default")
		// Straight into the row, as a hand-edited database or a hostile backup
		// would put it: the write path refuses these values.
		s.setTunnelEndpoint(node.ID, hostile)

		job, err := s.tryRun("node.probe", nodeRef(node), nil)
		if err == nil && job.State == domain.JobSucceeded {
			t.Errorf("hostname %q: the probe of a node with a hostile tunnel hostname succeeded", hostile)
		}
		t.Logf("hostname %q: %s", hostile, outcome(job, err))
	}
	if started := s.carrierStarts(); started != 0 {
		t.Errorf("%d carrier processes were started for hostile hostnames, want 0", started)
	}
}

func TestANodeNameThatMakesNoValidHostnameIsRefusedBeforeCloudflareIsTouched(t *testing.T) {
	// Names the node API accepts but ssh-<name>.<zone> cannot carry.
	for _, name := range []string{"web-", "a.b", "a_b", strings.Repeat("n", 60)} {
		s := newStack(t, stackOptions{})
		node := s.addNode(name, unreachable(t), "secret://ssh/default")
		job, err := s.tryRun("node.setup", nodeRef(node), map[string]any{"tunnel": "true", "logs_mode": "journal-group", "docker_access": "false"})
		if err == nil && job.State == domain.JobSucceeded {
			t.Errorf("node %q: tunnel setup succeeded", name)
		}
		t.Logf("node %q: %s", name, outcome(job, err))
		if n := s.cf.CommittedMutations(); n != 0 {
			t.Errorf("node %q: %d Cloudflare mutations before the name was refused, want 0", name, n)
		}
		if got := s.node(node.ID).Endpoint.Transport.Effective(); got != domain.TransportDirect {
			t.Errorf("node %q: transport = %s, want direct", name, got)
		}
		if s.carrierStarts() != 0 {
			t.Errorf("node %q: a carrier was started", name)
		}
	}
}

// fastPool keeps a probe of an unreachable address from waiting for the
// production connect timeout.
var fastPool = func() sshtransport.PoolConfig {
	c := defaultPoolConfig()
	c.ConnectTimeout = 2 * time.Second
	return c
}()

func TestAHostileCloudflaredPathNeverStartsAProcess(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	for _, path := range []string{
		"/usr/bin/cloudflared; touch " + marker,
		"/usr/bin/cloudflared%h",
		"cloudflared",
		"./cloudflared",
		"-oProxyCommand=touch " + marker,
		"/nonexistent/cloudflared",
		"/usr/bin/cloudflared\n",
	} {
		s := newStack(t, stackOptions{carrier: path, poolConfig: &fastPool})
		node := s.addNode("web1", unreachable(t), "secret://ssh/default")
		s.setTunnelEndpoint(node.ID, "ssh-web1.example.test")
		_, _ = s.store.Put(context.Background(), "cloudflare/access-service-token", "id.access:secret-value", nil)

		job, err := s.tryRun("node.probe", nodeRef(node), nil)
		if err == nil && job.State == domain.JobSucceeded {
			t.Errorf("path %q: the probe succeeded", path)
		}
		t.Logf("path %q: %s", path, outcome(job, err))
		if s.carrierStarts() != 0 {
			t.Errorf("path %q: a carrier was started", path)
		}
	}
	if fileExists(marker) {
		t.Error("a hostile cloudflared path ran a shell command")
	}
}
