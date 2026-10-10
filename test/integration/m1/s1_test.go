//go:build fixtures

package m1

import (
	"strings"
	"testing"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/test/fixtures/fixture"
)

// Scenario: gestionar dos nodos sin agente.
// Given two Linux fixture nodes reachable over SSH with pinned host keys,
// when they are added, probed and listed, then systemd/Docker and their
// services are discovered without installing an agent.
func TestM1_ManageTwoNodesWithoutAgent(t *testing.T) {
	nodes := startNodes(t, fixture.Options{DemoContainer: true}, fixture.Options{})
	nodeA, nodeB := nodes[0], nodes[1]
	in := newInstance(t, instanceOptions{})
	in.startDaemon()
	api := in.client()

	a := addNode(t, api, in, nodeA, "node-a", "staging")
	b := addNode(t, api, in, nodeB, "node-b", "staging")
	waitDiscovered(t, api, a.ID)
	waitDiscovered(t, api, b.ID)
	probe(t, api, a.ID)
	probe(t, api, b.ID)

	a, err := api.GetNode(t.Context(), a.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if a.Setup != nil {
		t.Fatalf("a node that was never set up reports setup %+v", a.Setup)
	}
	for _, c := range []string{"node.ssh", "node.read", "service.read", "service.logs"} {
		if !hasCapability(a, c) {
			t.Errorf("node A lacks capability %s after the probe: %v", c, capabilityNames(a))
		}
	}
	b, err = api.GetNode(t.Context(), b.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if !hasCapability(b, "service.read") {
		t.Errorf("node B lacks service.read after the probe: %v", capabilityNames(b))
	}

	setup(t, api, a, true, allVerbs(demoUnit)...)
	setup(t, api, b, false, allVerbs(demoUnit)...)
	probe(t, api, a.ID)
	probe(t, api, b.ID)

	a, _ = api.GetNode(t.Context(), a.ID, false)
	b, _ = api.GetNode(t.Context(), b.ID, false)
	if a.Setup == nil || !a.Setup.DockerAccess {
		t.Errorf("node A setup = %+v, want docker access", a.Setup)
	}
	if b.Setup == nil || b.Setup.DockerAccess {
		t.Errorf("node B setup = %+v, want no docker access", b.Setup)
	}
	if !hasCapability(a, "docker.read") || !hasCapability(a, "service.restart") {
		t.Errorf("node A after setup advertises %v, want docker.read and service.restart", capabilityNames(a))
	}
	if hasCapability(b, "docker.read") {
		t.Errorf("node B (docker_access false) advertises docker.read: %v", capabilityNames(b))
	}

	t.Run("lists the discovered systemd and docker services", func(t *testing.T) {
		unit := serviceNamed(t, api, a.ID, demoUnit)
		if unit.RuntimeType != "systemd" {
			t.Errorf("%s runtime = %s, want systemd", demoUnit, unit.RuntimeType)
		}
		web := serviceNamed(t, api, a.ID, demoContainer)
		if web.RuntimeType != "docker" {
			t.Errorf("%s runtime = %s, want docker", demoContainer, web.RuntimeType)
		}
		if got := serviceNamed(t, api, b.ID, demoUnit); got.RuntimeType != "systemd" {
			t.Errorf("node B %s runtime = %s, want systemd", demoUnit, got.RuntimeType)
		}
		page, err := api.ListServices(t.Context(), b.ID, wire.PageQuery{})
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range page.Items {
			if s.RuntimeType == "docker" {
				t.Errorf("node B (no docker access) lists docker service %s", s.Name)
			}
		}
	})

	t.Run("the nodes list shows both nodes as reachable", func(t *testing.T) {
		page, err := api.ListNodes(t.Context(), wire.NodeQuery{})
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Items) != 2 {
			t.Fatalf("listed %d nodes, want 2", len(page.Items))
		}
		for _, n := range page.Items {
			if n.Reachability != "reachable" {
				t.Errorf("node %s reachability = %s, want reachable", n.Name, n.Reachability)
			}
		}
	})

	t.Run("automated sessions run as the dedicated user", func(t *testing.T) {
		for _, n := range []*node{nodeA, nodeB} {
			journal := n.sh(t, "journalctl -u ssh --no-pager")
			if !strings.Contains(journal, "Accepted publickey for supermgmt") {
				t.Errorf("%s: sshd never accepted the supermgmt user after setup:\n%s", n.Name, journal)
			}
		}
	})

	t.Run("no SuperMgmt process or binary is installed on the nodes", func(t *testing.T) {
		for _, n := range []*node{nodeA, nodeB} {
			if out := n.sh(t, `find / -xdev -type f -perm /111 \( -name sm -o -name 'supermgmt*' -o -name 'sm-agent*' \) -not -path '/proc/*' -not -path '/etc/systemd/*' 2>/dev/null`); out != "" {
				t.Errorf("%s: SuperMgmt executables found on the node:\n%s", n.Name, out)
			}
			procs := n.sh(t, `ps -eo user:20,comm | awk '$1=="supermgmt" {print $2}' | sort -u`)
			for _, p := range strings.Fields(procs) {
				switch p {
				case "sshd", "sshd-session", "sh", "ps", "awk", "sort", "systemd", "(sd-pam)":
				default:
					t.Errorf("%s: unexpected process of the supermgmt user: %s", n.Name, p)
				}
			}
			home := n.sh(t, `find /var/lib/supermgmt -type f -perm /111 | wc -l`)
			if home != "0" {
				t.Errorf("%s: %s executable file(s) under /var/lib/supermgmt", n.Name, home)
			}
		}
	})

	t.Run("the dedicated user holds exactly the generated instance key", func(t *testing.T) {
		key, err := api.SSHKey(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		want, _, _, _, err := cryptossh.ParseAuthorizedKey([]byte(key.AuthorizedKey))
		if err != nil {
			t.Fatalf("parse instance public key: %v", err)
		}
		wantFields := strings.TrimSpace(string(cryptossh.MarshalAuthorizedKey(want)))
		for _, n := range []*node{nodeA, nodeB} {
			lines := strings.Split(n.sh(t, "cat /var/lib/supermgmt/.ssh/authorized_keys"), "\n")
			if len(lines) != 1 || !strings.HasPrefix(lines[0], "restrict "+wantFields+" supermgmt@") {
				t.Errorf("%s: authorized_keys = %q, want one `restrict %s supermgmt@<instance>` line", n.Name, lines, wantFields)
			}
		}
	})
}

func hasCapability(n wire.Node, name string) bool {
	for _, c := range n.Capabilities {
		if c.Name == name && c.Available {
			return true
		}
	}
	return false
}

func capabilityNames(n wire.Node) []string {
	var names []string
	for _, c := range n.Capabilities {
		if c.Available {
			names = append(names, c.Name)
		}
	}
	return names
}
