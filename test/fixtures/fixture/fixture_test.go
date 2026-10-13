//go:build fixtures

package fixture_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/autarquico/supermgmt/test/fixtures/fixture"
)

func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	err := fixture.Build(ctx)
	cancel()
	if err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func startNode(t *testing.T) *fixture.Node {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)
	n, err := fixture.Start(ctx, fixture.Options{})
	if err != nil {
		t.Fatalf("start fixture: %v", err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("fixture console:\n%s", n.Logs(context.WithoutCancel(ctx)))
		}
		if err := n.Stop(context.WithoutCancel(ctx)); err != nil {
			t.Errorf("stop fixture: %v", err)
		}
	})
	return n
}

func dial(t *testing.T, n *fixture.Node, user string) (*cryptossh.Client, error) {
	t.Helper()
	return cryptossh.Dial("tcp", n.Addr(), &cryptossh.ClientConfig{
		User:            user,
		Auth:            []cryptossh.AuthMethod{cryptossh.PublicKeys(n.ClientSigner)},
		HostKeyCallback: cryptossh.FixedHostKey(n.HostKey),
		Timeout:         10 * time.Second,
	})
}

func run(t *testing.T, c *cryptossh.Client, cmd string) (string, error) {
	t.Helper()
	s, err := c.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer s.Close()
	out, err := s.CombinedOutput(cmd)
	return strings.TrimSpace(string(out)), err
}

func TestNodeAllowsAdminWithPasswordlessSudo(t *testing.T) {
	n := startNode(t)
	c, err := dial(t, n, fixture.AdminUser)
	if err != nil {
		t.Fatalf("dial as admin with the pinned host key: %v", err)
	}
	defer c.Close()

	if out, err := run(t, c, "id -un"); err != nil || out != "admin" {
		t.Fatalf("id -un = %q, %v; want admin", out, err)
	}
	if out, err := run(t, c, "sudo -n id -un"); err != nil || out != "root" {
		t.Fatalf("sudo -n id -un = %q, %v; want root", out, err)
	}
}

func TestNodeHasNoSupermgmtUserAndRefusesRoot(t *testing.T) {
	n := startNode(t)
	c, err := dial(t, n, fixture.AdminUser)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	if out, err := run(t, c, "getent passwd supermgmt"); err == nil {
		t.Fatalf("supermgmt must not exist before node.setup, got %q", out)
	}
	if rc, err := dial(t, n, "root"); err == nil {
		rc.Close()
		t.Fatal("root login must be refused")
	}
}

func TestNodeRejectsAChangedHostKey(t *testing.T) {
	n := startNode(t)
	other := startNode(t)
	_, err := cryptossh.Dial("tcp", n.Addr(), &cryptossh.ClientConfig{
		User:            fixture.AdminUser,
		Auth:            []cryptossh.AuthMethod{cryptossh.PublicKeys(n.ClientSigner)},
		HostKeyCallback: cryptossh.FixedHostKey(other.HostKey),
		Timeout:         10 * time.Second,
	})
	if err == nil {
		t.Fatal("dial must fail when the host key differs from the pinned one")
	}
}

func TestNodeRunsSystemdAndDocker(t *testing.T) {
	n := startNode(t)
	c, err := dial(t, n, fixture.AdminUser)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	for _, unit := range []string{"sm-demo.service", "sm-slow.service", "docker.service"} {
		if out, err := run(t, c, "systemctl is-active "+unit); err != nil || out != "active" {
			t.Errorf("%s is-active = %q, %v; want active", unit, out, err)
		}
	}
	if out, err := run(t, c, "sudo -n docker info --format '{{.ServerVersion}}'"); err != nil || out == "" {
		t.Errorf("docker info = %q, %v; want a server version", out, err)
	}
}

func TestDemoContainerRunsInsideTheNode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	n, err := fixture.Start(ctx, fixture.Options{DemoContainer: true})
	if err != nil {
		t.Fatalf("start fixture: %v", err)
	}
	defer func() { _ = n.Stop(context.WithoutCancel(ctx)) }()

	out, err := n.Exec(ctx, "docker", "inspect", "--format", "{{.State.Running}}", "sm-demo-web")
	if err != nil || strings.TrimSpace(out) != "true" {
		t.Fatalf("sm-demo-web running = %q, %v; want true", out, err)
	}
}

func TestUnknownDistroIsRejected(t *testing.T) {
	t.Setenv(fixture.DistroEnv, "alpine")
	if err := fixture.Build(context.Background()); err == nil || !strings.Contains(err.Error(), "alpine") {
		t.Fatalf("Build with unknown distro = %v; want an error naming it", err)
	}
	if _, err := fixture.Start(context.Background(), fixture.Options{}); err == nil {
		t.Fatal("Start with unknown distro must fail")
	}
}

func TestNodeRunsTheSelectedDistro(t *testing.T) {
	want := map[string]string{"": "debian", "debian13": "debian", "ubuntu2404": "ubuntu"}[os.Getenv(fixture.DistroEnv)]
	if want == "" {
		t.Skipf("unsupported %s", fixture.DistroEnv)
	}
	n := startNode(t)
	out, err := n.Exec(context.Background(), "sh", "-c", ". /etc/os-release && echo $ID")
	if err != nil || strings.TrimSpace(out) != want {
		t.Fatalf("os-release ID = %q, %v; want %q", out, err, want)
	}
}
