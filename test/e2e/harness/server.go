//go:build e2e

package harness

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Paths of a server installation (spec Appendix A).
const (
	ServerBinary = "/usr/local/bin/sm"
	ServerConfig = "/etc/supermgmt/config.yaml"
	ServerData   = "/var/lib/supermgmt"
	unitPath     = "/etc/systemd/system/supermgmt.service"
)

// TLSMode is how clients reach the server.
type TLSMode string

const (
	// Direct terminates TLS in `sm server` with an operator certificate.
	Direct TLSMode = "direct"
	// Proxy runs `sm server` on loopback behind a TLS-terminating proxy container.
	Proxy TLSMode = "proxy"
)

// Server is `sm server` running under systemd in a clean Debian container.
type Server struct {
	C       *Container
	Mode    TLSMode
	URL     string // what clients use: https://localhost:<published port>
	CA      *CA
	CAFile  string // host path of the CA that signed the server certificate
	Network *Network
	Proxy   *Container
	t       testing.TB
}

// ServerOptions tune StartServer.
type ServerOptions struct {
	Mode TLSMode
	// TrustCAs are installed in the container's trust store (the IdP's CA).
	TrustCAs []*CA
	// Name is an extra DNS alias on the network.
	Aliases []string
}

// NewServerHost prepares a clean Debian systemd container the way an operator's VM would be
// before the install: the CAs of the services it must reach are trusted and a certificate for
// localhost sits in /opt/tls (for --tls direct). Nothing of SuperMgmt is installed.
func NewServerHost(t testing.TB, net *Network, ca *CA, o ServerOptions) *Server {
	t.Helper()
	ctx := context.Background()
	c := Host(t, net, []string{"8443"}, o.Aliases...)
	s := &Server{C: c, Mode: o.Mode, CA: ca, Network: net, t: t}
	s.URL = fmt.Sprintf("https://localhost:%d", c.HostPort("8443"))
	dir := t.TempDir()
	s.CAFile = ca.WriteCA(t, dir)
	for _, other := range o.TrustCAs {
		c.TrustCA(ctx, other.CertPEM)
	}
	leaf := ca.Issue(t, []string{"localhost", "sm.test"}, []string{"127.0.0.1"})
	certPath, keyPath := leaf.WriteTo(t, dir, "server")
	c.MustExec(ctx, "mkdir", "-p", "/opt/tls")
	c.CopyRoot(ctx, certPath, "/opt/tls/server.crt")
	c.CopyRoot(ctx, keyPath, "/opt/tls/server.key")
	c.MustExec(ctx, "chmod", "0644", "/opt/tls/server.crt", "/opt/tls/server.key") // throwaway key; the service user must read it
	return s
}

// StartServer provisions a server the way the installer does and waits until it is ready. In
// direct mode it is `sm install server --tls direct`; in proxy mode the files are written by
// the harness (see Server.provisionProxy) and a TLS proxy container shares the server's network
// namespace.
func StartServer(t testing.TB, net *Network, ca *CA, o ServerOptions) *Server {
	t.Helper()
	ctx := context.Background()
	s := NewServerHost(t, net, ca, o)
	c := s.C
	dir := t.TempDir()
	c.InstallSM(ctx, t, "/root/sm")
	switch o.Mode {
	case Direct:
		res := c.Env(ctx, "", map[string]string{"SUPERMGMT_NONINTERACTIVE": "1"}, "/root/sm", "install", "server",
			"--tls", "direct", "--tls-cert", "/opt/tls/server.crt", "--tls-key", "/opt/tls/server.key",
			"--public-url", s.URL, "--listen", "0.0.0.0:8443", "--yes")
		if res.Code != 0 {
			t.Fatalf("sm install server --tls direct exited %d\n%s", res.Code, res.Output())
		}
	case Proxy:
		s.provisionProxy(ctx, t, dir)
	default:
		t.Fatalf("unknown TLS mode %q", o.Mode)
	}
	return s
}

// provisionProxy does by hand what `sm install server --tls proxy` does, minus its readiness
// probe (BUG-1: the probe sends no X-Forwarded-Proto, so the proxy-mode server answers 400; see
// TestM2_CurlBashInstallsServer/proxy), then starts the TLS proxy in a container of its own that shares
// the server's network namespace, as a sidecar would.
func (s *Server) provisionProxy(ctx context.Context, t testing.TB, dir string) {
	c := s.C
	c.MustExec(ctx, "useradd", "--system", "--user-group", "--home-dir", ServerData, "--no-create-home", "--shell", "/usr/sbin/nologin", "supermgmt")
	c.MustExec(ctx, "install", "-d", "-m", "0750", "-o", "root", "-g", "supermgmt", "/etc/supermgmt")
	c.MustExec(ctx, "install", "-d", "-m", "0750", "-o", "supermgmt", "-g", "supermgmt", ServerData, ServerData+"/backups")
	c.MustExec(ctx, "install", "-d", "-m", "0700", "-o", "supermgmt", "-g", "supermgmt", ServerData+"/secrets", ServerData+"/secrets/keys")
	c.MustExec(ctx, "install", "-m", "0755", "/root/sm", ServerBinary)
	config := fmt.Sprintf(`version: 1
instance:
    name: supermgmt
    mode: server
    data_dir: %s
server:
    listen: 127.0.0.1:8787
    public_url: %s
    tls:
        mode: proxy
    trusted_proxies:
        - 127.0.0.1/32
`, ServerData, s.URL)
	c.WriteFile(ctx, ServerConfig, []byte(config), "0640")
	c.MustExec(ctx, "chown", "root:supermgmt", ServerConfig)
	unit, err := os.ReadFile(filepath.Join(RepoRoot(), "packaging", "systemd", "supermgmt.service"))
	if err != nil {
		t.Fatal(err)
	}
	c.WriteFile(ctx, unitPath, unit, "0644")
	c.MustExec(ctx, "systemctl", "daemon-reload")
	c.MustExec(ctx, "systemctl", "enable", "--now", "supermgmt")
	s.WaitReady(ctx)

	leaf := s.CA.Issue(t, []string{"localhost", "sm.test"}, []string{"127.0.0.1"})
	certPath, keyPath := leaf.WriteTo(t, dir, "proxy")
	_ = os.Chmod(keyPath, 0o644)
	s.Proxy = Start(t, RunOptions{
		Image: Image(t), Network: "container:" + c.Name,
		Cmd:   []string{"/e2etool", "proxy", "-listen", ":8443", "-cert", "/proxy.crt", "-key", "/proxy.key", "-target", "http://127.0.0.1:8787"},
		Files: map[string]string{"/e2etool": Tool(t), "/proxy.crt": certPath, "/proxy.key": keyPath},
	})
}

var bootstrapLine = regexp.MustCompile(`Bootstrap code \(shown once, single use\): (\S+)`)

// BootstrapCode extracts the code from the installer's output.
func BootstrapCode(output string) (string, bool) {
	m := bootstrapLine.FindStringSubmatch(output)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// Sm runs the installed `sm` inside the server container against its own configuration.
func (s *Server) Sm(ctx context.Context, stdin string, args ...string) Result {
	argv := append([]string{ServerBinary}, args...)
	return s.C.Exec(ctx, stdin, argv...)
}

// IssueBootstrapCode asks the admin socket for a code (root may).
func (s *Server) IssueBootstrapCode(ctx context.Context) string {
	s.t.Helper()
	res := s.Sm(ctx, "", "admin", "bootstrap-code", "--config", ServerConfig)
	if res.Code != 0 {
		s.t.Fatalf("sm admin bootstrap-code exited %d\n%s", res.Code, res.Output())
	}
	return strings.TrimSpace(res.Stdout)
}

// Restart restarts the service and waits for readiness through the server's own address.
func (s *Server) Restart(ctx context.Context) {
	s.t.Helper()
	s.C.MustExec(ctx, "systemctl", "restart", "supermgmt")
	s.WaitReady(ctx)
}

// WaitReady polls the readiness endpoint inside the container.
func (s *Server) WaitReady(ctx context.Context) {
	s.t.Helper()
	probe := []string{"curl", "-fsS", "--max-time", "3", "-H", "X-Forwarded-Proto: https", "http://127.0.0.1:8787/health/ready"}
	if s.Mode == Direct {
		probe = []string{"curl", "-fsS", "--max-time", "3", "--cacert", "/opt/tls/server.crt", "https://localhost:8443/health/ready"}
	}
	deadline := Now().Add(time.Minute)
	for Now().Before(deadline) {
		if s.C.Exec(ctx, "", probe...).Code == 0 {
			return
		}
		time.Sleep(time.Second)
	}
	s.t.Fatalf("server did not become ready\n%s", s.C.Exec(ctx, "", "journalctl", "-u", "supermgmt", "--no-pager", "-n", "30").Output())
}

// AppendConfig adds top-level YAML to the server configuration.
func (s *Server) AppendConfig(ctx context.Context, yaml string) {
	s.t.Helper()
	current, err := s.C.Fetch(ctx, ServerConfig)
	if err != nil {
		s.t.Fatal(err)
	}
	s.C.WriteFile(ctx, ServerConfig, []byte(strings.TrimRight(current, "\n")+"\n"+yaml), "0640")
	s.C.MustExec(ctx, "chown", "root:supermgmt", ServerConfig)
}

// WriteHostFile is a convenience for the tests' scratch files on the host.
func WriteHostFile(t testing.TB, dir, name string, content []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatal(err)
	}
	return path
}
