//go:build fixtures

package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/runtimes/systemd"
	"github.com/autarquico/supermgmt/internal/transport"
	sshtransport "github.com/autarquico/supermgmt/internal/transport/ssh"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
	"github.com/autarquico/supermgmt/test/fixtures/fixture"
)

const (
	demoUnit  = "sm-demo.service"
	agentRef  = "ssh-agent://default"
	nodeName  = "web1"
	tunnelSvc = "supermgmt-cloudflared.service"
)

var (
	buildImageOnce sync.Once
	buildImageErr  error
)

// ---- the operator's ssh-agent (admin_user, ADR-0015) ------------------------

type signerAgent struct{ signers []cryptossh.Signer }

var _ agent.Agent = (*signerAgent)(nil)

func (a *signerAgent) List() ([]*agent.Key, error) {
	keys := make([]*agent.Key, 0, len(a.signers))
	for _, s := range a.signers {
		keys = append(keys, &agent.Key{Format: s.PublicKey().Type(), Blob: s.PublicKey().Marshal()})
	}
	return keys, nil
}

func (a *signerAgent) Sign(key cryptossh.PublicKey, data []byte) (*cryptossh.Signature, error) {
	for _, s := range a.signers {
		if string(s.PublicKey().Marshal()) == string(key.Marshal()) {
			return s.Sign(rand.Reader, data)
		}
	}
	return nil, errors.New("agent: unknown key")
}

func (a *signerAgent) Signers() ([]cryptossh.Signer, error) { return a.signers, nil }
func (*signerAgent) Add(agent.AddedKey) error               { return errors.New("read-only agent") }
func (*signerAgent) Remove(cryptossh.PublicKey) error       { return errors.New("read-only agent") }
func (*signerAgent) RemoveAll() error                       { return errors.New("read-only agent") }
func (*signerAgent) Lock([]byte) error                      { return errors.New("read-only agent") }
func (*signerAgent) Unlock([]byte) error                    { return errors.New("read-only agent") }

// useAgent serves signers on a temp socket and points SSH_AUTH_SOCK at it.
func useAgent(t *testing.T, signers ...cryptossh.Signer) {
	t.Helper()
	dir, err := os.MkdirTemp("", "sma")
	must(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", filepath.Join(dir, "a.sock"))
	must(t, err)
	t.Cleanup(func() { _ = l.Close() })
	ag := &signerAgent{signers: signers}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = agent.ServeAgent(ag, c)
			}()
		}
	}()
	t.Setenv("SSH_AUTH_SOCK", l.Addr().String())
}

// ---- the node ---------------------------------------------------------------

// stubCloudflared is the package the tunnel setup finds installed on the
// node. apt cannot reach pkg.cloudflare.com from CI, and setup uses a
// cloudflared that is already installed without managing it (the package step
// is skipped; the token file, the unit and the service are installed for
// real). The fixture image is untouched: the test builds
// and installs a one-file .deb with dpkg-deb. The binary is a Perl script
// (perl-base is on every Debian) that notifies systemd, so the unit's
// Type=notify holds, and records what it was started with on its stdout,
// which systemd sends to the journal: the unit's sandbox leaves it no
// writable file system. One stubLine per record: its argv, its environment
// and the size of its token file. It never prints the token.
const stubCloudflared = `#!/usr/bin/perl
use strict;
use warnings;
use Socket;
$| = 1;
print "cloudflared-stub argv: ", join(" ", @ARGV), "\n";
print "cloudflared-stub env: $_=$ENV{$_}\n" for sort keys %ENV;
my ($i) = grep { $ARGV[$_] eq "--token-file" } 0 .. $#ARGV;
my $size = (defined $i && -f $ARGV[$i + 1]) ? (-s $ARGV[$i + 1]) : -1;
print "cloudflared-stub token-file-size: $size\n";
if ($ENV{NOTIFY_SOCKET}) {
	my $path = $ENV{NOTIFY_SOCKET};
	$path =~ s/^@/\0/;
	socket(my $n, PF_UNIX, SOCK_DGRAM, 0) or die "socket: $!";
	send($n, "READY=1", 0, pack_sockaddr_un($path)) or die "notify: $!";
}
$SIG{TERM} = sub { exit 0 };
sleep 3600 while 1;
`

const stubControl = "Package: cloudflared\nVersion: 2026.10.0\nArchitecture: all\nMaintainer: Tests <tests@example.test>\n" +
	"Description: stand-in for the cloudflared package of the tunnel suites\n"

// tunnelFixture is a running Debian fixture node, an instance whose
// cloudflared carrier forwards to that node's sshd, and the node's record.
type tunnelFixture struct {
	*stack
	docker *fixture.Node
	node   domain.Node
}

// fixtureOptions tune newTunnelFixture.
type fixtureOptions struct {
	stack stackOptions
}

// startDocker builds the fixture image once and starts one node.
func startDocker(t *testing.T) *fixture.Node {
	t.Helper()
	buildImageOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 10*time.Minute)
		defer cancel()
		buildImageErr = fixture.Build(ctx)
	})
	if buildImageErr != nil {
		t.Fatalf("build the fixture image: %v", buildImageErr)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	n, err := fixture.Start(ctx, fixture.Options{})
	if err != nil {
		t.Fatalf("start the fixture: %v", err)
	}
	t.Cleanup(func() {
		bg := context.WithoutCancel(t.Context())
		if t.Failed() {
			t.Logf("fixture console:\n%s", n.Logs(bg))
			if journal, err := n.Exec(bg, "journalctl", "--no-pager", "-b", "-n", "200"); err == nil {
				t.Logf("node journal:\n%s", journal)
			}
		}
		if err := n.Stop(bg); err != nil {
			t.Errorf("stop the fixture: %v", err)
		}
	})
	return n
}

func sh(t *testing.T, n *fixture.Node, script string) string {
	t.Helper()
	out, err := n.Exec(t.Context(), "sh", "-c", script)
	if err != nil {
		t.Fatalf("on the node: %q: %v\n%s", script, err, out)
	}
	return strings.TrimSpace(out)
}

func trySh(t *testing.T, n *fixture.Node, script string) (string, error) {
	t.Helper()
	out, err := n.Exec(t.Context(), "sh", "-c", script)
	return strings.TrimSpace(out), err
}

// stubRecords is what the stand-in printed when it started, as the journal
// holds it.
const stubRecords = "journalctl --no-pager -a -o cat -u " + tunnelSvc + " | grep '^cloudflared-stub '"

// stubRecord returns the last value the stand-in printed for key, waiting for
// the journal to hold it.
func stubRecord(t *testing.T, n *fixture.Node, key string) string {
	t.Helper()
	prefix := "cloudflared-stub " + key + ": "
	deadline := time.Now().Add(10 * time.Second) //nolint:forbidigo // wall-clock budget of a polling loop
	for {
		out, _ := trySh(t, n, stubRecords)
		value, found := "", false
		for _, line := range strings.Split(out, "\n") {
			if v, ok := strings.CutPrefix(line, prefix); ok {
				value, found = v, true
			}
		}
		if found {
			return value
		}
		if time.Now().After(deadline) { //nolint:forbidigo // see above
			t.Fatalf("the journal holds no %q record of the stand-in:\n%s", key, out)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// installStubPackage installs the cloudflared stand-in as a real dpkg package.
func installStubPackage(t *testing.T, n *fixture.Node) {
	t.Helper()
	b64 := base64.StdEncoding.EncodeToString([]byte(stubCloudflared))
	// systemd 257 mounts a unit's LoadCredential directory from a helper
	// namespace and relies on the mount propagating back, as / does on a host.
	// Docker makes / private, so /run/credentials alone is made shared.
	script := `set -e
mkdir -p /run/credentials
mount --bind /run/credentials /run/credentials
mount --make-shared /run/credentials
d=$(mktemp -d)
mkdir -p "$d/DEBIAN" "$d/usr/bin"
printf %s "$1" > "$d/DEBIAN/control"
printf %s "$0" | base64 -d > "$d/usr/bin/cloudflared"
chmod 0755 "$d/usr/bin/cloudflared"
dpkg-deb --root-owner-group --build "$d" "$d.deb" >/dev/null
dpkg -i "$d.deb" >/dev/null
rm -rf "$d" "$d.deb"`
	out, err := n.Exec(t.Context(), "sh", "-c", script, b64, stubControl)
	if err != nil {
		t.Fatalf("install the cloudflared stand-in package: %v\n%s", err, out)
	}
	if got := sh(t, n, "dpkg-query -W -f='${db:Status-Abbrev}' cloudflared"); !strings.HasPrefix(got, "ii") {
		t.Fatalf("the stand-in package is %q, want installed", got)
	}
}

func authorizedKey(k cryptossh.PublicKey) string {
	return strings.TrimSpace(string(cryptossh.MarshalAuthorizedKey(k)))
}

// newTunnelFixture starts a node and an instance that has the node in its
// inventory but has not set it up.
func newTunnelFixture(t *testing.T, o fixtureOptions) *tunnelFixture {
	t.Helper()
	docker := startDocker(t)
	installStubPackage(t, docker)
	useAgent(t, docker.ClientSigner)
	s := newStack(t, o.stack)
	f := &tunnelFixture{stack: s, docker: docker}
	f.carrierForwardsTo(docker)
	f.node = s.addNode(nodeName, domain.NodeEndpoint{
		Host: docker.Host, Port: docker.Port, User: "supermgmt", AdminUser: fixture.AdminUser, AdminCredentialRef: agentRef,
		HostPublicKey: authorizedKey(docker.HostKey),
	}, "secret://ssh/default")
	return f
}

// carrierForwardsTo points the cloudflared stand-in at a node's sshd.
func (s *stack) carrierForwardsTo(n *fixture.Node) {
	s.t.Helper()
	must(s.t, os.WriteFile(filepath.Join(s.home, "forward"), []byte(n.Addr()+"\n"), 0o600))
}

// setup runs node.setup for the fixture node, with or without the tunnel.
func (f *tunnelFixture) setup(tunnel bool) jobs.Job {
	f.t.Helper()
	grants := make([]any, 0, len(domain.AllServiceVerbs()))
	for _, v := range domain.AllServiceVerbs() {
		grants = append(grants, string(v)+" "+demoUnit)
	}
	params := map[string]any{"docker_access": "false", "logs_mode": "journal-group", "grants": grants}
	if tunnel {
		params["tunnel"] = "true"
	}
	return f.run("node.setup", nodeRef(f.node), params)
}

func (f *tunnelFixture) mustSucceed(job jobs.Job, what string) {
	f.t.Helper()
	if job.State != domain.JobSucceeded {
		f.t.Fatalf("%s: %s", what, outcome(job, nil))
	}
}

// refresh reloads the node record.
func (f *tunnelFixture) refresh() domain.Node {
	f.t.Helper()
	f.node = f.stack.node(f.node.ID)
	return f.node
}

// setEndpointAddress rewrites where the node's direct route points, keeping
// every other field (the tunnel fields included) as the jobs left them.
func (f *tunnelFixture) setEndpointAddress(host string, port int) {
	f.t.Helper()
	n := f.refresh()
	doc, err := json.Marshal(map[string]any{
		"host": host, "port": port, "user": n.Endpoint.User, "admin_user": n.Endpoint.AdminUser,
		"admin_credential_ref": n.Endpoint.AdminCredentialRef, "host_public_key": n.Endpoint.HostPublicKey,
		"transport": n.Endpoint.Transport, "tunnel_hostname": n.Endpoint.TunnelHostname,
	})
	must(f.t, err)
	f.setRawEndpoint(n.ID, string(doc))
	f.pool.InvalidateNode(n.ID)
}

// blockDirectRoute makes the recorded direct address unroutable (TEST-NET-1).
// Anything that still works afterwards went through the tunnel.
func (f *tunnelFixture) blockDirectRoute() { f.setEndpointAddress("192.0.2.1", 22) }

// restoreDirectRoute points the direct route at the fixture again.
func (f *tunnelFixture) restoreDirectRoute() { f.setEndpointAddress(f.docker.Host, f.docker.Port) }

// setupMeta is the node.setup metadata the job recorded.
func (f *tunnelFixture) setupMeta() runtimes.SetupMeta {
	f.t.Helper()
	c, err := database.GetNodeCapability(context.Background(), f.db.Reader(), f.node.ID, "node.setup")
	must(f.t, err)
	raw, err := json.Marshal(c.Metadata)
	must(f.t, err)
	var meta runtimes.SetupMeta
	must(f.t, json.Unmarshal(raw, &meta))
	return meta
}

// session is the dedicated user's executor, the way automation reaches the
// node: through the transport the node record names.
func (f *tunnelFixture) session() transport.Executor {
	f.t.Helper()
	meta := f.setupMeta()
	ex, err := app.Connector{Remote: f.pool}.Automated(f.refresh(), &meta)
	must(f.t, err)
	return ex
}

func (f *tunnelFixture) serviceRef() runtimes.ServiceRef {
	return runtimes.ServiceRef{NodeID: f.node.ID, Kind: domain.ServiceSystemdUnit, NativeID: demoUnit, Name: demoUnit}
}

// restartDemo restarts the demo unit through the systemd adapter and returns
// the evidence class, which is complete when systemd proved the restart.
func (f *tunnelFixture) restartDemo(marker string) error {
	f.t.Helper()
	ex, sd, ref, meta := f.session(), systemd.New(), f.serviceRef(), f.setupMeta()
	pre, err := sd.PreState(f.t.Context(), ex, ref)
	if err != nil {
		return err
	}
	cmd, err := sd.Mutate(ref, domain.VerbRestart, marker, meta)
	if err != nil {
		return err
	}
	res, err := ex.Run(f.t.Context(), cmd)
	if err != nil {
		return err
	}
	if res.ExitStatus != 0 {
		return fmt.Errorf("restart exited %d: %s", res.ExitStatus, res.Stderr)
	}
	ev, err := sd.Observe(f.t.Context(), ex, ref, domain.VerbRestart, marker, pre, time.Now()) //nolint:forbidigo // evidence time of a live node
	if err != nil {
		return err
	}
	if !ev.Done || ev.ExitStatus != 0 {
		return errors.New("systemd did not prove the restart")
	}
	return nil
}

// readLogs reads the demo unit's journal through the tunnel.
func (f *tunnelFixture) readLogs() error {
	f.t.Helper()
	_, err := systemd.New().Logs(f.t.Context(), f.session(), f.serviceRef(), runtimes.LogQuery{Lines: 20, Mode: f.setupMeta().LogsMode})
	return err
}

// directRouteIsDead proves the recorded direct address answers nothing: a
// direct session to it fails within the budget.
func (f *tunnelFixture) directRouteIsDead() error {
	n := f.refresh()
	ctx, cancel := context.WithTimeout(f.t.Context(), 4*time.Second)
	defer cancel()
	cmd, err := templates.Render("systemd.show", map[string]string{"unit": demoUnit})
	must(f.t, err)
	_, err = f.pool.For(sshtransport.Target{
		NodeID: n.ID, Host: n.Endpoint.Host, Port: n.Endpoint.Port, User: fixture.AdminUser,
		HostKey: n.Endpoint.HostPublicKey, CredentialRef: agentRef,
	}).Run(ctx, cmd)
	return err
}
