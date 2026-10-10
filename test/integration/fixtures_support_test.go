//go:build fixtures

package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/runtimes/systemd"
	"github.com/autarquico/supermgmt/internal/secrets"
	"github.com/autarquico/supermgmt/internal/transport"
	sshtransport "github.com/autarquico/supermgmt/internal/transport/ssh"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
	"github.com/autarquico/supermgmt/test/fixtures/fixture"
)

const (
	dedicatedUser = "supermgmt"
	instanceID    = "inst-fixture"
	demoUnit      = "sm-demo.service"
	demoContainer = "sm-demo-web"
	agentRef      = "ssh-agent://default"
	identityRef   = "secret://ssh/default@1"
)

var (
	buildOnce sync.Once
	buildErr  error
)

// fixtureNode is a running fixture container plus the pinned host key in the
// form the database stores it.
type fixtureNode struct {
	*fixture.Node
	id         domain.ID
	hostKeyPin string
}

// startNode builds the image once, starts a node and removes it with the test.
func startNode(t *testing.T, o fixture.Options) *fixtureNode {
	t.Helper()
	buildOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 10*time.Minute)
		defer cancel()
		buildErr = fixture.Build(ctx)
	})
	if buildErr != nil {
		t.Fatalf("build fixture image: %v", buildErr)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	n, err := fixture.Start(ctx, o)
	if err != nil {
		t.Fatalf("start fixture: %v", err)
	}
	t.Cleanup(func() {
		bg := context.WithoutCancel(t.Context())
		if t.Failed() {
			t.Logf("fixture console:\n%s", n.Logs(bg))
		}
		if err := n.Stop(bg); err != nil {
			t.Errorf("stop fixture: %v", err)
		}
	})
	return &fixtureNode{Node: n, id: domain.ID(n.Name), hostKeyPin: authorizedKey(n.HostKey)}
}

func authorizedKey(k cryptossh.PublicKey) string {
	return strings.TrimSpace(string(cryptossh.MarshalAuthorizedKey(k)))
}

// shell runs a script as root inside the node (docker exec) and fails the test on error.
func (n *fixtureNode) shell(t *testing.T, script string) string {
	t.Helper()
	out, err := n.Exec(t.Context(), "sh", "-c", script)
	if err != nil {
		t.Fatalf("node shell %q: %v\n%s", script, err, out)
	}
	return strings.TrimSpace(out)
}

// tryShell is shell without the fatal: it returns the output and the error.
func (n *fixtureNode) tryShell(t *testing.T, script string) (string, error) {
	out, err := n.Exec(t.Context(), "sh", "-c", script)
	return strings.TrimSpace(out), err
}

// target is an endpoint authenticated through the in-process agent.
func (n *fixtureNode) target(user string) sshtransport.Target {
	return sshtransport.Target{
		NodeID: n.id, Host: n.Host, Port: n.Port, User: user,
		HostKey: n.hostKeyPin, CredentialRef: agentRef,
	}
}

// signerAgent is an in-memory ssh-agent holding fixed signers. The fixture
// helper only exposes the admin key as a Signer, so agent.NewKeyring cannot hold it.
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

// useAgent serves signers on a temp socket and points SSH_AUTH_SOCK at it for
// the test (ADR-0015: the human's agent authenticates admin_user).
func useAgent(t *testing.T, signers ...cryptossh.Signer) {
	t.Helper()
	dir, err := os.MkdirTemp("", "sm") // short path: unix socket paths are limited on macOS
	if err != nil {
		t.Fatalf("agent socket dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", filepath.Join(dir, "a.sock"))
	if err != nil {
		t.Fatalf("listen on agent socket: %v", err)
	}
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

// identity is a freshly generated stand-in for the instance SSH identity
// (secret://ssh/default): the key node.setup authorizes for the dedicated user.
type identity struct {
	signer cryptossh.Signer
	public string
}

func newIdentity(t *testing.T) identity {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	signer, err := cryptossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("identity signer: %v", err)
	}
	return identity{signer: signer, public: authorizedKey(signer.PublicKey())}
}

// signerSource hands the generated identity to the real credential resolver.
type signerSource struct{ id identity }

func (s signerSource) Signer(context.Context, secrets.Ref) (cryptossh.Signer, error) {
	return s.id.signer, nil
}

// harness is a pool and the clock it runs on.
type harness struct {
	pool  *sshtransport.Pool
	clock *domaintest.FakeClock
}

var fixtureEpoch = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

func defaultPoolConfig() sshtransport.PoolConfig {
	return sshtransport.PoolConfig{
		ConnectTimeout: 10 * time.Second, CommandTimeout: 30 * time.Second, KeepaliveInterval: 15 * time.Second,
		MaxDialsInFlight: 4, MaxConnections: 8, MaxSessionsPerConnection: 10, IdleConnectionTTL: time.Minute,
	}
}

// newHarness builds a pool with the real credential resolver.
func newHarness(t *testing.T, cfg sshtransport.PoolConfig, id identity) *harness {
	t.Helper()
	clock := domaintest.NewFakeClock(fixtureEpoch)
	pool := sshtransport.NewPool(cfg, sshtransport.NewCredentials(signerSource{id: id}), clock)
	t.Cleanup(pool.Close)
	return &harness{pool: pool, clock: clock}
}

// run renders a read template and runs it.
func run(t *testing.T, ex transport.Executor, name string, args map[string]string) transport.Result {
	t.Helper()
	c, err := templates.Render(name, args)
	if err != nil {
		t.Fatalf("render %s: %v", name, err)
	}
	res, err := ex.Run(t.Context(), c)
	if err != nil {
		t.Fatalf("run %s: %v", name, err)
	}
	return res
}

func codeOf(err error) smerr.Code { return smerr.CodeOf(err) }

func reasonOf(err error) smerr.Reason {
	var e *smerr.Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ""
}

// recorder logs the template of every command, so tests can assert which setup
// steps ran.
type recorder struct {
	inner transport.Executor
	mu    sync.Mutex
	seen  []string
}

func (r *recorder) Run(ctx context.Context, c templates.Command) (transport.Result, error) {
	r.mu.Lock()
	r.seen = append(r.seen, c.Template)
	r.mu.Unlock()
	return r.inner.Run(ctx, c)
}

func (r *recorder) ran(prefix string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, name := range r.seen {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// setupParams is a typical node.setup request for the fixture.
func setupParams(id identity, mutate func(*systemd.SetupParams)) systemd.SetupParams {
	p := systemd.SetupParams{
		User: dedicatedUser, InstanceID: instanceID, AuthorizedKey: id.public,
		Grants:   []runtimes.UnitGrant{{Unit: demoUnit, Verbs: domain.AllServiceVerbs()}},
		LogsMode: runtimes.LogsJournalGroup,
	}
	if mutate != nil {
		mutate(&p)
	}
	return p
}

func verifyParams(p systemd.SetupParams, out systemd.SetupOutcome) systemd.VerifyParams {
	return systemd.VerifyParams{User: p.User, SystemctlPath: out.SystemctlPath, Grants: p.Grants, LogsMode: p.LogsMode}
}

func setupMeta(p systemd.SetupParams, out systemd.SetupOutcome) runtimes.SetupMeta {
	return runtimes.SetupMeta{
		SetupVersion: runtimes.SetupVersion, SystemctlPath: out.SystemctlPath, Units: p.Grants,
		LogsMode: p.LogsMode, DockerAccess: p.DockerAccess, KeyRef: "ssh/default", KeyVersion: 1,
	}
}

// superTarget is the endpoint of the dedicated user, authenticated with the
// instance identity the way the connection-user rule (ADR-0009 b) prescribes.
func (n *fixtureNode) superTarget() sshtransport.Target {
	t := n.target(dedicatedUser)
	t.CredentialRef = identityRef
	return t
}

// provisioned is a node that completed node.setup and verify.
type provisioned struct {
	*fixtureNode
	identity identity
	params   systemd.SetupParams
	outcome  systemd.SetupOutcome
	meta     runtimes.SetupMeta
	admin    transport.Executor
	super    transport.Executor
	h        *harness
}

// provision starts a node, runs Setup as admin_user (sudo -n) and Verify as the
// dedicated user, the way the node.setup handler sequences them.
func provision(t *testing.T, o fixture.Options, mutate func(*systemd.SetupParams)) *provisioned {
	t.Helper()
	n := startNode(t, o)
	id := newIdentity(t)
	useAgent(t, n.ClientSigner)
	h := newHarness(t, defaultPoolConfig(), id)
	p := setupParams(id, mutate)
	admin := h.pool.For(n.target(fixture.AdminUser))
	out, err := systemd.Setup(t.Context(), admin, p)
	if err != nil {
		t.Fatalf("node.setup: %v", err)
	}
	super := h.pool.For(n.superTarget())
	if err := systemd.Verify(t.Context(), super, verifyParams(p, out)); err != nil {
		t.Fatalf("node.setup verify: %v", err)
	}
	return &provisioned{
		fixtureNode: n, identity: id, params: p, outcome: out, meta: setupMeta(p, out),
		admin: admin, super: super, h: h,
	}
}

func capability(t *testing.T, caps []database.NodeCapability, name string) database.NodeCapability {
	t.Helper()
	for _, c := range caps {
		if c.Capability == name {
			return c
		}
	}
	t.Fatalf("capability %s not reported in %v", name, caps)
	return database.NodeCapability{}
}
