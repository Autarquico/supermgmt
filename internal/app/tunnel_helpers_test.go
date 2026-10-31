package app

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/netguard"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare/cffake"
	"github.com/autarquico/supermgmt/internal/secrets"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// memSecrets is the secret store of the tunnel tests: versioned, in memory.
type memSecrets struct {
	mu   sync.Mutex
	vals map[string][]audit.Secret
	// crashAfterPut makes the k-th Put (1-based; 0 never) store its value and
	// then fail, as a worker that dies right after it. afterPut observes every
	// stored value.
	crashAfterPut int
	puts          int
	afterPut      func()
}

func newMemSecrets() *memSecrets { return &memSecrets{vals: map[string][]audit.Secret{}} }

func (m *memSecrets) Get(_ context.Context, ref secrets.Ref) (audit.Secret, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	versions := m.vals[ref.Name]
	if len(versions) == 0 {
		return "", smerr.New(smerr.CodeNotFound, "", "secret not found")
	}
	return versions[len(versions)-1], nil
}

func (m *memSecrets) Purge(_ context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.vals, name)
	return nil
}

func (m *memSecrets) Put(_ context.Context, name string, plaintext audit.Secret, _ map[string]any) (secrets.Ref, error) {
	m.mu.Lock()
	m.vals[name] = append(m.vals[name], plaintext)
	m.puts++
	ref, crash, observe := secrets.Ref{Name: name, Version: len(m.vals[name])}, m.puts == m.crashAfterPut, m.afterPut
	m.mu.Unlock()
	if observe != nil {
		observe()
	}
	if crash {
		return ref, errCrash
	}
	return ref, nil
}

func (m *memSecrets) versions(name string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.vals[name])
}

// chaosAPI decorates the Cloudflare client with one fault at the k-th
// mutation: the process dies after the mutation took effect (crash), or the
// worker's lease expires right after it (lease loss).
type chaosAPI struct {
	CloudflareAPI
	mu    sync.Mutex
	k     int // 1-based mutation that suffers the fault; 0 means never
	mode  string
	count int
	fired bool
	clock func(time.Duration)
	// afterMutation observes the state after every mutation, whatever its fault.
	afterMutation func()
	// onToken runs when the tunnel token is read, the last Cloudflare call
	// before the node install.
	onToken func()
}

var errCrash = errors.New("the worker died")

func (c *chaosAPI) after(err error) error {
	if c.afterMutation != nil {
		c.afterMutation()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.count++
	if c.k == 0 || c.fired || c.count != c.k {
		return err
	}
	c.fired = true
	switch c.mode {
	case "crash":
		return errCrash
	case "lease loss":
		c.clock(time.Minute)
	}
	return err
}

func (c *chaosAPI) TunnelToken(ctx context.Context, id string) (audit.Secret, error) {
	token, err := c.CloudflareAPI.TunnelToken(ctx, id)
	if c.onToken != nil {
		c.onToken()
	}
	return token, err
}

func (c *chaosAPI) CreateTunnel(ctx context.Context, name string) (cloudflare.Tunnel, error) {
	t, err := c.CloudflareAPI.CreateTunnel(ctx, name)
	return t, c.after(err)
}

func (c *chaosAPI) PutTunnelIngress(ctx context.Context, id string, in []cloudflare.IngressRule) (cloudflare.TunnelConfig, error) {
	cfg, err := c.CloudflareAPI.PutTunnelIngress(ctx, id, in)
	return cfg, c.after(err)
}

func (c *chaosAPI) CreateAccessPolicy(ctx context.Context, spec cloudflare.PolicySpec) (cloudflare.AccessPolicy, error) {
	p, err := c.CloudflareAPI.CreateAccessPolicy(ctx, spec)
	return p, c.after(err)
}

func (c *chaosAPI) UpdateAccessPolicy(ctx context.Context, id string, spec cloudflare.PolicySpec) (cloudflare.AccessPolicy, error) {
	p, err := c.CloudflareAPI.UpdateAccessPolicy(ctx, id, spec)
	return p, c.after(err)
}

func (c *chaosAPI) CreateAccessApp(ctx context.Context, spec cloudflare.AppSpec) (cloudflare.AccessApp, error) {
	a, err := c.CloudflareAPI.CreateAccessApp(ctx, spec)
	return a, c.after(err)
}

func (c *chaosAPI) CreateTunnelCNAME(ctx context.Context, zone, host, tunnel, comment string) (cloudflare.DNSRecord, error) {
	d, err := c.CloudflareAPI.CreateTunnelCNAME(ctx, zone, host, tunnel, comment)
	return d, c.after(err)
}

func (c *chaosAPI) CreateServiceToken(ctx context.Context, name string) (cloudflare.NewServiceToken, error) {
	t, err := c.CloudflareAPI.CreateServiceToken(ctx, name)
	return t, c.after(err)
}

func (c *chaosAPI) UpdateAccessApp(ctx context.Context, id string, spec cloudflare.AppSpec) (cloudflare.AccessApp, error) {
	a, err := c.CloudflareAPI.UpdateAccessApp(ctx, id, spec)
	return a, c.after(err)
}

func (c *chaosAPI) DeleteAccessApp(ctx context.Context, id string) error {
	return c.after(c.CloudflareAPI.DeleteAccessApp(ctx, id))
}

func (c *chaosAPI) DeleteDNSRecord(ctx context.Context, zone, id string) error {
	return c.after(c.CloudflareAPI.DeleteDNSRecord(ctx, zone, id))
}

func (c *chaosAPI) DeleteTunnel(ctx context.Context, id string) error {
	return c.after(c.CloudflareAPI.DeleteTunnel(ctx, id))
}

func (c *chaosAPI) CleanupTunnelConnections(ctx context.Context, id string) error {
	return c.after(c.CloudflareAPI.CleanupTunnelConnections(ctx, id))
}

func (c *chaosAPI) DeleteServiceToken(ctx context.Context, id string) error {
	return c.after(c.CloudflareAPI.DeleteServiceToken(ctx, id))
}

// tunnelSetting is a node.setup fixture with a Cloudflare connection backed by
// cffake, a scripted node that keeps the files setup installs, and a node
// reachable through the tunnel.
type tunnelSetting struct {
	*setting
	cf      *cffake.Fake
	secrets *memSecrets
	chaos   *chaosAPI
	cfg     config.Cloudflare
	files   map[string]string // what the admin session installed on the node
	queued  jobs.Job
	current jobs.Handler // the handler attempt runs; the setup handler when nil
	disable tunnelDisableHandler
	rotate  tunnelRotateHandler
	slept   []time.Duration // the backoff waits requested instead of taken
}

const (
	testAPIToken    = "secret://cloudflare/api-token"
	testAccessToken = "secret://cloudflare/access-service-token"
)

func newTunnelSetting(t *testing.T, cfOptions ...cffake.Option) *tunnelSetting {
	t.Helper()
	cfg := config.Cloudflare{
		AccountID: cffake.DefaultAccountID, Zone: cffake.DefaultZone, APITokenRef: testAPIToken, AccessTokenRef: testAccessToken,
		OwnerEmails: []string{"owner@example.test"}, AccessIdentityProviders: []string{"11111111-1111-4111-8111-111111111111"},
	}
	s := newSetting(t, func(c *Config) { c.Cloudflare = &cfg })
	ts := &tunnelSetting{setting: s, cfg: cfg, secrets: newMemSecrets(), files: map[string]string{}}
	ts.cf = cffake.New(t, append([]cffake.Option{cffake.WithClock(s.clock.Now)}, cfOptions...)...)
	_, _ = ts.secrets.Put(context.Background(), "cloudflare/api-token", audit.Secret(ts.cf.Token()), nil)

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ts.cf.CAPEM())
	ts.chaos = &chaosAPI{clock: s.clock.Advance}
	engine, err := newTunnelEngine(s.handler.core, &TunnelOptions{
		Config: cfg, Secrets: ts.secrets,
		Sleep: func(_ context.Context, d time.Duration) { ts.slept = append(ts.slept, d) },
		NewAPI: func(account string, token audit.Secret) (CloudflareAPI, error) {
			client, err := cloudflare.New(ts.cf.Endpoint(), account, token,
				cloudflare.WithNetguardOptions(netguard.WithRootCAs(pool), netguard.WithTestDialer(ts.cf.Dial)))
			ts.chaos.CloudflareAPI = client
			return ts.chaos, err
		},
	})
	mustf(t, err, "newTunnelEngine")
	s.handler.tunnel = engine
	ts.disable = tunnelDisableHandler{core: s.handler.core, store: s.store, conn: s.conn, prober: s.handler.prober, tunnel: engine}
	ts.rotate = tunnelRotateHandler{store: s.store, tunnel: engine}
	ts.scriptNode(s.dialer.as("admin"))
	s.dialer.tunnel["admin"] = s.dialer.as("admin") // once switched, the admin session goes through the tunnel too
	scriptDedicated(s.dialer.through("supermgmt"))
	return ts
}

// scriptNode makes the admin session behave like a Debian 13 node that keeps
// the files setup installs, so the tunnel steps converge and can be repeated.
func (ts *tunnelSetting) scriptNode(admin *fakeNode) {
	installed := false
	for _, suffix := range []string{"", templates.SudoVariantSuffix} {
		admin.on("setup.os_release"+suffix, func(templates.Command) (transport.Result, error) {
			return transport.Result{Stdout: []byte("debian trixie\n")}, nil
		})
		admin.on("setup.file_stage"+suffix, func(c templates.Command) (transport.Result, error) {
			ts.files[argument(c.Line, -1)] = string(c.Stdin)
			return transport.Result{}, nil
		})
		admin.on("setup.file_commit"+suffix, func(c templates.Command) (transport.Result, error) {
			ts.files[argument(c.Line, -1)] = ts.files[argument(c.Line, -2)]
			delete(ts.files, argument(c.Line, -2))
			return transport.Result{}, nil
		})
		admin.on("setup.file_sha256"+suffix, func(c templates.Command) (transport.Result, error) {
			content, ok := ts.files[argument(c.Line, -1)]
			if !ok {
				return transport.Result{ExitStatus: 3}, nil
			}
			return transport.Result{Stdout: []byte(sha256Of(content) + "  -\n")}, nil
		})
		admin.on("setup.file_remove"+suffix, func(c templates.Command) (transport.Result, error) {
			delete(ts.files, argument(c.Line, -1))
			return transport.Result{}, nil
		})
		admin.on("setup.apt_install_cloudflared"+suffix, func(templates.Command) (transport.Result, error) {
			installed = true
			return transport.Result{}, nil
		})
	}
	admin.on("setup.cloudflared_package", func(templates.Command) (transport.Result, error) {
		if installed {
			return transport.Result{Stdout: []byte("ii  2026.10.1\n")}, nil
		}
		return transport.Result{ExitStatus: 1}, nil
	})
	admin.reply("systemd.show", "ActiveState=active\n")
}

// plan submits and approves a node.setup with tunnel=true.
func (ts *tunnelSetting) plan() jobs.Job {
	params := defaultSetup()
	params["tunnel"] = "true"
	ts.queued = ts.setupPlan(params)
	return ts.queued
}

// attempt claims the job and runs the handler once; the job stays running on
// failure, as when a worker dies.
func (ts *tunnelSetting) attempt() error {
	ts.t.Helper()
	claimed, ok := ts.claim()
	if !ok {
		ts.t.Fatal("no job to claim")
	}
	ts.lease = claimed.Lease
	var handler jobs.Handler = ts.handler
	if ts.current != nil {
		handler = ts.current
	}
	err := handler.Run(context.Background(), claimed.Lease)
	if err == nil {
		mustf(ts.t, ts.store.Succeed(context.Background(), claimed.Lease), "Succeed")
	}
	return err
}

// converge runs attempts, taking the job over after each failure, until one
// succeeds; it returns the errors of the failed attempts.
func (ts *tunnelSetting) converge(maxAttempts int) []error {
	ts.t.Helper()
	var failures []error
	for range maxAttempts {
		err := ts.attempt()
		if err == nil {
			return failures
		}
		failures = append(failures, err)
		interruptAndRequeue(ts.t, ts.fixture, ts.queued.ID)
	}
	ts.t.Fatalf("did not converge in %d attempts: %v", maxAttempts, failures)
	return failures
}

func (ts *tunnelSetting) operations() []database.TunnelOperation {
	ts.t.Helper()
	ops, err := database.ListTunnelOperations(context.Background(), ts.db.Reader(), ts.node.ID)
	mustf(ts.t, err, "ListTunnelOperations")
	return ops
}

func (ts *tunnelSetting) currentNode() domain.Node {
	ts.t.Helper()
	n, err := database.GetNode(context.Background(), ts.db.Reader(), ts.node.ID)
	mustf(ts.t, err, "GetNode")
	return n
}

func (ts *tunnelSetting) hostname() string { return "ssh-web-1." + cffake.DefaultZone }

// wantOneOfEach fails unless Cloudflare holds exactly the objects of one
// enabled node and the hostname was never routable without Access.
func (ts *tunnelSetting) wantOneOfEach() {
	ts.t.Helper()
	snap := ts.cf.Snapshot()
	if len(snap.Tunnels) != 1 || len(snap.Apps) != 1 || len(snap.DNSRecords) != 1 || len(snap.Policies) != 2 || len(snap.ServiceTokens) != 1 {
		ts.t.Fatalf("objects: %d tunnels, %d apps, %d dns, %d policies, %d tokens; want 1, 1, 1, 2, 1",
			len(snap.Tunnels), len(snap.Apps), len(snap.DNSRecords), len(snap.Policies), len(snap.ServiceTokens))
	}
	if routable := ts.cf.EverRoutableWithoutAccess(); len(routable) != 0 {
		ts.t.Fatalf("routable without Access at some point: %v", routable)
	}
}

// wantRecorded fails unless the operation record and the instance state hold
// the ID of every object Cloudflare has.
func (ts *tunnelSetting) wantRecorded() {
	ts.t.Helper()
	snap := ts.cf.Snapshot()
	active := ts.operations()[0]
	if active.Objects.TunnelID != snap.Tunnels[0].ID || active.Objects.AccessAppID != snap.Apps[0].ID || active.Objects.DNSRecordID != snap.DNSRecords[0].ID {
		ts.t.Errorf("record %+v does not hold the IDs of %+v", active.Objects, snap)
	}
	state, err := database.GetCloudflareState(context.Background(), ts.db.Reader())
	mustf(ts.t, err, "GetCloudflareState")
	ids := map[string]bool{state.ServicePolicyID: true, state.OwnersPolicyID: true}
	for _, p := range snap.Policies {
		if !ids[p.ID] {
			ts.t.Errorf("policy %s is not recorded", p.ID)
		}
	}
	if state.Token.ID != snap.ServiceTokens[0].ID {
		ts.t.Errorf("service token %s is not the recorded %s", snap.ServiceTokens[0].ID, state.Token.ID)
	}
}

func sha256Of(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

// argument returns the i-th space separated word of line, unquoted; negative
// i counts from the end.
func argument(line string, i int) string {
	words := strings.Fields(line)
	if i < 0 {
		i += len(words)
	}
	return strings.Trim(words[i], "'")
}
