package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/policy"
	"github.com/autarquico/supermgmt/internal/providers/proxmox"
	"github.com/autarquico/supermgmt/internal/secrets"
	"github.com/autarquico/supermgmt/internal/textsafe"
)

// Provider statuses discovery writes to providers.status.
const (
	ProviderStatusOK      = "ok"
	ProviderStatusError   = "error"
	ProviderStatusRemoved = "removed" // left the configuration file: not synced, nothing deleted
)

// Presence of a discovered object, in the proxmox.status observation
// (ADR-0024). Absent: the token can still see where the object would be and
// it is gone. Inaccessible: the token cannot, so nothing is known.
const (
	PresencePresent      = "present"
	PresenceAbsent       = "absent"
	PresenceInaccessible = "inaccessible"
)

// Keys of providers.config_json that discovery reads.
const (
	providerConfigCAFile       = "ca_file"
	providerConfigSyncInterval = "sync_interval"
)

const (
	// CapabilityVMPower is advertised for a guest the token may power-manage.
	CapabilityVMPower = "proxmox.vm.power"

	// ObservationProxmoxSync is the provider observation that holds the
	// outcome of the latest sync whose outcome differed from the one before.
	ObservationProxmoxSync = "proxmox.sync"

	eventProviderSync = "provider.sync"
	proxmoxSource     = "proxmox"

	privVMAudit   = "VM.Audit"
	privSysAudit  = "Sys.Audit"
	privPowerMgmt = "VM.PowerMgmt"

	defaultSyncInterval = 30 * time.Second
	defaultSyncTick     = time.Second
	defaultSyncTimeout  = time.Minute
	syncErrorLimit      = 200
)

// ProxmoxStatus is the value of a node's proxmox.status observation: the power
// state PVE reported, and whether the object is there at all. It is never
// written to reachability (spec §15.3).
type ProxmoxStatus struct {
	Status   string `json:"status"`
	Presence string `json:"presence"`
}

// SyncReport is the value of the provider's proxmox.sync observation.
type SyncReport struct {
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
	Nodes    int    `json:"nodes"`
	Guests   int    `json:"guests"`
	Storages int    `json:"storages"`
	// ClockSkew is the PVE answer's Date header minus the local clock (ADR-0025:
	// task correlation tolerates 120s).
	ClockSkew time.Duration `json:"clock_skew_ns"`
}

// StorageObservation is one storage in the provider's proxmox.storage
// observation.
type StorageObservation struct {
	ID      string   `json:"id"`
	Node    string   `json:"node"`
	Plugin  string   `json:"plugin"`
	Content []string `json:"content"`
	Total   int64    `json:"total_bytes"`
	Used    int64    `json:"used_bytes"`
	Shared  bool     `json:"shared"`
}

// SyncFailure is a sync that could not read the cluster (credentials, trust,
// network, privileges). It has been recorded on the provider; callers that
// only need the provider's state may ignore it.
type SyncFailure struct{ Err error }

func (e *SyncFailure) Error() string { return "proxmox sync failed: " + e.Err.Error() }
func (e *SyncFailure) Unwrap() error { return e.Err }

// TokenSource resolves a credential_ref ("secret://...") to the PVE API token
// "<user>@<realm>!<tokenid>=<secret>".
type TokenSource func(ctx context.Context, ref string) (audit.Secret, error)

// SecretToken resolves "secret://<name>" references from the secret store.
func SecretToken(store *secrets.Store) TokenSource {
	return func(ctx context.Context, ref string) (audit.Secret, error) {
		name, ok := strings.CutPrefix(ref, "secret://")
		if !ok {
			return "", fmt.Errorf("credential reference %q is not a secret:// reference", ref)
		}
		return store.Get(ctx, secrets.Ref{Name: name})
	}
}

// ProxmoxSyncOptions tune the ProxmoxSync.
type ProxmoxSyncOptions struct {
	Token TokenSource // required
	// ReadFile reads ca_file; default os.ReadFile.
	ReadFile func(string) ([]byte, error)
	// Client are passed to proxmox.New; tests use them to reach a fake.
	Client []proxmox.Option
	// Tick is how often due providers are looked for; default 1s.
	Tick time.Duration
	// DefaultInterval applies to a provider with no sync_interval; default 30s.
	DefaultInterval time.Duration
	// Timeout bounds one sync; default 1m.
	Timeout time.Duration
	// OnError receives the syncs that failed; the failure is also on the provider.
	OnError func(provider domain.ID, err error)
}

// ProxmoxSync discovers Proxmox clusters (spec §15.1, §15.3, ADR-0024): it
// reads cluster nodes, VMs, LXCs, storages and metrics with the provider's
// token, keeps them as discovered nodes and observations, and tells an object
// that is gone from one the token can no longer see. One sync runs per
// provider at a time; a request that arrives meanwhile shares its outcome.
type ProxmoxSync struct {
	core
	opts ProxmoxSyncOptions

	mu       sync.Mutex
	inflight map[domain.ID]*flight
	started  map[domain.ID]time.Time
	clients  map[domain.ID]cachedClient
	running  sync.WaitGroup
}

type flight struct {
	done chan struct{}
	err  error
}

type cachedClient struct {
	key    string
	client proxmox.Client
}

// NewProxmoxSync validates cfg and the options.
func NewProxmoxSync(cfg Config, o ProxmoxSyncOptions) (*ProxmoxSync, error) {
	c, err := newCore(cfg)
	if err != nil {
		return nil, err
	}
	if o.Token == nil {
		return nil, errors.New("app: a token source is required")
	}
	if o.ReadFile == nil {
		o.ReadFile = os.ReadFile
	}
	o.Tick = orDefaultDuration(o.Tick, defaultSyncTick)
	o.DefaultInterval = orDefaultDuration(o.DefaultInterval, defaultSyncInterval)
	o.Timeout = orDefaultDuration(o.Timeout, defaultSyncTimeout)
	if o.OnError == nil {
		o.OnError = func(domain.ID, error) {}
	}
	return &ProxmoxSync{
		core: c, opts: o, inflight: map[domain.ID]*flight{}, started: map[domain.ID]time.Time{}, clients: map[domain.ID]cachedClient{},
	}, nil
}

func orDefaultDuration(d, fallback time.Duration) time.Duration {
	if d <= 0 {
		return fallback
	}
	return d
}

// Run starts the syncs that are due every tick until ctx ends, then waits for
// the ones in flight (they are cancelled with ctx).
func (s *ProxmoxSync) Run(ctx context.Context) error {
	defer s.Wait()
	ticker := time.NewTicker(s.opts.Tick)
	defer ticker.Stop()
	for {
		if err := s.pass(ctx); err != nil && ctx.Err() == nil {
			s.opts.OnError("", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// Wait blocks until every sync Run started has finished.
func (s *ProxmoxSync) Wait() { s.running.Wait() }

func (s *ProxmoxSync) pass(ctx context.Context) error {
	providers, err := database.ListProviders(ctx, s.cfg.DB.Reader())
	if err != nil {
		return err
	}
	now := s.cfg.Clock.Now()
	for _, p := range providers {
		if s.syncs(p) && s.due(p, now) {
			s.running.Go(func() {
				if err := s.Sync(ctx, p.ID); err != nil && ctx.Err() == nil {
					s.opts.OnError(p.ID, err)
				}
			})
		}
	}
	return nil
}

func (s *ProxmoxSync) syncs(p domain.Provider) bool {
	return p.Type == proxmox.ProviderType && p.Status != ProviderStatusRemoved
}

// due claims the provider's next sync when its interval has passed.
func (s *ProxmoxSync) due(p domain.Provider, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if last, ok := s.started[p.ID]; ok && now.Sub(last) < s.interval(p) {
		return false
	}
	s.started[p.ID] = now
	return true
}

func (s *ProxmoxSync) interval(p domain.Provider) time.Duration {
	if d, ok := configuredSyncInterval(p); ok {
		return d
	}
	return s.opts.DefaultInterval
}

// ProviderSyncInterval is how often a Proxmox provider is synced.
func ProviderSyncInterval(p domain.Provider) time.Duration {
	if d, ok := configuredSyncInterval(p); ok {
		return d
	}
	return defaultSyncInterval
}

func configuredSyncInterval(p domain.Provider) (time.Duration, bool) {
	text, _ := p.Config[providerConfigSyncInterval].(string)
	d, err := time.ParseDuration(text)
	return d, err == nil && d > 0
}

// Sync runs one discovery of the provider, or joins the one already running
// and returns its outcome. A *SyncFailure means the cluster could not be read;
// the failure is recorded on the provider. Any other error is a local failure
// (storage, cancellation, a provider that is not a Proxmox cluster).
func (s *ProxmoxSync) Sync(ctx context.Context, id domain.ID) error {
	s.mu.Lock()
	if running, ok := s.inflight[id]; ok {
		s.mu.Unlock()
		select {
		case <-running.done:
			return running.err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	f := &flight{done: make(chan struct{})}
	s.inflight[id] = f
	s.mu.Unlock()

	f.err = s.syncOnce(ctx, id)

	s.mu.Lock()
	delete(s.inflight, id)
	s.mu.Unlock()
	close(f.done)
	return f.err
}

func (s *ProxmoxSync) syncOnce(ctx context.Context, id domain.ID) error {
	ctx = context.WithValue(ctx, sourceKey{}, proxmoxSource)
	p, err := database.GetProvider(ctx, s.cfg.DB.Reader(), id)
	if err != nil {
		return err
	}
	if err := requireSyncable(p); err != nil {
		return err
	}
	read, cancel := context.WithTimeout(ctx, s.opts.Timeout)
	defer cancel()
	state, err := s.read(read, p)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := s.recordFailure(ctx, p, err); err != nil {
			return err
		}
		return &SyncFailure{Err: err}
	}
	return s.apply(ctx, p, state)
}

func requireSyncable(p domain.Provider) error {
	switch {
	case p.Type != proxmox.ProviderType:
		return smerr.New(smerr.CodeInvalidArgument, "", fmt.Sprintf("provider %q is not a Proxmox provider", p.Name))
	case p.Status == ProviderStatusRemoved:
		return smerr.New(smerr.CodeInvalidArgument, "", fmt.Sprintf("provider %q was removed from the configuration file", p.Name))
	}
	return nil
}

// clusterRead is one successful read of a cluster: what it reports, and what
// the token may do on the ACL paths the sync decides on (each asked of PVE
// for that exact path, never inferred from the paths PVE lists).
type clusterRead struct {
	inventory proxmox.Inventory
	access    map[string]proxmox.Privileges
	readAt    time.Time
}

func (s *ProxmoxSync) read(ctx context.Context, p domain.Provider) (clusterRead, error) {
	client, err := s.clientFor(ctx, p)
	if err != nil {
		return clusterRead{}, err
	}
	inventory, err := client.Resources(ctx)
	if err != nil {
		return clusterRead{}, fmt.Errorf("read the cluster: %w", err)
	}
	known, err := database.ListNodes(ctx, s.cfg.DB.Reader())
	if err != nil {
		return clusterRead{}, err
	}
	access, err := readAccess(ctx, client, aclPathsToJudge(p, inventory, known))
	if err != nil {
		return clusterRead{}, fmt.Errorf("read the token's permissions: %w", err)
	}
	return clusterRead{inventory: inventory, access: access, readAt: s.cfg.Clock.Now()}, nil
}

// aclPathsToJudge are the paths whose privileges the sync acts on: the
// guests it may advertise power for, and where an object of an earlier sync
// that this read did not report would be.
func aclPathsToJudge(p domain.Provider, inventory proxmox.Inventory, known []domain.Node) []string {
	seen := map[string]bool{}
	var paths []string
	add := func(path string) {
		if path != "" && !seen[path] {
			seen[path] = true
			paths = append(paths, path)
		}
	}
	for _, g := range inventory.Guests {
		if !g.Template {
			add(guestACLPath(g.Ref.VMID))
		}
	}
	reported := reportedNatives(inventory)
	for _, n := range known {
		if n.ProviderID == p.ID && isDiscoveredKind(n.Kind) && !reported[n.NativeID] {
			add(visibilityPath(n))
		}
	}
	return paths
}

func reportedNatives(inventory proxmox.Inventory) map[string]bool {
	out := map[string]bool{}
	for _, n := range inventory.Nodes {
		out[clusterNodeSpec(n).native] = true
	}
	for _, g := range inventory.Guests {
		out[guestSpec(g).native] = true
	}
	return out
}

func readAccess(ctx context.Context, client proxmox.Client, paths []string) (map[string]proxmox.Privileges, error) {
	access := make(map[string]proxmox.Privileges, len(paths))
	for _, path := range paths {
		privs, err := client.PathPermissions(ctx, path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		access[path] = privs
	}
	return access, nil
}

// clientFor builds the provider's client, reusing the last one while the
// endpoint, the CA and the token are unchanged.
func (s *ProxmoxSync) clientFor(ctx context.Context, p domain.Provider) (proxmox.Client, error) {
	token, err := s.opts.Token(ctx, p.CredentialRef)
	if err != nil {
		return nil, fmt.Errorf("the API token is unavailable: %w", err)
	}
	var ca []byte
	if path, _ := p.Config[providerConfigCAFile].(string); path != "" {
		if ca, err = s.opts.ReadFile(path); err != nil {
			return nil, fmt.Errorf("read ca_file: %w", err)
		}
	}
	key := clientKey(p.Endpoint, ca, token)
	s.mu.Lock()
	cached, ok := s.clients[p.ID]
	s.mu.Unlock()
	if ok && cached.key == key {
		return cached.client, nil
	}
	client, err := proxmox.New(p.Endpoint, ca, token, s.opts.Client...)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.clients[p.ID] = cachedClient{key: key, client: client}
	s.mu.Unlock()
	return client, nil
}

func clientKey(endpoint string, ca []byte, token audit.Secret) string {
	h := sha256.New()
	for _, part := range [][]byte{[]byte(endpoint), ca, []byte(token.Reveal())} {
		h.Write(strconv.AppendInt(nil, int64(len(part)), 10))
		h.Write([]byte{0})
		h.Write(part)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ---- recording ---------------------------------------------------------------

// fence refuses a write made from a read of the provider as it was at the start
// of the sync when the provider has since been removed from the configuration
// or reconfigured: a sync in flight must not undo either.
func (s *ProxmoxSync) fence(ctx context.Context, q database.Querier, read domain.Provider) error {
	now, err := database.GetProvider(ctx, q, read.ID)
	if err != nil {
		return err
	}
	if now.Status == ProviderStatusRemoved || now.SpecRevision != read.SpecRevision {
		return smerr.New(smerr.CodeConflict, "", fmt.Sprintf("provider %q changed while it was being synced", read.Name))
	}
	return nil
}

func (s *ProxmoxSync) recordFailure(ctx context.Context, p domain.Provider, cause error) error {
	message := limitText(textsafe.Line(cause.Error()), syncErrorLimit)
	return s.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		if err := s.fence(ctx, tx, p); err != nil {
			return err
		}
		if err := database.SetProviderStatus(ctx, tx, p.ID, ProviderStatusError, nil); err != nil {
			return err
		}
		return s.recordOutcome(ctx, tx, p, SyncReport{Error: message})
	})
}

// recordOutcome keeps the sync observation current and audits a change of
// status. It writes only when the outcome differs from the last recorded one,
// so a cluster that stays down does not fill the log every interval.
func (s *ProxmoxSync) recordOutcome(ctx context.Context, q database.Querier, p domain.Provider, report SyncReport) error {
	previous, known := LatestSyncReport(ctx, q, p.ID)
	status := ProviderStatusError
	if report.OK {
		status = ProviderStatusOK
	}
	transition := p.Status != status
	if known && !transition && previous.Error == report.Error {
		return nil
	}
	if err := s.observe(ctx, q, providerRef(p.ID), ObservationProxmoxSync, report, s.cfg.Clock.Now()); err != nil {
		return err
	}
	if !transition {
		return nil
	}
	result, data := domain.ResultSucceeded, map[string]any{"name": p.Name, "status": status}
	if !report.OK {
		result, data["error"] = domain.ResultFailed, report.Error
	}
	return s.emit(ctx, q, systemActor, eventProviderSync, providerRef(p.ID), result, data)
}

func (s *ProxmoxSync) observe(ctx context.Context, q database.Querier, ref domain.ResourceRef, kind string, value any, at time.Time) error {
	return database.RecordObservation(ctx, q, database.Observation{
		ID: s.cfg.IDs.NewID(), ResourceType: ref.Type, ResourceID: ref.ID, Kind: kind, Value: value, ObservedAt: at,
	})
}

// LatestSyncReport is the most recent recorded outcome of a provider's sync.
func LatestSyncReport(ctx context.Context, q database.Querier, provider domain.ID) (SyncReport, bool) {
	o, err := database.LatestObservation(ctx, q, providerRef(provider), ObservationProxmoxSync)
	if err != nil {
		return SyncReport{}, false
	}
	var report SyncReport
	if decodeObservation(o, &report) != nil {
		return SyncReport{}, false
	}
	return report, true
}

// apply stores one successful read in a single transaction: the provider's
// status first, so a reader never sees fresh objects under a stale status.
func (s *ProxmoxSync) apply(ctx context.Context, p domain.Provider, c clusterRead) error {
	return s.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		if err := s.fence(ctx, tx, p); err != nil {
			return err
		}
		tree, err := s.newTreeSync(ctx, tx, p, c)
		if err != nil {
			return err
		}
		if err := tree.run(); err != nil {
			return err
		}
		storages := storageObservations(c.inventory.Storages)
		if err := s.observe(ctx, tx, providerRef(p.ID), proxmox.ObservationStorage, map[string]any{"storages": storages}, c.readAt); err != nil {
			return err
		}
		syncedAt := c.readAt
		if err := database.SetProviderStatus(ctx, tx, p.ID, ProviderStatusOK, &syncedAt); err != nil {
			return err
		}
		return s.recordOutcome(ctx, tx, p, SyncReport{
			OK: true, Nodes: len(c.inventory.Nodes), Guests: len(c.inventory.Guests), Storages: len(c.inventory.Storages),
		})
	})
}

func storageObservations(in []proxmox.Storage) []StorageObservation {
	out := make([]StorageObservation, len(in))
	for i, st := range in {
		out[i] = StorageObservation{
			ID: st.ID, Node: st.Node, Plugin: st.Plugin, Content: nonNil(st.Content),
			Total: st.Total, Used: st.Used, Shared: st.Shared,
		}
	}
	return out
}

// ---- the tree ----------------------------------------------------------------

// treeSync writes the cluster nodes and guests of one read.
type treeSync struct {
	*ProxmoxSync
	ctx      context.Context
	q        database.Querier
	provider domain.Provider
	cluster  clusterRead
	existing map[string]domain.Node
	statuses map[domain.ID]database.Observation
}

func (s *ProxmoxSync) newTreeSync(ctx context.Context, q database.Querier, p domain.Provider, c clusterRead) (*treeSync, error) {
	nodes, err := database.ListNodes(ctx, q)
	if err != nil {
		return nil, err
	}
	statuses, err := database.LatestObservations(ctx, q, domain.ResourceNode, proxmox.ObservationStatus)
	if err != nil {
		return nil, err
	}
	t := &treeSync{ProxmoxSync: s, ctx: ctx, q: q, provider: p, cluster: c, existing: map[string]domain.Node{}, statuses: statuses}
	for _, n := range nodes {
		if n.ProviderID == p.ID {
			t.existing[n.NativeID] = n
		}
	}
	return t, nil
}

func (t *treeSync) run() error {
	seen := map[string]bool{}
	for _, n := range t.cluster.inventory.Nodes {
		spec := clusterNodeSpec(n)
		seen[spec.native] = true
		if err := t.present(spec); err != nil {
			return err
		}
	}
	for _, g := range t.cluster.inventory.Guests {
		spec := guestSpec(g)
		seen[spec.native] = true
		if err := t.present(spec); err != nil {
			return err
		}
	}
	return t.missing(seen)
}

// objectSpec is what the cluster says about one node or guest.
type objectSpec struct {
	native, name, kind string
	metadata           map[string]any
	status             string
	metrics            wire.Metrics
	powerPath          string // the ACL path that grants power over the guest; empty for cluster nodes
}

func clusterNodeSpec(n proxmox.ClusterNode) objectSpec {
	return objectSpec{
		native: "node/" + n.Name, name: n.Name, kind: proxmox.KindNode, status: n.Status,
		metadata: map[string]any{"pve_node": n.Name, "type": "node", "maxcpu": n.MaxCPU, "maxmem": n.MaxMem},
		metrics: wire.Metrics{
			CPUPercent: n.CPU * 100, MemoryUsedBytes: n.Mem, MemoryTotalBytes: n.MaxMem, UptimeSeconds: n.Uptime,
		},
	}
}

func guestSpec(g proxmox.Guest) objectSpec {
	vmid := strconv.Itoa(g.Ref.VMID)
	kind := proxmox.KindQEMU
	if g.Ref.Type == proxmox.GuestLXC {
		kind = proxmox.KindLXC
	}
	name := g.Name
	if name == "" {
		name = string(g.Ref.Type) + "-" + vmid
	}
	metadata := map[string]any{
		"pve_node": g.Ref.Node, "vmid": g.Ref.VMID, "type": string(g.Ref.Type), "template": g.Template,
		"maxcpu": g.MaxCPU, "maxmem": g.MaxMem, "maxdisk": g.MaxDisk,
	}
	if g.Pool != "" {
		metadata["pool"] = g.Pool
	}
	return objectSpec{
		native: string(g.Ref.Type) + "/" + vmid, name: name, kind: kind, status: g.Status, metadata: metadata,
		metrics: wire.Metrics{
			CPUPercent: g.CPU * 100, MemoryUsedBytes: g.Mem, MemoryTotalBytes: g.MaxMem,
			DiskUsedBytes: g.Disk, DiskTotalBytes: g.MaxDisk, UptimeSeconds: g.Uptime,
		},
		powerPath: guestACLPath(g.Ref.VMID),
	}
}

// guestACLPath is the ACL path of a guest. PVE resolves the guest's pool and
// the paths above it when asked about this one, so nothing else is consulted.
func guestACLPath(vmid int) string { return "/vms/" + strconv.Itoa(vmid) }

// visibilityPath is the ACL path on which the audit privilege decides whether
// the token could see n.
func visibilityPath(n domain.Node) string {
	if n.Kind == proxmox.KindNode {
		name, _ := n.Metadata["pve_node"].(string)
		return "/nodes/" + name
	}
	vmid, _ := n.Metadata["vmid"].(float64) // metadata comes back from JSON
	return guestACLPath(int(vmid))
}

func (t *treeSync) grants(priv, path string) bool { return t.cluster.access[path].Has(priv) }

// present stores an object the cluster reported.
func (t *treeSync) present(o objectSpec) error {
	node, err := t.upsert(o)
	if err != nil {
		return err
	}
	at := t.cluster.readAt
	if err := database.TouchLastSeen(t.ctx, t.q, node.ID, at); err != nil {
		return err
	}
	o.metrics.ObservedAt = at
	if err := t.observe(t.ctx, t.q, nodeRef(node.ID), observationMetrics, o.metrics, at); err != nil {
		return err
	}
	if err := t.observe(t.ctx, t.q, nodeRef(node.ID), proxmox.ObservationStatus, ProxmoxStatus{Status: o.status, Presence: PresencePresent}, at); err != nil {
		return err
	}
	return t.advertisePower(node.ID, o)
}

// advertisePower keeps proxmox.vm.power in step with the token's privilege.
// Templates cannot be powered. Cluster nodes have no such capability.
func (t *treeSync) advertisePower(node domain.ID, o objectSpec) error {
	if o.powerPath == "" {
		return nil
	}
	template, _ := o.metadata["template"].(bool)
	available := !template && t.grants(privPowerMgmt, o.powerPath)
	return t.setPower(node, available)
}

func (t *treeSync) setPower(node domain.ID, available bool) error {
	return database.SetNodeCapability(t.ctx, t.q, node, database.NodeCapability{
		Capability: CapabilityVMPower, Available: available, CheckedAt: t.cluster.readAt,
	})
}

// metadataIncarnation is the node metadata key that names one life of a guest:
// discovery assigns it when it first sees the guest and again whenever the
// guest comes back after the cluster stopped reporting it, because a VMID that
// was freed can be given to another guest.
const metadataIncarnation = "incarnation"

// upsert creates the object as a discovered node or brings the existing row up
// to date. A rename or a new incarnation changes what a plan was made for, so
// either bumps spec_revision; a move to another PVE node only rewrites the
// observed metadata.
func (t *treeSync) upsert(o objectSpec) (domain.Node, error) {
	current, found := t.existing[o.native]
	if !found {
		return t.create(o)
	}
	incarnation, reborn := t.incarnationOf(current, o)
	if incarnation != "" {
		o.metadata[metadataIncarnation] = incarnation
	}
	if fields := changedByDiscovery(current, o, reborn); len(fields) > 0 {
		stored, err := t.reviseSpec(current, o, fields)
		if err != nil {
			return domain.Node{}, err
		}
		current.Name, current.SpecRevision = stored.Name, stored.SpecRevision
	}
	if !sameJSON(current.Metadata, o.metadata) {
		if err := database.SetNodeMetadata(t.ctx, t.q, current.ID, o.metadata); err != nil {
			return domain.Node{}, err
		}
		current.Metadata = o.metadata
	}
	t.existing[o.native] = current
	return current, nil
}

func (t *treeSync) create(o objectSpec) (domain.Node, error) {
	now := t.cluster.readAt
	if o.powerPath != "" {
		o.metadata[metadataIncarnation] = t.cfg.IDs.NewID().String()
	}
	created, err := database.CreateNode(t.ctx, t.q, domain.Node{
		ID: t.cfg.IDs.NewID(), ProviderID: t.provider.ID, NativeID: o.native, Name: o.name, Kind: o.kind,
		ManagementState: domain.ManagementDiscovered, Reachability: domain.ReachabilityUnknown,
		Tags: []string{}, Metadata: o.metadata, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		return domain.Node{}, err
	}
	t.existing[o.native] = created
	return created, t.emit(t.ctx, t.q, systemActor, actionNodeAdd, nodeRef(created.ID), domain.ResultSucceeded,
		map[string]any{"name": o.name, "kind": o.kind, "origin": "discovery", "provider": t.provider.Name})
}

// incarnationOf is the incarnation the guest has after this read, and whether
// it is a new one because the guest was gone from the previous read. Rows
// written before incarnations existed get theirs without a new revision.
func (t *treeSync) incarnationOf(current domain.Node, o objectSpec) (id string, reborn bool) {
	if o.powerPath == "" {
		return "", false
	}
	id, _ = current.Metadata[metadataIncarnation].(string)
	switch presence := t.presenceOf(current.ID); {
	case id == "":
		return t.cfg.IDs.NewID().String(), false
	case presence != "" && presence != PresencePresent:
		return t.cfg.IDs.NewID().String(), true
	}
	return id, false
}

func changedByDiscovery(current domain.Node, o objectSpec, reborn bool) []string {
	var fields []string
	if current.Name != o.name {
		fields = append(fields, "name")
	}
	if reborn {
		fields = append(fields, metadataIncarnation)
	}
	return fields
}

func (t *treeSync) reviseSpec(current domain.Node, o objectSpec, fields []string) (domain.Node, error) {
	next := current
	next.Name, next.UpdatedAt = o.name, t.cluster.readAt
	stored, err := database.UpdateNodeSpec(t.ctx, t.q, next, current.SpecRevision)
	if err != nil {
		return domain.Node{}, err
	}
	err = t.emit(t.ctx, t.q, systemActor, actionNodeUpdate, nodeRef(current.ID), domain.ResultSucceeded,
		map[string]any{"fields": fields, "spec_revision": stored.SpecRevision, "origin": "discovery"})
	return stored, err
}

func sameJSON(a, b any) bool {
	x, errA := json.Marshal(a)
	y, errB := json.Marshal(b)
	return errA == nil && errB == nil && string(x) == string(y)
}

// missing marks the objects of earlier syncs that this read did not report.
// The row is kept; whether the object is gone or merely out of the token's
// sight decides the presence.
func (t *treeSync) missing(seen map[string]bool) error {
	for native, n := range t.existing {
		if seen[native] || !isDiscoveredKind(n.Kind) {
			continue
		}
		presence := PresenceInaccessible
		if t.visibleToToken(n) {
			presence = PresenceAbsent
		}
		if err := t.markMissing(n, presence); err != nil {
			return err
		}
	}
	return nil
}

func isDiscoveredKind(kind string) bool {
	return kind == proxmox.KindNode || kind == proxmox.KindQEMU || kind == proxmox.KindLXC
}

// visibleToToken reports whether the token could see n if it existed: the
// audit privilege on its path (ADR-0024).
func (t *treeSync) visibleToToken(n domain.Node) bool {
	if n.Kind == proxmox.KindNode {
		return t.grants(privSysAudit, visibilityPath(n))
	}
	return t.grants(privVMAudit, visibilityPath(n))
}

func (t *treeSync) markMissing(n domain.Node, presence string) error {
	if n.Kind != proxmox.KindNode {
		if err := t.setPower(n.ID, false); err != nil {
			return err
		}
	}
	if t.presenceOf(n.ID) == presence {
		return nil
	}
	return t.observe(t.ctx, t.q, nodeRef(n.ID), proxmox.ObservationStatus, ProxmoxStatus{Status: "unknown", Presence: presence}, t.cluster.readAt)
}

func (t *treeSync) presenceOf(node domain.ID) string {
	o, ok := t.statuses[node]
	if !ok {
		return ""
	}
	var status ProxmoxStatus
	if decodeObservation(o, &status) != nil {
		return ""
	}
	return status.Presence
}

// ---- on demand ---------------------------------------------------------------

// Refresh runs a discovery now, for a caller that may read the provider
// (spec §15.3, §23: POST /providers/{id}/refresh is action provider.read and
// writes observations and discovered rows only). It answers with the
// provider as the sync left it, also when the cluster could not be read: its
// status says so.
func (s *ProxmoxSync) Refresh(ctx context.Context, by Caller, id domain.ID) (wire.Provider, error) {
	q := s.cfg.DB.Reader()
	actor, err := s.beginRequest(ctx, q, by)
	if err != nil {
		return wire.Provider{}, err
	}
	p, err := database.GetProvider(ctx, q, id)
	if err != nil {
		return wire.Provider{}, err
	}
	if err := s.allowRead(ctx, actor, p); err != nil {
		return wire.Provider{}, err
	}
	if err := requireSyncable(p); err != nil {
		return wire.Provider{}, err
	}
	var failure *SyncFailure
	if err := s.Sync(ctx, id); err != nil && !errors.As(err, &failure) {
		return wire.Provider{}, err
	}
	p, err = database.GetProvider(ctx, s.cfg.DB.Reader(), id)
	return ProviderViewIn(ctx, s.cfg.DB.Reader(), p), err
}

func (s *ProxmoxSync) allowRead(ctx context.Context, actor domain.Actor, p domain.Provider) error {
	const action = "provider.read"
	target := policy.Target{Ref: providerRef(p.ID), Attrs: policy.Attributes{Provider: p.Name}}
	res := s.authorize(policy.Request{Actor: actor, Action: action, Targets: []policy.Target{target}})
	if res.Decision == policy.DecisionAllow {
		return nil
	}
	return s.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		if err := s.auditDecision(ctx, tx, actor, action, target.Ref, res); err != nil {
			return err
		}
		return reject(decisionError(res))
	})
}
