package app

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/discovery"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/transport"
)

// Prober learns what a node looks like and records it as observations. One
// probe is one SSH session (spec §12); the runtime adapters add one read
// session each when services are discovered. It is shared by the node.probe
// job and the Refresher.
type Prober struct {
	core
	conn     Connector
	adapters Adapters
}

// NewProber validates cfg.
func NewProber(cfg Config, conn Connector, adapters Adapters) (*Prober, error) {
	c, err := newCore(cfg)
	if err != nil {
		return nil, err
	}
	if adapters == nil {
		adapters = DefaultAdapters()
	}
	return &Prober{core: c, conn: conn, adapters: adapters}, nil
}

// ProbeScope says how much a probe learns.
type ProbeScope int

const (
	// ProbeStatus refreshes reachability, metrics, addresses and capabilities.
	ProbeStatus ProbeScope = iota
	// ProbeFull also re-discovers runtimes and their services (the
	// refresh.discovery_interval pass).
	ProbeFull
)

// Probe probes the node and records the result. Fence, when set, runs first in
// the write transaction so a job handler's lease is checked. A failure to
// reach the node marks it unreachable (spec §6.4: observed) and is returned.
func (p *Prober) Probe(ctx context.Context, id domain.ID, scope ProbeScope, fence func(context.Context, database.Querier) error) error {
	node, err := database.GetNode(ctx, p.cfg.DB.Reader(), id)
	if err != nil {
		return err
	}
	if node.ManagementState == domain.ManagementRetired {
		return smerr.New(smerr.CodeConflict, "", "the node is retired")
	}
	setup, err := loadSetup(ctx, p.cfg.DB.Reader(), id)
	if err != nil {
		return err
	}
	ex, err := p.conn.Automated(node, setup)
	if err != nil {
		return err
	}
	snapshot, err := discovery.Probe(ctx, ex)
	if err != nil {
		return p.unreachable(ctx, node, err)
	}
	snapshot.TakenAt = p.cfg.Clock.Now()
	snapshot.Setup = setup
	found := p.discover(ctx, ex, snapshot, scope)
	return p.record(ctx, node, snapshot, found, scope == ProbeFull, fence)
}

// discovered is what one runtime adapter found on the node. Failed means the
// adapter could not tell, which keeps what is already known about it.
type discovered struct {
	runtime domain.RuntimeType
	found   runtimes.Discovered
	failed  bool
}

func (p *Prober) discover(ctx context.Context, ex transport.Executor, s discovery.Snapshot, scope ProbeScope) []discovered {
	if scope != ProbeFull {
		return nil
	}
	var out []discovered
	for _, candidate := range []struct {
		runtime domain.RuntimeType
		present bool
	}{
		{domain.RuntimeSystemd, s.Systemd.Active},
		{domain.RuntimeDocker, s.Docker.Reachable()},
	} {
		adapter, ok := p.adapters[candidate.runtime]
		if !candidate.present || !ok {
			continue
		}
		found, err := adapter.Discover(ctx, ex, runtimes.Filter{})
		out = append(out, discovered{runtime: candidate.runtime, found: found, failed: err != nil})
	}
	return out
}

// record persists one probe in a single transaction.
func (p *Prober) record(ctx context.Context, node domain.Node, s discovery.Snapshot, found []discovered, full bool, fence func(context.Context, database.Querier) error) error {
	return p.cfg.DB.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		if fence != nil {
			if err := fence(ctx, tx); err != nil {
				return err
			}
		}
		if err := p.recordReachability(ctx, tx, node, domain.ReachabilityReachable, ""); err != nil {
			return err
		}
		if err := database.TouchLastSeen(ctx, tx, node.ID, s.TakenAt); err != nil {
			return err
		}
		if err := p.recordFacts(ctx, tx, node, s); err != nil {
			return err
		}
		return p.recordServices(ctx, tx, node, s.TakenAt, found, full)
	})
}

func (p *Prober) recordFacts(ctx context.Context, q database.Querier, node domain.Node, s discovery.Snapshot) error {
	for _, c := range discovery.Capabilities(s, isLocal(node)) {
		if err := database.SetNodeCapability(ctx, q, node.ID, c); err != nil {
			return err
		}
	}
	if err := database.ReplaceNodeAddresses(ctx, q, node.ID, database.SourceProbe, p.addresses(node.ID, s)); err != nil {
		return err
	}
	for kind, value := range map[string]any{observationSystem: systemOf(s), observationMetrics: metricsOf(s)} {
		err := database.RecordObservation(ctx, q, database.Observation{
			ID: p.cfg.IDs.NewID(), ResourceType: domain.ResourceNode, ResourceID: node.ID,
			Kind: kind, Value: value, ObservedAt: s.TakenAt,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *Prober) addresses(node domain.ID, s discovery.Snapshot) []database.NodeAddress {
	out := make([]database.NodeAddress, 0, len(s.Addresses))
	for k, a := range s.Addresses {
		out = append(out, database.NodeAddress{
			ID: p.cfg.IDs.NewID(), NodeID: node, Address: a.Address,
			Family: database.AddressFamily(a.Family), Scope: database.AddressScope(a.Scope), Source: database.SourceProbe,
			Preferred: k == 0, LastSeenAt: s.TakenAt,
		})
	}
	return out
}

func systemOf(s discovery.Snapshot) systemInfo {
	arch := ""
	if fields := strings.Fields(s.Kernel); len(fields) > 0 {
		arch = fields[len(fields)-1]
	}
	name := s.OS.Name
	if name == "" {
		name = strings.TrimSpace(s.OS.ID + " " + s.OS.Version)
	}
	return systemInfo{OS: name, Arch: arch, Kernel: s.Kernel, Hostname: s.Hostname}
}

func metricsOf(s discovery.Snapshot) wire.Metrics {
	return wire.Metrics{
		ObservedAt: s.TakenAt, CPUPercent: s.CPU.UsagePercent,
		MemoryUsedBytes:  bytesOf(s.Memory.TotalKB - min(s.Memory.AvailableKB, s.Memory.TotalKB)),
		MemoryTotalBytes: bytesOf(s.Memory.TotalKB),
		DiskUsedBytes:    bytesOf(s.Disk.UsedKB), DiskTotalBytes: bytesOf(s.Disk.TotalKB),
		UptimeSeconds: int64(s.Uptime.Seconds()),
	}
}

// bytesOf converts kibibytes, saturating instead of overflowing.
func bytesOf(kib uint64) int64 {
	const unit = 1024
	return int64(min(kib, math.MaxInt64/unit)) * unit
}

// recordServices upserts what the adapters found and retires what is gone. An
// adapter that failed this time keeps its runtime and services as they were.
func (p *Prober) recordServices(ctx context.Context, q database.Querier, node domain.Node, at time.Time, found []discovered, full bool) error {
	if !full {
		return nil // a status probe does not discover
	}
	var seen []database.RuntimeKey
	for _, d := range found {
		if d.failed {
			existing, err := database.ListRuntimes(ctx, q, node.ID)
			if err != nil {
				return err
			}
			for _, r := range existing {
				if domain.RuntimeType(r.Type) == d.runtime {
					seen = append(seen, database.RuntimeKey{Type: r.Type, NativeID: r.NativeID})
				}
			}
			continue
		}
		key, err := p.recordRuntime(ctx, q, node, at, d.found)
		if err != nil {
			return err
		}
		seen = append(seen, key)
	}
	_, err := database.RetireMissingRuntimes(ctx, q, node.ID, seen)
	return err
}

func (p *Prober) recordRuntime(ctx context.Context, q database.Querier, node domain.Node, at time.Time, d runtimes.Discovered) (database.RuntimeKey, error) {
	rt, err := database.UpsertRuntime(ctx, q, domain.Runtime{
		ID: p.cfg.IDs.NewID(), NodeID: node.ID, Type: string(d.Runtime.Type), NativeID: d.Runtime.NativeID,
		Version: d.Runtime.Version, Status: d.Runtime.Status, Metadata: d.Runtime.Metadata, LastSeenAt: &at,
	})
	if err != nil {
		return database.RuntimeKey{}, err
	}
	seen := make([]string, 0, len(d.Services))
	for _, s := range d.Services {
		_, err := database.UpsertService(ctx, q, domain.Service{
			ID: p.cfg.IDs.NewID(), RuntimeID: rt.ID, NodeID: node.ID, NativeID: s.NativeID, Name: s.Name,
			Kind: string(s.Kind), Status: s.Status, Health: s.Health, Metadata: s.Metadata, LastSeenAt: &at,
		})
		if err != nil {
			return database.RuntimeKey{}, err
		}
		seen = append(seen, s.NativeID)
	}
	if _, err := database.RetireMissingServices(ctx, q, rt.ID, seen); err != nil {
		return database.RuntimeKey{}, err
	}
	return database.RuntimeKey{Type: rt.Type, NativeID: rt.NativeID}, nil
}

// unreachable records that the node could not be reached, when that is what
// err says, and returns err. Cancellation and parsing problems are not
// observations about the node.
func (p *Prober) unreachable(ctx context.Context, node domain.Node, err error) error {
	if ctx.Err() != nil || !connectivityFailure(err) {
		return err
	}
	reason := string(smerr.CodeOf(err))
	werr := p.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		return p.recordReachability(ctx, tx, node, domain.ReachabilityUnreachable, reason)
	})
	return errors.Join(err, werr)
}

func connectivityFailure(err error) bool {
	code := smerr.CodeOf(err)
	return code == smerr.CodeNodeUnreachable || code == smerr.CodeTimeout || code == smerr.CodeSSHHostKeyMismatch
}

// recordReachability stores the observed reachability and audits the change.
func (p *Prober) recordReachability(ctx context.Context, q database.Querier, node domain.Node, to domain.Reachability, reason string) error {
	current, err := database.GetNode(ctx, q, node.ID)
	if err != nil {
		return err
	}
	if current.Reachability == to {
		return nil
	}
	if err := database.SetNodeReachability(ctx, q, node.ID, to); err != nil {
		return err
	}
	data := map[string]any{"from": string(current.Reachability), "to": string(to)}
	if reason != "" {
		data["reason"] = reason
	}
	return p.emit(ctx, q, systemActor, "node.reachability", nodeRef(node.ID), domain.ResultSucceeded, data)
}

// probeHandler is the node.probe job (idempotent, spec §11.2).
type probeHandler struct {
	prober *Prober
	store  *jobs.Store
}

func (h probeHandler) Run(ctx context.Context, lease jobs.Lease) error {
	job, err := h.store.Get(ctx, h.prober.cfg.DB.Reader(), lease.JobID)
	if err != nil {
		return err
	}
	if err := h.prober.Probe(ctx, job.Resource.ID, ProbeFull, lease.Fence); err != nil {
		return fmt.Errorf("probe node %s: %w", job.Resource.ID, err)
	}
	return nil
}
