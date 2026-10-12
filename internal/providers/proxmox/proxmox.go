// Package proxmox is the Proxmox VE provider (spec §15; ADR-0023, ADR-0024,
// ADR-0025): a client for the PVE HTTP API over netguard, the node kinds and
// native ids discovery writes, UPID parsing and task correlation. It touches
// no storage; internal/app turns its results into rows, observations and jobs.
//
// Frozen in M3 W0. T2 implements, in this package:
//
//	func New(endpoint string, caPEM []byte, token audit.Secret, opts ...Option) (Client, error)
//	func ParseUPID(s string) (UPID, error)
//	func Correlate(tasks []TaskStatus, want Want) (UPID, CorrelationResult)
package proxmox

import (
	"context"
	"time"

	"github.com/autarquico/supermgmt/internal/config"
)

const (
	// ProviderType is the providers.type of a Proxmox provider.
	ProviderType = config.ProviderProxmox

	// Node kinds (nodes.kind) and native id prefixes (ADR-0024).
	KindNode = "proxmox.node" // native id node/<name>
	KindQEMU = "proxmox.qemu" // native id qemu/<vmid>
	KindLXC  = "proxmox.lxc"  // native id lxc/<vmid>

	// ObservationStatus is the observations.kind of a guest's power state.
	ObservationStatus = "proxmox.status"
	// ObservationStorage is the observations.kind of a storage on the provider.
	ObservationStorage = "proxmox.storage"

	// OperationPrefix marks task-tracked intents (ADR-0025 quiescence).
	OperationPrefix = "proxmox."

	// Power deadlines (ADR-0025): the job's deadline_at for each verb.
	DeadlineStart    = 5 * time.Minute
	DeadlineShutdown = 5 * time.Minute
	DeadlineReboot   = 5 * time.Minute
	DeadlineStop     = 2 * time.Minute
)

// GuestType is the PVE guest type.
type GuestType string

const (
	GuestQEMU GuestType = "qemu"
	GuestLXC  GuestType = "lxc"
)

// GuestRef addresses one guest on the node that currently hosts it.
type GuestRef struct {
	Node string
	Type GuestType
	VMID int
}

// Version is GET /version.
type Version struct {
	Version string // e.g. "9.0.3"
	Release string // e.g. "9.0"
}

// ClusterNode is a cluster member from /cluster/resources (type node).
type ClusterNode struct {
	Name   string
	Status string // online | offline | unknown
	MaxCPU int
	MaxMem int64
	CPU    float64
	Mem    int64
	Uptime int64
}

// Guest is a VM or container from /cluster/resources (type vm).
type Guest struct {
	Ref      GuestRef
	Name     string
	Status   string // running | stopped | paused | …
	Template bool
	Pool     string
	MaxCPU   int
	MaxMem   int64
	MaxDisk  int64
	CPU      float64
	Mem      int64
	Disk     int64
	Uptime   int64
}

// Storage is a storage from /cluster/resources (type storage).
type Storage struct {
	ID      string
	Node    string
	Plugin  string
	Content []string
	Total   int64
	Used    int64
	Shared  bool
}

// Inventory is one complete read of the cluster.
type Inventory struct {
	Nodes    []ClusterNode
	Guests   []Guest
	Storages []Storage
}

// Perms is GET /access/permissions for the token: path -> privilege -> granted.
type Perms map[string]map[string]bool

// Has reports whether priv is effective on path. PVE lists the effective set
// per path, and a deeper entry replaces what a parent grants, so the nearest
// listed ancestor ("/vms/101", then "/vms", then "/") decides alone.
func (p Perms) Has(path, priv string) bool {
	for {
		if privs, listed := p[path]; listed {
			return privs[priv]
		}
		if path == "/" || path == "" {
			return false
		}
		i := len(path) - 1
		for i > 0 && path[i] != '/' {
			i--
		}
		path = path[:i]
		if path == "" {
			path = "/"
		}
	}
}

// UPID is a decoded PVE task id:
// UPID:<node>:<pid>:<pstart>:<starttime>:<type>:<id>:<user>:
type UPID struct {
	Raw       string
	Node      string
	PID       int64
	PStart    int64
	StartTime time.Time
	Type      string // qmstart, vzstart, qmshutdown, …
	ID        string // the vmid for guest tasks
	User      string // user@realm!tokenid for token tasks
}

// TaskStatus is one task's state.
type TaskStatus struct {
	UPID       UPID
	Status     string // running | stopped
	ExitStatus string // "OK" or the error text; empty while running
}

// Stopped reports whether the task has finished.
func (t TaskStatus) Stopped() bool { return t.Status == "stopped" }

// TaskFilter narrows a node's task list (all pages are always read).
type TaskFilter struct {
	VMID     int
	TypeName string
	User     string
	Since    time.Time
	Until    time.Time
}

// PowerOutcome classifies a power POST (ADR-0025).
type PowerOutcome int

const (
	// PowerAccepted returned a UPID.
	PowerAccepted PowerOutcome = iota + 1
	// PowerRejected is a definite refusal before any UPID: nothing was accepted.
	PowerRejected
	// PowerUncertain may have been accepted: never retried, correlation decides.
	PowerUncertain
)

// Want describes the task a dispatch without a recorded UPID may have started.
type Want struct {
	Type  string
	VMID  int
	User  string
	From  time.Time
	Until time.Time
}

// CorrelationResult is the number of candidate tasks that matched exactly.
type CorrelationResult int

const (
	CorrelatedNone CorrelationResult = iota
	CorrelatedOne
	CorrelatedMany
)

// Client is the PVE API surface SuperMgmt uses. Every call is bounded by
// ctx; an error never carries the token.
type Client interface {
	Version(ctx context.Context) (Version, error)
	Resources(ctx context.Context) (Inventory, error)
	Permissions(ctx context.Context) (Perms, error)
	Power(ctx context.Context, g GuestRef, verb string) (UPID, PowerOutcome, error)
	Task(ctx context.Context, u UPID) (TaskStatus, error)
	Tasks(ctx context.Context, node string, f TaskFilter) ([]TaskStatus, error)
}
