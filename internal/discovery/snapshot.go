// Package discovery turns one node probe (spec §12) into a typed snapshot and
// the node's capabilities (spec §7). Read capabilities always follow what the
// probe saw; mutating ones are advertised only on SSH nodes that completed
// node.setup (ADR-0009 g).
package discovery

import (
	"strings"
	"time"

	"github.com/autarquico/supermgmt/internal/runtimes"
)

// Snapshot is one probe. A zero value means the probe did not learn it: an
// empty probe section is "unknown", never "false" (the Known flags and empty
// strings say which).
type Snapshot struct {
	// TakenAt is stamped by the caller (Probe has no clock); it becomes the
	// CheckedAt of every capability.
	TakenAt time.Time

	Kernel   string // "Linux 6.12.0 x86_64"
	Hostname string
	OS       OSInfo
	Uptime   time.Duration // 0 when unknown
	CPU      CPU
	Load     [3]float64
	Memory   Memory
	Disk     Disk
	// PackageManagers lists those found, in probe order.
	PackageManagers []string
	Systemd         Systemd
	Docker          Docker
	Tools           Tools
	// PasswordlessSudo is true when `sudo -n true` worked for the probing user.
	PasswordlessSudo bool
	Probed           ProbedAs
	Addresses        []Address

	// Setup is the node's recorded node.setup metadata (ADR-0009 f). The probe
	// cannot know it: the caller fills it from the stored capability.
	Setup *runtimes.SetupMeta
}

// KernelName is the first word of Kernel ("Linux", "Darwin"), or "an unknown
// kernel" when the probe did not learn it.
func (s Snapshot) KernelName() string {
	if name, _, _ := strings.Cut(s.Kernel, " "); name != "" {
		return name
	}
	return "an unknown kernel"
}

// IsLinux: node.setup and everything it enables are Linux only.
func (s Snapshot) IsLinux() bool { return s.KernelName() == "Linux" }

type OSInfo struct{ ID, Name, Version string }

// CPU: Cores is 0 when unknown; UsagePercent is valid when UsageKnown.
type CPU struct {
	Cores        int
	UsagePercent float64
	UsageKnown   bool
}

type Memory struct{ TotalKB, AvailableKB uint64 }

type Disk struct{ TotalKB, UsedKB, AvailableKB uint64 }

type Systemd struct {
	Active        bool // systemd is the running init
	SystemctlPath string
	Version       string
}

type Docker struct {
	Path           string
	ServerVersion  string // empty: daemon unreachable or access denied
	ComposeVersion string
}

// Reachable reports whether the probing user can talk to a Docker daemon.
func (d Docker) Reachable() bool { return d.ServerVersion != "" }

// Tools are the node binaries the probe looked for. The first three are
// interactive helpers; the rest back deployments (ADR-0030).
type Tools struct {
	Lazydocker, Btop, Tmux         bool
	Curl, Bash, Timeout, Flock, Jq bool
	Ss, Sha256sum, Base64, Df      bool
}

// ProbedAs is the setup state seen from the probing session.
type ProbedAs struct {
	User            string
	HomeExists      bool
	MarkersWritable bool
}

// Address is one node address (node_addresses.scope: global, private, link, loopback).
type Address struct {
	Address string
	Family  string // ipv4 | ipv6
	Scope   string
}
