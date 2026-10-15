// Package runtimes defines the contract every service runtime adapter
// (runtimes/systemd, runtimes/docker; spec §16, §17) implements. Adapters only
// render templates and parse what an Executor returns: they never dial, and
// they never decide policy.
package runtimes

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// MaxLogLines bounds LogQuery.Lines (spec §16: the broker accepts ≤ 10000).
const MaxLogLines = 10000

// LogsMode is how unit logs are read on a node (spec §16, `ssh.logs_mode`).
type LogsMode string

const (
	LogsJournalGroup LogsMode = "journal-group"
	LogsBroker       LogsMode = "broker"
)

// ServiceRef identifies one service on one node.
type ServiceRef struct {
	NodeID   domain.ID
	Kind     domain.ServiceKind
	NativeID string
	Name     string
}

// Filter selects which services discovery reports. Patterns are shell globs
// on the service name; an empty Include means the adapter's default selection.
// Exclude wins over Include.
type Filter struct {
	Include []string
	Exclude []string
}

// Discovered is one runtime on a node and the services it manages.
type Discovered struct {
	Runtime  DiscoveredRuntime
	Services []DiscoveredService
}

// DiscoveredRuntime is the observed runtime itself (runtimes table).
type DiscoveredRuntime struct {
	Type     domain.RuntimeType
	NativeID string
	Version  string
	Status   string
	Metadata map[string]any
}

// DiscoveredService is one observed service (services table). Status and
// Health are separate observations.
type DiscoveredService struct {
	Kind     domain.ServiceKind
	NativeID string
	Name     string
	Status   string
	Health   string
	Metadata map[string]any
}

// LogQuery asks for the last Lines lines (1..MaxLogLines). Mode comes from the
// node's setup metadata; nodes without setup read through the journal group.
type LogQuery struct {
	Lines int
	Mode  LogsMode
}

// LogChunk is sanitized, bounded log output, oldest line first.
type LogChunk struct {
	Lines     []string
	Truncated bool
}

// UnitGrant is the set of verbs node.setup granted on one unit through the
// sudoers drop-in (ADR-0009 d).
type UnitGrant struct {
	Unit  string               `json:"unit"`
	Verbs []domain.ServiceVerb `json:"verbs"`
}

// SetupVersion is the setup_version this build writes (ADR-0009 f). Version 3
// adds the optional tunnel state (ADR-0037); versions 1 and 2 stay readable and
// read as "no tunnel", and every check that asks for version 2 accepts 3.
const SetupVersion = 3

// SupportedComposeVersion is the only Compose CLI release deployments run on
// (ADR-0006). On the node fixture `docker compose version --short` prints it
// without a "v", while the long form prints "v5.5.1".
const SupportedComposeVersion = "5.5.1"

// ComposeSupported reports whether short, the output of
// `docker compose version --short`, names the supported CLI. The match is
// exact: a "v" prefix or any other release is unsupported.
func ComposeSupported(short string) bool {
	return strings.TrimSpace(short) == SupportedComposeVersion
}

// SetupMeta is the metadata of a node's `node.setup` capability (ADR-0009 f),
// written by the setup job in the same fenced transaction as the capability.
// The executor signs automated sessions with exactly KeyRef@KeyVersion.
type SetupMeta struct {
	SetupVersion   int         `json:"setup_version"`
	SystemctlPath  string      `json:"systemctl_path"`
	Units          []UnitGrant `json:"units"`
	LogsMode       LogsMode    `json:"logs_mode"`
	DockerAccess   bool        `json:"docker_access"`
	DeployRoot     string      `json:"deploy_root,omitempty"`
	KeyRef         string      `json:"key_ref"`
	KeyVersion     int         `json:"key_version"`
	KeyFingerprint string      `json:"key_fingerprint"`
	Tunnel         *TunnelMeta `json:"tunnel,omitempty"`
}

// TunnelMeta records that setup installed the Cloudflare tunnel connector on
// the node (ADR-0037). It holds no credential: the token lives only in the
// node's root-only file and in the secret store.
type TunnelMeta struct {
	Hostname    string    `json:"hostname"`
	InstalledAt time.Time `json:"installed_at"`
}

// Granted reports whether setup granted verb on unit.
func (m SetupMeta) Granted(unit string, verb domain.ServiceVerb) bool {
	return slices.ContainsFunc(m.Units, func(g UnitGrant) bool {
		return g.Unit == unit && slices.Contains(g.Verbs, verb)
	})
}

// Adapter is one runtime. Every method that takes an Executor runs bounded
// read templates only, except that the command Mutate returns is the one
// mutating dispatch, which the caller sends after recording its intent.
type Adapter interface {
	Type() domain.RuntimeType

	// Discover lists the runtime and its services.
	Discover(ctx context.Context, ex transport.Executor, f Filter) (Discovered, error)

	// Logs reads bounded, sanitized logs of s.
	Logs(ctx context.Context, ex transport.Executor, s ServiceRef, q LogQuery) (LogChunk, error)

	// Preflight checks that s may be acted on: for systemd the unit trust
	// profile of spec §16 (CAPABILITY_UNAVAILABLE / UNIT_NOT_ELIGIBLE).
	Preflight(ctx context.Context, ex transport.Executor, s ServiceRef) error

	// PreState captures the state Observe compares against (spec §20.4: the
	// InvocationID for systemd, State.StartedAt for Docker). It is recorded in
	// the intent before dispatch.
	PreState(ctx context.Context, ex transport.Executor, s ServiceRef) (json.RawMessage, error)

	// Mutate renders the marker-wrapped command performing v on s.
	Mutate(s ServiceRef, v domain.ServiceVerb, marker string, setup SetupMeta) (templates.Command, error)

	// Observe collects completion evidence and classifies the outcome of a
	// dispatched v (evidence mapping in ADR-0015). An error means no evidence yet
	// (still settling, or unreachable); the reconciler asks again later.
	Observe(ctx context.Context, ex transport.Executor, s ServiceRef, v domain.ServiceVerb, marker string,
		pre json.RawMessage, dispatchedAt time.Time) (jobs.Evidence, error)
}
