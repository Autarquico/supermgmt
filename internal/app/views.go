package app

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
	"github.com/autarquico/supermgmt/internal/providers/proxmox"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/textsafe"
	"github.com/autarquico/supermgmt/internal/transport/ssh"

	sshnode "github.com/autarquico/supermgmt/internal/providers/ssh"
)

// The views are the wire shapes themselves, under the names of the contract.
type (
	NodeView    = wire.Node
	ConnectInfo = wire.ConnectInfo
	Session     = wire.Session
)

// Observation kinds the app records and reads (spec §6.4).
const (
	observationSystem  = "system"
	observationMetrics = "metrics"
)

// systemInfo is the "system" observation: what the probe learned about the machine.
type systemInfo struct {
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Kernel   string `json:"kernel"`
	Hostname string `json:"hostname"`
}

const lastErrorLimit = 200

// viewer builds the wire views of nodes and services from the database and
// the connection pool state. It never dials (ADR-0014): a listing answers from
// what the refresher last observed.
type viewer struct {
	conn       Connector
	now        time.Time
	staleAfter time.Duration
}

// lookups are the tables a node listing reads once instead of once per node.
type lookups struct {
	providers map[domain.ID]domain.Provider
	envs      map[domain.ID]domain.Environment
	metrics   map[domain.ID]database.Observation
	system    map[domain.ID]database.Observation
	proxmox   map[domain.ID]database.Observation
}

func (v viewer) lookups(ctx context.Context, q database.Querier) (lookups, error) {
	providers, err := database.ListProviders(ctx, q)
	if err != nil {
		return lookups{}, err
	}
	envs, err := database.ListEnvironments(ctx, q)
	if err != nil {
		return lookups{}, err
	}
	l := lookups{providers: map[domain.ID]domain.Provider{}, envs: map[domain.ID]domain.Environment{}}
	for _, p := range providers {
		l.providers[p.ID] = p
	}
	for _, e := range envs {
		l.envs[e.ID] = e
	}
	if l.metrics, err = database.LatestObservations(ctx, q, domain.ResourceNode, observationMetrics); err != nil {
		return lookups{}, err
	}
	if l.system, err = database.LatestObservations(ctx, q, domain.ResourceNode, observationSystem); err != nil {
		return lookups{}, err
	}
	if l.proxmox, err = database.LatestObservations(ctx, q, domain.ResourceNode, proxmox.ObservationStatus); err != nil {
		return lookups{}, err
	}
	return l, nil
}

// node is the view of n. Capabilities and addresses are read per node.
func (v viewer) node(ctx context.Context, q database.Querier, l lookups, n domain.Node) (wire.Node, error) {
	caps, err := database.ListNodeCapabilities(ctx, q, n.ID)
	if err != nil {
		return wire.Node{}, err
	}
	addrs, err := database.ListNodeAddresses(ctx, q, n.ID)
	if err != nil {
		return wire.Node{}, err
	}
	provider := l.providers[n.ProviderID]
	out := wire.Node{
		ID: n.ID, Name: n.Name, Kind: n.Kind, ProviderID: n.ProviderID, Provider: provider.Name, Origin: provider.Origin,
		ManagementState: n.ManagementState, Reachability: n.Reachability,
		Endpoint:           v.endpoint(n),
		CredentialRef:      n.CredentialRef,
		AdminCredentialRef: n.Endpoint.AdminCredentialRef,
		Tags:               nonNil(n.Tags),
		Capabilities:       capabilityViews(caps),
		Addresses:          addressViews(addrs),
		Connection:         v.connection(n),
		Stale:              v.stale(n),
		SpecRevision:       n.SpecRevision, LastSeenAt: n.LastSeenAt, UpdatedAt: n.UpdatedAt,
	}
	if env, ok := l.envs[derefID(n.EnvironmentID)]; ok {
		out.Environment = env.Name
	}
	if obs, ok := l.system[n.ID]; ok {
		var info systemInfo
		if decodeObservation(obs, &info) == nil {
			out.OS, out.Arch = info.OS, info.Arch
		}
	}
	if obs, ok := l.metrics[n.ID]; ok {
		var m wire.Metrics
		if decodeObservation(obs, &m) == nil {
			out.Metrics = &m
		}
	}
	if setup := setupFrom(caps); setup != nil {
		out.Setup = setupView(*setup)
	}
	out.Proxmox = proxmoxView(n, l.proxmox[n.ID])
	return out, nil
}

// proxmoxView is the Proxmox side of a node: identity from the discovered
// metadata, power state and presence from the latest proxmox.status
// observation. Nil for a node Proxmox did not discover.
func proxmoxView(n domain.Node, status database.Observation) *wire.ProxmoxGuest {
	if !strings.HasPrefix(n.Kind, proxmox.OperationPrefix) {
		return nil
	}
	guest := &wire.ProxmoxGuest{Type: metadataString(n.Metadata, "type"), PVENode: metadataString(n.Metadata, "pve_node"), Status: "unknown"}
	if vmid, ok := n.Metadata["vmid"].(float64); ok { // metadata comes back from JSON
		guest.VMID = int(vmid)
	}
	guest.Template, _ = n.Metadata["template"].(bool)
	var observed ProxmoxStatus
	if status.Value != nil && decodeObservation(status, &observed) == nil {
		guest.Status = observed.Status
		guest.Absent = observed.Presence == PresenceAbsent
		guest.Inaccessible = observed.Presence == PresenceInaccessible
	}
	return guest
}

func metadataString(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func (v viewer) endpoint(n domain.Node) wire.Endpoint {
	e := wire.Endpoint{
		Host: n.Endpoint.Host, Port: n.Endpoint.Port, User: n.Endpoint.User, AdminUser: n.Endpoint.AdminUser,
		HostPublicKey: n.Endpoint.HostPublicKey, Transport: n.Endpoint.Transport, TunnelHostname: n.Endpoint.TunnelHostname,
	}
	if n.Endpoint.HostPublicKey != "" {
		if fp, err := sshnode.Fingerprint(n.Endpoint.HostPublicKey); err == nil {
			e.HostKeyFingerprintSHA256 = fp
		}
	}
	return e
}

func (v viewer) connection(n domain.Node) wire.Connection {
	state := v.conn.State(n)
	out := wire.Connection{State: wire.ConnUnknown}
	switch state.Status {
	case ssh.ConnConnected:
		out.State = wire.ConnConnected
	case ssh.ConnIdle:
		out.State = wire.ConnIdle
	case ssh.ConnBackoff:
		out.State = wire.ConnBackoff
	case ssh.ConnUnknown:
	}
	if state.LastError != nil {
		out.LastError = limitText(textsafe.Line(state.LastError.Error()), lastErrorLimit)
	}
	if !state.NextDialAt.IsZero() {
		at := state.NextDialAt
		out.NextDialAt = &at
	}
	return out
}

func (v viewer) stale(n domain.Node) bool {
	return n.LastSeenAt == nil || v.now.Sub(*n.LastSeenAt) > v.staleAfter
}

func decodeObservation(o database.Observation, into any) error {
	raw, ok := o.Value.(json.RawMessage)
	if !ok {
		return fmt.Errorf("observation %s has no JSON value", o.Kind)
	}
	return json.Unmarshal(raw, into)
}

func limitText(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "..."
	}
	return s
}

func capabilityViews(caps []database.NodeCapability) []wire.Capability {
	out := make([]wire.Capability, len(caps))
	for i, c := range caps {
		out[i] = wire.Capability{Name: c.Capability, Available: c.Available, CheckedAt: c.CheckedAt}
	}
	return out
}

func addressViews(addrs []database.NodeAddress) []wire.Address {
	out := make([]wire.Address, len(addrs))
	for i, a := range addrs {
		out[i] = wire.Address{Address: a.Address, Family: string(a.Family), Scope: string(a.Scope), Preferred: a.Preferred}
	}
	return out
}

func setupFrom(caps []database.NodeCapability) *runtimes.SetupMeta {
	for _, c := range caps {
		if c.Capability == capabilitySetup {
			meta, err := setupOf(c)
			if err != nil {
				return nil
			}
			return meta
		}
	}
	return nil
}

func setupView(m runtimes.SetupMeta) *wire.Setup {
	units := make([]wire.UnitGrant, len(m.Units))
	for i, g := range m.Units {
		units[i] = wire.UnitGrant{Unit: g.Unit, Verbs: g.Verbs}
	}
	return &wire.Setup{
		SetupVersion: m.SetupVersion, LogsMode: string(m.LogsMode), DockerAccess: m.DockerAccess,
		Units: units, KeyFingerprint: m.KeyFingerprint,
	}
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func derefID(id *domain.ID) domain.ID {
	if id == nil {
		return ""
	}
	return *id
}

// ProviderView is the wire form of a provider row.
func ProviderView(p domain.Provider) wire.Provider {
	return wire.Provider{
		ID: p.ID, Type: p.Type, Name: p.Name, Origin: p.Origin, Status: p.Status,
		SpecRevision: p.SpecRevision, LastSyncAt: p.LastSyncAt,
	}
}

// ProviderViewIn is ProviderView plus why the latest sync failed, read from
// the provider's latest proxmox.sync observation.
func ProviderViewIn(ctx context.Context, q database.Querier, p domain.Provider) wire.Provider {
	view := ProviderView(p)
	if report, ok := LatestSyncReport(ctx, q, p.ID); ok && !report.OK {
		view.LastError = limitText(textsafe.Line(report.Error), lastErrorLimit)
	}
	return view
}

// ---- services --------------------------------------------------------------

// serviceView is the wire form of a service. Actions lists the verbs the node
// advertises for it today: none until node.setup, then per grant (systemd) or
// docker_access (containers) (ADR-0009 g).
func serviceView(s domain.Service, nodeName string, runtime domain.RuntimeType, setup *runtimes.SetupMeta) wire.Service {
	return wire.Service{
		ID: s.ID, NodeID: s.NodeID, Node: nodeName, RuntimeType: runtime, Kind: domain.ServiceKind(s.Kind),
		NativeID: s.NativeID, Name: s.Name, Status: s.Status, Health: s.Health,
		Metadata: nonNilMap(s.Metadata), Actions: actionsFor(s, setup),
		SpecRevision: s.SpecRevision, LastSeenAt: s.LastSeenAt,
	}
}

func actionsFor(s domain.Service, setup *runtimes.SetupMeta) []domain.ServiceVerb {
	actions := []domain.ServiceVerb{}
	if setup == nil || s.Status == database.StatusGone {
		return actions
	}
	for _, verb := range domain.AllServiceVerbs() {
		switch domain.ServiceKind(s.Kind) {
		case domain.ServiceSystemdUnit:
			if setup.Granted(s.NativeID, verb) {
				actions = append(actions, verb)
			}
		case domain.ServiceDockerContainer:
			if setup.DockerAccess {
				actions = append(actions, verb)
			}
		}
	}
	return actions
}

func nonNilMap(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

// ---- jobs ------------------------------------------------------------------

// JobView is the wire form of a job.
func JobView(j jobs.Job) wire.Job {
	out := wire.Job{
		ID: j.ID, Type: j.Type, Resource: wire.ResourceRef{Type: j.Resource.Type, ID: j.Resource.ID}, ActorID: j.ActorID,
		State: j.State, Risk: j.Risk, RetryClass: j.RetryClass, PlanID: j.PlanID, PlanHash: j.PlanHash,
		Attempts: j.Attempts, MaxAttempts: j.MaxAttempts, CreatedAt: j.CreatedAt, ScheduledAt: j.ScheduledAt,
		StartedAt: j.StartedAt, FinishedAt: j.FinishedAt,
	}
	if j.Error != nil {
		out.Error = &wire.Failure{Code: j.Error.Code, Reason: j.Error.Reason, Message: j.Error.Message}
	}
	return out
}

// PolicyView is the wire form of a policy verdict.
func PolicyView(r policy.Result) wire.Policy {
	return wire.Policy{Decision: string(r.Decision), ApprovalRequired: r.ApprovalRequired, Quorum: r.Quorum, Reason: r.Reason}
}

// SubmissionView is the wire form of a submitted job and its verdict.
func SubmissionView(s Submission) wire.Submission {
	return wire.Submission{Job: JobView(s.Job), Policy: PolicyView(s.Policy)}
}

// CreatedPlanView is the wire form of POST /plans' answer.
func CreatedPlanView(c CreatedPlan) wire.CreatedPlan {
	return wire.CreatedPlan{
		PlanID: c.Record.ID, Plan: json.RawMessage(c.Record.PlanJSON), PlanHash: c.Record.PlanHash,
		ExpiresAt: c.Record.ExpiresAt, Policy: PolicyView(c.Policy),
	}
}
