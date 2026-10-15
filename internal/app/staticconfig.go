package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"reflect"
	"slices"
	"strconv"

	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/providers/github"
	"github.com/autarquico/supermgmt/internal/providers/proxmox"
	sshnode "github.com/autarquico/supermgmt/internal/providers/ssh"
)

// configSource is the event source of changes the file causes.
const configSource = "config"

// StaticReconciler makes the database agree with the environments, SSH
// providers, Proxmox providers and GitHub providers declared in the
// configuration file (plan Q5, Q9; ADR-0024, ADR-0028), as the system
// actor, at daemon start. A changed environment or node endpoint bumps
// spec_revision and is audited, so a plan made before the change goes stale
// (spec §6.4, §20.4). A node whose provider left the file is retired. Nodes
// created through the API are never touched.
type StaticReconciler struct {
	core
	mode config.Mode
}

// NewStaticReconciler validates cfg.
func NewStaticReconciler(cfg Config, mode config.Mode) (*StaticReconciler, error) {
	c, err := newCore(cfg)
	if err != nil {
		return nil, err
	}
	return &StaticReconciler{core: c, mode: mode}, nil
}

// ConfigSources are the exact bytes of the configuration file and of the
// policy file (nil when none is in force) the daemon is activating.
type ConfigSources struct {
	Config []byte
	Policy []byte
}

// Activate applies the file in one transaction and stores
// settings.config_snapshot (spec §29.1): the exact source bytes and the next generation commit in the same transaction as the
// reconcile, so a backup never sees a configuration whose effects are missing
// or effects whose configuration is missing. Every activation advances the
// generation, even when the bytes are unchanged: it counts daemon activations.
func (s *StaticReconciler) Activate(ctx context.Context, src ConfigSources, envs []config.Environment, providers []config.Provider) error {
	if len(src.Config) == 0 {
		return smerr.New(smerr.CodeInvalidArgument, "", "the configuration snapshot needs the configuration file bytes")
	}
	return s.reconcile(ctx, envs, providers, &src)
}

func (s *StaticReconciler) reconcile(ctx context.Context, envs []config.Environment, providers []config.Provider, snapshot *ConfigSources) error {
	return s.write(context.WithValue(ctx, sourceKey{}, configSource), func(ctx context.Context, tx *database.Tx) error {
		if err := s.apply(ctx, tx, envs, providers); err != nil {
			return err
		}
		if snapshot == nil {
			return nil
		}
		return s.storeSnapshot(ctx, tx, *snapshot)
	})
}

func (s *StaticReconciler) apply(ctx context.Context, tx *database.Tx, envs []config.Environment, providers []config.Provider) error {
	if err := s.environments(ctx, tx, envs); err != nil {
		return err
	}
	var problems []error
	wanted := map[string]bool{}
	for _, p := range providers {
		switch {
		case p.SSH != nil:
			wanted[p.SSH.Name] = true
			if err := s.sshNode(ctx, tx, *p.SSH); err != nil {
				problems = append(problems, fmt.Errorf("provider %q: %w", p.SSH.Name, err))
			}
		case p.Proxmox != nil:
			wanted[p.Proxmox.Name] = true
			if err := s.proxmoxProvider(ctx, tx, *p.Proxmox); err != nil {
				problems = append(problems, fmt.Errorf("provider %q: %w", p.Proxmox.Name, err))
			}
		case p.GitHub != nil:
			wanted[p.GitHub.Name] = true
			if err := s.githubProvider(ctx, tx, *p.GitHub); err != nil {
				problems = append(problems, fmt.Errorf("provider %q: %w", p.GitHub.Name, err))
			}
		}
	}
	if err := errors.Join(problems...); err != nil {
		return err
	}
	if err := s.retireRemoved(ctx, tx, wanted); err != nil {
		return err
	}
	return s.stopRemovedProviders(ctx, tx, wanted)
}

func (s *StaticReconciler) storeSnapshot(ctx context.Context, tx *database.Tx, src ConfigSources) error {
	stored, err := database.PutConfigSnapshot(ctx, tx, src.Config, src.Policy, s.cfg.Clock.Now())
	if err != nil {
		return err
	}
	data := map[string]any{"generation": stored.Generation, "config_sha256": sha256Hex(src.Config)}
	if len(src.Policy) > 0 {
		data["policy_sha256"] = sha256Hex(src.Policy)
	}
	return s.emit(ctx, tx, systemActor, "config.activate", domain.ResourceRef{Type: domain.ResourceInstance}, domain.ResultSucceeded, data)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (s *StaticReconciler) environments(ctx context.Context, q database.Querier, envs []config.Environment) error {
	stored, err := database.ListEnvironments(ctx, q)
	if err != nil {
		return err
	}
	for _, want := range envs {
		desired := domain.Environment{
			Name: want.Name, RiskLevel: domain.EnvironmentRiskLevel(want.RiskLevel), RequireProvenance: want.RequireProvenance,
			ApprovalsRequired: want.ApprovalsRequired, AllowAutomaticRollback: want.AllowAutomaticRollback,
		}
		i := slices.IndexFunc(stored, func(e domain.Environment) bool { return e.Name == want.Name })
		if i < 0 {
			desired.ID = s.cfg.IDs.NewID()
			if _, err := database.CreateEnvironment(ctx, q, desired); err != nil {
				return err
			}
			if err := s.emit(ctx, q, systemActor, "environment.write", domain.ResourceRef{Type: domain.ResourceEnvironment, ID: desired.ID},
				domain.ResultSucceeded, map[string]any{"name": want.Name, "risk_level": want.RiskLevel, "change": "created"}); err != nil {
				return err
			}
			continue
		}
		current := stored[i]
		if sameEnvironment(current, desired) {
			continue
		}
		desired.ID = current.ID
		if _, err := database.UpdateEnvironmentSpec(ctx, q, desired, current.SpecRevision); err != nil {
			return err
		}
		if err := s.emit(ctx, q, systemActor, "environment.write", domain.ResourceRef{Type: domain.ResourceEnvironment, ID: current.ID},
			domain.ResultSucceeded, map[string]any{"name": want.Name, "risk_level": want.RiskLevel, "change": "updated"}); err != nil {
			return err
		}
	}
	return nil
}

func sameEnvironment(a, b domain.Environment) bool {
	return a.RiskLevel == b.RiskLevel && a.RequireProvenance == b.RequireProvenance &&
		a.ApprovalsRequired == b.ApprovalsRequired && a.AllowAutomaticRollback == b.AllowAutomaticRollback
}

// sshNode creates the provider and node of a configured SSH provider, or
// brings an existing one in line with the file.
func (s *StaticReconciler) sshNode(ctx context.Context, q database.Querier, p config.SSHProvider) error {
	providers, err := database.ListProviders(ctx, q)
	if err != nil {
		return err
	}
	environment, err := s.environmentOf(ctx, q, p.Environment)
	if err != nil {
		return err
	}
	endpoint := sshnode.FromConfig(p, s.mode)
	i := slices.IndexFunc(providers, func(x domain.Provider) bool { return x.Name == p.Name })
	if i < 0 {
		return s.createSSHNode(ctx, q, p, endpoint, environment)
	}
	if providers[i].Origin != domain.ProviderStatic {
		return errors.New("a provider of that name was created through the API; rename one of them")
	}
	return s.syncSSHNode(ctx, q, providers[i], p, endpoint, environment)
}

func (s *StaticReconciler) environmentOf(ctx context.Context, q database.Querier, name string) (*domain.ID, error) {
	if name == "" {
		return nil, nil
	}
	env, err := environmentNamed(ctx, q, name)
	if err != nil {
		return nil, err
	}
	return &env.ID, nil
}

func (s *StaticReconciler) createSSHNode(ctx context.Context, q database.Querier, p config.SSHProvider, e sshnode.Endpoint, environment *domain.ID) error {
	now := s.cfg.Clock.Now()
	provider, err := database.CreateProvider(ctx, q, domain.Provider{
		ID: s.cfg.IDs.NewID(), Type: sshnode.ProviderType, Name: p.Name, Origin: domain.ProviderStatic,
		Endpoint: net.JoinHostPort(e.Host, strconv.Itoa(e.Port)), CredentialRef: e.CredentialRef, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		return err
	}
	node, err := database.CreateNode(ctx, q, domain.Node{
		ID: s.cfg.IDs.NewID(), ProviderID: provider.ID, NativeID: p.Name, Name: p.Name, Kind: sshnode.NodeKind,
		EnvironmentID: environment, ManagementState: domain.ManagementManaged, Reachability: domain.ReachabilityUnknown,
		Endpoint: e.NodeEndpoint(), CredentialRef: e.CredentialRef, Tags: nonNil(p.Tags), CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		return err
	}
	return s.emit(ctx, q, systemActor, actionNodeAdd, nodeRef(node.ID), domain.ResultSucceeded,
		map[string]any{"name": p.Name, "host": e.Host, "port": e.Port, "origin": string(domain.ProviderStatic)})
}

func (s *StaticReconciler) syncSSHNode(ctx context.Context, q database.Querier, provider domain.Provider, p config.SSHProvider, e sshnode.Endpoint, environment *domain.ID) error {
	nodes, err := database.ListNodes(ctx, q)
	if err != nil {
		return err
	}
	i := slices.IndexFunc(nodes, func(n domain.Node) bool { return n.ProviderID == provider.ID })
	if i < 0 {
		return errors.New("the provider has no node")
	}
	current := nodes[i]
	want := current
	want.Endpoint, want.CredentialRef, want.EnvironmentID = e.NodeEndpoint(), e.CredentialRef, environment
	// The tunnel jobs own these two fields (ADR-0037); the file never carries them.
	want.Endpoint.Transport, want.Endpoint.TunnelHostname = current.Endpoint.Transport, current.Endpoint.TunnelHostname
	want.Tags = slices.Sorted(slices.Values(p.Tags))
	want.ManagementState, want.UpdatedAt = domain.ManagementManaged, s.cfg.Clock.Now()
	changed := changedFields(current, want)
	if len(changed) == 0 {
		return nil
	}
	stored, err := database.UpdateNodeSpec(ctx, q, want, current.SpecRevision)
	if err != nil {
		return err
	}
	return s.emit(ctx, q, systemActor, actionNodeUpdate, nodeRef(stored.ID), domain.ResultSucceeded,
		map[string]any{"fields": changed, "spec_revision": stored.SpecRevision, "origin": string(domain.ProviderStatic)})
}

func changedFields(a, b domain.Node) []string {
	var changed []string
	for _, f := range []struct {
		name string
		same bool
	}{
		{"endpoint", a.Endpoint == b.Endpoint},
		{"credential_ref", a.CredentialRef == b.CredentialRef},
		{"environment", reflect.DeepEqual(a.EnvironmentID, b.EnvironmentID)},
		{"tags", slices.Equal(a.Tags, b.Tags)},
		{"management_state", a.ManagementState == b.ManagementState},
	} {
		if !f.same {
			changed = append(changed, f.name)
		}
	}
	return changed
}

// retireRemoved retires the node of every static SSH provider that is no
// longer in the file (plan Q9).
func (s *StaticReconciler) retireRemoved(ctx context.Context, q database.Querier, wanted map[string]bool) error {
	providers, err := database.ListProviders(ctx, q)
	if err != nil {
		return err
	}
	nodes, err := database.ListNodes(ctx, q)
	if err != nil {
		return err
	}
	for _, p := range providers {
		if p.Origin != domain.ProviderStatic || p.Type != sshnode.ProviderType || wanted[p.Name] {
			continue
		}
		for _, n := range nodes {
			if n.ProviderID != p.ID || n.ManagementState == domain.ManagementRetired {
				continue
			}
			n.ManagementState, n.UpdatedAt = domain.ManagementRetired, s.cfg.Clock.Now()
			stored, err := database.UpdateNodeSpec(ctx, q, n, n.SpecRevision)
			if err != nil {
				return err
			}
			if err := s.emit(ctx, q, systemActor, actionNodeRemove, nodeRef(stored.ID), domain.ResultSucceeded,
				map[string]any{"name": stored.Name, "reason": "removed from the configuration file"}); err != nil {
				return err
			}
		}
	}
	return nil
}

// Events the Proxmox branch of the reconciler records.
const (
	eventProviderAdd    = "provider.add"
	eventProviderUpdate = "provider.update"
	eventProviderRemove = "provider.remove"
)

func providerRef(id domain.ID) domain.ResourceRef {
	return domain.ResourceRef{Type: domain.ResourceProvider, ID: id}
}

// proxmoxProviderConfig is what discovery needs besides the endpoint and the
// credential reference: the CA that signed the PVE certificate and how often
// to sync.
func proxmoxProviderConfig(p config.ProxmoxProvider) map[string]any {
	return map[string]any{providerConfigCAFile: p.CAFile, providerConfigSyncInterval: p.SyncInterval.String()}
}

// proxmoxProvider creates the provider of a configured Proxmox cluster or
// brings an existing one in line with the file. Its guests are not created
// here: discovery finds them (ADR-0024).
func (s *StaticReconciler) proxmoxProvider(ctx context.Context, q database.Querier, p config.ProxmoxProvider) error {
	return s.staticProvider(ctx, q, "Proxmox", domain.Provider{
		Type: proxmox.ProviderType, Name: p.Name,
		Endpoint: p.Endpoint, CredentialRef: p.CredentialRef, Config: proxmoxProviderConfig(p),
	})
}

// githubStaticConfig is what the GitHub client factory and the webhook read
// besides the endpoint (the API URL) and the credential reference: the CA and
// the webhook secret reference, each only when configured (the convention of
// providers created through the API).
func githubStaticConfig(p config.GitHubProvider) map[string]any {
	conf := map[string]any{}
	if p.CAFile != "" {
		conf[providerConfigCAFile] = p.CAFile
	}
	if p.WebhookSecretRef != "" {
		conf[providerConfigWebhookSecretRef] = p.WebhookSecretRef
	}
	return conf
}

// githubProvider creates the provider of a configured GitHub connector or
// brings an existing one in line with the file (ADR-0028).
func (s *StaticReconciler) githubProvider(ctx context.Context, q database.Querier, p config.GitHubProvider) error {
	return s.staticProvider(ctx, q, "GitHub", domain.Provider{
		Type: github.ProviderType, Name: p.Name,
		Endpoint: p.APIURL, CredentialRef: p.CredentialRef, Config: githubStaticConfig(p),
	})
}

// staticProvider creates the static provider want describes (identified by
// Name), or brings the stored one in line: an unchanged one is left alone, a
// changed one bumps spec_revision and is audited, and one that had left the
// file returns to service. The observed status is never reset.
func (s *StaticReconciler) staticProvider(ctx context.Context, q database.Querier, label string, want domain.Provider) error {
	providers, err := database.ListProviders(ctx, q)
	if err != nil {
		return err
	}
	now := s.cfg.Clock.Now()
	want.Origin, want.UpdatedAt = domain.ProviderStatic, now
	i := slices.IndexFunc(providers, func(x domain.Provider) bool { return x.Name == want.Name })
	if i < 0 {
		want.ID, want.CreatedAt = s.cfg.IDs.NewID(), now
		created, err := database.CreateProvider(ctx, q, want)
		if err != nil {
			return err
		}
		return s.emit(ctx, q, systemActor, eventProviderAdd, providerRef(created.ID), domain.ResultSucceeded,
			map[string]any{"name": want.Name, "type": want.Type, "origin": string(domain.ProviderStatic)})
	}
	current := providers[i]
	if current.Origin != domain.ProviderStatic || current.Type != want.Type {
		return fmt.Errorf("a provider of that name exists and is not a static %s provider; rename one of them", label)
	}
	if current.Status == ProviderStatusRemoved {
		if err := database.SetProviderStatus(ctx, q, current.ID, "", nil); err != nil {
			return err
		}
	}
	if current.Endpoint == want.Endpoint && current.CredentialRef == want.CredentialRef && reflect.DeepEqual(current.Config, want.Config) {
		return nil
	}
	want.ID = current.ID
	stored, err := database.UpdateProviderSpec(ctx, q, want, current.SpecRevision)
	if err != nil {
		return err
	}
	return s.emit(ctx, q, systemActor, eventProviderUpdate, providerRef(stored.ID), domain.ResultSucceeded,
		map[string]any{"name": want.Name, "spec_revision": stored.SpecRevision, "origin": string(domain.ProviderStatic)})
}

// revokeGuestPower withdraws proxmox.vm.power from every guest of a provider
// that is no longer configured: nothing may be powered through a token the
// operator removed. The guests themselves stay.
func (s *StaticReconciler) revokeGuestPower(ctx context.Context, q database.Querier, p domain.Provider) error {
	nodes, err := database.ListNodes(ctx, q)
	if err != nil {
		return err
	}
	for _, n := range nodes {
		if n.ProviderID != p.ID || (n.Kind != proxmox.KindQEMU && n.Kind != proxmox.KindLXC) {
			continue
		}
		err := database.SetNodeCapability(ctx, q, n.ID, database.NodeCapability{
			Capability: CapabilityVMPower, Available: false, CheckedAt: s.cfg.Clock.Now(),
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// stopRemovedProviders marks every static Proxmox or GitHub provider that left
// the file as removed. For Proxmox that stops its sync, stales the plans that
// used it and withdraws power over its guests. Nodes and observations stay:
// removing a provider never deletes what it discovered (spec §29.4).
func (s *StaticReconciler) stopRemovedProviders(ctx context.Context, q database.Querier, wanted map[string]bool) error {
	providers, err := database.ListProviders(ctx, q)
	if err != nil {
		return err
	}
	for _, p := range providers {
		if p.Origin != domain.ProviderStatic || !markedOnRemoval(p.Type) || wanted[p.Name] || p.Status == ProviderStatusRemoved {
			continue
		}
		if err := database.MarkProviderRemoved(ctx, q, p.ID, ProviderStatusRemoved); err != nil {
			return err
		}
		if p.Type == proxmox.ProviderType {
			if err := s.revokeGuestPower(ctx, q, p); err != nil {
				return err
			}
		}
		err := s.emit(ctx, q, systemActor, eventProviderRemove, providerRef(p.ID), domain.ResultSucceeded,
			map[string]any{"name": p.Name, "reason": "removed from the configuration file"})
		if err != nil {
			return err
		}
	}
	return nil
}

func markedOnRemoval(providerType string) bool {
	return providerType == proxmox.ProviderType || providerType == github.ProviderType
}
