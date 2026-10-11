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
	sshnode "github.com/autarquico/supermgmt/internal/providers/ssh"
)

// configSource is the event source of changes the file causes.
const configSource = "config"

// StaticReconciler makes the database agree with the environments and SSH
// providers declared in the configuration file (plan Q5, Q9), as the system
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

// Reconcile applies the file in one transaction. Proxmox providers arrive in
// M3 and are ignored here. It stores no configuration snapshot: the daemon
// calls Activate.
func (s *StaticReconciler) Reconcile(ctx context.Context, envs []config.Environment, providers []config.Provider) error {
	return s.reconcile(ctx, envs, providers, nil)
}

// Activate is Reconcile plus settings.config_snapshot (spec §29.1): the exact
// source bytes and the next generation commit in the same transaction as the
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
		if p.SSH == nil {
			continue
		}
		wanted[p.SSH.Name] = true
		if err := s.sshNode(ctx, tx, *p.SSH); err != nil {
			problems = append(problems, fmt.Errorf("provider %q: %w", p.SSH.Name, err))
		}
	}
	if err := errors.Join(problems...); err != nil {
		return err
	}
	return s.retireRemoved(ctx, tx, wanted)
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
