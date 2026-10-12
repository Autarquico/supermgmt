package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/deployments/compose"
	"github.com/autarquico/supermgmt/internal/deployments/manifest"
	"github.com/autarquico/supermgmt/internal/domain/plan"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// Execution snapshots (ADR-0007): the content a deployment executes is frozen
// in immutable, content-addressed rows, and the plan binds their hashes. A
// worker reads these rows and the plan, never live configuration; a rollback
// reads the rows of the known-good deployment.

// composeSnapshot is the content of a compose_model snapshot: the target-bound
// frozen model with everything a worker needs to rebuild a compose.Frozen. It
// holds no secret value; the secrets are references with their bound version.
type composeSnapshot struct {
	Public    string           `json:"public"`
	Effective json.RawMessage  `json:"effective"`
	Images    []snapshotImage  `json:"images"`
	Secrets   []snapshotSecret `json:"secrets"`
	HostPorts []snapshotPort   `json:"host_ports"`
}

type snapshotImage struct {
	Service string `json:"service"`
	Ref     string `json:"ref"`
	Binding string `json:"binding"`
}

type snapshotSecret struct {
	Service string `json:"service"`
	EnvName string `json:"env_name"`
	Ref     string `json:"ref"`
	Version int64  `json:"version"`
}

type snapshotPort struct {
	Service string `json:"service"`
	Addr    string `json:"addr"`
	Port    uint16 `json:"port"`
	Proto   string `json:"proto"`
}

// policySnapshot is the content of a deployment_policy snapshot: the
// control-plane policy after §19 precedence, without the health check (which
// has its own snapshot).
type policySnapshot struct {
	Rollback             string           `json:"rollback"`
	Stateful             bool             `json:"stateful"`
	PreDeployBackup      *manifest.Backup `json:"pre_deploy_backup"`
	AllowedBindAddresses []netip.Addr     `json:"allowed_bind_addresses"`
}

// composeSnapshotOf freezes f with the secret versions bound to its uses.
func composeSnapshotOf(f compose.Frozen) composeSnapshot {
	s := composeSnapshot{
		Public: string(f.Public), Effective: f.Effective,
		Images: []snapshotImage{}, Secrets: []snapshotSecret{}, HostPorts: []snapshotPort{},
	}
	for _, i := range f.Images {
		s.Images = append(s.Images, snapshotImage{Service: i.Service, Ref: i.Ref, Binding: i.Binding})
	}
	for _, u := range f.Secrets {
		s.Secrets = append(s.Secrets, snapshotSecret{Service: u.Service, EnvName: u.EnvName, Ref: u.Ref, Version: u.Version})
	}
	for _, p := range f.HostPorts {
		s.HostPorts = append(s.HostPorts, snapshotPort{Service: p.Service, Addr: p.Addr.String(), Port: p.Port, Proto: p.Proto})
	}
	return s
}

// Frozen rebuilds the model a worker executes. hash is the address of the
// snapshot, which is the plan's compose_hash.
func (s composeSnapshot) Frozen(hash string) (compose.Frozen, error) {
	f := compose.Frozen{Public: []byte(s.Public), Hash: hash, Effective: s.Effective}
	for _, i := range s.Images {
		f.Images = append(f.Images, compose.ImageUse(i))
	}
	for _, u := range s.Secrets {
		f.Secrets = append(f.Secrets, compose.SecretUse(u))
	}
	for _, p := range s.HostPorts {
		addr, err := netip.ParseAddr(p.Addr)
		if err != nil {
			return compose.Frozen{}, fmt.Errorf("compose snapshot: host port address %q: %w", p.Addr, err)
		}
		f.HostPorts = append(f.HostPorts, compose.HostPort{Service: p.Service, Addr: addr, Port: p.Port, Proto: p.Proto})
	}
	return f, nil
}

// snapshotSet is the four snapshots a deployment plan binds, with their hashes.
type snapshotSet struct {
	items                                  []database.ExecutionSnapshot
	compose, exceptions, health, deployPol string
}

// newSnapshotSet renders the snapshots. It writes nothing: the hashes go into
// the plan first, and the rows are stored only once the plan is accepted.
func newSnapshotSet(now time.Time, model composeSnapshot, exceptions wire.ComposeExceptions, eff manifest.EffectivePolicy) (snapshotSet, error) {
	binds := eff.AllowedBindAddresses
	if binds == nil {
		binds = []netip.Addr{}
	}
	policy := policySnapshot{
		Rollback: eff.Rollback, Stateful: eff.Stateful, PreDeployBackup: eff.PreDeployBackup, AllowedBindAddresses: binds,
	}
	var set snapshotSet
	for _, part := range []struct {
		kind  database.ExecutionSnapshotKind
		value any
		hash  *string
	}{
		{database.SnapshotComposeModel, model, &set.compose},
		{database.SnapshotExceptions, exceptions, &set.exceptions},
		{database.SnapshotHealth, eff.Health, &set.health},
		{database.SnapshotDeploymentPolicy, policy, &set.deployPol},
	} {
		content, err := json.Marshal(part.value)
		if err != nil {
			return snapshotSet{}, fmt.Errorf("encode %s snapshot: %w", part.kind, err)
		}
		hash := database.ExecutionSnapshotHash(content)
		set.items = append(set.items, database.ExecutionSnapshot{Hash: hash, Kind: part.kind, Content: content, CreatedAt: now})
		*part.hash = hash
	}
	return set, nil
}

// store writes the rows; a row that already exists is left as it is.
func (s snapshotSet) store(ctx context.Context, q database.Querier) error {
	for _, item := range s.items {
		if err := database.PutExecutionSnapshot(ctx, q, item); err != nil {
			return err
		}
	}
	return nil
}

// policyOfTarget reads app_targets.deployment_policy_json in the shape §19
// precedence takes.
func policyOfTarget(row database.AppTarget) (manifest.DeploymentPolicy, error) {
	stored, err := decodeStored[wire.DeploymentPolicy](row.DeploymentPolicyJSON, "deployment policy")
	if err != nil {
		return manifest.DeploymentPolicy{}, err
	}
	out := manifest.DeploymentPolicy{
		Rollback: stored.Rollback, Stateful: stored.Stateful, Snapshot: stored.Snapshot,
		AllowedBindAddresses: bindAddressesOf(stored.AllowedBindAddresses),
	}
	if stored.PreDeployBackup != nil {
		timeout, err := time.ParseDuration(stored.PreDeployBackup.Timeout)
		if err != nil {
			return manifest.DeploymentPolicy{}, fmt.Errorf("stored backup timeout is unreadable: %w", err)
		}
		out.PreDeployBackup = &manifest.Backup{
			Template: stored.PreDeployBackup.Template, Args: stored.PreDeployBackup.Args, Timeout: timeout,
		}
	}
	if stored.Health != nil {
		check, err := healthCheckOf(*stored.Health)
		if err != nil {
			return manifest.DeploymentPolicy{}, err
		}
		out.Health = &check
	}
	return out, nil
}

// ---- reading a known-good deployment back --------------------------------------------------

// knownGood is the frozen state of a succeeded deployment, read back from its
// plan and snapshot rows (ADR-0007 rollback mode). Nothing in it comes from the
// app's live configuration.
type knownGood struct {
	deployment database.Deployment
	plan       plan.Plan
	policy     policySnapshot
}

// loadKnownGood reads dep's plan and verifies every snapshot row and secret
// version it binds still exists. Anything missing makes a rollback to it
// unavailable (ROLLBACK_UNAVAILABLE with the cause), before anything is enqueued.
func loadKnownGood(ctx context.Context, q database.Querier, dep database.Deployment) (knownGood, error) {
	if !dep.KnownGood || dep.PlanID == nil {
		return knownGood{}, rollbackUnavailable(deployments.CauseNoKnownGood, "deployment %s is not a known-good deployment", dep.ID)
	}
	rec, err := database.GetPlan(ctx, q, *dep.PlanID)
	if err != nil {
		return knownGood{}, err
	}
	frozen, err := plan.Parse(rec.PlanJSON)
	if err != nil {
		return knownGood{}, err
	}
	kg := knownGood{deployment: dep, plan: *frozen}
	if err := kg.readSnapshots(ctx, q); err != nil {
		return knownGood{}, err
	}
	if err := kg.requireSecretVersions(ctx, q); err != nil {
		return knownGood{}, err
	}
	return kg, nil
}

func (k *knownGood) readSnapshots(ctx context.Context, q database.Querier) error {
	c := k.plan.Content
	for _, hash := range []*string{c.ComposeHash, c.ExceptionsHash, c.HealthHash, c.DeploymentPolicyHash} {
		if hash == nil {
			return rollbackUnavailable(deployments.CauseSnapshotGone, "the plan of %s names no snapshot", k.deployment.ID)
		}
		row, err := readSnapshot(ctx, q, *hash)
		if err != nil {
			return err
		}
		if *hash == *c.DeploymentPolicyHash {
			if err := json.Unmarshal(row.Content, &k.policy); err != nil {
				return fmt.Errorf("stored policy snapshot is unreadable: %w", err)
			}
		}
	}
	return nil
}

func readSnapshot(ctx context.Context, q database.Querier, hash string) (database.ExecutionSnapshot, error) {
	row, err := database.GetExecutionSnapshot(ctx, q, hash)
	switch {
	case smerr.CodeOf(err) == smerr.CodeNotFound:
		return row, rollbackUnavailable(deployments.CauseSnapshotGone, "snapshot %s no longer exists", hash)
	case errors.Is(err, smerr.FromReason(smerr.ReasonStagingFailed, "")):
		return row, rollbackUnavailable(deployments.CauseSnapshotMismatch, "snapshot %s no longer matches its hash", hash)
	}
	return row, err
}

func (k knownGood) requireSecretVersions(ctx context.Context, q database.Querier) error {
	for _, b := range k.plan.Content.SecretBindings {
		_, err := database.GetSecret(ctx, q, b.SecretID, int(b.Version))
		if smerr.CodeOf(err) == smerr.CodeNotFound {
			return rollbackUnavailable(deployments.CauseSecretVersionGone, "version %d of secret %s no longer exists", b.Version, b.SecretID)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func rollbackUnavailable(cause, format string, args ...any) *smerr.Error {
	e := smerr.FromReason(smerr.ReasonRollbackUnavailable, fmt.Sprintf(format, args...))
	e.Details = map[string]any{"cause": cause}
	return e
}

// ---- secret versions ------------------------------------------------------------------------

// bindSecretVersions pins every secret a frozen model uses to the newest stored
// version (ADR-0008) and returns the plan's bindings and inputs. A secret that
// does not exist cannot be deployed.
func bindSecretVersions(ctx context.Context, q database.Querier, f *compose.Frozen) ([]plan.SecretBinding, []plan.Input, error) {
	newest := map[string]int64{}
	bindings := make([]plan.SecretBinding, 0, len(f.Secrets))
	for i, use := range f.Secrets {
		version, seen := newest[use.Ref]
		if !seen {
			stored, err := database.GetSecret(ctx, q, use.Ref, 0)
			if smerr.CodeOf(err) == smerr.CodeNotFound {
				return nil, nil, invalidArgument("secret %s of %s/%s does not exist", use.Ref, use.Service, use.EnvName)
			}
			if err != nil {
				return nil, nil, err
			}
			version = int64(stored.Version)
			newest[use.Ref] = version
		}
		f.Secrets[i].Version = version
		bindings = append(bindings, plan.SecretBinding{Service: use.Service, EnvName: use.EnvName, SecretID: use.Ref, Version: version})
	}
	return bindings, secretInputs(newest), nil
}

// secretInputs lists the secret versions a plan reads as inputs.
func secretInputs(versions map[string]int64) []plan.Input {
	inputs := make([]plan.Input, 0, len(versions))
	for name, version := range versions {
		inputs = append(inputs, plan.Input{Type: plan.InputTypeSecret, ID: name, Version: snapshotPtr(version)})
	}
	return inputs
}

func snapshotPtr[T any](v T) *T { return &v }
