package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/deployments/compose"
	"github.com/autarquico/supermgmt/internal/deployments/manifest"
	"github.com/autarquico/supermgmt/internal/domain/plan"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/health"
)

func snapFrozen() compose.Frozen {
	return compose.Frozen{
		Public:    []byte("services:\n  web:\n    image: ghcr.io/acme/web@" + depWebDigest + "\n"),
		Effective: json.RawMessage(`{"services":{"web":{"environment":{"A":"sha256:00"}}}}`),
		Images:    []compose.ImageUse{{Service: "web", Ref: "ghcr.io/acme/web@" + depWebDigest, Binding: compose.BindingPinned}},
		Secrets:   []compose.SecretUse{{Service: "web", EnvName: "DATABASE_URL", Ref: finSecretName, Version: 3}},
		HostPorts: []compose.HostPort{{Service: "web", Addr: netip.MustParseAddr("127.0.0.1"), Port: 8080, Proto: "tcp"}},
	}
}

func snapEffective() manifest.EffectivePolicy {
	return manifest.EffectivePolicy{
		Rollback: "manual", Stateful: true,
		PreDeployBackup:      &manifest.Backup{Template: "postgres-dump", Args: map[string]string{"database": "app"}, Timeout: time.Minute},
		AllowedBindAddresses: []netip.Addr{netip.MustParseAddr("10.0.0.5")},
		Health:               &health.Check{Origin: health.OriginControlPlane, Type: health.TypeHTTP, Scope: health.ScopeNode, Port: 8080, Path: "/", Timeout: time.Second, Interval: time.Second, Attempts: 3},
	}
}

func TestSnapshots_ComposeSnapshotRebuildsTheFrozenModelAtItsOwnAddress(t *testing.T) {
	frozen := snapFrozen()
	content, err := json.Marshal(composeSnapshotOf(frozen))
	mustf(t, err, "marshal")
	var read composeSnapshot
	mustf(t, json.Unmarshal(content, &read), "unmarshal")

	rebuilt, err := read.Frozen(database.ExecutionSnapshotHash(content))

	mustf(t, err, "Frozen")
	frozen.Hash = database.ExecutionSnapshotHash(content)
	if !reflect.DeepEqual(rebuilt, frozen) {
		t.Errorf("rebuilt = %+v, want %+v", rebuilt, frozen)
	}
}

func TestSnapshots_ARebuiltModelWithABadPortAddressIsRefused(t *testing.T) {
	s := composeSnapshotOf(snapFrozen())
	s.HostPorts[0].Addr = "not-an-address"

	if _, err := s.Frozen("sha256:x"); err == nil {
		t.Fatal("Frozen accepted a host port address that is not an address")
	}
}

func TestSnapshots_HashesAreContentAddressedAndStable(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	build := func(mutate func(*compose.Frozen)) snapshotSet {
		frozen := snapFrozen()
		if mutate != nil {
			mutate(&frozen)
		}
		set, err := newSnapshotSet(now, composeSnapshotOf(frozen), wire.ComposeExceptions{}, snapEffective())
		mustf(t, err, "newSnapshotSet")
		return set
	}

	a, b := build(nil), build(nil)
	rotated := build(func(f *compose.Frozen) { f.Secrets[0].Version = 4 })

	if a.compose != b.compose || a.exceptions != b.exceptions || a.health != b.health || a.deployPol != b.deployPol {
		t.Errorf("the same inputs hashed differently: %+v vs %+v", a, b)
	}
	if rotated.compose == a.compose || rotated.health != a.health || rotated.deployPol != a.deployPol {
		t.Errorf("a new secret version must change only the compose snapshot: %+v vs %+v", rotated, a)
	}
	kinds := map[database.ExecutionSnapshotKind]bool{}
	for _, item := range a.items {
		kinds[item.Kind] = true
		if item.Hash != database.ExecutionSnapshotHash(item.Content) {
			t.Errorf("%s snapshot is not stored at its own hash", item.Kind)
		}
	}
	if len(kinds) != 4 {
		t.Errorf("kinds = %v, want compose_model, exceptions, health and deployment_policy", kinds)
	}
}

func TestSnapshots_StoreIsIdempotent(t *testing.T) {
	f := newFinFixture(t, finOptions{})
	set, err := newSnapshotSet(f.clock.Now(), composeSnapshotOf(snapFrozen()), wire.ComposeExceptions{}, snapEffective())
	mustf(t, err, "newSnapshotSet")

	for range 2 {
		f.inTx(func(ctx context.Context, tx *database.Tx) error { return set.store(ctx, tx) })
	}

	for _, item := range set.items {
		if _, err := database.GetExecutionSnapshot(context.Background(), f.db.Reader(), item.Hash); err != nil {
			t.Errorf("%s: %v", item.Kind, err)
		}
	}
}

func TestSnapshots_PolicySnapshotHoldsNoHealthCheck(t *testing.T) {
	set, err := newSnapshotSet(time.Now(), composeSnapshotOf(snapFrozen()), wire.ComposeExceptions{}, snapEffective())
	mustf(t, err, "newSnapshotSet")

	for _, item := range set.items {
		if item.Kind == database.SnapshotDeploymentPolicy && strings.Contains(string(item.Content), "attempts") {
			t.Errorf("deployment_policy snapshot carries the health check: %s", item.Content)
		}
	}
}

func TestSnapshots_HostPortStrings(t *testing.T) {
	ports := []compose.HostPort{
		{Addr: netip.MustParseAddr("127.0.0.1"), Port: 8080, Proto: "tcp"},
		{Addr: netip.MustParseAddr("127.0.0.1"), Port: 8080, Proto: "tcp"},
		{Addr: netip.MustParseAddr("127.0.0.1"), Port: 53, Proto: "udp"},
		{Addr: netip.MustParseAddr("::1"), Port: 9000, Proto: "tcp"},
	}

	got := hostPortStrings(ports)

	want := []string{"127.0.0.1:8080", "127.0.0.1:53/udp", "[::1]:9000"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("host ports = %v, want %v", got, want)
	}
}

func TestSnapshots_PolicyOfTargetReadsTheStoredPolicy(t *testing.T) {
	stored := wire.DeploymentPolicy{
		Rollback: "manual", Stateful: true,
		PreDeployBackup:      &wire.BackupPolicy{Template: "postgres-dump", Args: map[string]string{"database": "app"}, Timeout: "5m0s"},
		AllowedBindAddresses: []string{"10.0.0.5"},
		Health:               &wire.HealthCheck{Type: "http", Port: 8080, Path: "/up"},
	}
	raw, err := json.Marshal(stored)
	mustf(t, err, "marshal")

	got, err := policyOfTarget(database.AppTarget{DeploymentPolicyJSON: raw})

	mustf(t, err, "policyOfTarget")
	if got.Rollback != "manual" || !got.Stateful || got.PreDeployBackup.Timeout != 5*time.Minute ||
		got.PreDeployBackup.Template != "postgres-dump" || len(got.AllowedBindAddresses) != 1 {
		t.Errorf("policy = %+v", got)
	}
	if got.Health == nil || got.Health.Origin != health.OriginControlPlane || got.Health.Scope != health.ScopeNode || got.Health.Port != 8080 {
		t.Errorf("health = %+v", got.Health)
	}
}

func TestSnapshots_BindSecretVersionsSharesOneVersionPerSecret(t *testing.T) {
	f := newFinFixture(t, finOptions{})
	f.putSecret(finSecretName)
	f.putSecret("apps/web/other")
	frozen := compose.Frozen{Secrets: []compose.SecretUse{
		{Service: "web", EnvName: "A", Ref: finSecretName},
		{Service: "worker", EnvName: "B", Ref: finSecretName},
		{Service: "web", EnvName: "C", Ref: "apps/web/other"},
	}}

	var bindings []plan.SecretBinding
	var inputs []plan.Input
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		var err error
		bindings, inputs, err = bindSecretVersions(ctx, tx, &frozen)
		return err
	})

	if len(bindings) != 3 || bindings[0].Version != 2 || bindings[1].Version != 2 || bindings[2].Version != 1 {
		t.Errorf("bindings = %+v, want the newest version of each secret", bindings)
	}
	if len(inputs) != 2 {
		t.Errorf("inputs = %+v, want one per secret name", inputs)
	}
	if frozen.Secrets[0].Version != 2 || frozen.Secrets[2].Version != 1 {
		t.Errorf("the frozen model's uses carry the versions: %+v", frozen.Secrets)
	}
}

func TestSnapshots_BindSecretVersionsRefusesAMissingSecret(t *testing.T) {
	f := newFinFixture(t, finOptions{})
	frozen := compose.Frozen{Secrets: []compose.SecretUse{{Service: "web", EnvName: "A", Ref: "apps/web/nope"}}}

	err := f.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		_, _, err := bindSecretVersions(ctx, tx, &frozen)
		return err
	})

	wantAppsCode(t, err, smerr.CodeInvalidArgument)
}

// ---- reading a known-good deployment ---------------------------------------------------------------

func snapKnownGood(t *testing.T) (*finFixture, database.Deployment) {
	t.Helper()
	f := newFinFixture(t, finOptions{pinned: true})
	created := f.create()
	f.mustFinalize(created.ID)
	f.markKnownGood(created.ID)
	return f, f.row(created.ID)
}

func (f *finFixture) loadKnownGood(dep database.Deployment) (knownGood, error) {
	return loadKnownGood(context.Background(), f.db.Reader(), dep)
}

func wantRollbackCause(t *testing.T, err error, cause string) {
	t.Helper()
	var typed *smerr.Error
	if !errors.As(err, &typed) || typed.Reason != smerr.ReasonRollbackUnavailable || typed.Details["cause"] != cause {
		t.Fatalf("error = %v, want ROLLBACK_UNAVAILABLE with cause %s", err, cause)
	}
}

func TestSnapshots_LoadKnownGoodReadsThePlanAndThePolicy(t *testing.T) {
	f, good := snapKnownGood(t)

	kg, err := f.loadKnownGood(good)

	mustf(t, err, "loadKnownGood")
	if *kg.plan.Content.CommitSHA != depCommit || kg.policy.Rollback != "automatic" {
		t.Errorf("known good = %+v", kg)
	}
}

func TestSnapshots_LoadKnownGoodNeedsAKnownGoodDeploymentWithAPlan(t *testing.T) {
	f := newFinFixture(t, finOptions{pinned: true})
	created := f.create()

	_, err := f.loadKnownGood(f.row(created.ID))

	wantRollbackCause(t, err, deployments.CauseNoKnownGood)
}

func TestSnapshots_LoadKnownGoodDetectsEveryMissingPiece(t *testing.T) {
	tests := []struct {
		name    string
		breakIt func(f *finFixture, p plan.Plan)
		cause   string
	}{
		{"compose snapshot deleted", func(f *finFixture, p plan.Plan) {
			f.exec(`DROP TRIGGER execution_snapshots_no_delete`)
			f.exec(`DELETE FROM execution_snapshots WHERE hash = ?`, *p.Content.ComposeHash)
		}, deployments.CauseSnapshotGone},
		{"health snapshot deleted", func(f *finFixture, p plan.Plan) {
			f.exec(`DROP TRIGGER execution_snapshots_no_delete`)
			f.exec(`DELETE FROM execution_snapshots WHERE hash = ?`, *p.Content.HealthHash)
		}, deployments.CauseSnapshotGone},
		{"policy snapshot tampered", func(f *finFixture, p plan.Plan) {
			f.exec(`DROP TRIGGER execution_snapshots_no_update`)
			f.exec(`UPDATE execution_snapshots SET content = '{}' WHERE hash = ?`, *p.Content.DeploymentPolicyHash)
		}, deployments.CauseSnapshotMismatch},
		{"secret version deleted", func(f *finFixture, p plan.Plan) {
			f.exec(`DELETE FROM secrets WHERE name = ? AND version = ?`, p.Content.SecretBindings[0].SecretID, p.Content.SecretBindings[0].Version)
		}, deployments.CauseSecretVersionGone},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, good := snapKnownGood(t)
			tc.breakIt(f, f.planOf(good.ID))

			_, err := f.loadKnownGood(good)

			wantRollbackCause(t, err, tc.cause)
		})
	}
}
