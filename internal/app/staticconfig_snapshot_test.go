package app

import (
	"bytes"
	"context"
	"testing"

	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// Configuration snapshot (spec §29.1).

func (f *fixture) snapshot() (database.ConfigSnapshot, error) {
	return database.GetConfigSnapshot(context.Background(), f.db.Reader())
}

func TestActivateStoresTheExactSourceBytesWithTheReconcile(t *testing.T) {
	f := newFixture(t)
	src := ConfigSources{Config: []byte("instance:\r\n  name: lab\n\xff"), Policy: []byte("version: 1\n")}

	err := f.reconciler(t).Activate(context.Background(), src, fileEnvs(), []config.Provider{fileNode("edge-1", "10.1.0.1")})

	mustf(t, err, "Activate")
	snap, err := f.snapshot()
	mustf(t, err, "snapshot")
	if !bytes.Equal(snap.Config, src.Config) || !bytes.Equal(snap.Policy, src.Policy) || snap.Generation != 1 {
		t.Errorf("snapshot = %+v, want the source bytes at generation 1", snap)
	}
	if _, ok := f.nodeNamed("edge-1"); !ok {
		t.Error("the reconcile did not run")
	}
	events := f.events("config.activate")
	if len(events) != 1 || events[0].Data["generation"] != float64(1) || events[0].ActorType != domain.ActorSystem {
		t.Fatalf("config.activate events = %+v", events)
	}
	if _, leaked := events[0].Data["config"]; leaked || events[0].Data["config_sha256"] == "" || events[0].Data["policy_sha256"] == "" {
		t.Errorf("event data = %v; want digests and no bytes", events[0].Data)
	}
}

func TestEveryActivationAdvancesTheGenerationEvenForIdenticalBytes(t *testing.T) {
	f := newFixture(t)
	r := f.reconciler(t)
	src := ConfigSources{Config: []byte("a: 1\n")}

	mustf(t, r.Activate(context.Background(), src, fileEnvs(), nil), "first")
	mustf(t, r.Activate(context.Background(), src, fileEnvs(), nil), "second")

	snap, _ := f.snapshot()
	if snap.Generation != 2 || len(snap.Policy) != 0 {
		t.Errorf("snapshot = %+v, want generation 2 and no policy", snap)
	}
}

func TestActivateRefusesEmptyConfigurationBytes(t *testing.T) {
	f := newFixture(t)

	err := f.reconciler(t).Activate(context.Background(), ConfigSources{}, fileEnvs(), nil)

	wantError(t, err, smerr.CodeInvalidArgument, "")
	if _, err := f.snapshot(); smerr.CodeOf(err) != smerr.CodeNotFound {
		t.Errorf("snapshot after a refused activation = %v, want NOT_FOUND", err)
	}
}

func TestAFailingReconcileLeavesNoNewSnapshotAndTheOldOneIntact(t *testing.T) {
	f := newFixture(t)
	r := f.reconciler(t)
	good := ConfigSources{Config: []byte("good: 1\n")}
	mustf(t, r.Activate(context.Background(), good, fileEnvs(), nil), "good")

	bad := fileNode("ssh-hosts", "10.1.0.9") // collides with the API-created provider of the fixture
	err := r.Activate(context.Background(), ConfigSources{Config: []byte("bad: 1\n")}, fileEnvs(), []config.Provider{bad})

	if err == nil {
		t.Fatal("Activate succeeded with a conflicting provider")
	}
	snap, _ := f.snapshot()
	if string(snap.Config) != "good: 1\n" || snap.Generation != 1 {
		t.Errorf("snapshot = %+v; a failed activation must not replace it", snap)
	}
}

func TestAFailingSnapshotRollsTheReconcileBack(t *testing.T) {
	f := newFixture(t)
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		_, err := tx.ExecContext(ctx, `CREATE TRIGGER inject_snapshot_failure BEFORE INSERT ON settings
			WHEN NEW.key = 'config_snapshot' BEGIN SELECT RAISE(ABORT, 'injected snapshot failure'); END`)
		return err
	})
	events := len(f.events())

	err := f.reconciler(t).Activate(context.Background(), ConfigSources{Config: []byte("a: 1\n")}, fileEnvs(), []config.Provider{fileNode("edge-1", "10.1.0.1")})

	if err == nil {
		t.Fatal("Activate succeeded although the snapshot could not be stored")
	}
	if _, ok := f.nodeNamed("edge-1"); ok {
		t.Error("the node survived a failed snapshot: reconcile and snapshot did not commit atomically")
	}
	if _, err := environmentNamed(context.Background(), f.db.Reader(), "lab"); err == nil {
		t.Error("the environment survived a failed snapshot")
	}
	if got := len(f.events()); got != events {
		t.Errorf("events %d -> %d; a rolled-back activation must leave none", events, got)
	}
}

func TestReconcileAloneStoresNoSnapshot(t *testing.T) {
	f := newFixture(t)

	mustf(t, f.reconciler(t).Reconcile(context.Background(), fileEnvs(), nil), "Reconcile")

	if _, err := f.snapshot(); smerr.CodeOf(err) != smerr.CodeNotFound {
		t.Errorf("snapshot = %v, want NOT_FOUND", err)
	}
}
