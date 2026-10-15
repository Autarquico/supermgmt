package backup_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/backup"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/secrets"
)

// The tunnel records travel in the database copy; the three credentials the
// feature handles travel only as the existing encrypted secret records
// (ADR-0037 "Restore").
func TestArchiveKeepsTunnelRecordsAndNeverTheirPlaintextCredentials(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	credentials := map[string]string{
		"cloudflare/api-token":            "cf-api-token-PLAINTEXT-4f1c9a2e7b",
		"cloudflare/access-service-token": "svc-id.access:svc-secret-PLAINTEXT-8d3e5b6a",
		"node/tunnel-token":               "eyJhIjoiYWNjdCIsInQiOiJ0dW4tUExBSU5URVhUIiwicyI6InNlY3JldCJ9",
	}
	store := secrets.NewStore(f.keys, app.NewSecretsRepo(f.db, f.clock), f.ids, f.clock)
	for name, value := range credentials {
		if _, err := store.Put(ctx, name, audit.Secret(value), nil); err != nil {
			t.Fatalf("Put %s: %v", name, err)
		}
	}
	now := f.clock.Now()
	err := f.db.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		for _, stmt := range []string{
			`INSERT INTO providers (id, type, name, origin, created_at, updated_at) VALUES ('prov-1', 'ssh', 'ssh', 'static', ?1, ?1)`,
			`INSERT INTO nodes (id, provider_id, native_id, name, kind, management_state, reachability, created_at, updated_at)
				VALUES ('node-1', 'prov-1', 'n', 'web-1', 'host', 'managed', 'unknown', ?1, ?1)`,
		} {
			if _, err := tx.ExecContext(ctx, stmt, now.UnixMilli()); err != nil {
				return err
			}
		}
		op, err := database.CreateTunnelOperation(ctx, tx, database.TunnelOperation{
			ID: f.ids.NewID(), NodeID: "node-1", Kind: database.TunnelEnable, AccountID: "acct", Zone: "example.test",
			InstanceID: "inst", Hostname: "web-1.example.test", CreatedAt: now,
		})
		if err != nil {
			return err
		}
		if _, err = database.AdvanceTunnelPhase(ctx, tx, op.ID, op.Generation, database.PhaseStarted, database.PhaseTunnelCreated,
			database.TunnelObjects{TunnelID: "tunnel-id-1"}, now); err != nil {
			return err
		}
		_, err = database.SaveCloudflareState(ctx, tx, database.CloudflareState{
			AccountID: "acct", Token: database.CloudflareToken{ID: "svc-token-id", Name: "supermgmt-inst", CreatedAt: now, ExpiresAt: now.AddDate(1, 0, 0)},
			Rotation: database.RotationIdle, ServicePolicyID: "policy-svc", OwnersPolicyID: "policy-owners",
		}, 0, now)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	members := readArchive(t, f.create().Path)

	for _, m := range members {
		for name, value := range credentials {
			if bytes.Contains(m.data, []byte(value)) {
				t.Errorf("archive member %s holds the plaintext of %s", m.name, name)
			}
		}
		if bytes.Contains(m.data, []byte("svc-secret-PLAINTEXT")) {
			t.Errorf("archive member %s holds the service token secret", m.name)
		}
	}
	var snapshot []byte
	for _, m := range members {
		if m.name == backup.DatabaseName {
			snapshot = m.data
		}
	}
	path := filepath.Join(t.TempDir(), "restored.db")
	if err := os.WriteFile(path, snapshot, 0o600); err != nil {
		t.Fatal(err)
	}
	restored := openCopy(t, path)
	ops, err := database.ListTunnelOperations(ctx, restored.Reader(), "node-1")
	if err != nil || len(ops) != 1 || ops[0].Objects.TunnelID != "tunnel-id-1" || ops[0].Phase != database.PhaseTunnelCreated {
		t.Errorf("tunnel operations in the archive = %+v, %v", ops, err)
	}
	state, err := database.GetCloudflareState(ctx, restored.Reader())
	if err != nil || state.Token.ID != "svc-token-id" || state.ServicePolicyID != "policy-svc" {
		t.Errorf("cloudflare_state in the archive = %+v, %v", state, err)
	}
	for name := range credentials {
		sealed, err := database.GetSecret(ctx, restored.Reader(), name, 0)
		if err != nil || len(sealed.Ciphertext) == 0 {
			t.Errorf("secret %s in the archive = %+v, %v; want a sealed record", name, sealed, err)
		}
	}
}
