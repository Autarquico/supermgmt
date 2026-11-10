package database

import (
	"context"
	"testing"

	"github.com/autarquico/supermgmt/internal/domain"
)

func TestMigration000016FreesTheNamesAndTokenSlotsOfRetiredAPINodesOnly(t *testing.T) {
	ctx := context.Background()
	db := migratedTo(t, 15)
	provider := func(id, name, origin string) string {
		return `INSERT INTO providers (id, type, name, origin, created_at, updated_at) VALUES ('` + id + `', 'ssh', '` + name + `', '` + origin + `', 1, 1)`
	}
	node := func(id, provider, state string) string {
		return `INSERT INTO nodes (id, provider_id, native_id, name, kind, management_state, reachability, created_at, updated_at)
			VALUES ('` + id + `', '` + provider + `', '` + id + `', '` + id + `', 'ssh', '` + state + `', 'unknown', 1, 1)`
	}
	token := func(name string) string {
		return `INSERT INTO secrets (id, name, version, envelope_version, kek_id, wrapped_dek, ciphertext, created_at)
			VALUES ('s-` + name + `', '` + name + `', 1, 1, 'kek', x'01', x'02', 1)`
	}
	execAll(t, db,
		provider("p-retired", "old", "api"), node("old", "p-retired", "retired"),
		provider("p-live", "web", "api"), node("web", "p-live", "managed"),
		provider("p-static", "lab", "static"), node("lab-1", "p-static", "retired"),
		provider("p-empty", "pending", "api"),
		token("proxmox/old"), token("proxmox/web"), token("proxmox/lab-1"))

	if err := MigrateUpTo(ctx, db, 16); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	want := map[string]string{
		"p-retired": "old~retired-p-retired",
		"p-live":    "web",
		"p-static":  "lab",
		"p-empty":   "pending",
	}
	for id, name := range want {
		p, err := GetProvider(ctx, db.Reader(), domain.ID(id))
		if err != nil || p.Name != name {
			t.Errorf("provider %s = %q, %v; want %q", id, p.Name, err, name)
		}
	}
	for name, kept := range map[string]bool{"proxmox/old": false, "proxmox/web": true, "proxmox/lab-1": true} {
		if _, err := GetSecret(ctx, db.Reader(), name, 0); (err == nil) != kept {
			t.Errorf("%s: %v; want kept=%v (only a retired API node's token slot is forgotten)", name, err, kept)
		}
	}
	if n, err := GetNode(ctx, db.Reader(), domain.ID("old")); err != nil || n.Name != "old" {
		t.Errorf("retired node = %q, %v; it keeps its name for the audit trail", n.Name, err)
	}
}
