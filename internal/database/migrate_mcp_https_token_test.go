package database

import (
	"context"
	"testing"
)

func TestMigration000015MarksNoExistingClientAndOnlyLocalOnesCanBeMarked(t *testing.T) {
	ctx := context.Background()
	db := migratedTo(t, 14)
	execAll(t, db,
		`INSERT INTO identities (id, actor_type, subject, created_at) VALUES ('id-1', 'human', 'alice', 1)`,
		`INSERT INTO identities (id, actor_type, subject, created_at) VALUES ('id-m', 'mcp', 'client-1', 1)`,
		`INSERT INTO mcp_clients (id, identity_id, name, origin, state, requested_by, approved_at, created_at, updated_at)
			VALUES ('c-1', 'id-m', 'old', 'local', 'pending_token', 'id-1', 1, 1, 1)`)

	if err := MigrateUpTo(ctx, db, 15); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	client, err := GetMCPClient(ctx, db.Reader(), "c-1")
	if err != nil || client.OverHTTPS {
		t.Fatalf("existing client = %+v, %v; want unmarked", client, err)
	}
	execAll(t, db, `INSERT INTO identities (id, actor_type, subject, created_at) VALUES ('id-n', 'mcp', 'client-2', 1)`)
	state := map[string]string{"local": "pending_token", "remote": "active"}
	insert := func(origin string, marker int) error {
		return db.WithWriteTx(ctx, func(ctx context.Context, tx *Tx) error {
			_, err := tx.ExecContext(ctx, `INSERT INTO mcp_clients (id, identity_id, name, origin, over_https, state, requested_by, approved_at, created_at, updated_at)
				VALUES ('c-2', 'id-n', 'new', ?, ?, ?, 'id-1', 1, 1, 1)`, origin, marker, state[origin])
			return err
		})
	}
	if err := insert("remote", 1); err == nil {
		t.Error("a remote client was marked over_https")
	}
	if err := insert("remote", 0); err != nil {
		t.Fatalf("control: an unmarked remote client was refused: %v", err)
	}
	execAll(t, db, `DELETE FROM mcp_clients WHERE id = 'c-2'`)
	if err := insert("local", 2); err == nil {
		t.Error("over_https accepted 2")
	}
	if err := insert("local", 1); err != nil {
		t.Errorf("a local client could not be marked: %v", err)
	}
}
