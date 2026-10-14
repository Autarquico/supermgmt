package database

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	"github.com/autarquico/supermgmt/migrations"
)

const (
	m5Human   = idA
	m5Machine = idB
	m5Other   = "01970000-0000-7000-8000-00000000a003"
	m5Client  = "01970000-0000-7000-8000-00000000c001"
	m5Second  = "01970000-0000-7000-8000-00000000c002"
	yearMs    = 31536000000
)

// inM5Tx runs fn inside a write transaction that always rolls back, after
// seeding one human and two mcp identities.
func inM5Tx(t *testing.T, db *DB, fn func(ctx context.Context, tx *Tx) error) error {
	t.Helper()
	var result error
	_ = db.WithWriteTx(context.Background(), func(ctx context.Context, tx *Tx) error {
		for _, id := range []struct{ id, actor string }{{m5Human, "human"}, {m5Machine, "mcp"}, {m5Other, "mcp"}} {
			if _, err := tx.ExecContext(ctx, `INSERT INTO identities (id, actor_type, subject, created_at) VALUES (?, ?, ?, 1)`, id.id, id.actor, id.id); err != nil {
				t.Fatal(err)
			}
		}
		result = fn(ctx, tx)
		return fmt.Errorf("rollback")
	})
	return result
}

func mcpClientRow() map[string]any {
	return map[string]any{
		"id": m5Client, "identity_id": m5Machine, "name": "n", "origin": "local", "state": "pending_token",
		"requested_by": m5Human, "approved_at": 1, "created_at": 1, "updated_at": 1,
	}
}

func withColumns(row map[string]any, kv ...any) map[string]any {
	for i := 0; i < len(kv); i += 2 {
		row = override(row, kv[i].(string), kv[i+1])
	}
	return row
}

func oauthTokenRow() map[string]any {
	return map[string]any{
		"id": idA, "mcp_client_id": m5Client, "token_hash": "h", "issuer": "https://i", "issued_at": 1,
		"expires_at": 2, "first_seen_at": 1,
	}
}

func insertM5Client(ctx context.Context, tx *Tx, row map[string]any) error {
	return insertRow(ctx, tx, "mcp_clients", row)
}

func TestMCPClientChecksAcceptValidRows(t *testing.T) {
	db := migratedTest(t)
	cases := []struct {
		name string
		row  map[string]any
	}{
		{"pending local", mcpClientRow()},
		{"active local with a token", withColumns(mcpClientRow(), "state", "active", "token_hash", "h", "token_issued_at", 10, "token_expires_at", 20)},
		{"active remote without a token", withColumns(mcpClientRow(), "origin", "remote", "state", "active")},
		{"token of exactly 365 days", withColumns(mcpClientRow(), "state", "active", "token_hash", "h", "token_issued_at", 10, "token_expires_at", 10+yearMs)},
		{"deleted", withColumns(mcpClientRow(), "state", "deleted", "deleted_at", 5)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := inM5Tx(t, db, func(ctx context.Context, tx *Tx) error { return insertM5Client(ctx, tx, tc.row) })
			if err != nil {
				t.Fatalf("rejected: %v", err)
			}
		})
	}
}

func TestMCPClientChecksRejectInvalidRows(t *testing.T) {
	db := migratedTest(t)
	token := []any{"token_hash", "h", "token_issued_at", 10, "token_expires_at", 20}
	cases := []struct {
		name string
		row  map[string]any
	}{
		{"unknown origin", withColumns(mcpClientRow(), "origin", "cloud")},
		{"unknown state", withColumns(mcpClientRow(), "state", "paused")},
		{"remote client holding a token", withColumns(mcpClientRow(), append([]any{"origin", "remote", "state", "active"}, token...)...)},
		{"token hash without issue time", withColumns(mcpClientRow(), "token_hash", "h", "token_expires_at", 20)},
		{"issue time without token hash", withColumns(mcpClientRow(), "token_issued_at", 10, "token_expires_at", 20)},
		{"token valid for more than 365 days", withColumns(mcpClientRow(), "state", "active", "token_hash", "h", "token_issued_at", 10, "token_expires_at", 11+yearMs)},
		{"active local client without a token", withColumns(mcpClientRow(), "state", "active")},
		{"deleted without deleted_at", withColumns(mcpClientRow(), "state", "deleted")},
		{"deleted_at on a live client", withColumns(mcpClientRow(), "deleted_at", 5)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := inM5Tx(t, db, func(ctx context.Context, tx *Tx) error { return insertM5Client(ctx, tx, tc.row) })
			if err == nil || !strings.Contains(err.Error(), "CHECK constraint failed") {
				t.Fatalf("err = %v, want CHECK failure", err)
			}
		})
	}
}

func TestMCPClientUniquenessAndIdentityRules(t *testing.T) {
	db := migratedTest(t)
	active := withColumns(mcpClientRow(), "state", "active", "token_hash", "h", "token_issued_at", 10, "token_expires_at", 20)
	cases := []struct {
		name    string
		second  map[string]any
		wantErr string
	}{
		{"second live client for an identity", withColumns(mcpClientRow(), "id", m5Second, "name", "other"), "UNIQUE constraint failed"},
		{"live name taken", withColumns(mcpClientRow(), "id", m5Second, "identity_id", m5Other), "UNIQUE constraint failed"},
		{"token hash shared", withColumns(active, "id", m5Second, "identity_id", m5Other, "name", "other"), "UNIQUE constraint failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := inM5Tx(t, db, func(ctx context.Context, tx *Tx) error {
				if err := insertM5Client(ctx, tx, active); err != nil {
					t.Fatal(err)
				}
				return insertM5Client(ctx, tx, tc.second)
			})
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}

	t.Run("client on a human identity", func(t *testing.T) {
		err := inM5Tx(t, db, func(ctx context.Context, tx *Tx) error {
			return insertM5Client(ctx, tx, withColumns(mcpClientRow(), "identity_id", m5Human))
		})
		if err == nil || !strings.Contains(err.Error(), "must be an mcp identity") {
			t.Fatalf("err = %v, want the mcp identity trigger", err)
		}
	})

	t.Run("a deleted client frees its name and identity", func(t *testing.T) {
		err := inM5Tx(t, db, func(ctx context.Context, tx *Tx) error {
			if err := insertM5Client(ctx, tx, withColumns(mcpClientRow(), "state", "deleted", "deleted_at", 5)); err != nil {
				t.Fatal(err)
			}
			return insertM5Client(ctx, tx, withColumns(mcpClientRow(), "id", m5Second))
		})
		if err != nil {
			t.Fatalf("re-registration rejected: %v", err)
		}
	})
}

func TestMCPClientStateOnlyMovesForward(t *testing.T) {
	db := migratedTest(t)
	active := withColumns(mcpClientRow(), "state", "active", "token_hash", "h", "token_issued_at", 10, "token_expires_at", 20)
	deleted := withColumns(mcpClientRow(), "state", "deleted", "deleted_at", 5)
	cases := []struct {
		name   string
		row    map[string]any
		update string
	}{
		{"active back to pending_token", active, `UPDATE mcp_clients SET state = 'pending_token'`},
		{"deleted back to active", withColumns(deleted, "token_hash", "h", "token_issued_at", 10, "token_expires_at", 20), `UPDATE mcp_clients SET state = 'active', deleted_at = NULL`},
		{"deleted back to pending_token", deleted, `UPDATE mcp_clients SET state = 'pending_token', deleted_at = NULL`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := inM5Tx(t, db, func(ctx context.Context, tx *Tx) error {
				if err := insertM5Client(ctx, tx, tc.row); err != nil {
					t.Fatal(err)
				}
				_, err := tx.ExecContext(ctx, tc.update)
				return err
			})
			if err == nil || !strings.Contains(err.Error(), "invalid mcp client state transition") {
				t.Fatalf("err = %v, want the state trigger", err)
			}
		})
	}

	forward := []string{
		`UPDATE mcp_clients SET state = 'deleted', deleted_at = 5`,
		`UPDATE mcp_clients SET state = 'active', token_hash = 'h', token_issued_at = 10, token_expires_at = 20`,
	}
	for _, update := range forward {
		err := inM5Tx(t, db, func(ctx context.Context, tx *Tx) error {
			if err := insertM5Client(ctx, tx, mcpClientRow()); err != nil {
				t.Fatal(err)
			}
			_, err := tx.ExecContext(ctx, update)
			return err
		})
		if err != nil {
			t.Errorf("%s rejected: %v", update, err)
		}
	}
}

func TestMCPClientTokenIsSetOnce(t *testing.T) {
	db := migratedTest(t)
	active := withColumns(mcpClientRow(), "state", "active", "token_hash", "h", "token_issued_at", 10, "token_expires_at", 20)
	for _, update := range []string{
		`UPDATE mcp_clients SET token_hash = 'other'`,
		`UPDATE mcp_clients SET token_hash = NULL`,
	} {
		err := inM5Tx(t, db, func(ctx context.Context, tx *Tx) error {
			if err := insertM5Client(ctx, tx, active); err != nil {
				t.Fatal(err)
			}
			_, err := tx.ExecContext(ctx, update)
			return err
		})
		if err == nil || !strings.Contains(err.Error(), "token is issued once") {
			t.Errorf("%s: err = %v, want the token-once trigger", update, err)
		}
	}
}

func TestOAuthAccessTokensStayRevokedAndAttached(t *testing.T) {
	db := migratedTest(t)
	seed := func(ctx context.Context, tx *Tx) {
		for _, c := range []map[string]any{
			mcpClientRow(),
			withColumns(mcpClientRow(), "id", m5Second, "identity_id", m5Other, "name", "other"),
		} {
			if err := insertM5Client(ctx, tx, c); err != nil {
				t.Fatal(err)
			}
		}
		if err := insertRow(ctx, tx, "oauth_access_tokens", oauthTokenRow()); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name    string
		prepare string
		update  string
	}{
		{"un-revoke", `UPDATE oauth_access_tokens SET revoked_at = 5`, `UPDATE oauth_access_tokens SET revoked_at = NULL`},
		{"revoke again", `UPDATE oauth_access_tokens SET revoked_at = 5`, `UPDATE oauth_access_tokens SET revoked_at = 6`},
		{"re-attach a live token", `SELECT 1`, `UPDATE oauth_access_tokens SET mcp_client_id = '` + m5Second + `'`},
		{"re-attach a revoked token", `UPDATE oauth_access_tokens SET revoked_at = 5`, `UPDATE oauth_access_tokens SET mcp_client_id = '` + m5Second + `'`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := inM5Tx(t, db, func(ctx context.Context, tx *Tx) error {
				seed(ctx, tx)
				if _, err := tx.ExecContext(ctx, tc.prepare); err != nil {
					t.Fatal(err)
				}
				_, err := tx.ExecContext(ctx, tc.update)
				return err
			})
			if err == nil || !strings.Contains(err.Error(), "never changes client or un-revokes") {
				t.Fatalf("err = %v, want the stay-revoked trigger", err)
			}
		})
	}

	t.Run("revoking a live token and touching a revoked one are allowed", func(t *testing.T) {
		err := inM5Tx(t, db, func(ctx context.Context, tx *Tx) error {
			seed(ctx, tx)
			if _, err := tx.ExecContext(ctx, `UPDATE oauth_access_tokens SET revoked_at = 5`); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx, `UPDATE oauth_access_tokens SET last_used_at = 6`)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("one row per token hash", func(t *testing.T) {
		err := inM5Tx(t, db, func(ctx context.Context, tx *Tx) error {
			seed(ctx, tx)
			return insertRow(ctx, tx, "oauth_access_tokens", withColumns(oauthTokenRow(), "id", idB, "mcp_client_id", m5Second))
		})
		if err == nil || !strings.Contains(err.Error(), "UNIQUE constraint failed") {
			t.Fatalf("err = %v, want UNIQUE failure", err)
		}
	})

	t.Run("a token needs an existing client", func(t *testing.T) {
		err := inM5Tx(t, db, func(ctx context.Context, tx *Tx) error {
			if _, err := tx.ExecContext(ctx, `PRAGMA defer_foreign_keys = OFF`); err != nil {
				t.Fatal(err)
			}
			return insertRow(ctx, tx, "oauth_access_tokens", withColumns(oauthTokenRow(), "mcp_client_id", m5Second))
		})
		if err == nil || !strings.Contains(err.Error(), "FOREIGN KEY constraint failed") {
			t.Fatalf("err = %v, want FOREIGN KEY failure", err)
		}
	})
}

// A database migrated through 000005 keeps its data when 000006 is applied.
func TestMigration000006KeepsExistingData(t *testing.T) {
	ctx := context.Background()
	all, err := loadMigrations(migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	db, err := Open(ctx, filepath.Join(t.TempDir(), "sm.db"), Options{Clock: domaintest.NewFakeClock(testEpoch)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for _, m := range all {
		if m.version <= 5 {
			if err := db.apply(ctx, m); err != nil {
				t.Fatal(err)
			}
		}
	}
	err = db.WithWriteTx(ctx, func(ctx context.Context, tx *Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO identities (id, actor_type, subject, created_at) VALUES (?, 'human', 'alice', 1)`, m5Human); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO sessions (id, identity_id, token_hash, origin, created_at, expires_at) VALUES (?, ?, 'hs', 'oidc', 1, 2)`, idB, m5Human); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO events (event_id, timestamp, actor_type, actor_id, source, action, severity, result)
			VALUES (?, 1, 'system', 'x', 's', 'a', 'info', 'succeeded')`, idA)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate from version 5: %v", err)
	}

	for query, want := range map[string]int{
		`SELECT count(*) FROM identities WHERE subject = 'alice'`:                          1,
		`SELECT count(*) FROM sessions WHERE token_hash = 'hs'`:                            1,
		`SELECT count(*) FROM events`:                                                      1,
		`SELECT count(*) FROM mcp_clients`:                                                 0,
		`SELECT count(*) FROM oauth_access_tokens`:                                         0,
		`SELECT max(version) FROM schema_migrations`:                                       all[len(all)-1].version,
		`SELECT count(*) FROM schema_migrations WHERE version = 6`:                         1,
		`SELECT count(*) FROM pragma_foreign_key_check`:                                    0,
		`SELECT count(*) FROM pragma_table_list WHERE name = 'mcp_clients' AND strict = 1`: 1,
	} {
		if got := scalar[int](t, db.Reader(), query); got != want {
			t.Errorf("%s = %d, want %d", query, got, want)
		}
	}
}
