package backup_test

import (
	"context"
	"strconv"
	"testing"

	"github.com/autarquico/supermgmt/internal/backup"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
)

// seedMCPCredentials adds the MCP credentials a restore must kill: a local
// client holding a token, a remote client with an access token, and a local
// client still waiting for its token (it holds no credential yet).
func (s *site) seedMCPCredentials() {
	s.t.Helper()
	now := s.clock.Now().UnixMilli()
	s.exec(`INSERT INTO identities (id, actor_type, subject, created_at) VALUES ('mcp-human', 'human', 'alice', ?)`, now)
	for _, id := range []string{"mcp-id-local", "mcp-id-remote", "mcp-id-pending"} {
		s.exec(`INSERT INTO identities (id, actor_type, subject, created_at) VALUES (?, 'mcp', ?, ?)`, id, id, now)
	}
	client := func(id, identity, origin, state string) {
		s.exec(`INSERT INTO mcp_clients (id, identity_id, name, origin, state, requested_by, approved_at, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, 'mcp-human', ?, ?, ?)`, id, identity, id, origin, state, now, now, now)
	}
	client("mcpc-local", "mcp-id-local", "local", "pending_token")
	s.exec(`UPDATE mcp_clients SET token_hash = 'hash-m', token_issued_at = ?, token_expires_at = ?, state = 'active' WHERE id = 'mcpc-local'`,
		now, now+3_600_000)
	client("mcpc-remote", "mcp-id-remote", "remote", "active")
	client("mcpc-pending", "mcp-id-pending", "local", "pending_token")
	s.exec(`INSERT INTO oauth_access_tokens (id, mcp_client_id, token_hash, issuer, issued_at, expires_at, first_seen_at)
		VALUES ('oat-1', 'mcpc-remote', 'hash-o', 'https://issuer.example', ?, ?, ?)`, now, now+3_600_000, now)
}

func TestRestoreRevokesMCPCredentials(t *testing.T) {
	clock := domaintest.NewFakeClock(epoch)
	ids := domaintest.NewSequentialIDs()
	src := newSite(t, "source", clock, ids).withSecrets()
	src.seedMCPCredentials()
	tg := newTarget(t, src, src.archive())
	if err := backup.Restore(context.Background(), tg.options()); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	db := openDB(t, tg.dbPath, tg.clock)
	restoredAt := src.clock.Now().UnixMilli()

	if got := scalar[int64](t, db, `SELECT revoked_at FROM mcp_clients WHERE id = 'mcpc-local'`); got != restoredAt {
		t.Errorf("local client token revoked_at = %d, want the restore time %d", got, restoredAt)
	}
	if got := scalar[int64](t, db, `SELECT revoked_at FROM oauth_access_tokens WHERE id = 'oat-1'`); got != restoredAt {
		t.Errorf("oauth access token revoked_at = %d, want the restore time %d", got, restoredAt)
	}
	if got := scalar[string](t, db, `SELECT value_json FROM settings WHERE key = 'credentials_not_before'`); got != strconv.FormatInt(restoredAt, 10) {
		t.Errorf("credentials_not_before = %s, want the restore time %d", got, restoredAt)
	}
	for _, id := range []string{"mcpc-remote", "mcpc-pending"} {
		if n := scalar[int](t, db, `SELECT count(*) FROM mcp_clients WHERE id = ? AND revoked_at IS NULL AND state <> 'deleted'`, id); n != 1 {
			t.Errorf("%s changed: it holds no token, so restore must leave the row alone", id)
		}
	}
}
