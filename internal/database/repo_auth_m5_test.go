package database

import (
	"context"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
)

// oauthJob inserts a job that carries an OAuth access token credential.
func (f *fixture) oauthJob(ctx context.Context, q Querier, actor, token domain.ID, state string) {
	f.t.Helper()
	row := override(baselines()["jobs"], "id", f.ids.NewID().String())
	row = override(row, "actor_id", actor.String())
	row = override(row, "credential_kind", "oauth_access_token")
	row = override(row, "credential_id", token.String())
	row = override(row, "state", state)
	noErr(f.t, insertRow(ctx, q.(*Tx), "jobs", row))
}

// oauthDeployment inserts a provisional-shaped deployment carrying an OAuth access token.
func (f *fixture) oauthDeployment(ctx context.Context, q Querier, requester, token domain.ID, state string) {
	f.t.Helper()
	row := override(m4Baselines()["deployments"], "id", f.ids.NewID().String())
	row = override(row, "requested_by", requester.String())
	row = override(row, "credential_kind", "oauth_access_token")
	row = override(row, "credential_id", token.String())
	row = override(row, "state", state)
	f.deploymentParents(ctx, q)
	noErr(f.t, insertRow(ctx, q.(*Tx), "deployments", row))
}

// deploymentParents inserts, once, the rows every deployment refers to.
func (f *fixture) deploymentParents(ctx context.Context, q Querier) {
	f.t.Helper()
	var existing int
	noErr(f.t, q.QueryRowContext(ctx, `SELECT count(*) FROM app_targets`).Scan(&existing))
	if existing > 0 {
		return
	}
	b, m4 := baselines(), m4Baselines()
	for _, parent := range []struct {
		table string
		row   map[string]any
	}{
		{"environments", b["environments"]},
		{"providers", b["providers"]},
		{"nodes", b["nodes"]},
		{"apps", m4["apps"]},
		{"app_targets", m4["app_targets"]},
	} {
		noErr(f.t, insertRow(ctx, q.(*Tx), parent.table, parent.row))
	}
}

func TestSweepAuthRemovesExpiredOAuthAccessTokens(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		alice := f.identity(ctx, q, domain.ActorHuman, "alice")
		client := f.mcpClient(ctx, q, alice.ID, "remote", MCPOriginRemote)
		expired := f.oauthToken(client.ID, "expired")
		live := f.oauthToken(client.ID, "live")
		live.ExpiresAt = testEpoch.Add(time.Hour * 24)
		for _, tok := range []OAuthAccessToken{expired, live} {
			must(RecordOAuthAccessToken(ctx, q, tok))
		}

		got := must(SweepAuth(ctx, q, testEpoch.Add(2*time.Hour)))

		if got.OAuthAccessTokens != 1 {
			t.Fatalf("swept %+v, want one OAuth access token", got)
		}
		if _, err := GetOAuthAccessToken(ctx, q, expired.ID); err == nil {
			t.Error("the expired token survived")
		}
		noErr(t, nilIfNil(GetOAuthAccessToken(ctx, q, live.ID)))
	})
}

func TestSweepAuthKeepsOAuthAccessTokensStillNeeded(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		alice := f.identity(ctx, q, domain.ActorHuman, "alice")
		client := f.mcpClient(ctx, q, alice.ID, "remote", MCPOriginRemote)
		token := func(hash string) OAuthAccessToken {
			return must(RecordOAuthAccessToken(ctx, q, f.oauthToken(client.ID, hash)))
		}
		jobStates := map[string]bool{ // job state -> token is still needed
			"awaiting_approval": true, "queued": true, "running": true, "interrupted": true,
			"succeeded": false, "failed": false, "cancelled": false,
		}
		held := map[string]OAuthAccessToken{}
		for state, needed := range jobStates {
			tok := token("job-" + state)
			f.oauthJob(ctx, q, alice.ID, tok.ID, state)
			held[state] = tok
			_ = needed
		}
		deployStates := map[string]bool{"created": true, "waiting_ci": true, "queued": false, "succeeded": false, "failed": false, "cancelled": false}
		deployments := map[string]OAuthAccessToken{}
		for state := range deployStates {
			tok := token("deployment-" + state)
			f.oauthDeployment(ctx, q, alice.ID, tok.ID, state)
			deployments[state] = tok
		}
		unreferenced := token("unreferenced")

		must(SweepAuth(ctx, q, testEpoch.Add(2*time.Hour)))

		exists := func(tok OAuthAccessToken) bool { _, err := GetOAuthAccessToken(ctx, q, tok.ID); return err == nil }
		for state, needed := range jobStates {
			if exists(held[state]) != needed {
				t.Errorf("token of a %s job kept = %v, want %v", state, !needed, needed)
			}
		}
		for state, needed := range deployStates {
			if exists(deployments[state]) != needed {
				t.Errorf("token of a %s deployment kept = %v, want %v", state, !needed, needed)
			}
		}
		if exists(unreferenced) {
			t.Error("an unreferenced expired token survived")
		}
	})
}

func TestSweepAuthRemovesTheTokenOnceTheDeploymentIsTerminal(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		alice := f.identity(ctx, q, domain.ActorHuman, "alice")
		client := f.mcpClient(ctx, q, alice.ID, "remote", MCPOriginRemote)
		tok := must(RecordOAuthAccessToken(ctx, q, f.oauthToken(client.ID, "waiting")))
		f.oauthDeployment(ctx, q, alice.ID, tok.ID, "waiting_ci")

		if got := must(SweepAuth(ctx, q, testEpoch.Add(2*time.Hour))); got.OAuthAccessTokens != 0 {
			t.Fatalf("swept %+v while the deployment waits for CI", got)
		}
		if _, err := q.ExecContext(ctx, `UPDATE deployments SET state = 'failed'`); err != nil {
			t.Fatal(err)
		}
		if got := must(SweepAuth(ctx, q, testEpoch.Add(2*time.Hour))); got.OAuthAccessTokens != 1 {
			t.Fatalf("swept %+v after the deployment ended, want the token", got)
		}
	})
}

func TestSweepAuthNeverDeletesMCPClients(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		alice := f.identity(ctx, q, domain.ActorHuman, "alice")
		c := f.mcpClient(ctx, q, alice.ID, "local", MCPOriginLocal)
		must(IssueMCPToken(ctx, q, c.ID, "hash-1", testEpoch, testEpoch.Add(time.Minute)))

		must(SweepAuth(ctx, q, testEpoch.Add(100*24*time.Hour)))

		noErr(t, nilIfNil(GetMCPClient(ctx, q, c.ID)))
	})
}

func TestRevokeAllCredentialsCoversMCPAndOAuthTokens(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		alice := f.identity(ctx, q, domain.ActorHuman, "alice")
		local := f.mcpClient(ctx, q, alice.ID, "local", MCPOriginLocal)
		must(IssueMCPToken(ctx, q, local.ID, "hash-1", testEpoch, testEpoch.Add(time.Hour)))
		pending := f.mcpClient(ctx, q, alice.ID, "pending", MCPOriginLocal)
		remote := f.mcpClient(ctx, q, alice.ID, "remote", MCPOriginRemote)
		oauth := must(RecordOAuthAccessToken(ctx, q, f.oauthToken(remote.ID, "oat-1")))
		earlier := f.oauthToken(remote.ID, "oat-0")
		must(RecordOAuthAccessToken(ctx, q, earlier))
		must(RevokeOAuthTokensOfClient(ctx, q, remote.ID, testEpoch)) // both revoked; a later restore must not move the stamp
		fresh := must(RecordOAuthAccessToken(ctx, q, f.oauthToken(remote.ID, "oat-2")))
		at := testEpoch.Add(time.Hour)

		n := must(RevokeAllCredentials(ctx, q, at))

		if n != 2 {
			t.Fatalf("revoked %d, want the local token and the one live OAuth token", n)
		}
		if got := must(GetMCPClient(ctx, q, local.ID)); got.RevokedAt == nil || !got.RevokedAt.Equal(at) {
			t.Errorf("local client revoked_at = %v, want %s", got.RevokedAt, at)
		}
		if got := must(GetOAuthAccessToken(ctx, q, fresh.ID)); got.RevokedAt == nil || !got.RevokedAt.Equal(at) {
			t.Errorf("live OAuth token revoked_at = %v, want %s", got.RevokedAt, at)
		}
		if got := must(GetOAuthAccessToken(ctx, q, oauth.ID)); got.RevokedAt == nil || !got.RevokedAt.Equal(testEpoch) {
			t.Errorf("already revoked OAuth token revoked_at = %v, want the first revocation %s", got.RevokedAt, testEpoch)
		}
		for _, c := range []MCPClient{pending, remote} {
			if got := must(GetMCPClient(ctx, q, c.ID)); got.RevokedAt != nil {
				t.Errorf("%s holds no token yet revoked_at = %v", c.Name, got.RevokedAt)
			}
		}
	})
}

func TestRevokeAllCredentialsRaisesTheCredentialsNotBeforeFloor(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		if got := must(CredentialsNotBefore(ctx, q)); !got.IsZero() {
			t.Fatalf("floor before any restore = %s, want none", got)
		}
		at := testEpoch.Add(time.Hour)
		must(RevokeAllCredentials(ctx, q, at))
		if got := must(CredentialsNotBefore(ctx, q)); !got.Equal(at) {
			t.Errorf("floor = %s, want the restore time %s", got, at)
		}
	})
}
