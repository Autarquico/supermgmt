package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
)

func TestCredentialStatus_MCPToken(t *testing.T) {
	cases := []struct {
		name string
		do   func(w *mcpClientWorld)
		want app.CredentialState
	}{
		{"active", func(*mcpClientWorld) {}, app.CredentialActive},
		{"expired", func(w *mcpClientWorld) { w.clock.Advance(mcpLifetime) }, app.CredentialExpired},
		{"deleted", func(w *mcpClientWorld) { w.mcpDelete() }, app.CredentialRevoked},
		{"deleted and expired", func(w *mcpClientWorld) {
			w.mcpDelete()
			w.clock.Advance(mcpLifetime)
		}, app.CredentialRevoked},
		{"identity disabled", func(w *mcpClientWorld) { w.mcpDisableIdentity() }, app.CredentialRevoked},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newMCPClientWorld(t)
			tc.do(w)
			if got := w.mcpStatus(domain.CredentialMCPToken, w.client.ID); got != tc.want {
				t.Errorf("state = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestCredentialStatus_MCPTokenFailsClosedWhenThereIsNoToken(t *testing.T) {
	w := newMCPClientWorld(t)
	_, pending := w.mcpRegister("pending-client")

	if got := w.mcpStatus(domain.CredentialMCPToken, pending.ID); got != app.CredentialRevoked {
		t.Errorf("pending client state = %s, want revoked", got)
	}
	if got := w.mcpStatus(domain.CredentialMCPToken, "missing"); got != app.CredentialRevoked {
		t.Errorf("unknown client state = %s, want revoked", got)
	}
}

// mcpOAuthToken records an access token of the client that lives one hour.
func (w *mcpClientWorld) mcpOAuthToken() domain.ID {
	w.t.Helper()
	id := w.ids.NewID()
	w.mcpTx(func(ctx context.Context, tx *database.Tx) error {
		now := w.clock.Now()
		_, err := database.RecordOAuthAccessToken(ctx, tx, database.OAuthAccessToken{
			ID: id, MCPClientID: w.client.ID, TokenHash: "hash-" + id.String(), Issuer: "https://as.example",
			IssuedAt: now, ExpiresAt: now.Add(time.Hour), FirstSeenAt: now,
		})
		return err
	})
	return id
}

func (w *mcpClientWorld) mcpRevokeOAuthTokens() {
	w.t.Helper()
	w.mcpTx(func(ctx context.Context, tx *database.Tx) error {
		_, err := database.RevokeOAuthTokensOfClient(ctx, tx, w.client.ID, w.clock.Now())
		return err
	})
}

func TestCredentialStatus_OAuthAccessToken(t *testing.T) {
	cases := []struct {
		name string
		do   func(w *mcpClientWorld)
		want app.CredentialState
	}{
		{"active", func(*mcpClientWorld) {}, app.CredentialActive},
		{"natural expiry", func(w *mcpClientWorld) { w.clock.Advance(2 * time.Hour) }, app.CredentialExpired},
		{"client deleted", func(w *mcpClientWorld) { w.mcpDelete() }, app.CredentialRevoked},
		{"token revoked", func(w *mcpClientWorld) { w.mcpRevokeOAuthTokens() }, app.CredentialRevoked},
		{"revoked and expired", func(w *mcpClientWorld) {
			w.mcpRevokeOAuthTokens()
			w.clock.Advance(2 * time.Hour)
		}, app.CredentialRevoked},
		{"identity disabled", func(w *mcpClientWorld) { w.mcpDisableIdentity() }, app.CredentialRevoked},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newMCPClientWorld(t)
			id := w.mcpOAuthToken()
			tc.do(w)
			if got := w.mcpStatus(domain.CredentialOAuthAccessToken, id); got != tc.want {
				t.Errorf("state = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestCredentialStatus_OAuthAccessTokenUnknownIsRevoked(t *testing.T) {
	w := newMCPClientWorld(t)

	if got := w.mcpStatus(domain.CredentialOAuthAccessToken, "missing"); got != app.CredentialRevoked {
		t.Errorf("state = %s, want revoked", got)
	}
}
