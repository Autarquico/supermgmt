package auth_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/auth"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const mcpLifetime = 24 * time.Hour

// mcpClientWorld is a world with one local MCP client whose token was issued.
type mcpClientWorld struct {
	*world
	client   database.MCPClient
	identity domain.ID
	token    string
}

func newMCPClientWorld(t *testing.T) *mcpClientWorld {
	t.Helper()
	w := &mcpClientWorld{world: newWorld(t)}
	w.identity, w.client = w.mcpRegister("local-client")
	secret, hash, err := auth.Mint(auth.KindMCP)
	must(t, err, "Mint")
	w.token = secret.Reveal()
	w.mcpTx(func(ctx context.Context, tx *database.Tx) error {
		now := w.clock.Now()
		var err error
		w.client, err = database.IssueMCPToken(ctx, tx, w.client.ID, hash, now, now.Add(mcpLifetime))
		return err
	})
	return w
}

func (w *mcpClientWorld) mcpTx(fn func(context.Context, *database.Tx) error) {
	w.t.Helper()
	must(w.t, w.db.WithWriteTx(context.Background(), fn), "write tx")
}

func (w *mcpClientWorld) mcpDelete() {
	w.t.Helper()
	w.mcpTx(func(ctx context.Context, tx *database.Tx) error {
		_, err := database.DeleteMCPClient(ctx, tx, w.client.ID, w.clock.Now())
		return err
	})
}

func (w *mcpClientWorld) mcpRegister(name string) (domain.ID, database.MCPClient) {
	w.t.Helper()
	now := w.clock.Now()
	identity := w.ids.NewID()
	client := database.MCPClient{
		ID: w.ids.NewID(), IdentityID: identity, Name: name, Origin: database.MCPOriginLocal,
		State: database.MCPClientPendingToken, RequestedBy: w.admin, ApprovedAt: now, CreatedAt: now, UpdatedAt: now,
	}
	w.mcpTx(func(ctx context.Context, tx *database.Tx) error {
		err := database.CreateIdentity(ctx, tx, database.Identity{
			ID: identity, ActorType: domain.ActorMCP, Issuer: "supermgmt:mcp-local", Subject: client.ID.String(), CreatedAt: now,
		})
		if err != nil {
			return err
		}
		return database.CreateMCPClient(ctx, tx, client)
	})
	return identity, client
}

func (w *mcpClientWorld) mcpDisableIdentity() {
	w.t.Helper()
	w.mcpTx(func(ctx context.Context, tx *database.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE identities SET disabled_at = ? WHERE id = ?`, w.clock.Now().UnixMilli(), w.identity)
		return err
	})
}

func (w *mcpClientWorld) mcpResolver(enabled bool) auth.MCPResolver {
	return auth.MCPResolver{DB: w.db, Clock: w.clock, Enabled: enabled}
}

func (w *mcpClientWorld) mcpResolve(token string) (app.Caller, error) {
	return w.mcpResolver(true).Resolve(context.Background(), token)
}

func (w *mcpClientWorld) mcpStatus(kind domain.CredentialKind, id domain.ID) app.CredentialState {
	w.t.Helper()
	state, err := auth.CredentialStatus{DB: w.db, Clock: w.clock}.Status(context.Background(), domain.CredentialContext{Kind: kind, ID: id.String()})
	must(w.t, err, "Status")
	return state
}

func mcpWantRefused(t *testing.T, err error, code smerr.Code, reason smerr.Reason) {
	t.Helper()
	var typed *smerr.Error
	if !errors.As(err, &typed) || typed.Code != code || typed.Reason != reason {
		t.Fatalf("err = %v, want %s/%s", err, code, reason)
	}
}

func TestMCPResolverMapsTheTokenToTheMCPCallerOfItsClient(t *testing.T) {
	w := newMCPClientWorld(t)

	caller, err := w.mcpResolve(w.token)

	must(t, err, "Resolve")
	cred := caller.Credential
	if caller.ID != w.identity || cred.Kind != domain.CredentialMCPToken || cred.ID != w.client.ID.String() {
		t.Errorf("caller = %+v, want identity %s with mcp_token %s", caller, w.identity, w.client.ID)
	}
	if cred.ExpiresAt == nil || !cred.ExpiresAt.Equal(w.clock.Now().Add(mcpLifetime)) {
		t.Errorf("expiry = %v, want the token's expiry", cred.ExpiresAt)
	}
	if len(cred.Scopes) != 0 {
		t.Errorf("scopes = %v, want none: the identity's roles decide", cred.Scopes)
	}
}

func TestMCPResolverRefusals(t *testing.T) {
	cases := []struct {
		name   string
		do     func(w *mcpClientWorld) (token string, enabled bool)
		reason smerr.Reason
	}{
		{"mcp disabled", func(w *mcpClientWorld) (string, bool) { return w.token, false }, ""},
		{"expired", func(w *mcpClientWorld) (string, bool) {
			w.clock.Advance(mcpLifetime)
			return w.token, true
		}, smerr.ReasonCredentialExpired},
		{"revoked", func(w *mcpClientWorld) (string, bool) {
			w.mcpTx(func(ctx context.Context, tx *database.Tx) error {
				_, err := tx.ExecContext(ctx, `UPDATE mcp_clients SET revoked_at = ? WHERE id = ?`, w.clock.Now().UnixMilli(), w.client.ID)
				return err
			})
			return w.token, true
		}, smerr.ReasonCredentialRevoked},
		{"client deleted", func(w *mcpClientWorld) (string, bool) {
			w.mcpDelete()
			return w.token, true
		}, smerr.ReasonCredentialRevoked},
		{"identity disabled", func(w *mcpClientWorld) (string, bool) {
			w.mcpDisableIdentity()
			return w.token, true
		}, smerr.ReasonCredentialRevoked},
		{"unknown token", func(w *mcpClientWorld) (string, bool) {
			other, _, _ := auth.Mint(auth.KindMCP)
			return other.Reveal(), true
		}, ""},
		{"malformed", func(*mcpClientWorld) (string, bool) { return "smm_nope", true }, ""},
		{"api token kind", func(*mcpClientWorld) (string, bool) {
			other, _, _ := auth.Mint(auth.KindAPIToken)
			return other.Reveal(), true
		}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newMCPClientWorld(t)
			token, enabled := tc.do(w)

			_, err := w.mcpResolver(enabled).Resolve(context.Background(), token)

			mcpWantRefused(t, err, smerr.CodeUnauthenticated, tc.reason)
			if strings.Contains(err.Error(), token) {
				t.Errorf("error %q leaks the token", err)
			}
		})
	}
}

func TestMCPTokenKindIsRefusedByTheHTTPSResolver(t *testing.T) {
	w := newMCPClientWorld(t)

	_, err := w.resolve(w.token)

	mcpWantRefused(t, err, smerr.CodeUnauthenticated, "")
}

func TestMCPResolverStampsLastUseOncePerMinute(t *testing.T) {
	w := newMCPClientWorld(t)
	lastUse := func() *time.Time {
		c, err := database.GetMCPClient(context.Background(), w.db.Reader(), w.client.ID)
		must(t, err, "GetMCPClient")
		return c.LastUsedAt
	}
	_, err := w.mcpResolve(w.token)
	must(t, err, "first Resolve")
	first := lastUse()
	w.clock.Advance(10 * time.Second)
	_, err = w.mcpResolve(w.token)
	must(t, err, "second Resolve")

	if first == nil || !lastUse().Equal(*first) {
		t.Fatalf("last use moved within a minute: %v -> %v", first, lastUse())
	}
	w.clock.Advance(time.Minute)
	_, err = w.mcpResolve(w.token)
	must(t, err, "third Resolve")
	if !lastUse().After(*first) {
		t.Errorf("last use did not move after a minute")
	}
}

func TestMintedMCPTokenHasItsKindAndShape(t *testing.T) {
	secret, hash, err := auth.Mint(auth.KindMCP)
	must(t, err, "Mint")
	kind, gotHash, err := auth.Hash(secret.Reveal())

	if err != nil || kind != auth.KindMCP || gotHash != hash || !strings.HasPrefix(secret.Reveal(), "smm_") {
		t.Errorf("Hash = %c, %q, %v; want m, %q", kind, gotHash, err, hash)
	}
}
