package integration

import (
	"context"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/auth"
	"github.com/autarquico/supermgmt/internal/auth/oauthfake"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/secrets"
)

// Re-registration after deletion must not resurrect any credential of the old
// client (ADR-0032): through the real services and OAuth resolver for a remote
// client, and through the real daemon for a local one.

// ---- remote client -----------------------------------------------------------

// mcpRegistry is an mcpWorld with the services that register and delete MCP
// clients and the engine that applies the approved changes.
type mcpRegistry struct {
	*mcpWorld
	clients *app.MCPClientService
	admin   domain.ID
}

func newMCPRegistry(t *testing.T, issuer string) *mcpRegistry {
	t.Helper()
	m := newMCPWorld(t, mcpWorldGrant)
	clients, err := app.NewMCPClients(m.cfg, m.store, app.MCPClientsOptions{Tokens: auth.Minter{}, RemoteIssuer: issuer})
	mcpRigMust(t, err)
	inventory, err := app.NewInventory(m.cfg, app.InventoryOptions{Store: m.store, Connector: app.Connector{}, Mode: config.ModeLocal})
	mcpRigMust(t, err)
	prober, err := app.NewProber(m.cfg, app.Connector{}, nil)
	mcpRigMust(t, err)
	noKey := func(context.Context) (secrets.Identity, error) {
		return secrets.Identity{}, smerr.New(smerr.CodeInternal, "", "no ssh key in this suite")
	}
	handlers, err := app.NewHandlers(m.cfg, app.HandlersOptions{Store: m.store, Inventory: inventory, Prober: prober, Identity: noKey})
	mcpRigMust(t, err)
	runEngine(t, m.world, handlers.Map())

	r := &mcpRegistry{mcpWorld: m, clients: clients}
	m.inTx(func(ctx context.Context, tx *database.Tx) error {
		r.admin = m.ids.NewID()
		err := database.CreateIdentity(ctx, tx, database.Identity{ID: r.admin, ActorType: domain.ActorHuman, Subject: "root", CreatedAt: m.clock.Now()})
		if err != nil {
			return err
		}
		role, err := database.GetRoleByName(ctx, tx, "admin")
		if err != nil {
			return err
		}
		return database.CreateRoleBinding(ctx, tx, database.RoleBinding{ID: m.ids.NewID(), IdentityID: r.admin, RoleID: role.ID, CreatedAt: m.clock.Now()})
	})
	return r
}

// approveAndWait has the operators approve a change policy parked and waits
// for its job to finish; a change policy let through is already done.
func (r *mcpRegistry) approveAndWait(result app.DirectResult[wire.MCPClient], err error) {
	r.t.Helper()
	mcpRigMust(r.t, err)
	if result.Pending == nil {
		return
	}
	job := r.approveToQueued(result.Pending.Job)
	eventually(r.t, "the approved change to be applied", func() bool { return r.job(job.ID).State == domain.JobSucceeded })
}

func (r *mcpRegistry) register(name string, as *oauthfake.Server) {
	r.t.Helper()
	result, err := r.clients.Register(context.Background(), r.operator(r.admin), wire.RegisterMCPClientRequest{
		Name: name, Origin: wire.MCPOriginRemote, Subject: as.Subject, ClientID: as.ClientID,
	})
	r.approveAndWait(result, err)
}

func (r *mcpRegistry) liveClient(name string) database.MCPClient {
	r.t.Helper()
	all, err := database.ListMCPClients(context.Background(), r.db.Reader())
	mcpRigMust(r.t, err)
	for _, c := range all {
		if c.Name == name && c.State != database.MCPClientDeleted {
			return c
		}
	}
	r.t.Fatalf("no live client named %q", name)
	return database.MCPClient{}
}

func TestAReRegisteredRemoteClientStartsWithNoRolesAndNoneOfItsOldTokens(t *testing.T) {
	as := oauthfake.New()
	t.Cleanup(as.Close)
	r := newMCPRegistry(t, as.Issuer)
	resolver, err := auth.NewOAuthResolver(context.Background(), auth.OAuthConfig{
		Issuer: as.Issuer, Resource: as.Resource, JWKSURL: as.JWKSURL(), RequiredScopes: []string{"mcp:read"}, HTTP: as.Client(), Clock: r.clock,
	}, r.db)
	mcpRigMust(t, err)
	resolve := func(token string) (app.Caller, error) { return resolver.Resolve(context.Background(), token) }
	mint := func() string { return as.Sign(as.AccessToken(r.clock.Now())) }

	r.register("assistant", as)
	first := r.liveClient("assistant")
	seen, unseen := mint(), mint() // the second is issued but never presented while the client lives
	if _, err := resolve(seen); err != nil {
		t.Fatalf("a token of the registered client: %v", err)
	}

	r.approveAndWait(r.clients.Delete(context.Background(), r.operator(r.admin), first.ID))
	if _, err := resolve(seen); err == nil {
		t.Error("a token of a deleted client was accepted")
	}
	r.clock.Advance(time.Hour)
	r.register("assistant", as)
	again := r.liveClient("assistant")

	if again.ID == first.ID || again.IdentityID != first.IdentityID {
		t.Fatalf("re-registration = client %s identity %s, want a new client on identity %s", again.ID, again.IdentityID, first.IdentityID)
	}
	_, seenErr := resolve(seen)
	if smerr.CodeOf(seenErr) != smerr.CodeUnauthenticated || mcpSecReasonOf(seenErr) != smerr.ReasonCredentialRevoked {
		t.Errorf("the token seen before deletion = %v, want UNAUTHENTICATED/CREDENTIAL_REVOKED", seenErr)
	}
	_, unseenErr := resolve(unseen)
	if smerr.CodeOf(unseenErr) != smerr.CodeUnauthenticated || mcpSecReasonOf(unseenErr) != smerr.ReasonOAuthTokenInvalid {
		t.Errorf("the token minted before deletion and never seen = %v, want UNAUTHENTICATED/OAUTH_TOKEN_INVALID", unseenErr)
	}
	caller, err := resolve(mint())
	if err != nil || caller.ID != again.IdentityID {
		t.Errorf("a token issued after re-registration = %+v, %v, want the identity %s", caller, err, again.IdentityID)
	}
	var bindings int
	mcpRigMust(t, r.db.Reader().QueryRowContext(context.Background(), `SELECT COUNT(*) FROM role_bindings WHERE identity_id = ?`, again.IdentityID).Scan(&bindings))
	if bindings != 0 {
		t.Errorf("the re-registered identity holds %d role bindings, want none", bindings)
	}
	var history int
	mcpRigMust(t, r.db.Reader().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM mcp_clients WHERE identity_id = ? AND state = 'deleted'`, again.IdentityID).Scan(&history))
	if history != 1 {
		t.Errorf("%d deleted client rows kept as history, want 1", history)
	}
}

// ---- local client, through the daemon ---------------------------------------------

// approveParked approves the job a direct action left waiting.
func (d *mcpDaemon) approveParked(result wire.Direct[wire.MCPClient], err error) {
	d.t.Helper()
	mcpRigMust(d.t, err)
	if result.Pending == nil {
		d.t.Fatalf("the change was applied without approval: %+v", result)
	}
	_, err = d.human().Approve(context.Background(), result.Pending.Job.ID, wire.DecisionRequest{PlanHash: result.Pending.Job.PlanHash})
	mcpRigMust(d.t, err)
}

func (d *mcpDaemon) waitForState(id domain.ID, state wire.MCPClientState) {
	d.t.Helper()
	for range 1500 {
		page, err := d.human().ListMCPClients(context.Background())
		mcpRigMust(d.t, err)
		for _, listed := range page.Items {
			if listed.ID == id && listed.State == state {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	d.t.Fatalf("client %s never reached state %s", id, state)
}

func TestAReRegisteredLocalClientCannotUseItsOldTokenAndGetsANewOne(t *testing.T) {
	d := startMCPDaemon(t, "")
	ctx := context.Background()
	first, oldToken := d.issueToken("assistant")
	if _, err := d.withToken(oldToken).Me(ctx); err != nil {
		t.Fatalf("the token before deletion: %v", err)
	}

	removed, err := d.human().DeleteMCPClient(ctx, first.ID)
	if removed.Pending != nil {
		d.approveParked(removed, err)
	} else {
		mcpRigMust(t, err)
	}
	d.waitForState(first.ID, wire.MCPClientDeleted)
	if _, err := d.withToken(oldToken).Me(ctx); smerr.CodeOf(err) != smerr.CodeUnauthenticated {
		t.Errorf("the token of a deleted client = %v, want UNAUTHENTICATED", err)
	}

	again, newToken := d.issueToken("assistant")

	if again.ID == first.ID || again.IdentityID == first.IdentityID {
		t.Errorf("re-registration reused client %s / identity %s: a local client is always new", first.ID, first.IdentityID)
	}
	if newToken == oldToken {
		t.Error("the re-registered client was given the old token")
	}
	if _, err := d.withToken(oldToken).Me(ctx); smerr.CodeOf(err) != smerr.CodeUnauthenticated {
		t.Errorf("the old token after re-registration = %v, want UNAUTHENTICATED", err)
	}
	me, err := d.withToken(newToken).Me(ctx)
	if err != nil || me.IdentityID != again.IdentityID || len(me.Roles) != 0 {
		t.Errorf("the new token = %+v, %v, want the new identity with no roles", me, err)
	}
}
