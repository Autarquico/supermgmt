package app

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
)

const mcpcIssuer = "https://idp.example"

// mcpcFixture is the base fixture with the MCP clients service, the inventory
// that applies approved changes and a second admin.
type mcpcFixture struct {
	*fixture
	svc    *MCPClientService
	inv    *Inventory
	admin2 domain.ID
}

func newMCPClientsFixture(t *testing.T, tweak ...func(*Config)) *mcpcFixture {
	t.Helper()
	f := newFixture(t, tweak...)
	svc, err := NewMCPClients(f.cfg, f.store, MCPClientsOptions{Tokens: &countingMinter{}, RemoteIssuer: mcpcIssuer})
	mustf(t, err, "NewMCPClients")
	inv, err := NewInventory(f.cfg, InventoryOptions{Store: f.store, Connector: Connector{}, Mode: config.ModeLocal})
	mustf(t, err, "NewInventory")
	m := &mcpcFixture{fixture: f, svc: svc, inv: inv}
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		m.admin2 = f.identity(ctx, tx, "root2", domain.ActorHuman, f.role(ctx, tx, "admin"))
		return nil
	})
	return m
}

// applyJob runs the claimed control_plane.apply job to completion.
func (m *mcpcFixture) applyJob(job domain.ID) error {
	m.t.Helper()
	claimed, ok := m.claim()
	if !ok || claimed.Job.ID != job {
		m.t.Fatalf("job %s was not claimable", job)
	}
	if err := (applyHandler{inv: m.inv}).Run(context.Background(), claimed.Lease); err != nil {
		return err
	}
	return m.store.Succeed(context.Background(), claimed.Lease)
}

// approveUntilQueued has the operators approve until the job can run: the quorum
// of an identity change is not the one of a production node.
func (m *mcpcFixture) approveUntilQueued(job jobs.Job) {
	m.t.Helper()
	for _, approver := range []domain.ID{m.bob, m.carol} {
		if job.State != domain.JobAwaitingApproval {
			return
		}
		var err error
		job, err = m.approve(approver, job)
		mustf(m.t, err, "approve")
	}
}

// register asks as the first admin, has the operators approve and applies the job.
func (m *mcpcFixture) register(r wire.RegisterMCPClientRequest) database.MCPClient {
	m.t.Helper()
	res, err := m.svc.Register(context.Background(), m.caller(m.admin), r)
	mustf(m.t, err, "Register %s", r.Name)
	if res.Pending == nil {
		m.t.Fatalf("Register %s = %+v, want a request waiting for approval", r.Name, res)
	}
	m.approveUntilQueued(res.Pending.Job)
	mustf(m.t, m.applyJob(res.Pending.Job.ID), "apply registration of %s", r.Name)
	return m.clientNamed(r.Name)
}

// clientNamed is the live client of that name.
func (m *mcpcFixture) clientNamed(name string) database.MCPClient {
	m.t.Helper()
	all, err := database.ListMCPClients(context.Background(), m.db.Reader())
	mustf(m.t, err, "ListMCPClients")
	for _, c := range all {
		if c.Name == name && c.State != database.MCPClientDeleted {
			return c
		}
	}
	m.t.Fatalf("no live MCP client named %q in %+v", name, all)
	return database.MCPClient{}
}

func (m *mcpcFixture) clients() []database.MCPClient {
	m.t.Helper()
	all, err := database.ListMCPClients(context.Background(), m.db.Reader())
	mustf(m.t, err, "ListMCPClients")
	return all
}

func (m *mcpcFixture) identityRow(id domain.ID) database.Identity {
	m.t.Helper()
	identity, err := database.GetIdentity(context.Background(), m.db.Reader(), id)
	mustf(m.t, err, "GetIdentity")
	return identity
}

func (m *mcpcFixture) rolesOf(id domain.ID) []database.Role {
	m.t.Helper()
	roles, err := database.ListRolesForIdentity(context.Background(), m.db.Reader(), id)
	mustf(m.t, err, "ListRolesForIdentity")
	return roles
}

func (m *mcpcFixture) issue(by domain.ID, client domain.ID, lifetime time.Duration) (wire.MCPTokenIssued, error) {
	return m.svc.IssueToken(context.Background(), m.caller(by), client, wire.IssueMCPTokenRequest{ExpiresAt: m.clock.Now().Add(lifetime)})
}

func mcpcLocal(name string) wire.RegisterMCPClientRequest {
	return wire.RegisterMCPClientRequest{Name: name, Origin: wire.MCPOriginLocal}
}

func mcpcRemote(name, subject, clientID string) wire.RegisterMCPClientRequest {
	return wire.RegisterMCPClientRequest{Name: name, Origin: wire.MCPOriginRemote, Subject: subject, ClientID: clientID}
}

func TestMCPClientsRegister_WaitsForApprovalAndCreatesNothingBefore(t *testing.T) {
	m := newMCPClientsFixture(t)

	res, err := m.svc.Register(context.Background(), m.caller(m.admin), mcpcLocal("claude-code"))

	mustf(t, err, "Register")
	if res.Pending == nil || res.Applied != nil {
		t.Fatalf("result = %+v, want a pending request", res)
	}
	if got := m.clients(); len(got) != 0 {
		t.Errorf("an unapproved registration created %+v", got)
	}
}

func TestMCPClientsRegister_BorderValidation(t *testing.T) {
	m := newMCPClientsFixture(t)
	tests := map[string]wire.RegisterMCPClientRequest{
		"empty name":           mcpcLocal(""),
		"uppercase name":       mcpcLocal("Claude"),
		"unknown origin":       {Name: "x", Origin: "cloud"},
		"local with a subject": {Name: "x", Origin: wire.MCPOriginLocal, Subject: "s"},
		"remote no subject":    mcpcRemote("x", "", "c"),
		"remote no client_id":  mcpcRemote("x", "s", ""),
		"remote control chars": mcpcRemote("x", "s\x07", "c"),
	}
	for name, req := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := m.svc.Register(context.Background(), m.caller(m.admin), req)
			wantError(t, err, smerr.CodeInvalidArgument, "")
		})
	}
}

func TestMCPClientsRegister_RemoteRefusedUnlessRemoteMCPIsEnabled(t *testing.T) {
	f := newFixture(t)
	svc, err := NewMCPClients(f.cfg, f.store, MCPClientsOptions{Tokens: &countingMinter{}})
	mustf(t, err, "NewMCPClients")

	_, err = svc.Register(context.Background(), f.caller(f.admin), mcpcRemote("web", "sub", "cid"))

	wantError(t, err, smerr.CodeInvalidArgument, "")
}

func TestMCPClientsRegister_OperatorMayNot(t *testing.T) {
	m := newMCPClientsFixture(t)

	_, err := m.svc.Register(context.Background(), m.caller(m.alice), mcpcLocal("claude-code"))

	wantError(t, err, smerr.CodePolicyDenied, smerr.ReasonDefaultDeny)
}

func TestMCPClientsRegister_AnMCPActorMayNotEvenWithEveryActionGranted(t *testing.T) {
	m := newMCPClientsFixture(t, func(c *Config) { c.Policy = everythingAllowed(t); c.MCPWritesEnabled = true })
	var agent domain.ID
	m.inTx(func(ctx context.Context, tx *database.Tx) error {
		agent = m.identity(ctx, tx, "agent", domain.ActorMCP, "")
		return nil
	})

	_, err := m.svc.Register(context.Background(), m.caller(agent), mcpcLocal("sneaky"))

	wantError(t, err, smerr.CodePolicyDenied, smerr.ReasonMCPActionForbidden)
}

func TestMCPClientsRegister_ADuplicateLiveNameIsRefused(t *testing.T) {
	m := newMCPClientsFixture(t)
	m.register(mcpcLocal("claude-code"))

	_, err := m.svc.Register(context.Background(), m.caller(m.admin), mcpcLocal("claude-code"))

	wantError(t, err, smerr.CodeConflict, "")
}

func TestMCPClientsRegister_ANameClaimedByAnUnfinishedRegistrationIsRefused(t *testing.T) {
	m := newMCPClientsFixture(t)
	_, err := m.svc.Register(context.Background(), m.caller(m.admin), mcpcLocal("claude-code"))
	mustf(t, err, "first Register")

	_, err = m.svc.Register(context.Background(), m.caller(m.admin), mcpcLocal("claude-code"))

	wantError(t, err, smerr.CodeConflict, smerr.ReasonResourceLocked)
}

func TestMCPClientsRegister_TheCallersOwnKeyedRetryIsAReplayNotAClash(t *testing.T) {
	m := newMCPClientsFixture(t)
	keyed := func() Caller {
		by := m.caller(m.admin)
		by.Idempotency = &Idempotency{
			Key: "register-1", Method: "POST", Path: "/api/v1/mcp-clients", RequestHash: "h",
			Respond: func(any, error) (int, []byte) { return 202, []byte(`{"data":"submitted"}`) },
		}
		return by
	}
	_, err := m.svc.Register(context.Background(), keyed(), mcpcLocal("claude-code"))
	mustf(t, err, "first Register")

	_, err = m.svc.Register(context.Background(), keyed(), mcpcLocal("claude-code"))

	_ = asReplay(t, err)
}

func TestMCPClientsRegister_ARemoteTripleWithALiveClientIsRefused(t *testing.T) {
	m := newMCPClientsFixture(t)
	m.register(mcpcRemote("web-a", "sub-1", "cid-1"))

	res, err := m.svc.Register(context.Background(), m.caller(m.admin), mcpcRemote("web-b", "sub-1", "cid-1"))
	mustf(t, err, "Register")
	m.approveUntilQueued(res.Pending.Job)
	err = m.applyJob(res.Pending.Job.ID)

	wantError(t, err, smerr.CodeConflict, "")
	if got := len(m.clients()); got != 1 {
		t.Errorf("clients = %d, want only the first", got)
	}
}

func TestMCPClientsList_ShowsStatesAndTheOAuthTripleOfRemoteClients(t *testing.T) {
	m := newMCPClientsFixture(t)
	m.register(mcpcLocal("claude-code"))
	m.register(mcpcRemote("web", "sub-1", "cid-1"))

	got, err := m.svc.List(context.Background(), m.caller(m.alice))

	mustf(t, err, "List")
	if len(got) != 2 {
		t.Fatalf("list = %+v, want 2 clients", got)
	}
	local, remote := got[0], got[1]
	if local.State != wire.MCPClientPendingToken || local.Subject != "" || local.ClientID != "" || local.TokenIssuedAt != nil {
		t.Errorf("local = %+v", local)
	}
	if remote.State != wire.MCPClientActive || remote.Subject != "sub-1" || remote.ClientID != "cid-1" {
		t.Errorf("remote = %+v", remote)
	}
}

func TestMCPClientsList_RequiresIdentityRead(t *testing.T) {
	m := newMCPClientsFixture(t)

	_, err := m.svc.List(context.Background(), m.caller(m.dave))

	wantError(t, err, smerr.CodePolicyDenied, smerr.ReasonDefaultDeny)
}

func TestMCPClientsIssueToken_OnlyTheRequesterOnceAndOnlyPending(t *testing.T) {
	m := newMCPClientsFixture(t)
	client := m.register(mcpcLocal("claude-code"))

	_, err := m.issue(m.admin2, client.ID, time.Hour)
	wantError(t, err, smerr.CodePolicyDenied, smerr.ReasonNotPlanActor)

	issued, err := m.issue(m.admin, client.ID, 90*24*time.Hour)
	mustf(t, err, "IssueToken")
	if issued.Token == "" || issued.Client.State != wire.MCPClientActive || issued.Client.TokenExpiresAt == nil {
		t.Fatalf("issued = %+v, want a token and an active client", issued)
	}
	if want := m.clock.Now().Add(90 * 24 * time.Hour); !issued.Client.TokenExpiresAt.Equal(want) {
		t.Errorf("token expires %v, want %v", issued.Client.TokenExpiresAt, want)
	}

	_, err = m.issue(m.admin, client.ID, time.Hour)
	wantError(t, err, smerr.CodeConflict, smerr.ReasonInvalidTransition)
}

func TestMCPClientsIssueToken_NeverStoresOrAuditsThePlaintext(t *testing.T) {
	m := newMCPClientsFixture(t)
	client := m.register(mcpcLocal("claude-code"))

	issued, err := m.issue(m.admin, client.ID, time.Hour)
	mustf(t, err, "IssueToken")

	if _, err := database.GetMCPClientByTokenHash(context.Background(), m.db.Reader(), issued.Token); err == nil {
		t.Error("the plaintext token is stored as the hash")
	}
	if _, err := database.GetMCPClientByTokenHash(context.Background(), m.db.Reader(), "hash-"+issued.Token); err != nil {
		t.Errorf("the token hash is not stored: %v", err)
	}
	for _, e := range m.events(eventMCPClientIssuance) {
		if len(e.Data) == 0 {
			t.Error("the issuance is not described in the audit event")
		}
		for key, value := range e.Data {
			if s, ok := value.(string); ok && s == issued.Token {
				t.Errorf("audit data %q carries the token", key)
			}
		}
	}
}

func TestMCPClientsIssueToken_ConcurrentRequestsIssueOneToken(t *testing.T) {
	m := newMCPClientsFixture(t)
	client := m.register(mcpcLocal("claude-code"))

	const racers = 8
	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		tokens []string
		errs   []error
	)
	for range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			issued, err := m.issue(m.admin, client.ID, time.Hour)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			tokens = append(tokens, issued.Token)
		}()
	}
	wg.Wait()

	if len(tokens) != 1 || len(errs) != racers-1 {
		t.Fatalf("issued %d tokens with %d refusals, want 1 and %d", len(tokens), len(errs), racers-1)
	}
	for _, err := range errs {
		wantError(t, err, smerr.CodeConflict, smerr.ReasonInvalidTransition)
	}
}

func TestMCPClientsIssueToken_ClosesAfterTwentyFourHoursFromApproval(t *testing.T) {
	m := newMCPClientsFixture(t)
	client := m.register(mcpcLocal("claude-code"))

	m.clock.Set(client.ApprovedAt.Add(mcpIssuanceWindow - time.Second))
	if _, err := m.issue(m.admin, client.ID, time.Hour); err != nil {
		t.Fatalf("one second before the window closes: %v", err)
	}
	late := m.register(mcpcLocal("claude-desktop"))
	m.clock.Set(late.ApprovedAt.Add(mcpIssuanceWindow))

	_, err := m.issue(m.admin, late.ID, time.Hour)

	wantError(t, err, smerr.CodeConflict, smerr.ReasonIssuanceWindowExpired)
	if got := m.clientNamed("claude-desktop"); got.State != database.MCPClientPendingToken {
		t.Errorf("a late issuance changed the client: %+v", got)
	}
}

func TestMCPClientsIssueToken_ExpiryIsMandatoryAndAtMostAYear(t *testing.T) {
	m := newMCPClientsFixture(t)
	client := m.register(mcpcLocal("claude-code"))
	tests := map[string]time.Time{
		"missing":  {},
		"past":     m.clock.Now().Add(-time.Minute),
		"too long": m.clock.Now().Add(database.MCPTokenMaxLifetime + time.Hour),
	}
	for name, expiresAt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := m.svc.IssueToken(context.Background(), m.caller(m.admin), client.ID, wire.IssueMCPTokenRequest{ExpiresAt: expiresAt})
			wantError(t, err, smerr.CodeInvalidArgument, "")
		})
	}
	if got := m.clientNamed("claude-code"); got.State != database.MCPClientPendingToken {
		t.Errorf("a refused request changed the client: %+v", got)
	}
}

func TestMCPClientsIssueToken_RefusesAnIdempotencyKey(t *testing.T) {
	m := newMCPClientsFixture(t)
	client := m.register(mcpcLocal("claude-code"))
	by := m.caller(m.admin)
	by.Idempotency = &Idempotency{}

	_, err := m.svc.IssueToken(context.Background(), by, client.ID, wire.IssueMCPTokenRequest{ExpiresAt: m.clock.Now().Add(time.Hour)})

	wantError(t, err, smerr.CodeInvalidArgument, "")
}

func TestMCPClientsIssueToken_UnknownClient(t *testing.T) {
	m := newMCPClientsFixture(t)

	_, err := m.issue(m.admin, "no-such-client", time.Hour)

	wantError(t, err, smerr.CodeNotFound, "")
}

func TestMCPClientsDelete_AnMCPActorMayNotEvenWithEveryActionGranted(t *testing.T) {
	m := newMCPClientsFixture(t, func(c *Config) { c.Policy = everythingAllowed(t); c.MCPWritesEnabled = true })
	client := m.register(mcpcLocal("claude-code"))
	var agent domain.ID
	m.inTx(func(ctx context.Context, tx *database.Tx) error {
		agent = m.identity(ctx, tx, "agent", domain.ActorMCP, "")
		return nil
	})

	_, err := m.svc.Delete(context.Background(), m.caller(agent), client.ID)

	wantError(t, err, smerr.CodePolicyDenied, smerr.ReasonMCPActionForbidden)
	if got := m.clientNamed("claude-code"); got.ID != client.ID {
		t.Errorf("client = %+v", got)
	}
}
