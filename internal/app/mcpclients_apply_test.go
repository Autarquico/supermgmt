package app

import (
	"context"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/policy"
)

// deleteClient deletes as the first admin and applies the change whether policy
// parked it for approval or not.
func (m *mcpcFixture) deleteClient(id domain.ID) {
	m.t.Helper()
	res, err := m.svc.Delete(context.Background(), m.caller(m.admin), id)
	mustf(m.t, err, "Delete")
	switch {
	case res.Applied != nil:
	case res.Pending != nil:
		m.approveUntilQueued(res.Pending.Job)
		mustf(m.t, m.applyJob(res.Pending.Job.ID), "apply the deletion")
	default:
		m.t.Fatalf("Delete = %+v", res)
	}
}

// bindRole grants the admin role to an identity, as a careless operator could.
func (m *mcpcFixture) bindRole(identity domain.ID) {
	m.t.Helper()
	m.inTx(func(ctx context.Context, tx *database.Tx) error {
		return database.CreateRoleBinding(ctx, tx, database.RoleBinding{
			ID: m.ids.NewID(), IdentityID: identity, RoleID: m.role(ctx, tx, "admin"), CreatedAt: m.clock.Now(),
		})
	})
}

// seeOAuthToken records an access token of a remote client, as the resolver does.
func (m *mcpcFixture) seeOAuthToken(client database.MCPClient, hash string) {
	m.t.Helper()
	m.inTx(func(ctx context.Context, tx *database.Tx) error {
		_, err := database.RecordOAuthAccessToken(ctx, tx, database.OAuthAccessToken{
			ID: m.ids.NewID(), MCPClientID: client.ID, TokenHash: hash, Issuer: mcpcIssuer,
			IssuedAt: m.clock.Now(), ExpiresAt: m.clock.Now().Add(time.Hour), FirstSeenAt: m.clock.Now(),
		})
		return err
	})
}

func (m *mcpcFixture) oauthToken(hash string) database.OAuthAccessToken {
	m.t.Helper()
	token, err := database.GetOAuthAccessTokenByHash(context.Background(), m.db.Reader(), hash)
	mustf(m.t, err, "GetOAuthAccessTokenByHash")
	return token
}

func TestApplyApproved_MCPClientRegistrationGivesAnIdentityWithoutRolesEvenForAnAdminRequester(t *testing.T) {
	m := newMCPClientsFixture(t)

	client := m.register(mcpcLocal("claude-code"))

	identity := m.identityRow(client.IdentityID)
	if identity.ActorType != domain.ActorMCP || identity.Issuer != mcpLocalIssuer || identity.Subject != client.ID.String() || identity.ClientID != "" {
		t.Errorf("identity = %+v, want a local mcp identity named by the client", identity)
	}
	if identity.DisabledAt != nil {
		t.Error("the identity of a new client is disabled")
	}
	if roles := m.rolesOf(client.IdentityID); len(roles) != 0 {
		t.Errorf("roles = %+v, want none although %s is an admin", roles, m.admin)
	}
	if client.State != database.MCPClientPendingToken || client.RequestedBy != m.admin || client.RegistrationJobID == nil {
		t.Errorf("client = %+v", client)
	}
	if len(m.events(eventMCPClientRegistered)) != 1 {
		t.Error("the registration was not audited exactly once")
	}
}

func TestApplyApproved_MCPClientApprovedAtIsTheLastApproval(t *testing.T) {
	m := newMCPClientsFixture(t)
	res, err := m.svc.Register(context.Background(), m.caller(m.admin), mcpcLocal("claude-code"))
	mustf(t, err, "Register")
	job := res.Pending.Job

	job, err = m.approve(m.bob, job)
	mustf(t, err, "first approval")
	m.clock.Advance(5 * time.Minute)
	lastApproval := m.clock.Now()
	if job.State == domain.JobAwaitingApproval {
		_, err = m.approve(m.carol, job)
		mustf(t, err, "second approval")
	} else {
		lastApproval = lastApproval.Add(-5 * time.Minute)
	}
	m.clock.Advance(5 * time.Minute)
	mustf(t, m.applyJob(res.Pending.Job.ID), "apply")

	got := m.clientNamed("claude-code")
	if !got.ApprovedAt.Equal(lastApproval) {
		t.Errorf("approved_at = %v, want the last approval %v (applied at %v)", got.ApprovedAt, lastApproval, m.clock.Now())
	}
}

func TestApplyApproved_MCPClientRegistrationConvergesOnRetry(t *testing.T) {
	m := newMCPClientsFixture(t)
	client := m.register(mcpcLocal("claude-code"))
	params, err := payloadOf[mcpRegisterParams](m.job(*client.RegistrationJobID))
	mustf(t, err, "payload")

	m.inTx(func(ctx context.Context, tx *database.Tx) error {
		got, err := m.inv.applyMCPClientRegister(ctx, tx, domain.Actor{ID: m.admin, Type: domain.ActorHuman}, params, nil)
		if err != nil || got.ID != client.ID {
			t.Errorf("retry = %+v, %v, want the stored client", got, err)
		}
		return err
	})

	if got := len(m.clients()); got != 1 {
		t.Errorf("clients = %d after a retried apply", got)
	}
	if got := len(m.events(eventMCPClientRegistered)); got != 1 {
		t.Errorf("registration events = %d after a retried apply", got)
	}
}

func TestApplyApproved_MCPClientDeleteRevokesEverythingAndKeepsHistory(t *testing.T) {
	m := newMCPClientsFixture(t)
	client := m.register(mcpcRemote("web", "sub-1", "cid-1"))
	m.seeOAuthToken(client, "hash-a")
	m.seeOAuthToken(client, "hash-b")
	m.bindRole(client.IdentityID)

	m.deleteClient(client.ID)

	got, err := database.GetMCPClient(context.Background(), m.db.Reader(), client.ID)
	mustf(t, err, "GetMCPClient")
	if got.State != database.MCPClientDeleted || got.DeletedAt == nil || got.RevokedAt == nil {
		t.Errorf("client = %+v, want a deleted, revoked history row", got)
	}
	for _, hash := range []string{"hash-a", "hash-b"} {
		if m.oauthToken(hash).RevokedAt == nil {
			t.Errorf("access token %s is still valid after the client was deleted", hash)
		}
	}
	if m.identityRow(client.IdentityID).DisabledAt == nil {
		t.Error("the identity of a deleted client is still enabled")
	}
	if roles := m.rolesOf(client.IdentityID); len(roles) != 0 {
		t.Errorf("roles = %+v, want the bindings removed", roles)
	}
	if len(m.events(eventMCPClientDeleted)) != 1 {
		t.Error("the deletion was not audited exactly once")
	}
}

func TestApplyApproved_MCPClientDeleteRevokesTheLocalToken(t *testing.T) {
	m := newMCPClientsFixture(t)
	client := m.register(mcpcLocal("claude-code"))
	issued, err := m.issue(m.admin, client.ID, time.Hour)
	mustf(t, err, "IssueToken")

	m.deleteClient(client.ID)

	got, err := database.GetMCPClientByTokenHash(context.Background(), m.db.Reader(), "hash-"+issued.Token)
	mustf(t, err, "GetMCPClientByTokenHash")
	if got.State != database.MCPClientDeleted || got.RevokedAt == nil {
		t.Errorf("client = %+v, want its token revoked", got)
	}
}

func TestApplyApproved_MCPClientDeleteTwiceChangesNothing(t *testing.T) {
	m := newMCPClientsFixture(t)
	client := m.register(mcpcLocal("claude-code"))
	m.deleteClient(client.ID)

	m.deleteClient(client.ID)

	if got := len(m.events(eventMCPClientDeleted)); got != 1 {
		t.Errorf("deletion events = %d, want 1", got)
	}
}

func TestApplyApproved_MCPClientDeleteUnknownIsNotFound(t *testing.T) {
	m := newMCPClientsFixture(t)

	_, err := m.svc.Delete(context.Background(), m.caller(m.admin), "no-such-client")

	wantError(t, err, smerr.CodeNotFound, "")
}

func TestApplyApproved_MCPClientReRegisteringADeletedRemoteTripleReusesTheIdentityWithoutRoles(t *testing.T) {
	m := newMCPClientsFixture(t)
	old := m.register(mcpcRemote("web", "sub-1", "cid-1"))
	m.seeOAuthToken(old, "hash-old")
	m.deleteClient(old.ID)
	m.bindRole(old.IdentityID) // a role granted to the disabled identity must not survive re-registration

	renewed := m.register(mcpcRemote("web", "sub-1", "cid-1"))

	if renewed.ID == old.ID {
		t.Fatal("re-registration reused the client row")
	}
	if renewed.IdentityID != old.IdentityID {
		t.Errorf("identity = %s, want the one of the deleted client %s", renewed.IdentityID, old.IdentityID)
	}
	if m.identityRow(renewed.IdentityID).DisabledAt != nil {
		t.Error("the re-registered identity is still disabled")
	}
	if roles := m.rolesOf(renewed.IdentityID); len(roles) != 0 {
		t.Errorf("roles = %+v, want none", roles)
	}
	if m.oauthToken("hash-old").RevokedAt == nil {
		t.Error("the access token of the deleted client is valid again")
	}
	if oldRow, err := database.GetMCPClient(context.Background(), m.db.Reader(), old.ID); err != nil || oldRow.State != database.MCPClientDeleted {
		t.Errorf("the deleted client row = %+v, %v, want it kept as history", oldRow, err)
	}
	if renewed.State != database.MCPClientActive {
		t.Errorf("state = %s, want active (remote clients need no token issuance)", renewed.State)
	}
}

func TestApplyApproved_MCPClientRevokedAccessTokenCannotBeAttachedToTheNewClient(t *testing.T) {
	m := newMCPClientsFixture(t)
	old := m.register(mcpcRemote("web", "sub-1", "cid-1"))
	m.seeOAuthToken(old, "hash-old")
	m.deleteClient(old.ID)
	renewed := m.register(mcpcRemote("web", "sub-1", "cid-1"))

	err := m.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		_, err := database.RecordOAuthAccessToken(ctx, tx, database.OAuthAccessToken{
			ID: m.ids.NewID(), MCPClientID: renewed.ID, TokenHash: "hash-old", Issuer: mcpcIssuer,
			IssuedAt: m.clock.Now(), ExpiresAt: m.clock.Now().Add(time.Hour), FirstSeenAt: m.clock.Now(),
		})
		return err
	})

	wantError(t, err, smerr.CodeConflict, "")
}

func TestApplyApproved_MCPClientLocalReRegistrationUnderTheSameNameIsANewIdentity(t *testing.T) {
	m := newMCPClientsFixture(t)
	old := m.register(mcpcLocal("claude-code"))
	m.deleteClient(old.ID)

	renewed := m.register(mcpcLocal("claude-code"))

	if renewed.IdentityID == old.IdentityID || renewed.ID == old.ID {
		t.Errorf("renewed = %+v, old = %+v, want a fresh client and identity", renewed, old)
	}
	if m.identityRow(old.IdentityID).DisabledAt == nil {
		t.Error("the identity of the deleted client was re-enabled")
	}
}

func TestApplyApproved_MCPClientDeleteWaitingForApprovalChangesNothingUntilApplied(t *testing.T) {
	pol, err := policy.Parse([]byte(`version: 1
rules:
  - {name: admin, subjects: ['role:admin'], allow: ['mcp_client.register', 'mcp_client.delete'], require_approval: true, approvals: 1}
  - {name: approvers, subjects: ['role:operator'], allow: ['approval.grant', 'approval.reject']}
`))
	mustf(t, err, "Parse")
	m := newMCPClientsFixture(t, func(c *Config) { c.Policy = pol })
	client := m.register(mcpcLocal("claude-code"))

	res, err := m.svc.Delete(context.Background(), m.caller(m.admin), client.ID)

	mustf(t, err, "Delete")
	if res.Pending == nil {
		t.Fatalf("Delete = %+v, want a request waiting for approval", res)
	}
	if got := m.clientNamed("claude-code"); got.State != database.MCPClientPendingToken {
		t.Fatalf("an unapproved deletion changed the client: %+v", got)
	}
	m.approveUntilQueued(res.Pending.Job)
	mustf(t, m.applyJob(res.Pending.Job.ID), "apply the deletion")
	if got := m.clients(); len(got) != 1 || got[0].State != database.MCPClientDeleted {
		t.Errorf("clients = %+v, want the one client deleted", got)
	}
	if m.identityRow(client.IdentityID).DisabledAt == nil {
		t.Error("the identity of the deleted client is still enabled")
	}
}
