package app

import (
	"context"
	"slices"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/policy"
)

const (
	actionIdentityWrite   = "identity.write"
	eventIdentityDisabled = "identity.disabled"
	eventIdentityEnabled  = "identity.enabled"
	messageMCPIdentity    = "an MCP identity is managed with sm mcp clients; remove the client to disable it"
	messageSystemIdentity = "the system identity cannot be disabled or enabled"
	messageLastAdmin      = "this is the last enabled admin; make another admin first (sm admin bootstrap-code --recover, or sm admin grant)"
)

// authorizeIdentityAdmin allows only an enabled admin that policy also lets do
// identity.write on target. Holding the action through a custom rule is not
// enough: this surface reads and revokes other people's credentials.
func (c core) authorizeIdentityAdmin(actor domain.Actor, target domain.ResourceRef) policy.Result {
	res := c.authorize(policy.Request{Actor: actor, Action: actionIdentityWrite, Targets: []policy.Target{{Ref: target}}})
	if res.Decision == policy.DecisionAllow && !slices.Contains(actor.Roles, adminRoleName) {
		return policy.Result{Decision: policy.DecisionDeny, Reason: smerr.ReasonDefaultDeny}
	}
	return res
}

// requireIdentityAdminRead is authorizeIdentityAdmin for a read on the reader
// connection, which cannot audit a refusal.
func (c core) requireIdentityAdminRead(actor domain.Actor, target domain.ResourceRef) error {
	return decisionError(c.authorizeIdentityAdmin(actor, target))
}

// requireIdentityAdmin audits a refusal in tx and rejects it.
func (c core) requireIdentityAdmin(ctx context.Context, tx *database.Tx, actor domain.Actor, target domain.ResourceRef) error {
	res := c.authorizeIdentityAdmin(actor, target)
	if err := c.auditDecision(ctx, tx, actor, actionIdentityWrite, target, res); err != nil {
		return err
	}
	if err := decisionError(res); err != nil {
		return reject(err)
	}
	return nil
}

func identityTarget(id domain.ID) domain.ResourceRef {
	return domain.ResourceRef{Type: domain.ResourceIdentity, ID: id}
}

// ListIdentities lists every identity, disabled ones included. Admin only.
func (a *AuthService) ListIdentities(ctx context.Context, by Caller, page wire.PageQuery) (wire.Page[wire.Identity], error) {
	q := a.cfg.DB.Reader()
	actor, err := a.beginRequest(ctx, q, by)
	if err != nil {
		return wire.Page[wire.Identity]{}, err
	}
	if err := a.requireIdentityAdminRead(actor, domain.ResourceRef{Type: domain.ResourceIdentity}); err != nil {
		return wire.Page[wire.Identity]{}, err
	}
	rows, err := database.ListIdentities(ctx, q)
	if err != nil {
		return wire.Page[wire.Identity]{}, err
	}
	roles, err := database.RoleNamesByIdentity(ctx, q)
	if err != nil {
		return wire.Page[wire.Identity]{}, err
	}
	paged, err := paginate(rows, page, func(i database.Identity) domain.ID { return i.ID })
	if err != nil {
		return wire.Page[wire.Identity]{}, err
	}
	out := wire.Page[wire.Identity]{Items: make([]wire.Identity, len(paged.items)), NextCursor: paged.next}
	for i, row := range paged.items {
		out.Items[i] = identityView(row, roles[row.ID])
	}
	return out, nil
}

// ListIdentityTokens lists the API tokens of another identity, revoked ones
// included. Admin only.
func (a *AuthService) ListIdentityTokens(ctx context.Context, by Caller, identity domain.ID) ([]wire.Token, error) {
	q := a.cfg.DB.Reader()
	actor, err := a.beginRequest(ctx, q, by)
	if err != nil {
		return nil, err
	}
	if err := a.requireIdentityAdminRead(actor, identityTarget(identity)); err != nil {
		return nil, err
	}
	if _, err := database.GetIdentity(ctx, q, identity); err != nil {
		return nil, err
	}
	rows, err := database.ListAPITokens(ctx, q, identity)
	if err != nil {
		return nil, err
	}
	out := make([]wire.Token, len(rows))
	for i, row := range rows {
		out[i] = tokenView(row)
	}
	return out, nil
}

// DisableIdentity disables an identity: it revokes every credential it holds,
// removes its role bindings and audits identity.disabled, in one transaction.
// It also retires the MCP clients the identity requested, whose token only it
// holds, and invalidates the join tokens it created and nobody used yet.
// A job it already runs finishes; one it queued fails at claim, because the
// identity is disabled and its credential revoked. Disabling a disabled
// identity succeeds and audits once.
// It refuses the system identity, an MCP identity and the last enabled admin.
func (a *AuthService) DisableIdentity(ctx context.Context, by Caller, id domain.ID) (wire.Identity, error) {
	return commit(ctx, a.core, by, func(ctx context.Context, tx *database.Tx) (wire.Identity, error) {
		actor, err := a.beginRequest(ctx, tx, by)
		if err != nil {
			return wire.Identity{}, err
		}
		if err := a.requireIdentityAdmin(ctx, tx, actor, identityTarget(id)); err != nil {
			return wire.Identity{}, err
		}
		target, err := manageableIdentity(ctx, tx, id)
		if err != nil {
			return wire.Identity{}, err
		}
		roles, err := database.ListRolesForIdentity(ctx, tx, id)
		if err != nil {
			return wire.Identity{}, err
		}
		if target.DisabledAt != nil {
			return identityView(target, roleNames(roles)), nil
		}
		if err := keepOneAdmin(ctx, tx, roles); err != nil {
			return wire.Identity{}, err
		}
		now := a.cfg.Clock.Now()
		if err := database.SetIdentityDisabled(ctx, tx, id, &now); err != nil {
			return wire.Identity{}, err
		}
		revoked, err := database.RevokeIdentityCredentials(ctx, tx, id, now)
		if err != nil {
			return wire.Identity{}, err
		}
		if err := clearRoleBindings(ctx, tx, id); err != nil {
			return wire.Identity{}, err
		}
		retired, err := a.retireRequestedMCPClients(ctx, tx, actor, id)
		if err != nil {
			return wire.Identity{}, err
		}
		joins, err := database.InvalidateJoinTokensCreatedBy(ctx, tx, id, now)
		if err != nil {
			return wire.Identity{}, err
		}
		target.DisabledAt = &now
		err = a.emit(ctx, tx, actor, eventIdentityDisabled, identityTarget(id), domain.ResultSucceeded,
			map[string]any{"revoked": revoked, "roles_removed": roleNames(roles), "mcp_clients_retired": retired, "join_tokens_invalidated": joins, "self": id == by.ID})
		return identityView(target, nil), err
	})
}

// EnableIdentity enables a disabled identity. It restores neither its roles
// nor its credentials: the roles are granted again (sm admin grant) and the
// credentials are made again. Enabling an enabled identity succeeds and audits once.
func (a *AuthService) EnableIdentity(ctx context.Context, by Caller, id domain.ID) (wire.Identity, error) {
	return commit(ctx, a.core, by, func(ctx context.Context, tx *database.Tx) (wire.Identity, error) {
		actor, err := a.beginRequest(ctx, tx, by)
		if err != nil {
			return wire.Identity{}, err
		}
		if err := a.requireIdentityAdmin(ctx, tx, actor, identityTarget(id)); err != nil {
			return wire.Identity{}, err
		}
		target, err := manageableIdentity(ctx, tx, id)
		if err != nil {
			return wire.Identity{}, err
		}
		roles, err := database.ListRolesForIdentity(ctx, tx, id)
		if err != nil {
			return wire.Identity{}, err
		}
		if target.DisabledAt == nil {
			return identityView(target, roleNames(roles)), nil
		}
		if err := database.SetIdentityDisabled(ctx, tx, id, nil); err != nil {
			return wire.Identity{}, err
		}
		target.DisabledAt = nil
		err = a.emit(ctx, tx, actor, eventIdentityEnabled, identityTarget(id), domain.ResultSucceeded, nil)
		return identityView(target, roleNames(roles)), err
	})
}

// retireRequestedMCPClients deletes every live MCP client the identity
// requested, as sm mcp clients remove does, and returns how many.
func (a *AuthService) retireRequestedMCPClients(ctx context.Context, tx *database.Tx, actor domain.Actor, id domain.ID) (int, error) {
	clients, err := database.ListLiveMCPClientIDsRequestedBy(ctx, tx, id)
	if err != nil {
		return 0, err
	}
	for _, client := range clients {
		if _, err := a.applyMCPClientDelete(ctx, tx, actor, mcpDeleteParams{ClientID: client}); err != nil {
			return 0, err
		}
	}
	return len(clients), nil
}

// manageableIdentity loads the identity and refuses the ones that are not
// managed here: the system identity and the MCP identities.
func manageableIdentity(ctx context.Context, q database.Querier, id domain.ID) (database.Identity, error) {
	target, err := database.GetIdentity(ctx, q, id)
	if err != nil {
		return database.Identity{}, err
	}
	switch target.ActorType {
	case domain.ActorSystem:
		return database.Identity{}, smerr.New(smerr.CodeInvalidArgument, "", messageSystemIdentity)
	case domain.ActorMCP:
		return database.Identity{}, smerr.New(smerr.CodeInvalidArgument, "", messageMCPIdentity)
	case domain.ActorHuman, domain.ActorAutomation:
	}
	return target, nil
}

// keepOneAdmin refuses when roles include admin and no other enabled admin
// would be left. The count is taken in the same write transaction as the change.
func keepOneAdmin(ctx context.Context, q database.Querier, roles []database.Role) error {
	if !slices.Contains(roleNames(roles), adminRoleName) {
		return nil
	}
	admins, err := database.CountEnabledAdmins(ctx, q, adminRoleName)
	if err != nil {
		return err
	}
	if admins <= 1 {
		return smerr.New(smerr.CodeConflict, "", messageLastAdmin)
	}
	return nil
}

func roleNames(roles []database.Role) []string {
	names := make([]string, len(roles))
	for i, r := range roles {
		names[i] = r.Name
	}
	return names
}

func identityView(i database.Identity, roles []string) wire.Identity {
	if roles == nil {
		roles = []string{}
	}
	return wire.Identity{
		ID: i.ID, ActorType: i.ActorType, DisplayName: i.DisplayName, Email: i.Email, Roles: roles,
		CreatedAt: i.CreatedAt, LastSeenAt: i.LastSeenAt, DisabledAt: i.DisabledAt,
	}
}
