package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
)

// Identity is a principal known to SuperMgmt (spec §11.1).
type Identity struct {
	ID          domain.ID
	ActorType   domain.ActorType
	Issuer      string
	Subject     string
	ClientID    string
	DisplayName string
	Email       string
	CreatedAt   time.Time
	LastSeenAt  *time.Time
	DisabledAt  *time.Time
}

// Role is a named bundle of policy permissions.
type Role struct {
	ID          domain.ID
	Name        string
	Description string
}

// RoleBinding grants a role to an identity.
type RoleBinding struct {
	ID         domain.ID
	IdentityID domain.ID
	RoleID     domain.ID
	CreatedAt  time.Time
}

// CreateIdentity stores i; the (actor type, issuer, subject, client id) tuple is unique.
func CreateIdentity(ctx context.Context, q Querier, i Identity) error {
	_, err := q.ExecContext(ctx, `
		INSERT INTO identities (id, actor_type, issuer, subject, client_id, display_name, email,
		                        created_at, last_seen_at, disabled_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		i.ID, i.ActorType, i.Issuer, i.Subject, i.ClientID, i.DisplayName, i.Email,
		millis(i.CreatedAt), nullMillis(i.LastSeenAt), nullMillis(i.DisabledAt))
	if err != nil {
		return conflictIfDuplicate(err, "identity")
	}
	return nil
}

// GetIdentity returns the identity or NOT_FOUND.
func GetIdentity(ctx context.Context, q Querier, id domain.ID) (Identity, error) {
	var (
		i                  Identity
		created            int64
		lastSeen, disabled sql.NullInt64
	)
	err := q.QueryRowContext(ctx, `
		SELECT id, actor_type, issuer, subject, client_id, display_name, email,
		       created_at, last_seen_at, disabled_at
		FROM identities WHERE id = ?`, id).
		Scan(&i.ID, &i.ActorType, &i.Issuer, &i.Subject, &i.ClientID, &i.DisplayName, &i.Email,
			&created, &lastSeen, &disabled)
	if errors.Is(err, sql.ErrNoRows) {
		return Identity{}, notFound("identity")
	}
	if err != nil {
		return Identity{}, fmt.Errorf("get identity: %w", err)
	}
	i.CreatedAt = domain.FromUnixMillis(created)
	i.LastSeenAt, i.DisabledAt = timeOf(lastSeen), timeOf(disabled)
	return i, nil
}

// ListIdentities returns every identity, oldest first.
func ListIdentities(ctx context.Context, q Querier) ([]Identity, error) {
	return list(ctx, q, "identities", `
		SELECT id, actor_type, issuer, subject, client_id, display_name, email, created_at, last_seen_at, disabled_at
		FROM identities ORDER BY created_at, id`, func(s scanner) (Identity, error) {
		var (
			i                  Identity
			created            int64
			lastSeen, disabled sql.NullInt64
		)
		err := s.Scan(&i.ID, &i.ActorType, &i.Issuer, &i.Subject, &i.ClientID, &i.DisplayName, &i.Email,
			&created, &lastSeen, &disabled)
		i.CreatedAt = domain.FromUnixMillis(created)
		i.LastSeenAt, i.DisabledAt = timeOf(lastSeen), timeOf(disabled)
		return i, err
	})
}

// SetIdentityDisabled disables the identity at at, or enables it with nil. It
// reports NOT_FOUND for an unknown id.
func SetIdentityDisabled(ctx context.Context, q Querier, id domain.ID, at *time.Time) error {
	return updateOne(ctx, q, "identity", `UPDATE identities SET disabled_at = ? WHERE id = ?`, nullMillis(at), id)
}

// RoleNamesByIdentity returns the names of the roles bound to each identity, ordered by name.
func RoleNamesByIdentity(ctx context.Context, q Querier) (map[domain.ID][]string, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT b.identity_id, r.name FROM role_bindings b JOIN roles r ON r.id = b.role_id ORDER BY r.name`)
	if err != nil {
		return nil, fmt.Errorf("list role names: %w", err)
	}
	defer rows.Close()
	out := map[domain.ID][]string{}
	for rows.Next() {
		var id domain.ID
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, fmt.Errorf("scan role name: %w", err)
		}
		out[id] = append(out[id], name)
	}
	return out, rows.Err()
}

// CountEnabledAdmins counts the enabled identities bound to the role named admin.
func CountEnabledAdmins(ctx context.Context, q Querier, adminRole string) (int, error) {
	var n int
	err := q.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT i.id) FROM identities i
		JOIN role_bindings b ON b.identity_id = i.id JOIN roles r ON r.id = b.role_id
		WHERE r.name = ? AND i.disabled_at IS NULL`, adminRole).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count enabled admins: %w", err)
	}
	return n, nil
}

// CreateRole stores r; role names are unique.
func CreateRole(ctx context.Context, q Querier, r Role) error {
	_, err := q.ExecContext(ctx, `INSERT INTO roles (id, name, description) VALUES (?, ?, ?)`,
		r.ID, r.Name, r.Description)
	if err != nil {
		return conflictIfDuplicate(err, "role")
	}
	return nil
}

// GetRoleByName returns the named role or NOT_FOUND.
func GetRoleByName(ctx context.Context, q Querier, name string) (Role, error) {
	var r Role
	err := q.QueryRowContext(ctx, `SELECT id, name, description FROM roles WHERE name = ?`, name).
		Scan(&r.ID, &r.Name, &r.Description)
	if errors.Is(err, sql.ErrNoRows) {
		return Role{}, notFound("role")
	}
	if err != nil {
		return Role{}, fmt.Errorf("get role: %w", err)
	}
	return r, nil
}

// CreateRoleBinding grants a role to an identity; granting twice is a CONFLICT.
func CreateRoleBinding(ctx context.Context, q Querier, b RoleBinding) error {
	_, err := q.ExecContext(ctx,
		`INSERT INTO role_bindings (id, identity_id, role_id, created_at) VALUES (?, ?, ?, ?)`,
		b.ID, b.IdentityID, b.RoleID, millis(b.CreatedAt))
	if err != nil {
		return conflictIfDuplicate(err, "role binding")
	}
	return nil
}

// ListRolesForIdentity returns the roles bound to the identity, ordered by name.
func ListRolesForIdentity(ctx context.Context, q Querier, identityID domain.ID) ([]Role, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT r.id, r.name, r.description
		FROM role_bindings b JOIN roles r ON r.id = b.role_id
		WHERE b.identity_id = ? ORDER BY r.name`, identityID)
	if err != nil {
		return nil, fmt.Errorf("list roles for identity: %w", err)
	}
	defer rows.Close()
	var roles []Role
	for rows.Next() {
		var r Role
		if err := rows.Scan(&r.ID, &r.Name, &r.Description); err != nil {
			return nil, fmt.Errorf("scan role: %w", err)
		}
		roles = append(roles, r)
	}
	return roles, rows.Err()
}

// ListLiveMCPClientIDsRequestedBy returns the ids of the clients the identity
// requested that are not deleted. Their token is revealed to the requester only.
func ListLiveMCPClientIDsRequestedBy(ctx context.Context, q Querier, identity domain.ID) ([]domain.ID, error) {
	return list(ctx, q, "mcp clients", `SELECT id FROM mcp_clients WHERE requested_by = ? AND state <> 'deleted' ORDER BY created_at, id`,
		func(row scanner) (domain.ID, error) {
			var id domain.ID
			err := row.Scan(&id)
			return id, err
		}, identity)
}

// InvalidateJoinTokensCreatedBy invalidates the join tokens the identity
// created that are neither consumed nor invalidated, and returns how many.
func InvalidateJoinTokensCreatedBy(ctx context.Context, q Querier, identity domain.ID, at time.Time) (int64, error) {
	return affected(ctx, q, "join_tokens", `UPDATE join_tokens SET invalidated_at = ?
		WHERE created_by = ? AND consumed_at IS NULL AND invalidated_at IS NULL`, millis(at), identity)
}
