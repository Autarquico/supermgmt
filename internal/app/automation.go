package app

import (
	"context"
	"fmt"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/providers/github"
)

// The automation identity of an app is the principal its GitHub Actions
// deploy workflow authenticates as (spec §11.1, ADR-0028, Q5). It is created
// with no role: an admin grants it deployment rights explicitly.

// automationSubject is the subject of the identity bound to a repository and
// its deploy workflow.
func automationSubject(repositoryID int64, workflow string) string {
	return fmt.Sprintf("repository_id:%d:workflow:%s", repositoryID, workflow)
}

// automationLink names the identity an app links.
type automationLink struct {
	IdentityID domain.ID `json:"identity_id"`
	Subject    string    `json:"subject"`
}

// automationChange is what an app write does to the app's automation
// identity. It is decided when the request is made and carried by the plan, so
// an approved plan changes exactly what the approvers saw.
type automationChange struct {
	Link   *automationLink `json:"link"`
	Unlink bool            `json:"unlink"` // revoke the open OIDC credentials of the identity linked now
}

// planAutomation decides the change that leaves app appID linked to the
// identity of (repositoryID, workflow) when want is set, and unlinked when not.
// current is the identity linked now.
func (c core) planAutomation(ctx context.Context, q database.Querier, appID domain.ID, current *domain.ID, want bool, repositoryID int64, workflow string) (automationChange, error) {
	if !want {
		return automationChange{Unlink: current != nil}, nil
	}
	subject := automationSubject(repositoryID, workflow)
	if current != nil {
		linked, err := database.GetIdentity(ctx, q, *current)
		if err != nil {
			return automationChange{}, err
		}
		if linked.Subject == subject {
			return automationChange{}, nil
		}
	}
	link, err := c.linkFor(ctx, q, appID, subject)
	return automationChange{Link: &link, Unlink: current != nil}, err
}

// linkFor reuses the identity stored for subject, as long as no other app uses
// it, and otherwise names a new one.
func (c core) linkFor(ctx context.Context, q database.Querier, appID domain.ID, subject string) (automationLink, error) {
	id, found, err := automationIdentityOf(ctx, q, subject)
	if err != nil {
		return automationLink{}, err
	}
	if !found {
		return automationLink{IdentityID: c.cfg.IDs.NewID(), Subject: subject}, nil
	}
	taken, err := automationLinkedElsewhere(ctx, q, id, appID)
	if err != nil {
		return automationLink{}, err
	}
	if taken {
		return automationLink{}, smerr.New(smerr.CodeConflict, "", "another app already uses the automation identity of this repository and workflow")
	}
	return automationLink{IdentityID: id, Subject: subject}, nil
}

func automationIdentityOf(ctx context.Context, q database.Querier, subject string) (domain.ID, bool, error) {
	var id domain.ID
	err := q.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(id), '') FROM identities WHERE actor_type = ? AND issuer = ? AND subject = ? AND client_id = ''`,
		domain.ActorAutomation, github.ActionsIssuer, subject).Scan(&id)
	if err != nil {
		return "", false, fmt.Errorf("look up automation identity: %w", err)
	}
	return id, id != "", nil
}

func automationLinkedElsewhere(ctx context.Context, q database.Querier, identityID, appID domain.ID) (bool, error) {
	var taken bool
	err := q.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM apps WHERE automation_identity_id = ? AND id <> ?)`, identityID, appID).Scan(&taken)
	if err != nil {
		return false, fmt.Errorf("look up automation identity use: %w", err)
	}
	return taken, nil
}

// applyAutomation executes change on app (in memory; the caller stores it) and
// returns how many open OIDC credentials it revoked. Unlinking revokes the
// credentials of the identity linked until now, so a token minted before the
// unlink stops working at once (ADR-0028).
func (c core) applyAutomation(ctx context.Context, q database.Querier, app *database.App, change automationChange) (int64, error) {
	var revoked int64
	if change.Unlink && app.AutomationIdentityID != nil {
		n, err := database.RevokeGithubOIDCCredentialsByIdentity(ctx, q, *app.AutomationIdentityID, c.cfg.Clock.Now())
		if err != nil {
			return 0, err
		}
		revoked, app.AutomationIdentityID = n, nil
	}
	if change.Link != nil {
		if err := c.ensureAutomationIdentity(ctx, q, *change.Link); err != nil {
			return 0, err
		}
		id := change.Link.IdentityID
		app.AutomationIdentityID = &id
	}
	return revoked, nil
}

// ensureAutomationIdentity creates the identity when it does not exist yet. An
// identity an admin disabled stays disabled: linking it is refused.
func (c core) ensureAutomationIdentity(ctx context.Context, q database.Querier, link automationLink) error {
	existing, err := database.GetIdentity(ctx, q, link.IdentityID)
	switch {
	case err == nil:
		return requireLinkable(existing, link)
	case !isNotFoundError(err):
		return err
	}
	return database.CreateIdentity(ctx, q, database.Identity{
		ID: link.IdentityID, ActorType: domain.ActorAutomation, Issuer: github.ActionsIssuer, Subject: link.Subject,
		DisplayName: "GitHub Actions " + link.Subject, CreatedAt: c.cfg.Clock.Now(),
	})
}

func requireLinkable(existing database.Identity, link automationLink) error {
	switch {
	case existing.ActorType != domain.ActorAutomation || existing.Issuer != github.ActionsIssuer || existing.Subject != link.Subject:
		return smerr.New(smerr.CodeConflict, "", "the automation identity changed since the request was made")
	case existing.DisabledAt != nil:
		return smerr.New(smerr.CodeInvalidArgument, "", "the automation identity is disabled")
	}
	return nil
}
