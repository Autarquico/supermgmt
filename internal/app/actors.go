package app

import (
	"context"
	"errors"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
)

// loadActor builds the policy actor for an identity. Type and roles come from
// the database; only the credential is taken from the request.
func loadActor(ctx context.Context, q database.Querier, id domain.ID, cred domain.CredentialContext) (domain.Actor, error) {
	identity, err := database.GetIdentity(ctx, q, id)
	if err != nil {
		return domain.Actor{}, err
	}
	if identity.DisabledAt != nil {
		return domain.Actor{}, smerr.New(smerr.CodePolicyDenied, smerr.ReasonDefaultDeny, "identity is disabled")
	}
	roles, err := database.ListRolesForIdentity(ctx, q, id)
	if err != nil {
		return domain.Actor{}, err
	}
	names := make([]string, len(roles))
	for i, r := range roles {
		names[i] = r.Name
	}
	return domain.Actor{ID: id, Type: identity.ActorType, Roles: names, Credential: cred}, nil
}

// loadCaller is loadActor for the request path: the system actor is the
// daemon itself and never arrives as a request (spec §11.1).
func loadCaller(ctx context.Context, q database.Querier, by Caller) (domain.Actor, error) {
	actor, err := loadActor(ctx, q, by.ID, by.Credential)
	if err != nil {
		return domain.Actor{}, err
	}
	if actor.Type == domain.ActorSystem {
		return domain.Actor{}, smerr.New(smerr.CodePolicyDenied, smerr.ReasonDefaultDeny, "system identity cannot act through requests")
	}
	return actor, nil
}

// credentialOf is the credential context the job was submitted with.
func credentialOf(job jobs.Job) domain.CredentialContext {
	return domain.CredentialContext{Kind: job.CredentialKind, ID: job.CredentialID, Scopes: job.Scopes}
}

// isTyped reports whether err is a SuperMgmt error, as opposed to an
// infrastructure failure that must abort the operation.
func isTyped(err error) bool {
	var typed *smerr.Error
	return errors.As(err, &typed)
}
