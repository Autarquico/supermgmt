package api

import (
	"context"
	"errors"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/policy"
)

const actionConfigRead = "config.read"

// SSHKeys answers GET /ssh-key (action config.read, ADR-0016): the public half
// of the instance identity, so users can authorize it on nodes.
type SSHKeys struct {
	cfg      app.Config
	identity app.SSHIdentity
}

// NewSSHKeys requires the application config (database, policy, credentials)
// and the source of the instance identity.
func NewSSHKeys(cfg app.Config, identity app.SSHIdentity) (*SSHKeys, error) {
	switch {
	case cfg.DB == nil, cfg.Policy == nil, cfg.Credentials == nil:
		return nil, errors.New("api: ssh key reader needs the database, policy and credential store")
	case identity == nil:
		return nil, errors.New("api: ssh key reader needs the instance identity")
	}
	return &SSHKeys{cfg: cfg, identity: identity}, nil
}

// Get returns the public key to a caller that policy lets read the configuration.
func (k *SSHKeys) Get(ctx context.Context, by app.Caller) (wire.SSHKey, error) {
	if err := k.authorize(ctx, by); err != nil {
		return wire.SSHKey{}, err
	}
	id, err := k.identity(ctx)
	if err != nil {
		return wire.SSHKey{}, err
	}
	return wire.SSHKey{
		Ref: "secret://" + id.Ref.Name, Version: id.Ref.Version,
		AuthorizedKey: id.AuthorizedKey, FingerprintSHA256: id.FingerprintSHA256,
	}, nil
}

func (k *SSHKeys) authorize(ctx context.Context, by app.Caller) error {
	state, err := k.cfg.Credentials.Status(ctx, by.Credential)
	if err != nil {
		return err
	}
	if state != app.CredentialActive {
		return smerr.New(smerr.CodeUnauthenticated, "", "the credential is not active")
	}
	reader := k.cfg.DB.Reader()
	identity, err := database.GetIdentity(ctx, reader, by.ID)
	if err != nil {
		return err
	}
	if identity.DisabledAt != nil {
		return smerr.New(smerr.CodePolicyDenied, smerr.ReasonDefaultDeny, "identity is disabled")
	}
	roles, err := database.ListRolesForIdentity(ctx, reader, by.ID)
	if err != nil {
		return err
	}
	actor := domain.Actor{ID: by.ID, Type: identity.ActorType, Credential: by.Credential}
	for _, role := range roles {
		actor.Roles = append(actor.Roles, role.Name)
	}
	res := k.cfg.Policy.Evaluate(policy.Request{
		Actor: actor, Action: actionConfigRead,
		Targets: []policy.Target{{Ref: domain.ResourceRef{Type: domain.ResourceInstance}}},
	})
	if res.Decision == policy.DecisionAllow {
		return nil
	}
	reason := res.Reason
	if reason == "" {
		reason = smerr.ReasonDefaultDeny
	}
	return smerr.FromReason(reason, "action denied by policy")
}
