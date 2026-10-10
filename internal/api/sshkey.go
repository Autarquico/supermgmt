package api

import (
	"context"
	"errors"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/app"
)

const actionConfigRead = "config.read"

// SSHKeys answers GET /ssh-key (ADR-0016): the public half of the instance
// identity, so users can authorize it on nodes. The route authorizes
// config.read before calling Get.
type SSHKeys struct{ identity app.SSHIdentity }

// NewSSHKeys requires the source of the instance identity.
func NewSSHKeys(identity app.SSHIdentity) (*SSHKeys, error) {
	if identity == nil {
		return nil, errors.New("api: ssh key reader needs the instance identity")
	}
	return &SSHKeys{identity: identity}, nil
}

// Get returns the public key; the private half never leaves the daemon.
func (k *SSHKeys) Get(ctx context.Context) (wire.SSHKey, error) {
	id, err := k.identity(ctx)
	if err != nil {
		return wire.SSHKey{}, err
	}
	return wire.SSHKey{
		Ref: "secret://" + id.Ref.Name, Version: id.Ref.Version,
		AuthorizedKey: id.AuthorizedKey, FingerprintSHA256: id.FingerprintSHA256,
	}, nil
}
