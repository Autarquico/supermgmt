package client

import (
	"context"
	"net/http"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

// ---- login and sessions (spec §23.1, ADR-0018) -------------------------------
//
// None of these routes accepts an Idempotency-Key: they issue credentials
// once and are never replayed.

func (c *Client) OIDCStart(ctx context.Context, r wire.OIDCStartRequest) (wire.OIDCStart, error) {
	return call[wire.OIDCStart](ctx, c, postUnkeyed(wire.PathOIDCStart, r))
}

func (c *Client) OIDCExchange(ctx context.Context, r wire.OIDCExchangeRequest) (wire.LoginSession, error) {
	return call[wire.LoginSession](ctx, c, postUnkeyed(wire.PathOIDCExchange, r))
}

func (c *Client) DeviceStart(ctx context.Context) (wire.DeviceStart, error) {
	return call[wire.DeviceStart](ctx, c, postUnkeyed(wire.PathOIDCDevice, nil))
}

func (c *Client) DevicePoll(ctx context.Context, r wire.DevicePollRequest) (wire.DevicePoll, error) {
	return call[wire.DevicePoll](ctx, c, postUnkeyed(wire.PathOIDCDevicePoll, r))
}

// Bootstrap exchanges a one-time bootstrap code (spec §11.5).
func (c *Client) Bootstrap(ctx context.Context, r wire.BootstrapRequest) (wire.Bootstrapped, error) {
	return call[wire.Bootstrapped](ctx, c, postUnkeyed(wire.PathBootstrap, r))
}

// Logout revokes the session this client is signed in with.
func (c *Client) Logout(ctx context.Context) error {
	_, err := call[struct{}](ctx, c, postUnkeyed(wire.PathLogout, nil))
	return err
}

// ---- API tokens (spec §23) ----------------------------------------------------

func (c *Client) ListTokens(ctx context.Context) (wire.Page[wire.Token], error) {
	return call[wire.Page[wire.Token]](ctx, c, get(wire.PathTokens, nil))
}

// CreateToken issues an API token. The response carries its value once.
func (c *Client) CreateToken(ctx context.Context, r wire.CreateTokenRequest) (wire.TokenIssued, error) {
	return call[wire.TokenIssued](ctx, c, postUnkeyed(wire.PathTokens, r))
}

func (c *Client) RevokeToken(ctx context.Context, id domain.ID) error {
	req := request{method: http.MethodDelete, path: wire.Path(wire.PathToken, string(id)), unkeyed: true}
	_, err := call[struct{}](ctx, c, req)
	return err
}

// ---- keys and secrets (spec §10, ADR-0021) -------------------------------------

func (c *Client) ImportSecret(ctx context.Context, r wire.ImportSecretRequest) (wire.Direct[wire.SecretVersion], error) {
	return call[wire.Direct[wire.SecretVersion]](ctx, c, post(wire.PathSecrets, r))
}

func (c *Client) RotateMasterKey(ctx context.Context) (wire.Direct[wire.MasterKeyRotated], error) {
	return call[wire.Direct[wire.MasterKeyRotated]](ctx, c, post(wire.PathMasterKeyRotate, nil))
}

func (c *Client) RetireMasterKey(ctx context.Context, r wire.RetireKeyRequest) (wire.Direct[struct{}], error) {
	return call[wire.Direct[struct{}]](ctx, c, post(wire.PathMasterKeyRetire, r))
}

func (c *Client) RotateSSHKey(ctx context.Context) (wire.Direct[wire.SSHKey], error) {
	return call[wire.Direct[wire.SSHKey]](ctx, c, post(wire.PathSSHKeyRotate, nil))
}

// ExportMasterKey is the local-socket export (ADR-0021). Without a
// passphrase it only requests the export and answers Pending; with one it
// executes an approved request and answers Applied with the SMKEY1 file. The
// route never goes through the idempotency store.
func (c *Client) ExportMasterKey(ctx context.Context, r wire.ExportKeyRequest) (wire.Direct[wire.ExportedKey], error) {
	return call[wire.Direct[wire.ExportedKey]](ctx, c, postUnkeyed(wire.PathMasterKeyExport, r))
}

// ---- backups (spec §29.1) -------------------------------------------------------

func (c *Client) ListBackups(ctx context.Context) (wire.Page[wire.Backup], error) {
	return call[wire.Page[wire.Backup]](ctx, c, get(wire.PathBackups, nil))
}

func (c *Client) CreateBackup(ctx context.Context) (wire.Submission, error) {
	return call[wire.Submission](ctx, c, post(wire.PathBackups, nil))
}
