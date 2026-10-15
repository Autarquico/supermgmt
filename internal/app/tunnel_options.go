package app

import (
	"context"
	"strings"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/config"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare"
	"github.com/autarquico/supermgmt/internal/secrets"
	"github.com/autarquico/supermgmt/internal/transport/ssh"
)

// CloudflareAPI is the part of the Cloudflare client the tunnel jobs use.
// *cloudflare.Client implements it; tests substitute decorators over it.
type CloudflareAPI interface {
	ZoneByName(ctx context.Context, name string) (cloudflare.Zone, error)

	CreateTunnel(ctx context.Context, name string) (cloudflare.Tunnel, error)
	FindTunnels(ctx context.Context, name string) ([]cloudflare.Tunnel, error)
	GetTunnel(ctx context.Context, id string) (cloudflare.Tunnel, error)
	PutTunnelIngress(ctx context.Context, id string, ingress []cloudflare.IngressRule) (cloudflare.TunnelConfig, error)
	GetTunnelConfig(ctx context.Context, id string) (cloudflare.TunnelConfig, error)
	TunnelToken(ctx context.Context, id string) (audit.Secret, error)

	CreateAccessPolicy(ctx context.Context, spec cloudflare.PolicySpec) (cloudflare.AccessPolicy, error)
	UpdateAccessPolicy(ctx context.Context, id string, spec cloudflare.PolicySpec) (cloudflare.AccessPolicy, error)
	FindAccessPolicies(ctx context.Context, name string) ([]cloudflare.AccessPolicy, error)
	CreateAccessApp(ctx context.Context, spec cloudflare.AppSpec) (cloudflare.AccessApp, error)
	FindAccessApps(ctx context.Context, name string) ([]cloudflare.AccessApp, error)

	CreateTunnelCNAME(ctx context.Context, zoneID, hostname, tunnelID, comment string) (cloudflare.DNSRecord, error)
	FindDNSRecords(ctx context.Context, zoneID, hostname string) ([]cloudflare.DNSRecord, error)

	CreateServiceToken(ctx context.Context, name string) (cloudflare.NewServiceToken, error)
	FindServiceTokens(ctx context.Context, name string) ([]cloudflare.ServiceToken, error)
	DeleteServiceToken(ctx context.Context, id string) error
}

var _ CloudflareAPI = (*cloudflare.Client)(nil)

// TunnelSecrets is the secret store as the tunnel jobs use it.
// *secrets.Store implements it.
type TunnelSecrets interface {
	Get(ctx context.Context, ref secrets.Ref) (audit.Secret, error)
	Put(ctx context.Context, name string, plaintext audit.Secret, meta map[string]any) (secrets.Ref, error)
}

// TunnelOptions enable the tunnel jobs. Without them (no cloudflare: block)
// node.setup refuses tunnel=true and nothing else changes.
type TunnelOptions struct {
	Config  config.Cloudflare
	Secrets TunnelSecrets
	// NewAPI builds the provisioning client from the API token at job time;
	// nil builds the production client.
	NewAPI func(accountID string, token audit.Secret) (CloudflareAPI, error)
}

func (o TunnelOptions) api(token audit.Secret) (CloudflareAPI, error) {
	if o.NewAPI != nil {
		return o.NewAPI(o.Config.AccountID, token)
	}
	return cloudflare.New("", o.Config.AccountID, token)
}

// secretName turns a secret:// reference into the store name.
func secretName(ref string) (string, error) {
	name, ok := strings.CutPrefix(ref, "secret://")
	if !ok || name == "" {
		return "", smerr.New(smerr.CodeInvalidArgument, "", "cloudflare credential references must be secret:// references")
	}
	return name, nil
}

// AccessTokens is the dialler's view of the runtime service token: it reads
// the packed client_id:client_secret at dial time, so a rotated token is used
// by the next connection without a restart. ref is access_token_ref.
func AccessTokens(store TunnelSecrets, ref string) ssh.AccessTokenSource {
	return accessTokens{store: store, ref: ref}
}

type accessTokens struct {
	store TunnelSecrets
	ref   string
}

func (a accessTokens) AccessToken(ctx context.Context) (ssh.AccessToken, error) {
	name, err := secretName(a.ref)
	if err != nil {
		return ssh.AccessToken{}, err
	}
	stored, err := a.store.Get(ctx, secrets.Ref{Name: name})
	if err != nil {
		if smerr.CodeOf(err) == smerr.CodeNotFound {
			return ssh.AccessToken{}, smerr.New(smerr.CodeCapabilityUnavailable, "", "the Cloudflare Access service token is not set up: run a tunnel setup first")
		}
		return ssh.AccessToken{}, err
	}
	return ssh.ParseAccessToken(stored.Reveal())
}
