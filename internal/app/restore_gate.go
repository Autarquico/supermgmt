package app

import (
	"context"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/database"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare"
)

// holdGatedAPI refuses every Cloudflare mutation while a restore hold is in
// force (ADR-0037 "Restore"). Tunnel jobs are not claimed during a hold and
// their actions are refused at submission; this is the last line, on the
// client itself, so no step added later can mutate Cloudflare from a restored
// instance before `sm admin restore-complete`. The hold is read from the
// database on every mutation and an unreadable value refuses it.
type holdGatedAPI struct {
	CloudflareAPI
	q database.Querier
}

func gateOnRestoreHold(api CloudflareAPI, q database.Querier) CloudflareAPI {
	return holdGatedAPI{CloudflareAPI: api, q: q}
}

func (g holdGatedAPI) open(ctx context.Context) error {
	held, err := database.GetRestoreHold(ctx, g.q)
	if err != nil {
		return smerr.Wrap(err, smerr.CodeConflict, smerr.ReasonRestoreHold, "the restore hold cannot be read; refusing the Cloudflare change")
	}
	if held {
		return smerr.FromReason(smerr.ReasonRestoreHold, holdMessage)
	}
	return nil
}

func (g holdGatedAPI) CreateTunnel(ctx context.Context, name string) (cloudflare.Tunnel, error) {
	if err := g.open(ctx); err != nil {
		return cloudflare.Tunnel{}, err
	}
	return g.CloudflareAPI.CreateTunnel(ctx, name)
}

func (g holdGatedAPI) DeleteTunnel(ctx context.Context, id string) error {
	if err := g.open(ctx); err != nil {
		return err
	}
	return g.CloudflareAPI.DeleteTunnel(ctx, id)
}

func (g holdGatedAPI) CleanupTunnelConnections(ctx context.Context, id string) error {
	if err := g.open(ctx); err != nil {
		return err
	}
	return g.CloudflareAPI.CleanupTunnelConnections(ctx, id)
}

func (g holdGatedAPI) PutTunnelIngress(ctx context.Context, id string, ingress []cloudflare.IngressRule) (cloudflare.TunnelConfig, error) {
	if err := g.open(ctx); err != nil {
		return cloudflare.TunnelConfig{}, err
	}
	return g.CloudflareAPI.PutTunnelIngress(ctx, id, ingress)
}

func (g holdGatedAPI) CreateAccessPolicy(ctx context.Context, spec cloudflare.PolicySpec) (cloudflare.AccessPolicy, error) {
	if err := g.open(ctx); err != nil {
		return cloudflare.AccessPolicy{}, err
	}
	return g.CloudflareAPI.CreateAccessPolicy(ctx, spec)
}

func (g holdGatedAPI) UpdateAccessPolicy(ctx context.Context, id string, spec cloudflare.PolicySpec) (cloudflare.AccessPolicy, error) {
	if err := g.open(ctx); err != nil {
		return cloudflare.AccessPolicy{}, err
	}
	return g.CloudflareAPI.UpdateAccessPolicy(ctx, id, spec)
}

func (g holdGatedAPI) CreateAccessApp(ctx context.Context, spec cloudflare.AppSpec) (cloudflare.AccessApp, error) {
	if err := g.open(ctx); err != nil {
		return cloudflare.AccessApp{}, err
	}
	return g.CloudflareAPI.CreateAccessApp(ctx, spec)
}

func (g holdGatedAPI) UpdateAccessApp(ctx context.Context, id string, spec cloudflare.AppSpec) (cloudflare.AccessApp, error) {
	if err := g.open(ctx); err != nil {
		return cloudflare.AccessApp{}, err
	}
	return g.CloudflareAPI.UpdateAccessApp(ctx, id, spec)
}

func (g holdGatedAPI) DeleteAccessApp(ctx context.Context, id string) error {
	if err := g.open(ctx); err != nil {
		return err
	}
	return g.CloudflareAPI.DeleteAccessApp(ctx, id)
}

func (g holdGatedAPI) CreateTunnelCNAME(ctx context.Context, zoneID, hostname, tunnelID, comment string) (cloudflare.DNSRecord, error) {
	if err := g.open(ctx); err != nil {
		return cloudflare.DNSRecord{}, err
	}
	return g.CloudflareAPI.CreateTunnelCNAME(ctx, zoneID, hostname, tunnelID, comment)
}

func (g holdGatedAPI) DeleteDNSRecord(ctx context.Context, zoneID, recordID string) error {
	if err := g.open(ctx); err != nil {
		return err
	}
	return g.CloudflareAPI.DeleteDNSRecord(ctx, zoneID, recordID)
}

func (g holdGatedAPI) CreateServiceToken(ctx context.Context, name string) (cloudflare.NewServiceToken, error) {
	if err := g.open(ctx); err != nil {
		return cloudflare.NewServiceToken{}, err
	}
	return g.CloudflareAPI.CreateServiceToken(ctx, name)
}

func (g holdGatedAPI) DeleteServiceToken(ctx context.Context, id string) error {
	if err := g.open(ctx); err != nil {
		return err
	}
	return g.CloudflareAPI.DeleteServiceToken(ctx, id)
}

// TunnelToken changes nothing in Cloudflare, but it hands out the connector
// credential of a tunnel; a restored instance has no use for it before the
// hold ends.
func (g holdGatedAPI) TunnelToken(ctx context.Context, id string) (audit.Secret, error) {
	if err := g.open(ctx); err != nil {
		return "", err
	}
	return g.CloudflareAPI.TunnelToken(ctx, id)
}
