package app

import (
	"context"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/policy"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare"
)

// tunnelSetupSteps names the Cloudflare objects a node.setup with tunnel=true
// creates, so the plan hash, and with it the approval, covers those names.
// Any other plan has no steps.
// Planning and every rebuild call it, so a changed zone makes the plan stale.
func (c core) tunnelSetupSteps(ctx context.Context, q database.Querier, action string, target domain.ID, params map[string]any) ([]string, error) {
	if action != policy.ActionNodeSetup {
		return nil, nil
	}
	if tunnel, err := tunnelRequested(params[policy.ParamTunnel]); err != nil || !tunnel {
		return nil, err
	}
	if c.cfg.Cloudflare == nil {
		return nil, planStale() // the tunnel feature was switched off since planning
	}
	node, err := database.GetNode(ctx, q, target)
	if err != nil {
		return nil, err
	}
	instance, err := database.GetInstance(ctx, q)
	if err != nil {
		return nil, err
	}
	hostname, err := tunnelHostnameOf(node.Name, c.cfg.Cloudflare.Zone)
	if err != nil {
		return nil, err
	}
	return []string{
		"cloudflare tunnel: " + cloudflare.TunnelName(instance.ID.String(), node.ID.String()),
		"cloudflare access application: " + cloudflare.AccessAppName(instance.ID.String(), node.ID.String()),
		"cloudflare dns record: " + hostname,
	}, nil
}
