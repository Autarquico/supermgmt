package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/domain"
)

const (
	actionNodeSetup         = "node.setup"
	paramTunnel             = "tunnel"
	actionNodeTunnelDisable = "node.tunnel.disable"
	actionCloudflareRotate  = "cloudflare.access_token.rotate"
)

// transportPreview is the plan line for a setup that reaches the node through
// a Cloudflare Tunnel. The hostname is only known once the node has one.
func transportPreview(hostname string) string {
	if hostname == "" {
		return "transport: cloudflare"
	}
	return "transport: cloudflare via " + hostname
}

// submitPlan is the plan, preview, confirm, submit sequence every job command
// shares. details are extra preview lines shown after the plan summary.
func submitPlan(cmd *cobra.Command, api *client.Client, subject string, req wire.CreatePlanRequest, details []string, assumeYes bool) error {
	plan, err := api.CreatePlan(cmd.Context(), req)
	if err != nil {
		return err
	}
	if err := describePlan(cmd, subject, plan); err != nil {
		return err
	}
	for _, line := range details {
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(), line)
	}
	if err := confirm(cmd, "Submit this plan?", assumeYes); err != nil {
		return err
	}
	submission, err := api.SubmitPlan(cmd.Context(), plan.PlanID, plan.PlanHash)
	if err != nil {
		return err
	}
	return submissionOutput(cmd, submission)
}

func newNodesTunnelCmd(env []string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tunnel",
		Short: "Manage a node's Cloudflare Tunnel (enable it with `sm nodes setup --tunnel`)",
		Args:  noArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(newNodesTunnelDisableCmd(env))
	return cmd
}

func newNodesTunnelDisableCmd(env []string) *cobra.Command {
	var assumeYes bool
	cmd := &cobra.Command{
		Use:   "disable <node>",
		Short: "Return a node to direct SSH and remove its tunnel (a job; may wait for approval)",
		Long: "Run node.tunnel.disable: switch the node back to the direct transport, stop and remove cloudflared on it,\n" +
			"and delete the Cloudflare objects SuperMgmt created for it. Make sure the node's SSH port is reachable\n" +
			"directly first: the node is dialled directly from then on.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			id, err := resolveNode(cmd.Context(), api, args[0])
			if err != nil {
				return err
			}
			node, err := api.GetNode(cmd.Context(), id, false)
			if err != nil {
				return err
			}
			req := wire.CreatePlanRequest{Action: actionNodeTunnelDisable, Targets: []wire.ResourceRef{{Type: domain.ResourceNode, ID: id}}}
			return submitPlan(cmd, api, args[0], req, []string{"transport: " + string(node.Endpoint.Transport.Effective()) + " -> direct"}, assumeYes)
		},
	}
	cmd.Flags().BoolVar(&assumeYes, "yes", false, "do not ask for confirmation")
	return cmd
}
