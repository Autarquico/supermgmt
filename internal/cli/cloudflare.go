package cli

import (
	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

func newCloudflareCmd(env []string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cloudflare",
		Short: "Manage the instance's Cloudflare Tunnel integration",
		Args:  noArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(newCloudflareRotateCmd(env))
	return cmd
}

func newCloudflareRotateCmd(env []string) *cobra.Command {
	var assumeYes bool
	cmd := &cobra.Command{
		Use:   "rotate-access-token",
		Short: "Rotate the Cloudflare Access service token the control plane dials tunnel nodes with (a job)",
		Long: "Run cloudflare.access_token.rotate: create a new Access service token, admit it, switch the control plane\n" +
			"to it and only then revoke the old one, so tunnel nodes stay reachable throughout.",
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			req := wire.CreatePlanRequest{Action: actionCloudflareRotate, Targets: []wire.ResourceRef{{Type: domain.ResourceInstance}}}
			return submitPlan(cmd, api, "the instance", req, nil, assumeYes)
		},
	}
	cmd.Flags().BoolVar(&assumeYes, "yes", false, "do not ask for confirmation")
	return cmd
}
