package cli

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/api/wire"
)

func newSSHKeyRotateCmd(env []string) *cobra.Command {
	var assumeYes bool
	cmd := &cobra.Command{
		Use:   "rotate",
		Short: "Create a new version of the instance SSH key (a job; may wait for approval)",
		Long: "Create a new version of the instance SSH identity. Nodes keep the version they were set up with until\n" +
			"`sm nodes setup <node>` runs again and authorizes the new key.",
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := confirm(cmd, "Rotate the instance SSH key?", assumeYes); err != nil {
				return err
			}
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			direct, err := api.RotateSSHKey(cmd.Context())
			if err != nil {
				return err
			}
			return directOutput(cmd, direct, func(k wire.SSHKey) string {
				return fmt.Sprintf("%s is now version %d (%s); run `sm nodes setup` on each node to authorize it", k.Ref, k.Version, k.FingerprintSHA256)
			})
		},
	}
	cmd.Flags().BoolVar(&assumeYes, "yes", false, "do not ask for confirmation")
	return cmd
}

func newSSHKeyCmd(env []string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ssh-key",
		Short: "Show or rotate the instance SSH identity",
		Args:  noArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(newSSHKeyRotateCmd(env), &cobra.Command{
		Use:   "show",
		Short: "Print the public key SuperMgmt authenticates with (node setup authorizes it)",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			key, err := api.SSHKey(cmd.Context())
			if err != nil {
				return err
			}
			return emit(cmd, key, func(w io.Writer) error {
				_, err := fmt.Fprintf(w, "%s\n# %s v%d %s\n", key.AuthorizedKey, key.Ref, key.Version, key.FingerprintSHA256)
				return err
			})
		},
	})
	return cmd
}
