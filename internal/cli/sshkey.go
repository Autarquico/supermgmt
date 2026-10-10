package cli

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

func newSSHKeyCmd(env []string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ssh-key",
		Short: "Show the instance SSH identity",
		Args:  noArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(&cobra.Command{
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
