package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/api/wire"
)

func newIdentitiesCmd(env []string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "identities",
		Short: "List, disable and enable identities (admin)",
		Args:  noArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(newIdentitiesListCmd(env), newIdentitiesDisableCmd(env), newIdentitiesEnableCmd(env))
	return cmd
}

func newIdentitiesListCmd(env []string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List every identity, disabled ones included",
		Args:  noArgs,
	}
	page := addPageFlags(cmd)
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		api, err := newClient(cmd, env)
		if err != nil {
			return err
		}
		result, err := api.ListIdentities(cmd.Context(), *page)
		if err != nil {
			return err
		}
		return emit(cmd, result, func(w io.Writer) error {
			if err := writeIdentities(w, result.Items); err != nil {
				return err
			}
			moreHint(w, result.NextCursor)
			return nil
		})
	}
	return cmd
}

func writeIdentities(w io.Writer, identities []wire.Identity) error {
	rows := make([][]string, len(identities))
	for i, id := range identities {
		state := "enabled"
		if id.DisabledAt != nil {
			state = "disabled"
		}
		rows[i] = []string{
			string(id.ID), orDash(id.DisplayName), string(id.ActorType), state,
			orDash(strings.Join(id.Roles, ",")), formatTimePtr(id.LastSeenAt),
		}
	}
	return table(w, []string{"ID", "NAME", "TYPE", "STATE", "ROLES", "LAST SEEN"}, rows)
}

func newIdentitiesDisableCmd(env []string) *cobra.Command {
	return &cobra.Command{
		Use:   "disable <identity-id>",
		Short: "Disable an identity: revoke its sessions and tokens and remove its roles",
		Long: "Disable an identity. Its sessions and API tokens are revoked, the MCP clients it requested are removed, its unused join tokens are\ninvalidated and its roles removed at once.\n" +
			"A job it already runs finishes; a job it queued fails when a worker claims it. The last enabled admin\n" +
			"cannot be disabled. Undo with sm identities enable, then grant its roles again.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := parseID(args[0])
			if err != nil {
				return err
			}
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			disabled, err := api.DisableIdentity(cmd.Context(), id)
			if err != nil {
				return err
			}
			return emit(cmd, disabled, func(w io.Writer) error {
				_, err := fmt.Fprintf(w, "disabled identity %s: credentials revoked, roles removed\n", disabled.ID)
				return err
			})
		},
	}
}

func newIdentitiesEnableCmd(env []string) *cobra.Command {
	return &cobra.Command{
		Use:   "enable <identity-id>",
		Short: "Enable a disabled identity (no roles, no credentials)",
		Long: "Enable a disabled identity. Its roles and credentials are not restored: grant the roles again with\n" +
			"sm admin grant <identity-id> <role> (on the server), and it signs in again for new credentials.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := parseID(args[0])
			if err != nil {
				return err
			}
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			enabled, err := api.EnableIdentity(cmd.Context(), id)
			if err != nil {
				return err
			}
			return emit(cmd, enabled, func(w io.Writer) error {
				_, err := fmt.Fprintf(w, "enabled identity %s without roles or credentials; grant its roles again with sm admin grant\n", enabled.ID)
				return err
			})
		},
	}
}
