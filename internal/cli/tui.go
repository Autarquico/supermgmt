package cli

import (
	"context"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/tui"
)

// *client.Client is the whole API the TUI needs.
var _ tui.API = (*client.Client)(nil)

// daemonStartWait bounds the daemon autostart before the TUI takes the screen,
// so a missing daemon is a plain error instead of an empty full-screen UI.
const daemonStartWait = 10 * time.Second

func newTUICmd(env []string) *cobra.Command {
	return &cobra.Command{
		Use:   "tui",
		Short: "Open the terminal UI",
		Long:  "Open the terminal UI (also what plain `sm` does in an interactive terminal).",
		Args:  noArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return runTUI(cmd, env) },
	}
}

// runBareTUI is the RunE of the root command: the TUI in an interactive
// terminal, the help text otherwise (pipes, CI, `sm | cat`).
func runBareTUI(env []string) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, _ []string) error {
		if !isTerminal(cmd.InOrStdin()) || !isTerminal(cmd.OutOrStdout()) {
			return cmd.Help()
		}
		return runTUI(cmd, env)
	}
}

func runTUI(cmd *cobra.Command, env []string) error {
	if !isTerminal(cmd.InOrStdin()) || !isTerminal(cmd.OutOrStdout()) {
		return usageErrorf("the TUI needs an interactive terminal; use the sm subcommands in scripts")
	}
	api, where, err := connect(cmd, env)
	if err != nil {
		return err
	}
	ready, cancel := context.WithTimeout(cmd.Context(), daemonStartWait)
	defer cancel()
	if _, err := api.Me(ready); err != nil {
		return err
	}
	return tui.Run(cmd.Context(), api, tuiOptions(api, where))
}

// tuiOptions wires the TUI to its target. A local daemon is kept resident by
// presence; a remote server pushes events over SSE instead.
func tuiOptions(api *client.Client, where target) tui.Options {
	opts := tui.Options{Settings: tui.Settings{Profile: where.name, Server: api.Server()}}
	if !api.Remote() {
		opts.Presence = api.HoldPresence
		return opts
	}
	opts.Follow = func(ctx context.Context, handle func(wire.Event) error) error {
		return api.FollowEvents(ctx, wire.EventQuery{}, handle)
	}
	return opts
}

// isTerminal reports whether stream is a character device other than
// /dev/null, which is what a terminal looks like to the standard library.
func isTerminal(stream any) bool {
	file, ok := stream.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	if err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	null, err := os.Stat(os.DevNull)
	return err != nil || !os.SameFile(info, null)
}
