package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/client"
)

const (
	exitCommandNotFound = 127
	exitSignaled        = 255
	lazydockerInstall   = "https://github.com/jesseduffield/lazydocker#installation"
)

func newSSHCmd(env []string) *cobra.Command {
	var user string
	cmd := &cobra.Command{
		Use:   "ssh <node>",
		Short: "Open an interactive shell on a node with your own SSH credentials",
		Long: "Open an interactive shell on a node as its admin_user (override with --user). The session is\n" +
			"audited, and OpenSSH runs with your ssh_config ignored and only the node's pinned host key trusted.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := runInteractive(cmd, env, args[0], wire.ToolShell, user)
			return err
		},
	}
	cmd.Flags().StringVar(&user, "user", "", "log in as this user instead of the node's admin_user")
	return cmd
}

func newDockerCmd(env []string) *cobra.Command {
	var user string
	cmd := &cobra.Command{
		Use:   "docker <node>",
		Short: "Open lazydocker on a node over SSH",
		Long: "Open lazydocker on the node through an interactive SSH session. SuperMgmt never installs it:\n" +
			"when it is missing on the node, install it there yourself.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			code, err := runInteractive(cmd, env, args[0], wire.ToolLazydocker, user)
			if code == exitCommandNotFound {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "lazydocker is not installed on the node; see %s\n", lazydockerInstall)
			}
			return err
		},
	}
	cmd.Flags().StringVar(&user, "user", "", "log in as this user instead of the node's admin_user")
	return cmd
}

// runInteractive hands the terminal to OpenSSH and returns the program's exit
// code. A nonzero code also comes back as a *childExitError so sm exits with it.
func runInteractive(cmd *cobra.Command, env []string, nodeRef string, tool wire.Tool, user string) (int, error) {
	api, err := newClient(cmd, env)
	if err != nil {
		return 0, err
	}
	node, err := resolveNode(cmd.Context(), api, nodeRef)
	if err != nil {
		return 0, err
	}
	handoff, err := api.OpenInteractive(cmd.Context(), client.Interactive{Node: node, Tool: tool, User: user})
	if err != nil {
		return 0, err
	}
	handoff.Cmd.Stdin, handoff.Cmd.Stdout, handoff.Cmd.Stderr = cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr()

	// Ctrl-C belongs to the child while it owns the terminal; handling the
	// signal here (not ignoring it) keeps the child's default disposition.
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, os.Interrupt)
	runErr := handoff.Cmd.Run()
	signal.Stop(interrupts)

	var exited *exec.ExitError
	switch {
	case runErr == nil:
		handoff.Done(0, nil)
		return 0, nil
	case errors.As(runErr, &exited):
		code := exited.ExitCode()
		if code < 0 {
			code = exitSignaled
		}
		handoff.Done(code, nil)
		return code, &childExitError{code: code}
	}
	handoff.Done(0, runErr)
	return 0, fmt.Errorf("cannot run ssh: %w", runErr)
}
