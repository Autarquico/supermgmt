// Package cli builds the sm command tree.
package cli

import (
	"io"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/version"
)

var logLevels = []string{"debug", "info", "warn", "error"}

// Execute runs sm with args and returns the process exit code.
func Execute(args []string, stdout, stderr io.Writer) int {
	return execute(args, stdout, stderr, version.Info(), os.Environ())
}

// execute runs sm with env as its process environment ("KEY=value" entries).
func execute(args []string, stdout, stderr io.Writer, build version.Build, env []string) int {
	root := newRootCmd(build, env)
	root.SetArgs(append([]string{}, args...)) // cobra reads os.Args when given nil
	root.SetOut(stdout)
	root.SetErr(stderr)

	err := root.Execute()
	if err != nil {
		asJSON, _ := root.PersistentFlags().GetBool("json")
		reportError(stderr, err, asJSON)
	}
	return exitCode(err)
}

func newRootCmd(build version.Build, env []string) *cobra.Command {
	root := &cobra.Command{
		Use:               "sm",
		Short:             "SuperMgmt: manage your infrastructure",
		SilenceUsage:      true,
		SilenceErrors:     true,
		Args:              noArgs,
		PersistentPreRunE: validateLogLevel,
		RunE:              runBareTUI(env),
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
	}
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return usageErrorf("%s", err)
	})
	flags := root.PersistentFlags()
	flags.String("config", "", "path to the configuration file")
	flags.Bool("json", false, "machine-readable JSON output")
	flags.String("log-level", "info", "log level: "+strings.Join(logLevels, "|"))

	root.AddCommand(newVersionCmd(build), newCompletionCmd(), newConfigCmd(env), newDoctorCmd(env))
	root.AddCommand(clientCommands(env)...)
	root.AddCommand(newDaemonCmd(env))
	root.AddCommand(newTUICmd(env))
	root.AddCommand(newInstallCmd(env), newServerCmd(env), newAdminCmd(env))
	return root
}

func validateLogLevel(cmd *cobra.Command, _ []string) error {
	level, err := cmd.Flags().GetString("log-level")
	if err != nil {
		return err
	}
	if !slices.Contains(logLevels, level) {
		return usageErrorf("invalid --log-level %q: must be one of %s", level, strings.Join(logLevels, ", "))
	}
	return nil
}

// noArgs rejects positional arguments; at the root they mean an unknown command.
func noArgs(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return nil
	}
	if cmd.HasParent() {
		return usageErrorf("unexpected argument %q for %q", args[0], cmd.CommandPath())
	}
	return usageErrorf("unknown command %q for %q", args[0], cmd.CommandPath())
}
