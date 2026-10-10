package cli

import (
	"io"
	"slices"
	"strings"

	"github.com/spf13/cobra"
)

var shells = []string{"bash", "zsh", "fish", "powershell"}

func newCompletionCmd() *cobra.Command {
	return &cobra.Command{
		Use:       "completion " + strings.Join(shells, "|"),
		Short:     "Generate a shell completion script",
		ValidArgs: shells,
		Args:      shellArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			return writeCompletion(cmd.Root(), args[0], cmd.OutOrStdout())
		},
	}
}

func shellArg(_ *cobra.Command, args []string) error {
	if len(args) != 1 {
		return usageErrorf("expected exactly one shell: %s", strings.Join(shells, ", "))
	}
	if !slices.Contains(shells, args[0]) {
		return usageErrorf("unknown shell %q: must be one of %s", args[0], strings.Join(shells, ", "))
	}
	return nil
}

func writeCompletion(root *cobra.Command, shell string, w io.Writer) error {
	switch shell {
	case "bash":
		return root.GenBashCompletionV2(w, true)
	case "zsh":
		return root.GenZshCompletion(w)
	case "fish":
		return root.GenFishCompletion(w, true)
	default:
		return root.GenPowerShellCompletionWithDesc(w)
	}
}
