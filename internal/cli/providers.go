package cli

import "github.com/spf13/cobra"

// newProvidersCmd is `sm providers` (ADR-0024). M3 W0 registers the parent,
// hidden until it has subcommands: T3 adds `check --offline`, T8 adds
// list/get/refresh and unhides it.
func newProvidersCmd(_ []string) *cobra.Command {
	return &cobra.Command{
		Use:    "providers",
		Short:  "List, check and refresh providers",
		Hidden: true,
		Args:   noArgs,
	}
}
