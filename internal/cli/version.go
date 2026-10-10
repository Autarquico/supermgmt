package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/version"
)

type versionJSON struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Date      string `json:"date"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`
}

func newVersionCmd(build version.Build) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version, commit, build date, Go version and platform",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			if asJSON, _ := cmd.Flags().GetBool("json"); asJSON {
				return json.NewEncoder(out).Encode(versionJSON(build))
			}
			_, err := fmt.Fprintf(out, "version:    %s\ncommit:     %s\ndate:       %s\ngo_version: %s\nplatform:   %s\n",
				build.Version, build.Commit, build.Date, build.GoVersion, build.Platform)
			return err
		},
	}
}
