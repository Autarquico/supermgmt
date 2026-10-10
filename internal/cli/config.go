package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/policy"
)

const builtInPolicy = "built-in default"

func newConfigCmd(env []string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Inspect and validate configuration",
		Args:  noArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(newConfigValidateCmd(env))
	return cmd
}

func newConfigValidateCmd(env []string) *cobra.Command {
	var policyFlag string
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate the configuration and policy files without opening the database",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			configFlag, _ := cmd.Flags().GetString("config")
			asJSON, _ := cmd.Flags().GetBool("json")
			report := validateFiles(configPath(configFlag, env), policyFlag, env)
			if err := writeValidateReport(cmd.OutOrStdout(), report, asJSON); err != nil {
				return err
			}
			if !report.Valid {
				return usageErrorf("configuration is invalid")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&policyFlag, "policy", "", "policy file to validate instead of security.policy_file")
	return cmd
}

type validateReport struct {
	Valid  bool           `json:"valid"`
	Config configSection  `json:"config"`
	Policy *policySection `json:"policy,omitempty"`
}

type configSection struct {
	Path     string   `json:"path"`
	Problems []string `json:"problems"`
	Warnings []string `json:"warnings"`
}

type policySection struct {
	Source   string      `json:"source"`
	Rules    int         `json:"rules"`
	Problems []string    `json:"problems"`
	Diff     *policyDiff `json:"diff,omitempty"`
}

// policyDiff lists rule names that differ from the built-in default policy.
type policyDiff struct {
	Added   []string `json:"added"`
	Removed []string `json:"removed"`
	Changed []string `json:"changed"`
}

func (d policyDiff) empty() bool {
	return len(d.Added)+len(d.Removed)+len(d.Changed) == 0
}

func validateFiles(configFile, policyFlag string, env []string) validateReport {
	result, err := config.Load(configFile, env)
	report := validateReport{Config: configSection{
		Path:     configFile,
		Problems: configProblems(err),
		Warnings: nonNil(result.Warnings),
	}}
	policyFile := policyFlag
	if policyFile == "" && result.Config != nil {
		policyFile = result.Config.Security.PolicyFile
	}
	if err == nil || policyFlag != "" {
		report.Policy = validatePolicy(policyFile)
	}
	report.Valid = len(report.Config.Problems) == 0 && (report.Policy == nil || len(report.Policy.Problems) == 0)
	return report
}

// configProblems lists every problem of a failed load; empty on success.
func configProblems(err error) []string {
	var problems config.Problems
	switch {
	case err == nil:
		return []string{}
	case errors.As(err, &problems):
		lines := make([]string, len(problems))
		for i, p := range problems {
			lines[i] = p.String()
		}
		return lines
	}
	return []string{errorMessage(err)}
}

// validatePolicy checks the policy at file (the built-in default when empty)
// and diffs it against the built-in default.
func validatePolicy(file string) *policySection {
	section := &policySection{Source: builtInPolicy, Problems: []string{}}
	base, err := policy.Default()
	if err != nil {
		section.Problems = append(section.Problems, err.Error())
		return section
	}
	section.Rules = len(base.Rules())
	if file == "" {
		return section
	}
	section.Source = file
	section.Rules = 0
	custom, err := readPolicy(file)
	if err != nil {
		section.Problems = append(section.Problems, errorMessage(err))
		return section
	}
	section.Rules = len(custom.Rules())
	section.Diff = diffNames(policy.DiffPolicies(base, custom))
	return section
}

func readPolicy(file string) (*policy.Policy, error) {
	data, err := os.ReadFile(filepath.Clean(file))
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}
	return policy.Parse(data)
}

func diffNames(d policy.Diff) *policyDiff {
	out := &policyDiff{Added: []string{}, Removed: []string{}, Changed: []string{}}
	for _, r := range d.Added {
		out.Added = append(out.Added, r.Name)
	}
	for _, r := range d.Removed {
		out.Removed = append(out.Removed, r.Name)
	}
	for _, c := range d.Changed {
		out.Changed = append(out.Changed, c.Name)
	}
	return out
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
