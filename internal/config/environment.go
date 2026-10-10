package config

import (
	"fmt"

	"go.yaml.in/yaml/v3"
)

// Environment is a config-declared environment (spec §8.2.1).
type Environment struct {
	Name                   string `yaml:"name"`
	RiskLevel              string `yaml:"risk_level"`
	RequireProvenance      bool   `yaml:"require_provenance"`
	ApprovalsRequired      int    `yaml:"approvals_required"`
	AllowAutomaticRollback bool   `yaml:"allow_automatic_rollback"`
}

// UnmarshalYAML defaults approvals_required to 1 when the key is absent.
func (e *Environment) UnmarshalYAML(n *yaml.Node) error {
	type plain Environment
	p := plain{ApprovalsRequired: 1}
	if err := n.Decode(&p); err != nil {
		return fmt.Errorf("decode environment: %w", err)
	}
	*e = Environment(p)
	return nil
}
