package wire

import "github.com/autarquico/supermgmt/internal/domain"

// PlannableAction is one entry of GET /actions: an action an MCP client may
// ask to plan. It says nothing about what policy grants a given target.
// NeedsWriteTools is true for every entry today: only queries pass with MCP
// write tools off.
type PlannableAction struct {
	Name            string              `json:"name"`
	Target          domain.ResourceType `json:"target"`
	Risk            domain.RiskClass    `json:"risk"`
	Parameters      []ActionParameter   `json:"parameters"`
	NeedsWriteTools bool                `json:"needs_write_tools"`
}

// ActionParameter is one entry of an action's closed parameter schema.
// RiskByValue lists the values that raise the action's risk.
type ActionParameter struct {
	Name        string                      `json:"name"`
	Type        string                      `json:"type"`
	Required    bool                        `json:"required"`
	Values      []string                    `json:"values"`
	RiskByValue map[string]domain.RiskClass `json:"risk_by_value"`
}
