package domain

import "slices"

// RiskClass grades an action (spec §11.2). Governance sits outside the ordered scale.
type RiskClass string

const (
	RiskRead        RiskClass = "read"
	RiskOperational RiskClass = "operational"
	RiskHigh        RiskClass = "high"
	RiskDestructive RiskClass = "destructive"
	RiskGovernance  RiskClass = "governance"
)

func AllRiskClasses() []RiskClass {
	return []RiskClass{RiskRead, RiskOperational, RiskHigh, RiskDestructive, RiskGovernance}
}

func ParseRiskClass(s string) (RiskClass, error) { return parseEnum("risk class", AllRiskClasses(), s) }
func (v RiskClass) Valid() bool                  { return slices.Contains(AllRiskClasses(), v) }

// Rank orders read < operational < high < destructive. Governance and invalid
// values have no rank and return -1.
func (v RiskClass) Rank() int {
	switch v {
	case RiskRead:
		return 0
	case RiskOperational:
		return 1
	case RiskHigh:
		return 2
	case RiskDestructive:
		return 3
	case RiskGovernance:
		return -1
	}
	return -1
}

// AtLeast reports whether v is at least as risky as other. It is false
// whenever either side is unranked (governance or invalid).
func (v RiskClass) AtLeast(other RiskClass) bool {
	return v.Rank() >= 0 && other.Rank() >= 0 && v.Rank() >= other.Rank()
}
