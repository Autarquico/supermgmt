package wire

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/autarquico/supermgmt/internal/domain"
)

// ParseUnitSpec reads the CLI and TUI form of a unit grant,
// "<unit>[:<verb>[,<verb>...]]". Without verbs the unit gets all of them. The
// daemon validates the unit name when the plan is created.
func ParseUnitSpec(spec string) (UnitGrant, error) {
	unit, verbList, hasVerbs := strings.Cut(spec, ":")
	if unit == "" {
		return UnitGrant{}, fmt.Errorf("unit %q: the unit name is empty", spec)
	}
	if !hasVerbs {
		return UnitGrant{Unit: unit, Verbs: domain.AllServiceVerbs()}, nil
	}
	var verbs []domain.ServiceVerb
	for _, text := range strings.Split(verbList, ",") {
		verb, err := domain.ParseServiceVerb(text)
		if err != nil {
			return UnitGrant{}, fmt.Errorf("unit %q: %q is not start, stop or restart", spec, text)
		}
		if !slices.Contains(verbs, verb) {
			verbs = append(verbs, verb)
		}
	}
	return UnitGrant{Unit: unit, Verbs: verbs}, nil
}

// SetupUnits decides the unit grants of a node.setup run: the parsed specs
// when there are any, none when dropAll, and otherwise the grants the node
// already has, so re-running setup (after a key rotation, say) keeps them.
// kept reports that last case. Grants are merged per unit, units in
// first-seen order and verbs in canonical order, as the daemon stores them.
func SetupUnits(specs []string, dropAll bool, current *Setup) (grants []UnitGrant, kept bool, err error) {
	switch {
	case len(specs) > 0 && dropAll:
		return nil, false, fmt.Errorf("pass units or drop them all, not both")
	case dropAll:
		return nil, false, nil
	case len(specs) == 0:
		if current == nil {
			return nil, false, nil
		}
		grants = mergeGrants(current.Units)
		return grants, len(grants) > 0, nil
	}
	for _, spec := range specs {
		g, err := ParseUnitSpec(spec)
		if err != nil {
			return nil, false, err
		}
		grants = append(grants, g)
	}
	return mergeGrants(grants), false, nil
}

// mergeGrants folds repeated units together and drops units with no verb,
// which would write no sudoers line.
func mergeGrants(grants []UnitGrant) []UnitGrant {
	var units []string
	verbs := map[string][]domain.ServiceVerb{}
	for _, g := range grants {
		if _, seen := verbs[g.Unit]; !seen {
			units = append(units, g.Unit)
		}
		verbs[g.Unit] = append(verbs[g.Unit], g.Verbs...)
	}
	var merged []UnitGrant
	for _, unit := range units {
		var canonical []domain.ServiceVerb
		for _, v := range domain.AllServiceVerbs() {
			if slices.Contains(verbs[unit], v) {
				canonical = append(canonical, v)
			}
		}
		if len(canonical) > 0 {
			merged = append(merged, UnitGrant{Unit: unit, Verbs: canonical})
		}
	}
	return merged
}

// SetupParameters are node.setup's plan parameters.
func SetupParameters(dockerAccess bool, logsMode string, grants []UnitGrant) map[string]any {
	params := map[string]any{"docker_access": strconv.FormatBool(dockerAccess), "logs_mode": logsMode}
	if entries := GrantEntries(grants); len(entries) > 0 {
		params["grants"] = entries
	}
	return params
}

// UnitsChange is the line a plan preview shows: the grants the run writes and,
// when they differ from the node's, what they replace.
func UnitsChange(current *Setup, grants []UnitGrant, kept bool) string {
	line := "units: " + DescribeUnits(grants)
	switch {
	case kept:
		return line + " (kept from the previous setup)"
	case current != nil && len(current.Units) > 0:
		return line + " (was: " + DescribeUnits(current.Units) + ")"
	}
	return line
}

// GrantEntries renders grants as node.setup's grants parameter: one
// "<verb> <unit>" entry per sudoers line.
func GrantEntries(grants []UnitGrant) []string {
	var entries []string
	for _, g := range grants {
		for _, v := range g.Verbs {
			entries = append(entries, string(v)+" "+g.Unit)
		}
	}
	return entries
}

// DescribeUnits is the one-line human form, "nginx.service (start, stop,
// restart), app.service (restart)", or "none".
func DescribeUnits(grants []UnitGrant) string {
	if len(grants) == 0 {
		return "none"
	}
	parts := make([]string, len(grants))
	for i, g := range grants {
		verbs := make([]string, len(g.Verbs))
		for j, v := range g.Verbs {
			verbs[j] = string(v)
		}
		parts[i] = fmt.Sprintf("%s (%s)", g.Unit, strings.Join(verbs, ", "))
	}
	return strings.Join(parts, ", ")
}
