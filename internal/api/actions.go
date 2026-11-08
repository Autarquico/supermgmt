package api

import (
	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/policy"
)

const actionPlanCreate = "plan.create"

// plannableActions is the wire form of the catalog rows an MCP client may plan.
// Every one needs write tools: the gate lets only queries through without them.
func plannableActions(specs []policy.ActionSpec) wire.Page[wire.PlannableAction] {
	items := make([]wire.PlannableAction, len(specs))
	for i, spec := range specs {
		params := make([]wire.ActionParameter, len(spec.Params))
		for j, p := range spec.Params {
			params[j] = wire.ActionParameter{
				Name: p.Name, Type: string(p.Type), Required: p.Required,
				Values: orEmpty(p.Values), RiskByValue: orEmptyMap(p.RiskByValue),
			}
		}
		items[i] = wire.PlannableAction{Name: spec.Name, Target: spec.Resource, Risk: spec.Risk, Parameters: params, NeedsWriteTools: true}
	}
	return wire.Page[wire.PlannableAction]{Items: items}
}

func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func orEmptyMap[K comparable, V any](m map[K]V) map[K]V {
	if m == nil {
		return map[K]V{}
	}
	return m
}
