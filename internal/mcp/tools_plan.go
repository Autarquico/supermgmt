package mcp

import (
	"context"
	"encoding/json"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

const submitPlanTool = "infra_submit_plan"

// decisionDeny is the policy verdict that makes a plan unsubmittable.
const decisionDeny = "deny"

type planTarget struct {
	Type string `json:"type" jsonschema:"resource type, for example service or node"`
	Ref  string `json:"ref" jsonschema:"id or exact name; name@node for a service"`
}

type planActionInput struct {
	Action     string         `json:"action" jsonschema:"an action of the catalog, for example service.restart"`
	Targets    []planTarget   `json:"targets" jsonschema:"exactly one target"`
	Parameters map[string]any `json:"parameters,omitempty" jsonschema:"parameters of the action, validated against its closed schema"`
}

// planActionOutput is the plan view plus the tool that submits it, null when
// write tools are disabled.
type planActionOutput struct {
	PlanView
	SubmitVia *string `json:"submit_via"`
}

// addPlanTool registers infra_plan_action: it builds and stores a plan and
// never executes it. submittable says whether the submit tool exists.
func addPlanTool(s *sdk.Server, api API, submittable bool) {
	var submitVia *string
	if submittable {
		name := submitPlanTool
		submitVia = &name
	}
	actionTool(s, "infra_plan_action",
		"Build and store a plan for one action on one target (names or ids; the plan binds ids). "+
			"Nothing is executed. The result carries the plan hash and the policy verdict.",
		func(ctx context.Context, in planActionInput) (planActionOutput, error) {
			if len(in.Targets) != 1 {
				return planActionOutput{}, invalidArgument("exactly one target is required")
			}
			created, err := requestPlan(ctx, api, in.Action, in.Targets[0], in.Parameters)
			return planActionOutput{PlanView: ViewCreatedPlan(created), SubmitVia: submitVia}, err
		})
}

// requestPlan resolves the target to ids and asks the API for a plan. The
// API owns the action catalog, so an unknown action or parameter comes back
// as its INVALID_ARGUMENT.
func requestPlan(ctx context.Context, api API, action string, target planTarget, params map[string]any) (wire.CreatedPlan, error) {
	if action == "" {
		return wire.CreatedPlan{}, invalidArgument("action is required")
	}
	ref, err := resolveTarget(ctx, api, target)
	if err != nil {
		return wire.CreatedPlan{}, err
	}
	if params == nil {
		params = map[string]any{}
	}
	return api.CreatePlan(ctx, wire.CreatePlanRequest{Action: action, Targets: []wire.ResourceRef{ref}, Parameters: params})
}

// resolveTarget turns a target into a typed id. Nodes, services and apps may
// be named; any other type must be given by id.
func resolveTarget(ctx context.Context, api API, target planTarget) (wire.ResourceRef, error) {
	kind := domain.ResourceType(target.Type)
	if !kind.Valid() {
		return wire.ResourceRef{}, invalidArgument("target type is not a resource type")
	}
	var (
		id  domain.ID
		err error
	)
	switch target.Type {
	case string(domain.ResourceNode):
		id, err = resolveNode(ctx, api, target.Ref)
	case string(domain.ResourceService):
		id, err = resolveService(ctx, api, target.Ref)
	case string(domain.ResourceApp):
		id, err = resolveApp(ctx, api, target.Ref)
	default:
		if id, err = domain.ParseID(target.Ref); err != nil {
			err = invalidArgument("a " + target.Type + " target is given by id")
		}
	}
	return wire.ResourceRef{Type: kind, ID: id}, err
}

// planRisk reads the risk class out of the canonical plan document.
func planRisk(document json.RawMessage) string {
	var plan struct {
		Risk string `json:"risk"`
	}
	_ = json.Unmarshal(document, &plan)
	return plan.Risk
}
