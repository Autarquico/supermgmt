package mcp

import (
	"context"
	"fmt"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

// The app move tools (ADR-0041). A move is a plan the API always turns into a job: it is high risk, so an mcp
// identity's request waits for approval. Cleaning up the source and abandoning a move are not offered.

type listAppMovesInput struct {
	App         string `json:"app" jsonschema:"app id or exact app name"`
	Environment string `json:"environment" jsonschema:"environment id or exact environment name of the app target"`
}

type moveAppInput struct {
	App         string `json:"app" jsonschema:"app id or exact app name"`
	Environment string `json:"environment" jsonschema:"environment id or exact environment name of the app target"`
	ToNode      string `json:"to_node" jsonschema:"destination node id or exact node name"`
}

func listAppMoves(ctx context.Context, api API, in listAppMovesInput) (listResult[MoveView], error) {
	target, err := resolveAppTarget(ctx, api, in.App, in.Environment)
	if err != nil {
		return listResult[MoveView]{}, err
	}
	page, err := api.ListAppMoves(ctx, target.ID)
	if err != nil {
		return listResult[MoveView]{}, err
	}
	items := make([]MoveView, len(page.Items))
	for i, m := range page.Items {
		items[i] = ViewMove(m)
	}
	return listResult[MoveView]{Items: items}, nil
}

func moveApp(ctx context.Context, api API, in moveAppInput) (WriteResult, error) {
	target, err := resolveAppTarget(ctx, api, in.App, in.Environment)
	if err != nil {
		return WriteResult{}, err
	}
	to, err := resolveNode(ctx, api, in.ToNode)
	if err != nil {
		return WriteResult{}, err
	}
	res, err := api.MoveApp(ctx, target.ID, to)
	if err != nil {
		return WriteResult{}, err
	}
	return moveResult(res, target.ID), nil
}

// moveResult is built from control-plane fields only.
func moveResult(res wire.AppMoveSubmission, target domain.ID) WriteResult {
	out := submissionResult(res.Submission)
	stops := "the app keeps running until the destination is healthy"
	if res.Move.Stateful {
		stops = "the app stops while its volumes are copied"
	}
	out.Summary = fmt.Sprintf("move app target %s to node %s: job %s; %s", target, res.Move.DestNodeID, res.Submission.Job.State, stops)
	return out
}
