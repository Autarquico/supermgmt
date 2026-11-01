package client

import (
	"context"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

// ---- app moves between nodes (ADR-0041) ---------------------------------------

// MoveApp asks to move the target to node to. The answer is the move's record and the job, which waits for
// approval when policy asks.
func (c *Client) MoveApp(ctx context.Context, target, to domain.ID) (wire.AppMoveSubmission, error) {
	return call[wire.AppMoveSubmission](ctx, c, post(wire.Path(wire.PathAppTargetMoves, string(target)), wire.MoveAppRequest{ToNode: to}))
}

// CleanupAppMoveSource asks to remove the containers a done move left parked on its source node.
func (c *Client) CleanupAppMoveSource(ctx context.Context, target domain.ID) (wire.Submission, error) {
	return call[wire.Submission](ctx, c, post(wire.Path(wire.PathAppTargetMoveCleanup, string(target)), nil))
}

// AbandonAppMove asks to record the target's move, halted in compensation, as rolled back.
func (c *Client) AbandonAppMove(ctx context.Context, target domain.ID) (wire.Submission, error) {
	return call[wire.Submission](ctx, c, post(wire.Path(wire.PathAppTargetMoveAbandon, string(target)), nil))
}

// ListAppMoves returns the target's moves, newest first.
func (c *Client) ListAppMoves(ctx context.Context, target domain.ID) (wire.Page[wire.AppMove], error) {
	return call[wire.Page[wire.AppMove]](ctx, c, get(wire.Path(wire.PathAppTargetMoves, string(target)), nil))
}
