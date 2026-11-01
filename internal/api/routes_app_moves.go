package api

import (
	"context"
	"net/http"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/database"
)

const (
	actionAppTargetMove    = "app_target.move"
	actionAppTargetCleanup = "app_target.cleanup_source"
	actionAppTargetAbandon = "app_target.abandon_move"
)

// appMoves registers the routes that move an app target to another node (ADR-0041). A move, the removal of its
// parked source and the abandonment of a halted move are plans that always become a job, which waits for approval
// when policy asks, so all three answer 202; reading is app_target.read.
func (rs *routeSet) appMoves() {
	s := rs.s
	moves := s.svc.AppMoves
	rs.read(wire.PathAppTargetMoves, "app_target.read", reading(s, func(ctx context.Context, by app.Caller, in input) (wire.Page[wire.AppMove], error) {
		id, err := in.id("id")
		if err != nil {
			return wire.Page[wire.AppMove]{}, err
		}
		views, err := moves.List(ctx, by, id)
		return appMovePage(views), err
	}))
	rs.write(http.MethodPost, wire.PathAppTargetMoves, actionAppTargetMove, mutation(s,
		func(ctx context.Context, by app.Caller, in input) (app.AppMoveResult, error) {
			id, err := in.id("id")
			if err != nil {
				return app.AppMoveResult{}, err
			}
			req, err := decode[wire.MoveAppRequest](in)
			if err != nil {
				return app.AppMoveResult{}, err
			}
			return moves.Move(ctx, by, id, req.ToNode)
		},
		func(r app.AppMoveResult) (int, any) {
			return http.StatusAccepted, wire.AppMoveSubmission{
				Move: appMoveView(r.AppMoveView), Resumed: r.Resumed, Submission: app.SubmissionView(r.Submission),
			}
		}))
	rs.write(http.MethodPost, wire.PathAppTargetMoveCleanup, actionAppTargetCleanup, mutation(s,
		func(ctx context.Context, by app.Caller, in input) (app.Submission, error) {
			id, err := in.id("id")
			if err != nil {
				return app.Submission{}, err
			}
			return moves.CleanupSource(ctx, by, id)
		}, submitted))
	rs.write(http.MethodPost, wire.PathAppTargetMoveAbandon, actionAppTargetAbandon, mutation(s,
		func(ctx context.Context, by app.Caller, in input) (app.Submission, error) {
			id, err := in.id("id")
			if err != nil {
				return app.Submission{}, err
			}
			return moves.Abandon(ctx, by, id)
		}, submitted))
}

func appMovePage(views []app.AppMoveView) wire.Page[wire.AppMove] {
	items := make([]wire.AppMove, len(views))
	for i, v := range views {
		items[i] = appMoveView(v)
	}
	return wire.Page[wire.AppMove]{Items: items}
}

func appMoveView(v app.AppMoveView) wire.AppMove {
	m := v.Move
	volumes := make([]wire.AppMoveVolume, len(v.Volumes))
	for i, vol := range v.Volumes {
		volumes[i] = appMoveVolumeView(vol)
	}
	return wire.AppMove{
		ID: m.ID, AppTargetID: m.AppTargetID, SourceNodeID: m.SourceNodeID, DestNodeID: m.DestNodeID,
		Phase: string(m.Phase), HaltedPhase: string(m.HaltedPhase), Stateful: m.Stateful, Volumes: volumes,
		LastError: m.LastError, CreatedAt: m.CreatedAt, UpdatedAt: m.UpdatedAt,
	}
}

func appMoveVolumeView(v database.AppMoveVolume) wire.AppMoveVolume {
	return wire.AppMoveVolume{
		Name: v.VolumeName, Service: v.Service, Mount: v.MountTarget, State: string(v.State), Attempt: v.Attempt,
		CreatedByMove: v.CreatedByMove,
	}
}
