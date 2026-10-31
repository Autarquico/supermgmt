package api

import (
	"context"
	"net/http"
	"net/url"
	"slices"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/domain"
)

// apps registers the app and app-target routes (spec §23). Without the apps
// service the routes are not served at all.
func (rs *routeSet) apps() {
	s := rs.s
	if s.svc.Apps == nil {
		return
	}
	rs.read(wire.PathApps, "app.read", reading(s, func(ctx context.Context, by app.Caller, in input) (wire.Page[app.AppView], error) {
		page, err := wire.ParsePageQuery(in.r.URL.Query())
		if err != nil {
			return wire.Page[app.AppView]{}, err
		}
		return s.svc.Apps.List(ctx, by, page)
	}))
	rs.write(http.MethodPost, wire.PathApps, "app.write", mutation(s,
		func(ctx context.Context, by app.Caller, in input) (app.DirectResult[app.AppView], error) {
			req, err := decode[wire.CreateAppRequest](in)
			if err != nil {
				return app.DirectResult[app.AppView]{}, err
			}
			return s.svc.Apps.Create(ctx, by, req)
		},
		direct(http.StatusCreated, same[app.AppView])))
	rs.read(wire.PathApp, "app.read", reading(s, func(ctx context.Context, by app.Caller, in input) (app.AppView, error) {
		id, err := in.id("id")
		if err != nil {
			return app.AppView{}, err
		}
		return s.svc.Apps.Get(ctx, by, id)
	}))
	rs.write(http.MethodPatch, wire.PathApp, "app.write", mutation(s,
		func(ctx context.Context, by app.Caller, in input) (app.DirectResult[app.AppView], error) {
			id, err := in.id("id")
			if err != nil {
				return app.DirectResult[app.AppView]{}, err
			}
			revision, err := in.ifMatch()
			if err != nil {
				return app.DirectResult[app.AppView]{}, err
			}
			patch, err := decode[wire.AppPatch](in)
			if err != nil {
				return app.DirectResult[app.AppView]{}, err
			}
			return s.svc.Apps.Update(ctx, by, id, revision, patch)
		},
		direct(http.StatusOK, same[app.AppView])))
	rs.appTargets()
	rs.appRoutes()
}

func (rs *routeSet) appTargets() {
	s := rs.s
	rs.read(wire.PathAppTargets, "app_target.read", reading(s, func(ctx context.Context, by app.Caller, in input) (wire.Page[app.AppTargetView], error) {
		id, err := in.id("id")
		if err != nil {
			return wire.Page[app.AppTargetView]{}, err
		}
		targets, err := s.svc.Apps.ListTargets(ctx, by, id)
		if err != nil {
			return wire.Page[app.AppTargetView]{}, err
		}
		return wire.Page[app.AppTargetView]{Items: nonNil(targets)}, nil
	}))
	rs.write(http.MethodPost, wire.PathAppTargets, "app_target.write", mutation(s,
		func(ctx context.Context, by app.Caller, in input) (app.DirectResult[app.AppTargetView], error) {
			id, err := in.id("id")
			if err != nil {
				return app.DirectResult[app.AppTargetView]{}, err
			}
			req, err := decode[wire.CreateAppTargetRequest](in)
			if err != nil {
				return app.DirectResult[app.AppTargetView]{}, err
			}
			return s.svc.Apps.CreateTarget(ctx, by, id, req)
		},
		direct(http.StatusCreated, same[app.AppTargetView])))
	rs.read(wire.PathAppTarget, "app_target.read", reading(s, func(ctx context.Context, by app.Caller, in input) (app.AppTargetView, error) {
		id, err := in.id("id")
		if err != nil {
			return app.AppTargetView{}, err
		}
		return s.svc.Apps.GetTarget(ctx, by, id)
	}))
	rs.write(http.MethodPatch, wire.PathAppTarget, "app_target.write", mutation(s,
		func(ctx context.Context, by app.Caller, in input) (app.DirectResult[app.AppTargetView], error) {
			id, err := in.id("id")
			if err != nil {
				return app.DirectResult[app.AppTargetView]{}, err
			}
			revision, err := in.ifMatch()
			if err != nil {
				return app.DirectResult[app.AppTargetView]{}, err
			}
			patch, err := decode[wire.AppTargetPatch](in)
			if err != nil {
				return app.DirectResult[app.AppTargetView]{}, err
			}
			return s.svc.Apps.UpdateTarget(ctx, by, id, revision, patch)
		},
		direct(http.StatusOK, same[app.AppTargetView])))
}

func nonNil[T any](items []T) []T {
	if items == nil {
		return []T{}
	}
	return items
}

// repositories registers the repository listing of a GitHub provider.
func (rs *routeSet) repositories() {
	s := rs.s
	if s.svc.Repositories == nil {
		return
	}
	rs.read(wire.PathProviderRepositories, "provider.read", reading(s, func(ctx context.Context, by app.Caller, in input) (wire.Page[wire.Repository], error) {
		id, err := in.id("id")
		if err != nil {
			return wire.Page[wire.Repository]{}, err
		}
		page, err := wire.ParsePageQuery(in.r.URL.Query())
		if err != nil {
			return wire.Page[wire.Repository]{}, err
		}
		return s.svc.Repositories.List(ctx, by, id, page)
	}))
}

// deployments registers the deployment routes (spec §20, §23; ADR-0011). The
// two actions the GitHub Actions credential may call are deployment.create and
// deployment.read (see Server.requireScope).
func (rs *routeSet) deployments() {
	s := rs.s
	if s.svc.Deployments == nil {
		return
	}
	rs.read(wire.PathDeployments, "deployment.read", reading(s, func(ctx context.Context, by app.Caller, in input) (wire.Page[app.DeploymentView], error) {
		page, err := wire.ParsePageQuery(in.r.URL.Query())
		if err != nil {
			return wire.Page[app.DeploymentView]{}, err
		}
		filter, err := parseDeploymentFilter(in.r.URL.Query())
		if err != nil {
			return wire.Page[app.DeploymentView]{}, err
		}
		return s.svc.Deployments.List(ctx, by, filter, page)
	}))
	rs.write(http.MethodPost, wire.PathDeployments, "deployment.create", mutation(s,
		func(ctx context.Context, by app.Caller, in input) (app.DeploymentView, error) {
			req, err := decode[wire.CreateDeploymentRequest](in)
			if err != nil {
				return app.DeploymentView{}, err
			}
			if req.Kind != deployments.KindDeploy {
				return app.DeploymentView{}, invalid("kind must be %q; roll back with POST %s", deployments.KindDeploy, wire.PathDeploymentRollback)
			}
			return s.svc.Deployments.Create(ctx, by, createDeploymentOf(req))
		},
		accepted))
	rs.read(wire.PathDeployment, "deployment.read", reading(s, func(ctx context.Context, by app.Caller, in input) (app.DeploymentView, error) {
		id, err := in.id("id")
		if err != nil {
			return app.DeploymentView{}, err
		}
		return s.svc.Deployments.Get(ctx, by, id)
	}))
	rs.write(http.MethodPost, wire.PathDeploymentRollback, "deployment.rollback", mutation(s,
		func(ctx context.Context, by app.Caller, in input) (app.DeploymentView, error) {
			id, err := in.id("id")
			if err != nil {
				return app.DeploymentView{}, err
			}
			req, err := decodeOptional[wire.RollbackRequest](in)
			if err != nil {
				return app.DeploymentView{}, err
			}
			return s.svc.Deployments.Rollback(ctx, by, id, req)
		},
		accepted))
	rs.write(http.MethodPost, wire.PathDeploymentCancel, "job.cancel", mutation(s,
		func(ctx context.Context, by app.Caller, in input) (app.DeploymentView, error) {
			id, err := in.id("id")
			if err != nil {
				return app.DeploymentView{}, err
			}
			return s.svc.Deployments.Cancel(ctx, by, id)
		},
		func(d app.DeploymentView) (int, any) { return http.StatusOK, d }))
}

func accepted(d app.DeploymentView) (int, any) { return http.StatusAccepted, d }

// decodeOptional is decode for a body that may be empty (all defaults).
func decodeOptional[T any](in input) (T, error) {
	if len(in.body) == 0 {
		var zero T
		return zero, nil
	}
	return decode[T](in)
}

func createDeploymentOf(req wire.CreateDeploymentRequest) app.CreateDeployment {
	images := make([]app.RequestedImage, len(req.Images))
	for i, image := range req.Images {
		images[i] = app.RequestedImage{Service: image.Service, Digest: image.Digest}
	}
	return app.CreateDeployment{AppTargetID: req.AppTargetID, CommitSHA: req.CommitSHA, Images: images}
}

func parseDeploymentFilter(v url.Values) (database.DeploymentFilter, error) {
	var f database.DeploymentFilter
	for name, dst := range map[string]*domain.ID{wire.QueryAppID: &f.AppID, wire.QueryAppTargetID: &f.AppTargetID, wire.QueryEnvironmentID: &f.EnvironmentID} {
		if raw := v.Get(name); raw != "" {
			id, err := domain.ParseID(raw)
			if err != nil {
				return f, invalid("query parameter %s is not an id", name)
			}
			*dst = id
		}
	}
	if raw := v.Get(wire.QueryState); raw != "" {
		state := deployments.State(raw)
		if !slices.Contains(deployments.AllStates(), state) {
			return f, invalid("query parameter %s is not a deployment state", wire.QueryState)
		}
		f.State = state
	}
	return f, nil
}
