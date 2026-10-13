package client

import (
	"context"
	"net/url"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

// Query parameters of GET /deployments.
const (
	queryDeploymentApp         = "app_id"
	queryDeploymentAppTarget   = "app_target_id"
	queryDeploymentEnvironment = "environment_id"
)

// DeploymentQuery filters GET /deployments. Empty fields do not filter.
type DeploymentQuery struct {
	wire.PageQuery
	AppID         domain.ID
	AppTargetID   domain.ID
	EnvironmentID domain.ID
	State         string
}

func (q DeploymentQuery) values() url.Values {
	v := q.Values()
	for name, id := range map[string]domain.ID{
		queryDeploymentApp:         q.AppID,
		queryDeploymentAppTarget:   q.AppTargetID,
		queryDeploymentEnvironment: q.EnvironmentID,
	} {
		if id != "" {
			v.Set(name, string(id))
		}
	}
	if q.State != "" {
		v.Set(wire.QueryState, q.State)
	}
	return v
}

// ---- apps and targets ------------------------------------------------------

func (c *Client) ListApps(ctx context.Context, q wire.PageQuery) (wire.Page[wire.App], error) {
	return call[wire.Page[wire.App]](ctx, c, get(wire.PathApps, q.Values()))
}

func (c *Client) GetApp(ctx context.Context, id domain.ID) (wire.App, error) {
	return call[wire.App](ctx, c, get(wire.Path(wire.PathApp, string(id)), nil))
}

func (c *Client) CreateApp(ctx context.Context, r wire.CreateAppRequest) (wire.Direct[wire.App], error) {
	return call[wire.Direct[wire.App]](ctx, c, post(wire.PathApps, r))
}

func (c *Client) ListAppTargets(ctx context.Context, app domain.ID) (wire.Page[wire.AppTarget], error) {
	return call[wire.Page[wire.AppTarget]](ctx, c, get(wire.Path(wire.PathAppTargets, string(app)), nil))
}

func (c *Client) CreateAppTarget(ctx context.Context, app domain.ID, r wire.CreateAppTargetRequest) (wire.Direct[wire.AppTarget], error) {
	return call[wire.Direct[wire.AppTarget]](ctx, c, post(wire.Path(wire.PathAppTargets, string(app)), r))
}

// ---- deployments -----------------------------------------------------------

func (c *Client) ListDeployments(ctx context.Context, q DeploymentQuery) (wire.Page[wire.Deployment], error) {
	return call[wire.Page[wire.Deployment]](ctx, c, get(wire.PathDeployments, q.values()))
}

func (c *Client) GetDeployment(ctx context.Context, id domain.ID) (wire.Deployment, error) {
	return call[wire.Deployment](ctx, c, get(wire.Path(wire.PathDeployment, string(id)), nil))
}

func (c *Client) CreateDeployment(ctx context.Context, r wire.CreateDeploymentRequest) (wire.Deployment, error) {
	return call[wire.Deployment](ctx, c, post(wire.PathDeployments, r))
}

func (c *Client) RollbackDeployment(ctx context.Context, id domain.ID, r wire.RollbackRequest) (wire.Deployment, error) {
	return call[wire.Deployment](ctx, c, post(wire.Path(wire.PathDeploymentRollback, string(id)), r))
}

func (c *Client) CancelDeployment(ctx context.Context, id domain.ID) (wire.Deployment, error) {
	return call[wire.Deployment](ctx, c, post(wire.Path(wire.PathDeploymentCancel, string(id)), nil))
}
