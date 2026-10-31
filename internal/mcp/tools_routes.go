package mcp

import (
	"context"
	"fmt"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

// The app route tools (ADR-0040). Exposing is a plan the API always turns into a job: a public route is high
// risk and an mcp identity's writes of operational risk or more wait for approval.

const (
	routeAccessPublic = "public"
	routeAccessOwners = "owners"
)

type listAppRoutesInput struct {
	App         string `json:"app,omitempty" jsonschema:"only routes of this app (id or exact name)"`
	Environment string `json:"environment,omitempty" jsonschema:"only routes of this environment (id or exact name)"`
}

type exposeAppInput struct {
	App         string `json:"app" jsonschema:"app id or exact app name"`
	Environment string `json:"environment" jsonschema:"environment id or exact environment name of the app target"`
	Hostname    string `json:"hostname" jsonschema:"hostname under the configured Cloudflare zone"`
	Service     string `json:"service" jsonschema:"compose service that publishes the port"`
	Port        int    `json:"port" jsonschema:"published port"`
	Access      string `json:"access,omitempty" jsonschema:"public (reachable from the internet with no authentication, high risk) or owners (behind Cloudflare Access); default public"`
}

type unexposeAppInput struct {
	App         string `json:"app" jsonschema:"app id or exact app name"`
	Environment string `json:"environment" jsonschema:"environment id or exact environment name of the app target"`
	Hostname    string `json:"hostname" jsonschema:"hostname of the route to remove"`
}

func listAppRoutes(ctx context.Context, api API, in listAppRoutesInput) (listResult[RouteView], error) {
	targets, filtered, err := routeTargets(ctx, api, in)
	if err != nil {
		return listResult[RouteView]{}, err
	}
	page, err := api.ListAppRoutes(ctx)
	if err != nil {
		return listResult[RouteView]{}, err
	}
	items := []RouteView{}
	for _, r := range page.Items {
		if _, ok := targets[r.AppTargetID]; ok || !filtered {
			items = append(items, ViewRoute(r))
		}
	}
	return listResult[RouteView]{Items: items}, nil
}

func exposeApp(ctx context.Context, api API, in exposeAppInput) (WriteResult, error) {
	access := in.Access
	if access == "" {
		access = routeAccessPublic
	}
	if access != routeAccessPublic && access != routeAccessOwners {
		return WriteResult{}, invalidArgument("access must be public or owners")
	}
	target, err := resolveAppTarget(ctx, api, in.App, in.Environment)
	if err != nil {
		return WriteResult{}, err
	}
	res, err := api.ExposeAppRoute(ctx, target.ID, wire.ExposeAppRouteRequest{Hostname: in.Hostname, Service: in.Service, Port: in.Port, Access: access})
	return routeResult(res, fmt.Sprintf("expose %s of %s", access, operatorLine(in.Hostname)), target.ID), err
}

func unexposeApp(ctx context.Context, api API, in unexposeAppInput) (WriteResult, error) {
	target, err := resolveAppTarget(ctx, api, in.App, in.Environment)
	if err != nil {
		return WriteResult{}, err
	}
	res, err := api.UnexposeAppRoute(ctx, target.ID, in.Hostname)
	return routeResult(res, "unexpose "+operatorLine(in.Hostname), target.ID), err
}

// routeResult is built from control-plane fields and the caller's own input only.
func routeResult(res wire.AppRouteSubmission, what string, target domain.ID) WriteResult {
	out := submissionResult(res.Submission)
	out.Summary = fmt.Sprintf("%s on app target %s: job %s", what, target, res.Submission.Job.State)
	return out
}

// routeTargets are the app targets the input selects; filtered is false when it selects everything.
func routeTargets(ctx context.Context, api API, in listAppRoutesInput) (targets map[domain.ID]struct{}, filtered bool, _ error) {
	if in.App == "" && in.Environment == "" {
		return nil, false, nil
	}
	apps, err := appsOf(ctx, api, in.App)
	if err != nil {
		return nil, true, err
	}
	targets = map[domain.ID]struct{}{}
	for _, a := range apps {
		for _, t := range a.Targets {
			if in.Environment == "" || inEnvironment(t, in.Environment) {
				targets[t.ID] = struct{}{}
			}
		}
	}
	return targets, true, nil
}

// resolveAppTarget accepts an app (id or exact name) and an environment (id or exact name) and returns the
// app's target there.
func resolveAppTarget(ctx context.Context, api API, appRef, environment string) (wire.AppTarget, error) {
	app, err := findApp(ctx, api, appRef)
	if err != nil {
		return wire.AppTarget{}, err
	}
	var hits []wire.AppTarget
	for _, t := range app.Targets {
		if inEnvironment(t, environment) {
			hits = append(hits, t)
		}
	}
	return uniqueHit("target in environment", environment, hits)
}

func inEnvironment(t wire.AppTarget, ref string) bool {
	return t.Environment == ref || string(t.EnvironmentID) == ref
}

// appsOf is the app named by ref, or every app when ref is empty.
func appsOf(ctx context.Context, api API, ref string) ([]wire.App, error) {
	if ref != "" {
		app, err := findApp(ctx, api, ref)
		return []wire.App{app}, err
	}
	var apps []wire.App
	cursor := ""
	for range maxResolvePages {
		page, err := api.ListApps(ctx, resolvePage(cursor))
		if err != nil {
			return nil, err
		}
		apps = append(apps, page.Items...)
		if page.NextCursor == "" {
			return apps, nil
		}
		cursor = page.NextCursor
	}
	return nil, invalidArgument("too many apps to filter by environment; give an app")
}

// findApp accepts an app id or an exact app name.
func findApp(ctx context.Context, api API, ref string) (wire.App, error) {
	id, parsed := domain.ParseID(ref)
	return findUnique(ctx, "app", ref,
		func(cursor string) (wire.Page[wire.App], error) { return api.ListApps(ctx, resolvePage(cursor)) },
		func(a wire.App) bool { return a.Name == ref || parsed == nil && a.ID == id })
}
