package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/domain"
)

const (
	routeAccessPublic = "public"
	routeAccessOwners = "owners"

	publicRouteWarning = "warning: a public route is reachable from the internet with no authentication; the app owns its own auth"
)

func newAppsExposeCmd(env []string) *cobra.Command {
	var hostname, service, access string
	var port int
	cmd := &cobra.Command{
		Use:   "expose <app> <environment> --hostname <fqdn> --service <service> --port <n> [--access public|owners]",
		Short: "Publish a service port of an application through its node's Cloudflare Tunnel (experimental)",
		Long: "Request a route from the node's Cloudflare Tunnel to a port the target's newest known-good deployment\n" +
			"publishes on 127.0.0.1 or 0.0.0.0. The hostname must sit under the configured Cloudflare zone. An access of\n" +
			"public, the default, makes the app reachable from the internet with no authentication; owners puts it behind\n" +
			"Cloudflare Access for the owners. The request is a plan and waits for approval when policy asks (a public\n" +
			"route is high risk). A target with no known-good deployment yet gets a route that waits for one.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if hostname == "" || service == "" || port == 0 {
				return usageErrorf("--hostname, --service and --port are required")
			}
			if access == "" {
				access = routeAccessPublic
			}
			if access != routeAccessPublic && access != routeAccessOwners {
				return usageErrorf("--access must be %s or %s", routeAccessPublic, routeAccessOwners)
			}
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			_, target, err := resolveAppTarget(cmd.Context(), api, args[0], args[1])
			if err != nil {
				return err
			}
			if access == routeAccessPublic {
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(), publicRouteWarning)
			}
			res, err := api.ExposeAppRoute(cmd.Context(), target.ID, wire.ExposeAppRouteRequest{Hostname: hostname, Service: service, Port: port, Access: access})
			if err != nil {
				return err
			}
			return routeSubmissionOutput(cmd, res)
		},
	}
	cmd.Flags().StringVar(&hostname, "hostname", "", "hostname under the Cloudflare zone")
	cmd.Flags().StringVar(&service, "service", "", "Compose service that publishes the port")
	cmd.Flags().IntVar(&port, "port", 0, "published port")
	cmd.Flags().StringVar(&access, "access", routeAccessPublic, "public (no authentication) | owners (Cloudflare Access)")
	return cmd
}

func newAppsUnexposeCmd(env []string) *cobra.Command {
	var hostname string
	cmd := &cobra.Command{
		Use:   "unexpose <app> <environment> --hostname <fqdn>",
		Short: "Remove a route of an application (experimental)",
		Long: "Request the removal of the route for the hostname. It removes the DNS record, then the ingress rule, then\n" +
			"the Access app, and waits for approval when policy asks. The hostname can be exposed again afterwards.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if hostname == "" {
				return usageErrorf("--hostname is required")
			}
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			_, target, err := resolveAppTarget(cmd.Context(), api, args[0], args[1])
			if err != nil {
				return err
			}
			res, err := api.UnexposeAppRoute(cmd.Context(), target.ID, hostname)
			if err != nil {
				return err
			}
			return routeSubmissionOutput(cmd, res)
		},
	}
	cmd.Flags().StringVar(&hostname, "hostname", "", "hostname of the route")
	return cmd
}

// routeSubmissionOutput prints the job of an expose or unexpose and, when the route already exists, its row.
func routeSubmissionOutput(cmd *cobra.Command, res wire.AppRouteSubmission) error {
	return emit(cmd, res, func(w io.Writer) error {
		if _, err := fmt.Fprintln(w, describeSubmission(res.Submission)); err != nil {
			return err
		}
		if res.Route == nil {
			return nil
		}
		_, err := fmt.Fprintf(w, "route %s -> %s:%d (%s) is %s\n", res.Route.Hostname, res.Route.Service, res.Route.Port, res.Route.Access, res.Route.Phase)
		return err
	})
}

func newAppsRoutesCmd(env []string) *cobra.Command {
	return &cobra.Command{
		Use:   "routes [<app> [<environment>]]",
		Short: "List the routes of applications (experimental)",
		Args:  cobra.MaximumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			routes, labels, err := listRoutes(cmd.Context(), api, args)
			if err != nil {
				return err
			}
			return emit(cmd, wire.Page[wire.AppRoute]{Items: routes}, func(w io.Writer) error { return writeRoutes(w, routes, labels) })
		},
	}
}

// listRoutes reads the routes of every app, of one app, or of one app's environment, and names their targets.
func listRoutes(ctx context.Context, api *client.Client, args []string) ([]wire.AppRoute, map[domain.ID]string, error) {
	switch len(args) {
	case 0:
		apps, err := allApps(ctx, api)
		if err != nil {
			return nil, nil, err
		}
		page, err := api.ListAppRoutes(ctx)
		return page.Items, targetLabels(apps), err
	case 1:
		id, err := resolveApp(ctx, api, args[0])
		if err != nil {
			return nil, nil, err
		}
		app, err := api.GetApp(ctx, id)
		if err != nil {
			return nil, nil, err
		}
		routes, err := appRoutes(ctx, api, app)
		return routes, targetLabels([]wire.App{app}), err
	}
	app, target, err := resolveAppTarget(ctx, api, args[0], args[1])
	if err != nil {
		return nil, nil, err
	}
	page, err := api.ListAppTargetRoutes(ctx, target.ID)
	return page.Items, targetLabels([]wire.App{app}), err
}

// appRoutes are the routes of every target of the app.
func appRoutes(ctx context.Context, api *client.Client, app wire.App) ([]wire.AppRoute, error) {
	page, err := api.ListAppRoutes(ctx)
	if err != nil {
		return nil, err
	}
	labels := targetLabels([]wire.App{app})
	var routes []wire.AppRoute
	for _, r := range page.Items {
		if _, ours := labels[r.AppTargetID]; ours {
			routes = append(routes, r)
		}
	}
	return routes, nil
}

func allApps(ctx context.Context, api *client.Client) ([]wire.App, error) {
	query := wire.PageQuery{Limit: wire.MaxLimit}
	var apps []wire.App
	for {
		page, err := api.ListApps(ctx, query)
		if err != nil {
			return nil, err
		}
		apps = append(apps, page.Items...)
		if page.NextCursor == "" {
			return apps, nil
		}
		query.Cursor = page.NextCursor
	}
}

// targetLabels names each target "<app>/<environment>".
func targetLabels(apps []wire.App) map[domain.ID]string {
	labels := map[domain.ID]string{}
	for _, a := range apps {
		for _, t := range a.Targets {
			labels[t.ID] = a.Name + "/" + t.Environment
		}
	}
	return labels
}

func writeRoutes(w io.Writer, routes []wire.AppRoute, labels map[domain.ID]string) error {
	rows := make([][]string, len(routes))
	for i, r := range routes {
		target := labels[r.AppTargetID]
		if target == "" {
			target = string(r.AppTargetID)
		}
		phase := r.Phase
		if r.LastError != "" {
			phase += ": " + r.LastError
		}
		rows[i] = []string{r.Hostname, target, fmt.Sprintf("%s:%d", r.Service, r.Port), r.Access, phase}
	}
	return table(w, []string{"HOSTNAME", "TARGET", "SERVICE:PORT", "ACCESS", "PHASE"}, rows)
}
