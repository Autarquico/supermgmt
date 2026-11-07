package cli

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/api/wire"
)

const (
	routeAccessPublic = "public"
	routeAccessOwners = "owners"

	publicRouteWarning = "warning: a public route is reachable from the internet with no authentication; the service on the port owns its own auth"
)

func newNodesExposeCmd(env []string) *cobra.Command {
	var hostname, access string
	var port int
	cmd := &cobra.Command{
		Use:   "expose <node> --hostname <fqdn> --port <n> [--access public|owners]",
		Short: "Publish a port of a node through its Cloudflare Tunnel (experimental)",
		Long: "Request a route from the node's Cloudflare Tunnel to a port on the node. The hostname must sit under the\n" +
			"configured Cloudflare zone. An access of public, the default, makes the port reachable from the internet with\n" +
			"no authentication; owners puts it behind Cloudflare Access for the owners. The request is a plan and waits for\n" +
			"approval when policy asks (a public route is high risk).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if hostname == "" || port == 0 {
				return usageErrorf("--hostname and --port are required")
			}
			if access != routeAccessPublic && access != routeAccessOwners {
				return usageErrorf("--access must be %s or %s", routeAccessPublic, routeAccessOwners)
			}
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			node, err := resolveNode(cmd.Context(), api, args[0])
			if err != nil {
				return err
			}
			if access == routeAccessPublic {
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(), publicRouteWarning)
			}
			res, err := api.ExposeNodeRoute(cmd.Context(), node, wire.ExposeNodeRouteRequest{Hostname: hostname, Port: port, Access: access})
			if err != nil {
				return err
			}
			return routeSubmissionOutput(cmd, res)
		},
	}
	cmd.Flags().StringVar(&hostname, "hostname", "", "hostname under the Cloudflare zone")
	cmd.Flags().IntVar(&port, "port", 0, "port of the node to publish")
	cmd.Flags().StringVar(&access, "access", routeAccessPublic, "public (no authentication) | owners (Cloudflare Access)")
	return cmd
}

func newNodesUnexposeCmd(env []string) *cobra.Command {
	var hostname string
	cmd := &cobra.Command{
		Use:   "unexpose <node> --hostname <fqdn>",
		Short: "Remove a route of a node (experimental)",
		Long: "Request the removal of the route for the hostname. It removes the DNS record, then the ingress rule, then\n" +
			"the Access app, and waits for approval when policy asks. The hostname can be exposed again afterwards.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if hostname == "" {
				return usageErrorf("--hostname is required")
			}
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			node, err := resolveNode(cmd.Context(), api, args[0])
			if err != nil {
				return err
			}
			res, err := api.UnexposeNodeRoute(cmd.Context(), node, hostname)
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
func routeSubmissionOutput(cmd *cobra.Command, res wire.NodeRouteSubmission) error {
	if res.Submission.Policy.ApprovalRequired {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "to approve: sm jobs approve %s --plan-hash %s\n", res.Submission.Job.ID, res.Submission.Job.PlanHash)
	}
	return emit(cmd, res, func(w io.Writer) error {
		if _, err := fmt.Fprintln(w, describeSubmission(res.Submission)); err != nil {
			return err
		}
		if res.Route == nil {
			return nil
		}
		_, err := fmt.Fprintf(w, "route %s -> port %d (%s) is %s\n", res.Route.Hostname, res.Route.Port, res.Route.Access, res.Route.Phase)
		return err
	})
}

func newNodesRoutesCmd(env []string) *cobra.Command {
	var all bool
	cmd := &cobra.Command{
		Use:   "routes [<node>]",
		Short: "List the routes of every node, or of one (experimental)",
		Long:  "List the routes of every node, or of one. --all also lists removed routes with the note that says why.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			nodes, err := allNodes(cmd.Context(), api, wire.NodeQuery{})
			if err != nil {
				return err
			}
			var page wire.Page[wire.NodeRoute]
			if len(args) == 1 {
				node, err := resolveNode(cmd.Context(), api, args[0])
				if err != nil {
					return err
				}
				page, err = api.ListNodeRoutes(cmd.Context(), node, all)
				if err != nil {
					return err
				}
			} else if page, err = api.ListAllNodeRoutes(cmd.Context(), all); err != nil {
				return err
			}
			names := map[string]string{}
			for _, n := range nodes {
				names[string(n.ID)] = n.Name
			}
			return emit(cmd, page, func(w io.Writer) error { return writeNodeRoutes(w, page.Items, names) })
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "include removed routes")
	return cmd
}

func writeNodeRoutes(w io.Writer, routes []wire.NodeRoute, nodeNames map[string]string) error {
	rows := make([][]string, len(routes))
	for i, r := range routes {
		node := nodeNames[string(r.NodeID)]
		if node == "" {
			node = string(r.NodeID)
		}
		phase := r.Phase
		if r.LastError != "" {
			phase += ": " + r.LastError
		}
		rows[i] = []string{node, r.Hostname, fmt.Sprint(r.Port), r.Access, phase}
	}
	return table(w, []string{"NODE", "HOSTNAME", "PORT", "ACCESS", "PHASE"}, rows)
}
