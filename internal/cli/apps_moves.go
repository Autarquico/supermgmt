package cli

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/domain"
)

func newAppsMoveCmd(env []string) *cobra.Command {
	var to string
	var cleanup, abandon bool
	cmd := &cobra.Command{
		Use:   "move <app> <environment> (--to <node> | --cleanup-source | --abandon)",
		Short: "Move an application to another node (experimental)",
		Long: "Request the move of the target to a destination node. The destination is checked first and the target keeps\n" +
			"running on its node until the destination passes its health checks, except that a move of an app with\n" +
			"volumes stops the app while their data is copied. The request prints whether the app stops and which\n" +
			"volumes are copied, and waits for approval when policy asks. The routes of the target are repointed to the\n" +
			"new node inside the move; the request lists their hostnames. While a routed move is open the target cannot\n" +
			"be exposed or unexposed, and tunnel setup, rotation and disable are refused on both nodes.\n\n" +
			"--cleanup-source removes the containers a finished move left stopped on the old node; volumes are never\n" +
			"removed. --abandon records a move that halted while it was undoing itself as rolled back, leaving both\n" +
			"nodes as they are. A move whose job ended is resumed by running the same command again.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			modes := 0
			for _, on := range []bool{to != "", cleanup, abandon} {
				if on {
					modes++
				}
			}
			if modes != 1 {
				return usageErrorf("give exactly one of --to, --cleanup-source and --abandon")
			}
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			_, target, err := resolveAppTarget(cmd.Context(), api, args[0], args[1])
			if err != nil {
				return err
			}
			switch {
			case cleanup:
				sub, err := api.CleanupAppMoveSource(cmd.Context(), target.ID)
				if err != nil {
					return err
				}
				return submissionOutput(cmd, sub)
			case abandon:
				sub, err := api.AbandonAppMove(cmd.Context(), target.ID)
				if err != nil {
					return err
				}
				return submissionOutput(cmd, sub)
			}
			dest, err := resolveNode(cmd.Context(), api, to)
			if err != nil {
				return err
			}
			res, err := api.MoveApp(cmd.Context(), target.ID, dest)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintln(cmd.ErrOrStderr(), moveWarning(args[0]+"/"+args[1], res.Move))
			return emit(cmd, res, func(w io.Writer) error {
				_, err := fmt.Fprintf(w, "%s\nmove %s is %s\n", describeSubmission(res.Submission), res.Move.ID, res.Move.Phase)
				return err
			})
		},
	}
	cmd.Flags().StringVar(&to, "to", "", "destination node (name or id)")
	cmd.Flags().BoolVar(&cleanup, "cleanup-source", false, "remove the containers a finished move left on the old node")
	cmd.Flags().BoolVar(&abandon, "abandon", false, "record a move halted while undoing itself as rolled back")
	return cmd
}

// moveWarning says before approval whether the move stops the app, and which volumes it copies.
func moveWarning(label string, m wire.AppMove) string {
	routes := routesWarning(m)
	if !m.Stateful {
		return fmt.Sprintf("%s has no volume data to copy: the move does not stop it", label) + routes
	}
	names := make([]string, len(m.Volumes))
	for i, v := range m.Volumes {
		names[i] = fmt.Sprintf("%s (%s, %s)", v.Name, v.Service, v.Mount)
	}
	out := fmt.Sprintf("warning: moving %s stops it while its data is copied; it stays down until it is healthy on the new node.\nvolumes: %s",
		label, strings.Join(names, ", "))
	if routes != "" {
		out += routes + "\nwarning: if the move is rolled back after the hostnames are repointed, they serve errors until the app is " +
			"healthy again on the old node; writes made on the new node stay in its volumes"
	}
	return out
}

// routesWarning lists the hostnames the move repoints, or is empty when the target has no route.
func routesWarning(m wire.AppMove) string {
	if len(m.Routes) == 0 {
		return ""
	}
	names := make([]string, len(m.Routes))
	for i, r := range m.Routes {
		names[i] = r.Hostname
		if r.FrozenPhase == "waiting" {
			names[i] += " (waiting: activated on the new node when the move is done)"
		}
	}
	return "\nroutes repointed to the new node: " + strings.Join(names, ", ")
}

func newAppsMovesCmd(env []string) *cobra.Command {
	return &cobra.Command{
		Use:   "moves <app> <environment>",
		Short: "List the moves of an application target (experimental)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			_, target, err := resolveAppTarget(cmd.Context(), api, args[0], args[1])
			if err != nil {
				return err
			}
			page, err := api.ListAppMoves(cmd.Context(), target.ID)
			if err != nil {
				return err
			}
			names, err := nodeNames(cmd.Context(), api)
			if err != nil {
				return err
			}
			return emit(cmd, page, func(w io.Writer) error { return writeMoves(w, page.Items, names) })
		},
	}
}

func nodeNames(ctx context.Context, api *client.Client) (map[domain.ID]string, error) {
	all, err := allNodes(ctx, api, wire.NodeQuery{})
	names := make(map[domain.ID]string, len(all))
	for _, n := range all {
		names[n.ID] = n.Name
	}
	return names, err
}

func writeMoves(w io.Writer, moves []wire.AppMove, names map[domain.ID]string) error {
	nameOf := func(id domain.ID) string {
		if n := names[id]; n != "" {
			return n
		}
		return string(id)
	}
	rows := make([][]string, len(moves))
	for i, m := range moves {
		phase := m.Phase
		if m.HaltedPhase != "" {
			phase += " in " + m.HaltedPhase
		}
		if m.LastError != "" {
			phase += ": " + m.LastError
		}
		volumes := make([]string, len(m.Volumes))
		for j, v := range m.Volumes {
			volumes[j] = v.Name + ":" + v.State
		}
		routes := make([]string, len(m.Routes))
		for j, r := range m.Routes {
			routes[j] = r.Hostname + ":" + r.State
		}
		rows[i] = []string{
			phase, nameOf(m.SourceNodeID), nameOf(m.DestNodeID), strings.Join(volumes, ","), strings.Join(routes, ","),
			m.UpdatedAt.Format("2006-01-02 15:04"),
		}
	}
	return table(w, []string{"PHASE", "FROM", "TO", "VOLUMES", "ROUTES", "UPDATED"}, rows)
}
