package cli

import (
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/domain"
)

// appLogsPoll is how often `sm apps logs --follow` asks for new lines.
var appLogsPoll = 2 * time.Second

// newAppsCmd reads what runs on the nodes as Compose projects (spec app-panels). It only reads: the actions on
// an app's containers are the `sm services` ones. The group takes no arguments, so the retired app commands
// (`apps expose`, `apps move`) stay unknown.
func newAppsCmd(env []string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "apps",
		Short: "List the apps (Compose projects) on the nodes, show one and read its logs",
		Args:  noArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(newAppsListCmd(env), newAppsShowCmd(env), newAppsLogsCmd(env))
	return cmd
}

func newAppsListCmd(env []string) *cobra.Command {
	return &cobra.Command{
		Use:   "list [<node>]",
		Short: "List the apps of every node, or of one (id or name)",
		Long: "List the apps with their state, restarts, current CPU and memory and recent error count. The node is read\n" +
			"live; when it cannot be, the last discovery is shown and marked stale. A node whose Docker is not accessible\n" +
			"says which command a person runs to allow it. The error count needs permission to read logs.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			query := wire.AppsQuery{Stats: true, Errors: true}
			var nodes []wire.NodeApps
			if len(args) == 1 {
				node, err := resolveNode(cmd.Context(), api, args[0])
				if err != nil {
					return err
				}
				one, err := api.ListNodeApps(cmd.Context(), node, query)
				if err != nil {
					return err
				}
				nodes = []wire.NodeApps{one}
			} else {
				page, err := api.ListApps(cmd.Context(), query)
				if err != nil {
					return err
				}
				nodes = page.Items
			}
			return emit(cmd, nodes, func(w io.Writer) error { return writeNodeApps(w, nodes) })
		},
	}
}

func writeNodeApps(w io.Writer, nodes []wire.NodeApps) error {
	var rows [][]string
	for _, n := range nodes {
		for _, a := range n.Apps {
			rows = append(rows, []string{
				n.Node, a.Project, a.State + appStaleMark(a), strconv.Itoa(len(a.Components)),
				countOrDash(a.RestartCount), useText(a.Stats), countOrDash(a.RecentErrors), formatTime(a.ReadAt),
			})
		}
	}
	if err := table(w, []string{"NODE", "APP", "STATE", "COMPONENTS", "RESTARTS", "CPU / MEMORY", "ERRORS", "READ"}, rows); err != nil {
		return err
	}
	for _, n := range nodes {
		switch n.Problem {
		case wire.AppsProblemDocker:
			_, _ = fmt.Fprintf(w, "%s: apps cannot be read, Docker is not accessible; a person can allow it with: %s\n", n.Node, n.Hint)
		case wire.AppsProblemUnreachable:
			_, _ = fmt.Fprintf(w, "%s: the node cannot be reached; showing the last discovery\n", n.Node)
		}
		if len(n.OtherServices) > 0 {
			_, _ = fmt.Fprintf(w, "%s: %d other services outside an app (sm services list %s)\n", n.Node, len(n.OtherServices), n.Node)
		}
	}
	return nil
}

func appStaleMark(a wire.App) string {
	if a.Stale {
		return " (stale)"
	}
	return ""
}

func countOrDash(n *int) string {
	if n == nil {
		return "-"
	}
	return strconv.Itoa(*n)
}

func useText(u *wire.ResourceUse) string {
	if u == nil {
		return "-"
	}
	return fmt.Sprintf("%.1f%% / %s", u.CPUPercent, byteSize(u.MemUsedBytes))
}

func byteSize(n uint64) string {
	const unit = 1024
	size, suffix := float64(n), "B"
	for _, s := range []string{"KiB", "MiB", "GiB", "TiB"} {
		if size < unit {
			break
		}
		size, suffix = size/unit, s
	}
	return fmt.Sprintf("%.1f%s", size, suffix)
}

func newAppsShowCmd(env []string) *cobra.Command {
	return &cobra.Command{
		Use:   "show <node> <project>",
		Short: "Show an app: components, ports, volumes and configuration (secrets redacted)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			node, err := resolveNode(cmd.Context(), api, args[0])
			if err != nil {
				return err
			}
			app, err := api.GetNodeApp(cmd.Context(), node, args[1], wire.AppsQuery{Stats: true, Errors: true})
			if err != nil {
				return err
			}
			return emit(cmd, app, func(w io.Writer) error { return writeApp(w, app) })
		},
	}
}

func writeApp(w io.Writer, a wire.App) error {
	if err := fields(w, [][2]string{
		{"app", a.Project},
		{"node", a.Node},
		{"state", a.State + appStaleMark(a)},
		{"read", formatTime(a.ReadAt)},
		{"restarts", countOrDash(a.RestartCount)},
		{"cpu / memory", useText(a.Stats)},
		{"errors", countOrDash(a.RecentErrors)},
	}); err != nil {
		return err
	}
	rows := make([][]string, len(a.Components))
	for i, c := range a.Components {
		rows[i] = []string{c.Name, c.Status, orDash(c.Health), c.Image, countOrDash(c.RestartCount), useText(c.Stats), countOrDash(c.RecentErrors)}
	}
	_, _ = fmt.Fprintln(w)
	if err := table(w, []string{"COMPONENT", "STATUS", "HEALTH", "IMAGE", "RESTARTS", "CPU / MEMORY", "ERRORS"}, rows); err != nil {
		return err
	}
	for _, c := range a.Components {
		writeComponentDetail(w, c)
	}
	return nil
}

func writeComponentDetail(w io.Writer, c wire.AppComponent) {
	if len(c.Ports) == 0 && len(c.Mounts) == 0 && c.Config == nil {
		return
	}
	_, _ = fmt.Fprintf(w, "\n%s\n", c.Name)
	for _, p := range c.Ports {
		_, _ = fmt.Fprintf(w, "  port    %s\n", p)
	}
	for _, m := range c.Mounts {
		_, _ = fmt.Fprintf(w, "  volume  %s -> %s (%s)\n", orDash(firstOf(m.Name, m.Source)), m.Destination, m.Type)
	}
	if c.Config == nil {
		return
	}
	_, _ = fmt.Fprintf(w, "  restart %s\n", orDash(c.Config.RestartPolicy))
	for _, e := range c.Config.Env {
		_, _ = fmt.Fprintf(w, "  env     %s\n", e)
	}
	if len(c.Config.Command) > 0 {
		_, _ = fmt.Fprintf(w, "  command %s\n", strings.Join(c.Config.Command, " "))
	}
	for _, k := range slices.Sorted(mapKeys(c.Config.Labels)) {
		_, _ = fmt.Fprintf(w, "  label   %s=%s\n", k, c.Config.Labels[k])
	}
}

func firstOf(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func mapKeys(m map[string]string) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

func newAppsLogsCmd(env []string) *cobra.Command {
	var q wire.AppLogQuery
	var follow bool
	cmd := &cobra.Command{
		Use:   "logs <node> <project> <component>",
		Short: "Show the recent logs of an app's component, follow them or search them",
		Long: "Credentials are removed from the lines before they leave the daemon. --follow keeps reading until it is\n" +
			"interrupted and says when lines were lost between two reads. --search looks for a term in a bounded window\n" +
			"of recent lines and says which window it covered; the term is never sent to the node.",
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			if follow && q.Search != "" {
				return usageErrorf("--follow and --search do not combine")
			}
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			node, err := resolveNode(cmd.Context(), api, args[0])
			if err != nil {
				return err
			}
			q.Component = args[2]
			if follow {
				return followAppLogs(cmd, api, node, args[1], q)
			}
			logs, err := api.NodeAppLogs(cmd.Context(), node, args[1], q)
			if err != nil {
				return err
			}
			return emit(cmd, logs, func(w io.Writer) error { return writeAppLogs(cmd, w, logs) })
		},
	}
	cmd.Flags().IntVar(&q.Lines, "lines", 0, fmt.Sprintf("number of lines (default %d, max %d)", wire.DefaultLogLines, wire.MaxAppLogLines))
	cmd.Flags().BoolVar(&follow, "follow", false, "keep reading new lines")
	cmd.Flags().StringVar(&q.Search, "search", "", "only lines with this text, among the recent ones")
	return cmd
}

func writeAppLogs(cmd *cobra.Command, w io.Writer, logs wire.AppLogs) error {
	for _, line := range logs.Lines {
		_, _ = fmt.Fprintln(w, line)
	}
	if logs.Window != nil {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "searched the last %d lines%s\n", logs.Window.Lines, windowSpan(logs.Window))
	}
	if logs.Truncated {
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "output was truncated by the daemon")
	}
	return nil
}

func windowSpan(w *wire.LogWindow) string {
	if w.From == nil || w.To == nil {
		return ""
	}
	return " (" + formatTime(*w.From) + " to " + formatTime(*w.To) + ")"
}

// followAppLogs prints the recent lines, then what comes after, until the command is interrupted.
func followAppLogs(cmd *cobra.Command, api *client.Client, node domain.ID, project string, q wire.AppLogQuery) error {
	out, asJSON := cmd.OutOrStdout(), wantsJSON(cmd)
	for {
		logs, err := api.NodeAppLogs(cmd.Context(), node, project, q)
		if err != nil {
			if cmd.Context().Err() != nil {
				return nil
			}
			return err
		}
		if asJSON {
			if err := writeJSON(out, logs); err != nil {
				return err
			}
		} else {
			for _, line := range logs.Lines {
				_, _ = fmt.Fprintln(out, line)
			}
		}
		if logs.Gap {
			_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "gap: some lines were not delivered")
		}
		q.Cursor = logs.Cursor
		select {
		case <-cmd.Context().Done():
			return nil
		case <-time.After(appLogsPoll):
		}
	}
}
