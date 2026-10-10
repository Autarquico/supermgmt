package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

func newServicesCmd(env []string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "services",
		Short: "List services, read their logs and start, stop or restart them",
		Args:  noArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(newServicesListCmd(env), newServicesGetCmd(env), newServicesLogsCmd(env))
	for _, verb := range domain.AllServiceVerbs() {
		cmd.AddCommand(newServiceActionCmd(env, verb))
	}
	return cmd
}

func newServicesListCmd(env []string) *cobra.Command {
	var q wire.PageQuery
	cmd := &cobra.Command{
		Use:   "list <node>",
		Short: "List the services of a node (id or name)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			node, err := resolveNode(cmd.Context(), api, args[0])
			if err != nil {
				return err
			}
			page, err := api.ListServices(cmd.Context(), node, q)
			if err != nil {
				return err
			}
			return emit(cmd, page, func(w io.Writer) error { return writeServices(w, page) })
		},
	}
	cmd.Flags().IntVar(&q.Limit, "limit", 0, "maximum items per page (default 50, max 500)")
	cmd.Flags().StringVar(&q.Cursor, "cursor", "", "continue after this cursor")
	return cmd
}

func writeServices(w io.Writer, page wire.Page[wire.Service]) error {
	rows := make([][]string, len(page.Items))
	for i, s := range page.Items {
		rows[i] = []string{string(s.ID), s.Name, string(s.RuntimeType), s.Status, orDash(s.Health), verbList(s.Actions)}
	}
	if err := table(w, []string{"ID", "NAME", "RUNTIME", "STATUS", "HEALTH", "ACTIONS"}, rows); err != nil {
		return err
	}
	moreHint(w, page.NextCursor)
	return nil
}

func verbList(verbs []domain.ServiceVerb) string {
	names := make([]string, len(verbs))
	for i, v := range verbs {
		names[i] = string(v)
	}
	return orDash(strings.Join(names, ","))
}

func newServicesGetCmd(env []string) *cobra.Command {
	return &cobra.Command{
		Use:   "get <service-id>",
		Short: "Show one service",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := parseID(args[0])
			if err != nil {
				return err
			}
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			service, err := api.GetService(cmd.Context(), id)
			if err != nil {
				return err
			}
			return emit(cmd, service, func(w io.Writer) error {
				return fields(w, [][2]string{
					{"id", string(service.ID)},
					{"name", service.Name},
					{"node", service.Node},
					{"runtime", string(service.RuntimeType)},
					{"kind", string(service.Kind)},
					{"native id", service.NativeID},
					{"status", service.Status},
					{"health", orDash(service.Health)},
					{"actions", verbList(service.Actions)},
					{"last seen", formatTimePtr(service.LastSeenAt)},
				})
			})
		},
	}
}

func newServicesLogsCmd(env []string) *cobra.Command {
	var q wire.LogQuery
	cmd := &cobra.Command{
		Use:   "logs <service-id>",
		Short: "Show the latest log lines of a service",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := parseID(args[0])
			if err != nil {
				return err
			}
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			chunk, err := api.ServiceLogs(cmd.Context(), id, q)
			if err != nil {
				return err
			}
			return emit(cmd, chunk, func(w io.Writer) error {
				for _, line := range chunk.Lines {
					_, _ = fmt.Fprintln(w, line)
				}
				if chunk.Truncated {
					_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "output was truncated by the daemon")
				}
				return nil
			})
		},
	}
	cmd.Flags().IntVar(&q.Lines, "lines", 0, fmt.Sprintf("number of lines (default %d, max 10000)", wire.DefaultLogLines))
	return cmd
}

func newServiceActionCmd(env []string, verb domain.ServiceVerb) *cobra.Command {
	return &cobra.Command{
		Use:   string(verb) + " <service-id>",
		Short: fmt.Sprintf("%s a service (a job; production may wait for approval)", capitalize(string(verb))),
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := parseID(args[0])
			if err != nil {
				return err
			}
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			submission, err := api.ServiceAction(cmd.Context(), id, verb)
			if err != nil {
				return err
			}
			return submissionOutput(cmd, submission)
		},
	}
}

func capitalize(s string) string { return strings.ToUpper(s[:1]) + s[1:] }
