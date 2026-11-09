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
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// resolveService accepts a service id or <unit>@<node>, the unit name on a
// node given by id or name.
func resolveService(ctx context.Context, api *client.Client, ref string) (domain.ID, error) {
	at := strings.LastIndex(ref, "@")
	if at < 0 {
		return parseID(ref)
	}
	unit, nodeRef := ref[:at], ref[at+1:]
	if unit == "" || nodeRef == "" {
		return "", usageErrorf("%q is not <unit>@<node>", ref)
	}
	node, err := resolveNode(ctx, api, nodeRef)
	if err != nil {
		return "", err
	}
	var match []domain.ID
	for cursor := ""; ; {
		page, err := api.ListServices(ctx, node, wire.PageQuery{Limit: wire.MaxLimit, Cursor: cursor})
		if err != nil {
			return "", err
		}
		for _, s := range page.Items {
			if s.Name == unit {
				match = append(match, s.ID)
			}
		}
		if cursor = page.NextCursor; cursor == "" {
			break
		}
	}
	switch len(match) {
	case 0:
		return "", smerr.New(smerr.CodeNotFound, "", fmt.Sprintf("no service named %q on node %q", unit, nodeRef))
	case 1:
		return match[0], nil
	}
	return "", smerr.New(smerr.CodeConflict, smerr.ReasonAmbiguousTarget, fmt.Sprintf("%d services are named %q on node %q; use the id", len(match), unit, nodeRef))
}

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
		Use:   "get <service>",
		Short: "Show one service",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			id, err := resolveService(cmd.Context(), api, args[0])
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
		Use:   "logs <service>",
		Short: "Show the latest log lines of a service",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			id, err := resolveService(cmd.Context(), api, args[0])
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
	cmd := &cobra.Command{
		Use:   string(verb) + " <service>",
		Short: fmt.Sprintf("%s a service (a job; production may wait for approval)", capitalize(string(verb))),
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			id, err := resolveService(cmd.Context(), api, args[0])
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
	cmd.Flags().Bool("yes", false, "accepted for scripts; no confirmation is asked, and production jobs still wait for approval")
	return cmd
}

func capitalize(s string) string { return strings.ToUpper(s[:1]) + s[1:] }
