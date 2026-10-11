package cli

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/domain"
)

func newEventsCmd(env []string) *cobra.Command {
	var q wire.EventQuery
	var resourceType, resourceID string
	var follow bool
	cmd := &cobra.Command{
		Use:   "events",
		Short: "List audit events",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if resourceType != "" {
				t, err := domain.ParseResourceType(resourceType)
				if err != nil {
					return usageErrorf("%s", err)
				}
				q.ResourceType = t
			}
			if resourceID != "" {
				id, err := parseID(resourceID)
				if err != nil {
					return err
				}
				q.ResourceID = id
			}
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			if follow {
				return followEvents(cmd, api, q)
			}
			page, err := api.ListEvents(cmd.Context(), q)
			if err != nil {
				return err
			}
			return emit(cmd, page, func(w io.Writer) error { return writeEvents(w, page) })
		},
	}
	cmd.Flags().IntVar(&q.Limit, "limit", 0, "maximum items per page (default 50, max 500)")
	cmd.Flags().StringVar(&q.Cursor, "cursor", "", "continue after this cursor")
	cmd.Flags().StringVar(&resourceType, "resource-type", "", "only events about this resource type")
	cmd.Flags().StringVar(&resourceID, "resource-id", "", "only events about this resource")
	cmd.Flags().Int64Var(&q.AfterSeq, "after-seq", 0, "only events after this sequence number")
	cmd.Flags().BoolVar(&follow, "follow", false, "keep streaming new events (from now, or after --after-seq); reconnects by itself")
	return cmd
}

// followEvents prints events as they happen: one line each, or one JSON
// object per line with --json. It ends when the credential loses access.
func followEvents(cmd *cobra.Command, api *client.Client, q wire.EventQuery) error {
	q.Limit, q.Cursor = 0, ""
	out := cmd.OutOrStdout()
	asJSON := wantsJSON(cmd)
	return api.FollowEvents(cmd.Context(), q, func(e wire.Event) error {
		if asJSON {
			return writeJSON(out, e)
		}
		_, err := fmt.Fprintf(out, "%d  %s  %s  %s  %s:%s  %s:%s  %s  %s\n",
			e.Seq, formatTime(e.Timestamp), e.Severity, e.Action, e.Actor.Type, e.Actor.ID, e.Resource.Type, e.Resource.ID, e.Result, e.CorrelationID)
		return err
	})
}

func writeEvents(w io.Writer, page wire.Page[wire.Event]) error {
	rows := make([][]string, len(page.Items))
	for i, e := range page.Items {
		rows[i] = []string{
			fmt.Sprint(e.Seq), formatTime(e.Timestamp), string(e.Severity), e.Action,
			fmt.Sprintf("%s:%s", e.Actor.Type, e.Actor.ID), fmt.Sprintf("%s:%s", e.Resource.Type, e.Resource.ID),
			string(e.Result), e.CorrelationID,
		}
	}
	if err := table(w, []string{"SEQ", "TIME", "SEVERITY", "ACTION", "ACTOR", "RESOURCE", "RESULT", "CORRELATION"}, rows); err != nil {
		return err
	}
	moreHint(w, page.NextCursor)
	return nil
}
