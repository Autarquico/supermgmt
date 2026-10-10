package cli

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

func newEventsCmd(env []string) *cobra.Command {
	var q wire.EventQuery
	var resourceType, resourceID string
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
	return cmd
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
