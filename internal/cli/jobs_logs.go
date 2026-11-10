package cli

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/textsafe"
)

// newJobsLogsCmd prints what happened to a job: the audit events whose
// resource is the job (created, approved, claimed, each state it reached and
// why it failed). They are read from the event log, so they need event.read.
func newJobsLogsCmd(env []string) *cobra.Command {
	var follow bool
	cmd := &cobra.Command{
		Use:   "logs <job-id>",
		Short: "Show the events of a job: each state it reached, who moved it and why it failed",
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
			q := wire.EventQuery{ResourceType: domain.ResourceJob, ResourceID: id}
			if follow {
				return followEvents(cmd, api, q)
			}
			var events []wire.Event
			for {
				page, err := api.ListEvents(cmd.Context(), q)
				if err != nil {
					return err
				}
				events = append(events, page.Items...)
				if page.NextCursor == "" {
					break
				}
				q.Cursor = page.NextCursor
			}
			return emit(cmd, events, func(w io.Writer) error { return writeJobLogs(w, events) })
		},
	}
	cmd.Flags().BoolVar(&follow, "follow", false, "keep streaming the job's new events; reconnects by itself")
	return cmd
}

func writeJobLogs(w io.Writer, events []wire.Event) error {
	if len(events) == 0 {
		_, err := fmt.Fprintln(w, "no events for this job")
		return err
	}
	rows := make([][]string, len(events))
	for i, e := range events {
		rows[i] = []string{
			formatTime(e.Timestamp), textsafe.Line(e.Action), string(e.Result),
			fmt.Sprintf("%s:%s", e.Actor.Type, e.Actor.ID), textsafe.Line(compactData(e.Data)),
		}
	}
	return table(w, []string{"TIME", "ACTION", "RESULT", "ACTOR", "DETAIL"}, rows)
}

func compactData(data map[string]any) string {
	if len(data) == 0 {
		return "-"
	}
	text, err := json.Marshal(data)
	if err != nil {
		return "-"
	}
	return string(text)
}
