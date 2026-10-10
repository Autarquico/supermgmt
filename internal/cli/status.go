package cli

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/domain"
)

// statusReport is `sm status`: who you are to the daemon and what needs attention.
type statusReport struct {
	Me               wire.Me                     `json:"me"`
	Nodes            map[domain.Reachability]int `json:"nodes_by_reachability"`
	ActiveJobs       int                         `json:"active_jobs"`
	AwaitingApproval int                         `json:"awaiting_approval"`
}

var activeJobStates = []domain.JobState{domain.JobQueued, domain.JobRunning, domain.JobAwaitingApproval, domain.JobInterrupted}

func newStatusCmd(env []string) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show the daemon identity, node reachability and pending work",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			report, err := gatherStatus(cmd, api)
			if err != nil {
				return err
			}
			return emit(cmd, report, func(w io.Writer) error { return writeStatus(w, report) })
		},
	}
}

func gatherStatus(cmd *cobra.Command, api *client.Client) (statusReport, error) {
	ctx := cmd.Context()
	me, err := api.Me(ctx)
	if err != nil {
		return statusReport{}, err
	}
	report := statusReport{Me: me, Nodes: map[domain.Reachability]int{}}
	nodes := wire.NodeQuery{PageQuery: wire.PageQuery{Limit: wire.MaxLimit}}
	for {
		page, err := api.ListNodes(ctx, nodes)
		if err != nil {
			return statusReport{}, err
		}
		for _, n := range page.Items {
			report.Nodes[n.Reachability]++
		}
		if page.NextCursor == "" {
			break
		}
		nodes.Cursor = page.NextCursor
	}
	if report.ActiveJobs, err = countJobs(cmd, api, activeJobStates); err != nil {
		return statusReport{}, err
	}
	if report.AwaitingApproval, err = countJobs(cmd, api, []domain.JobState{domain.JobAwaitingApproval}); err != nil {
		return statusReport{}, err
	}
	return report, nil
}

func countJobs(cmd *cobra.Command, api *client.Client, states []domain.JobState) (int, error) {
	q := wire.JobQuery{PageQuery: wire.PageQuery{Limit: wire.MaxLimit}, States: states}
	total := 0
	for {
		page, err := api.ListJobs(cmd.Context(), q)
		if err != nil {
			return 0, err
		}
		total += len(page.Items)
		if page.NextCursor == "" {
			return total, nil
		}
		q.Cursor = page.NextCursor
	}
}

func writeStatus(w io.Writer, r statusReport) error {
	nodes := 0
	for _, n := range r.Nodes {
		nodes += n
	}
	pairs := [][2]string{
		{"caller", fmt.Sprintf("%s (%s, %s)", r.Me.DisplayName, r.Me.ActorType, r.Me.Credential)},
		{"mode", r.Me.InstanceMode},
		{"nodes", fmt.Sprint(nodes)},
	}
	for _, reach := range domain.AllReachabilities() {
		if n := r.Nodes[reach]; n > 0 {
			pairs = append(pairs, [2]string{"  " + string(reach), fmt.Sprint(n)})
		}
	}
	pairs = append(pairs, [2]string{"active jobs", fmt.Sprint(r.ActiveJobs)}, [2]string{"awaiting approval", fmt.Sprint(r.AwaitingApproval)})
	return fields(w, pairs)
}
