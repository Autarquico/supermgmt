package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/domain"
)

const defaultWatchInterval = 2 * time.Second

type jobListFlags struct {
	page     wire.PageQuery
	states   []string
	watch    bool
	interval time.Duration
}

func (f *jobListFlags) bind(cmd *cobra.Command) {
	cmd.Flags().IntVar(&f.page.Limit, "limit", 0, "maximum items per page (default 50, max 500)")
	cmd.Flags().StringVar(&f.page.Cursor, "cursor", "", "continue after this cursor")
	cmd.Flags().StringSliceVar(&f.states, "state", nil, "only jobs in this state (repeatable)")
	cmd.Flags().BoolVar(&f.watch, "watch", false, "keep running and print the list whenever it changes")
	cmd.Flags().DurationVar(&f.interval, "interval", defaultWatchInterval, "with --watch: how often to poll")
}

func (f *jobListFlags) query() (wire.JobQuery, error) {
	q := wire.JobQuery{PageQuery: f.page}
	for _, s := range f.states {
		state, err := domain.ParseJobState(s)
		if err != nil {
			return wire.JobQuery{}, usageErrorf("%s", err)
		}
		q.States = append(q.States, state)
	}
	return q, nil
}

func newJobsCmd(env []string) *cobra.Command {
	var f jobListFlags
	cmd := &cobra.Command{
		Use:   "jobs",
		Short: "List and govern jobs (default: list)",
		Args:  noArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return runJobsList(cmd, env, &f) },
	}
	f.bind(cmd)
	list := &cobra.Command{
		Use:   "list",
		Short: "List jobs",
		Args:  noArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return runJobsList(cmd, env, &f) },
	}
	cmd.AddCommand(list, newJobsGetCmd(env), newJobsApproveCmd(env), newJobsRejectCmd(env),
		newJobsResolveCmd(env), newJobsCancelCmd(env))
	return cmd
}

func runJobsList(cmd *cobra.Command, env []string, f *jobListFlags) error {
	q, err := f.query()
	if err != nil {
		return err
	}
	api, err := newClient(cmd, env)
	if err != nil {
		return err
	}
	if f.watch {
		return watchJobs(cmd, api, q, f.interval)
	}
	page, err := api.ListJobs(cmd.Context(), q)
	if err != nil {
		return err
	}
	return emit(cmd, page, func(w io.Writer) error { return writeJobs(w, page) })
}

func writeJobs(w io.Writer, page wire.Page[wire.Job]) error {
	rows := make([][]string, len(page.Items))
	for i, j := range page.Items {
		rows[i] = []string{
			string(j.ID), j.Type, string(j.State), string(j.Risk), string(j.Resource.ID),
			fmt.Sprintf("%d/%d", j.Attempts, j.MaxAttempts), formatTime(j.CreatedAt), failureCode(j.Error),
		}
	}
	if err := table(w, []string{"ID", "TYPE", "STATE", "RISK", "RESOURCE", "ATTEMPTS", "CREATED", "ERROR"}, rows); err != nil {
		return err
	}
	moreHint(w, page.NextCursor)
	return nil
}

func failureCode(f *wire.Failure) string {
	if f == nil {
		return "-"
	}
	return string(f.Code)
}

// watchJobs prints the job list whenever it changes, until interrupted. It
// holds presence, so the daemon stays resident while someone watches.
func watchJobs(cmd *cobra.Command, api *client.Client, q wire.JobQuery, interval time.Duration) error {
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() { _ = api.HoldPresence(ctx) }()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var shown, failed string
	for {
		frame, err := jobsFrame(ctx, cmd, api, q)
		switch {
		case err != nil && ctx.Err() == nil && err.Error() != failed:
			failed = err.Error()
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "error: %s\n", failed)
		case err == nil && frame != shown:
			failed, shown = "", frame
			_, _ = io.WriteString(cmd.OutOrStdout(), frame)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func jobsFrame(ctx context.Context, cmd *cobra.Command, api *client.Client, q wire.JobQuery) (string, error) {
	page, err := api.ListJobs(ctx, q)
	if err != nil {
		return "", err
	}
	var b bytes.Buffer
	if wantsJSON(cmd) {
		err = writeJSON(&b, page)
	} else {
		err = writeJobs(&b, page)
		b.WriteString("\n")
	}
	return b.String(), err
}

func newJobsGetCmd(env []string) *cobra.Command {
	return &cobra.Command{
		Use:   "get <job-id>",
		Short: "Show a job, its plan hash and what the reconciler saw",
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
			detail, err := api.GetJob(cmd.Context(), id)
			if err != nil {
				return err
			}
			return emit(cmd, detail, func(w io.Writer) error { return writeJobDetail(w, detail) })
		},
	}
}

func writeJobDetail(w io.Writer, d wire.JobDetail) error {
	j := d.Job
	pairs := [][2]string{
		{"id", string(j.ID)},
		{"type", j.Type},
		{"state", string(j.State)},
		{"risk", string(j.Risk)},
		{"retry class", string(j.RetryClass)},
		{"resource", fmt.Sprintf("%s %s", j.Resource.Type, j.Resource.ID)},
		{"plan hash", orDash(j.PlanHash)},
		{"attempts", fmt.Sprintf("%d/%d", j.Attempts, j.MaxAttempts)},
		{"created", formatTime(j.CreatedAt)},
		{"started", formatTimePtr(j.StartedAt)},
		{"finished", formatTimePtr(j.FinishedAt)},
	}
	if j.Error != nil {
		pairs = append(pairs, [2]string{"error", fmt.Sprintf("%s: %s", j.Error.Code, j.Error.Message)})
	}
	if err := fields(w, pairs); err != nil {
		return err
	}
	if len(d.Intents) == 0 {
		return nil
	}
	rows := make([][]string, len(d.Intents))
	for i, in := range d.Intents {
		rows[i] = []string{in.Step, string(in.State), in.Operation, in.Target, orDash(in.Outcome), formatTimePtr(in.DispatchedAt)}
	}
	_, _ = fmt.Fprintln(w, "\nintents:")
	return table(w, []string{"STEP", "STATE", "OPERATION", "TARGET", "OUTCOME", "DISPATCHED"}, rows)
}

// The governance commands bind the decision to the plan the user read, so
// each requires --plan-hash instead of fetching it on the user's behalf.

func newJobsApproveCmd(env []string) *cobra.Command {
	var planHash string
	cmd := &cobra.Command{
		Use:   "approve <job-id> --plan-hash <hash>",
		Short: "Approve a job awaiting approval, bound to the plan you reviewed",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return decide(cmd, env, args[0], planHash, func(api *client.Client, id domain.ID) (wire.Job, error) {
				return api.Approve(cmd.Context(), id, wire.DecisionRequest{PlanHash: planHash})
			})
		},
	}
	cmd.Flags().StringVar(&planHash, "plan-hash", "", "plan hash shown by `sm approvals`")
	return cmd
}

func newJobsRejectCmd(env []string) *cobra.Command {
	var planHash, reason string
	cmd := &cobra.Command{
		Use:   "reject <job-id> --plan-hash <hash> --reason <text>",
		Short: "Reject a job awaiting approval",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if reason == "" {
				return usageErrorf("--reason is required")
			}
			return decide(cmd, env, args[0], planHash, func(api *client.Client, id domain.ID) (wire.Job, error) {
				return api.Reject(cmd.Context(), id, wire.DecisionRequest{PlanHash: planHash, Reason: reason})
			})
		},
	}
	cmd.Flags().StringVar(&planHash, "plan-hash", "", "plan hash shown by `sm approvals`")
	cmd.Flags().StringVar(&reason, "reason", "", "why the job is rejected")
	return cmd
}

func newJobsCancelCmd(env []string) *cobra.Command {
	var planHash string
	cmd := &cobra.Command{
		Use:   "cancel <job-id> --plan-hash <hash>",
		Short: "Cancel a job that has not started running",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return decide(cmd, env, args[0], planHash, func(api *client.Client, id domain.ID) (wire.Job, error) {
				return api.CancelJob(cmd.Context(), id, planHash)
			})
		},
	}
	cmd.Flags().StringVar(&planHash, "plan-hash", "", "plan hash of the job (see `sm jobs get`)")
	return cmd
}

func newJobsResolveCmd(env []string) *cobra.Command {
	var planHash, outcome, note string
	var assumeQuiescent bool
	cmd := &cobra.Command{
		Use:   "resolve <job-id> --plan-hash <hash> --outcome <succeeded|failed|rollback_failed>",
		Short: "Settle an interrupted job after checking the node yourself",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch o := wire.Outcome(outcome); o {
			case wire.OutcomeSucceeded, wire.OutcomeFailed, wire.OutcomeRollbackFailed:
			default:
				return usageErrorf("--outcome must be succeeded, failed or rollback_failed")
			}
			return decide(cmd, env, args[0], planHash, func(api *client.Client, id domain.ID) (wire.Job, error) {
				return api.ResolveJob(cmd.Context(), id, wire.ResolveRequest{
					PlanHash: planHash, Outcome: wire.Outcome(outcome), Note: note, AssumeQuiescent: assumeQuiescent,
				})
			})
		},
	}
	cmd.Flags().StringVar(&planHash, "plan-hash", "", "plan hash of the job (see `sm jobs get`)")
	cmd.Flags().StringVar(&outcome, "outcome", "", "what actually happened on the node")
	cmd.Flags().StringVar(&note, "note", "", "why you chose this outcome (audited)")
	cmd.Flags().BoolVar(&assumeQuiescent, "assume-quiescent", false, "the node is unreachable and I accept that nothing is still running (audited)")
	return cmd
}

// decide runs one governance call on a job and prints the resulting job.
func decide(cmd *cobra.Command, env []string, jobArg, planHash string, act func(*client.Client, domain.ID) (wire.Job, error)) error {
	id, err := parseID(jobArg)
	if err != nil {
		return err
	}
	if planHash == "" {
		return usageErrorf("--plan-hash is required: it binds your decision to the plan you reviewed")
	}
	api, err := newClient(cmd, env)
	if err != nil {
		return err
	}
	job, err := act(api, id)
	if err != nil {
		return err
	}
	return emit(cmd, job, func(w io.Writer) error {
		_, err := fmt.Fprintf(w, "job %s (%s) is now %s\n", job.ID, job.Type, job.State)
		return err
	})
}

func newApprovalsCmd(env []string) *cobra.Command {
	var page *wire.PageQuery
	var showPlan bool
	cmd := &cobra.Command{
		Use:   "approvals",
		Short: "List jobs awaiting approval with the plan hash to approve against",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			result, err := api.ListApprovals(cmd.Context(), *page)
			if err != nil {
				return err
			}
			return emit(cmd, result, func(w io.Writer) error { return writeApprovals(w, result, showPlan) })
		},
	}
	page = addPageFlags(cmd)
	cmd.Flags().BoolVar(&showPlan, "plan", false, "print each plan document")
	return cmd
}

func writeApprovals(w io.Writer, page wire.Page[wire.Approval], showPlan bool) error {
	rows := make([][]string, len(page.Items))
	for i, a := range page.Items {
		rows[i] = []string{
			string(a.Job.ID), a.Job.Type, orDash(strings.Join(a.Environments, ",")),
			fmt.Sprintf("%d/%d", a.Approvals, a.Quorum), formatTime(a.ExpiresAt), a.Job.PlanHash,
		}
	}
	if err := table(w, []string{"JOB", "TYPE", "ENVIRONMENT", "APPROVALS", "EXPIRES", "PLAN HASH"}, rows); err != nil {
		return err
	}
	if showPlan {
		for _, a := range page.Items {
			if err := writePlan(w, a); err != nil {
				return err
			}
		}
	}
	moreHint(w, page.NextCursor)
	return nil
}

func writePlan(w io.Writer, a wire.Approval) error {
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, a.Plan, "  ", "  "); err != nil {
		pretty.Reset()
		pretty.Write(a.Plan)
	}
	_, err := fmt.Fprintf(w, "\nplan for %s:\n  %s\n", a.Job.ID, pretty.String())
	return err
}
