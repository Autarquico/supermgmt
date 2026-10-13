package cli

import (
	"bytes"
	"context"
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
	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const shortCommitLen = 12

// deploymentCommands are the root commands of deployments (spec §20): deploy,
// rollback and the deployments group.
func deploymentCommands(env []string) []*cobra.Command {
	return []*cobra.Command{newDeployCmd(env), newRollbackCmd(env), newDeploymentsCmd(env)}
}

// waitFlags are shared by the commands that can wait for a deployment to settle.
type waitFlags struct {
	wait     bool
	interval time.Duration
}

func (f *waitFlags) bind(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&f.wait, "wait", false, "wait until the deployment settles; exit non-zero unless it succeeded")
	cmd.Flags().DurationVar(&f.interval, "interval", defaultWatchInterval, "with --wait: how often to poll")
}

// ---- sm deploy -------------------------------------------------------------

func newDeployCmd(env []string) *cobra.Command {
	var commit string
	var images []string
	var w waitFlags
	cmd := &cobra.Command{
		Use:   "deploy <app> <environment> --commit <sha> --image <service>=<digest>",
		Short: "Deploy a commit's images to an application's environment",
		Long: "Request a deployment of the exact commit and image digests CI built. The daemon verifies CI for the\n" +
			"commit, freezes the plan and, when policy asks for it, waits for approval: this command prints that plan\n" +
			"preview. With --wait it blocks until the deployment succeeds, fails or is rolled back.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			requested, err := parseImages(images)
			if err != nil {
				return err
			}
			if commit == "" {
				return usageErrorf("--commit is required")
			}
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			app, target, err := resolveAppTarget(cmd.Context(), api, args[0], args[1])
			if err != nil {
				return err
			}
			d, err := api.CreateDeployment(cmd.Context(), wire.CreateDeploymentRequest{
				AppTargetID: target.ID, Kind: "deploy", CommitSHA: commit, Images: requested,
			})
			if err != nil {
				return err
			}
			if err := emitUnlessWaiting(cmd, d, w.wait, func(out io.Writer) error { return writePlanPreview(out, app.Name, target, d) }); err != nil {
				return err
			}
			return w.settle(cmd, api, d)
		},
	}
	cmd.Flags().StringVar(&commit, "commit", "", "full commit SHA CI built")
	cmd.Flags().StringArrayVar(&images, "image", nil, "service=sha256:<digest> to deploy (repeatable)")
	w.bind(cmd)
	return cmd
}

// parseImages reads service=digest pairs; the daemon checks the digests.
func parseImages(pairs []string) ([]wire.RequestedImage, error) {
	if len(pairs) == 0 {
		return nil, usageErrorf("--image <service>=<digest> is required (repeatable)")
	}
	images := make([]wire.RequestedImage, len(pairs))
	for i, pair := range pairs {
		service, digest, ok := strings.Cut(pair, "=")
		if !ok || service == "" || digest == "" {
			return nil, usageErrorf("--image %q must be <service>=<digest>", pair)
		}
		images[i] = wire.RequestedImage{Service: service, Digest: digest}
	}
	return images, nil
}

// resolveAppTarget finds the application and its target in one environment.
func resolveAppTarget(ctx context.Context, api *client.Client, appRef, environment string) (wire.App, wire.AppTarget, error) {
	id, err := resolveApp(ctx, api, appRef)
	if err != nil {
		return wire.App{}, wire.AppTarget{}, err
	}
	app, err := api.GetApp(ctx, id)
	if err != nil {
		return wire.App{}, wire.AppTarget{}, err
	}
	for _, t := range app.Targets {
		if t.Environment == environment {
			return app, t, nil
		}
	}
	return wire.App{}, wire.AppTarget{}, smerr.New(smerr.CodeNotFound, "", fmt.Sprintf("app %q has no target in environment %q", app.Name, environment))
}

// emitUnlessWaiting prints the deployment now, except with --wait, where the
// settled timeline is the single answer.
func emitUnlessWaiting(cmd *cobra.Command, d wire.Deployment, waiting bool, human func(io.Writer) error) error {
	if waiting {
		return nil
	}
	return emit(cmd, d, human)
}

// writePlanPreview is what the user reviews before anything runs: the target,
// the exact commit and digests, and the plan hash once the plan is frozen.
func writePlanPreview(w io.Writer, appName string, target wire.AppTarget, d wire.Deployment) error {
	pairs := [][2]string{
		{"deployment", string(d.ID)},
		{"kind", d.Kind},
		{"app", appName},
		{"environment", target.Environment},
		{"node", string(target.NodeID)},
		{"compose project", target.ComposeProject},
		{"commit", d.CommitSHA},
		{"state", d.State},
		{"plan hash", planHashOrPending(d)},
	}
	if err := fields(w, pairs); err != nil {
		return err
	}
	if err := writeImages(w, d.Images); err != nil {
		return err
	}
	_, err := fmt.Fprintln(w, nextStepHint(d))
	return err
}

func planHashOrPending(d wire.Deployment) string {
	if d.PlanHash == nil {
		return "- (set once CI is verified and the plan is frozen)"
	}
	return *d.PlanHash
}

func writeImages(w io.Writer, images []wire.RequestedImage) error {
	if len(images) == 0 {
		return nil
	}
	rows := make([][]string, len(images))
	for i, img := range images {
		rows[i] = []string{img.Service, img.Digest}
	}
	_, _ = fmt.Fprintln(w, "\nimages:")
	return table(w, []string{"SERVICE", "DIGEST"}, rows)
}

func nextStepHint(d wire.Deployment) string {
	switch {
	case d.State == string(deployments.StateAwaitingApproval) && d.PlanHash != nil && d.JobID != nil:
		return fmt.Sprintf("\nreview, then: sm jobs approve %s --plan-hash %s", *d.JobID, *d.PlanHash)
	case deployments.State(d.State).Terminal():
		return ""
	}
	return fmt.Sprintf("\nfollow it: sm deployments get %s --follow", d.ID)
}

// settle implements --wait: poll until the deployment is terminal, print its
// timeline, and fail unless it succeeded.
func (f *waitFlags) settle(cmd *cobra.Command, api *client.Client, d wire.Deployment) error {
	if !f.wait {
		return nil
	}
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() { _ = api.HoldPresence(ctx) }()
	final, err := pollUntilTerminal(ctx, api, d, f.interval, nil)
	if err != nil {
		return err
	}
	if err := emit(cmd, final, func(w io.Writer) error { return writeTimeline(w, final) }); err != nil {
		return err
	}
	return outcomeError(final)
}

// outcomeError is nil for a succeeded deployment and otherwise carries the
// deployment's own code and reason, so scripts see why it did not.
func outcomeError(d wire.Deployment) error {
	if deployments.State(d.State) == deployments.StateSucceeded {
		return nil
	}
	code := d.StateCode
	if code == "" {
		code = smerr.CodeDeploymentFailed
	}
	return smerr.New(code, d.StateReason, fmt.Sprintf("deployment %s ended %s%s", d.ID, d.State, reasonSuffix(d)))
}

func reasonSuffix(d wire.Deployment) string {
	if d.StateReason == "" {
		return ""
	}
	if d.StateCause != "" {
		return " (" + string(d.StateReason) + ": " + d.StateCause + ")"
	}
	return " (" + string(d.StateReason) + ")"
}

// reasonWithCause is the reason, followed by its recorded cause when there is one.
func reasonWithCause(d wire.Deployment) string {
	if d.StateCause == "" {
		return string(d.StateReason)
	}
	return string(d.StateReason) + " (" + d.StateCause + ")"
}

// pollUntilTerminal refreshes d every interval until it is terminal, calling
// onChange (when set) with every distinct view of it, the first included.
func pollUntilTerminal(ctx context.Context, api *client.Client, d wire.Deployment, interval time.Duration, onChange func(wire.Deployment) error) (wire.Deployment, error) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var shown string
	for {
		if view := deploymentFingerprint(d); view != shown && onChange != nil {
			shown = view
			if err := onChange(d); err != nil {
				return d, err
			}
		}
		if deployments.State(d.State).Terminal() {
			return d, nil
		}
		select {
		case <-ctx.Done():
			return d, ctx.Err()
		case <-ticker.C:
		}
		next, err := api.GetDeployment(ctx, d.ID)
		if err != nil {
			return d, err
		}
		d = next
	}
}

// deploymentFingerprint changes whenever something the timeline shows does.
func deploymentFingerprint(d wire.Deployment) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s|%s|%s|%s", d.State, d.StateCode, d.StateReason, d.StateCause)
	for _, s := range d.Steps {
		fmt.Fprintf(&b, "|%d:%s:%d", s.Ordinal, s.State, s.Attempt)
	}
	return b.String()
}

// ---- sm rollback -----------------------------------------------------------

func newRollbackCmd(env []string) *cobra.Command {
	var to string
	var w waitFlags
	cmd := &cobra.Command{
		Use:   "rollback <app> <environment>",
		Short: "Redeploy the last known-good deployment of an application's environment",
		Long: "Request a rollback of the newest deployment of the target to its newest earlier known-good one\n" +
			"(--to picks another known-good deployment of the same target). The daemon freezes the known-good\n" +
			"snapshot; no CI gate applies.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			req := wire.RollbackRequest{}
			if cmd.Flags().Changed("to") {
				id, err := parseID(to)
				if err != nil {
					return err
				}
				req.ToDeploymentID = &id
			}
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			app, target, err := resolveAppTarget(cmd.Context(), api, args[0], args[1])
			if err != nil {
				return err
			}
			latest, err := newestDeployment(cmd.Context(), api, target.ID)
			if err != nil {
				return err
			}
			d, err := api.RollbackDeployment(cmd.Context(), latest.ID, req)
			if err != nil {
				return err
			}
			if err := emitUnlessWaiting(cmd, d, w.wait, func(out io.Writer) error { return writePlanPreview(out, app.Name, target, d) }); err != nil {
				return err
			}
			return w.settle(cmd, api, d)
		},
	}
	cmd.Flags().StringVar(&to, "to", "", "known-good deployment id to roll back to")
	w.bind(cmd)
	return cmd
}

func newestDeployment(ctx context.Context, api *client.Client, target domain.ID) (wire.Deployment, error) {
	page, err := api.ListDeployments(ctx, client.DeploymentQuery{PageQuery: wire.PageQuery{Limit: 1}, AppTargetID: target})
	if err != nil {
		return wire.Deployment{}, err
	}
	if len(page.Items) == 0 {
		return wire.Deployment{}, smerr.New(smerr.CodeNotFound, smerr.ReasonRollbackUnavailable, "the target has no deployment to roll back")
	}
	return page.Items[0], nil
}

// ---- sm deployments ----------------------------------------------------------

func newDeploymentsCmd(env []string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "deployments",
		Short: "List, inspect, follow and cancel deployments",
		Args:  noArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(newDeploymentsListCmd(env), newDeploymentsGetCmd(env), newDeploymentsCancelCmd(env))
	return cmd
}

func newDeploymentsListCmd(env []string) *cobra.Command {
	var page *wire.PageQuery
	var app, target, state string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List deployments, newest first",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			q := client.DeploymentQuery{PageQuery: *page, State: state}
			if app != "" {
				if q.AppID, err = resolveApp(cmd.Context(), api, app); err != nil {
					return err
				}
			}
			if target != "" {
				if q.AppTargetID, err = parseID(target); err != nil {
					return err
				}
			}
			result, err := api.ListDeployments(cmd.Context(), q)
			if err != nil {
				return err
			}
			return emit(cmd, result, func(w io.Writer) error { return writeDeployments(w, result) })
		},
	}
	page = addPageFlags(cmd)
	cmd.Flags().StringVar(&app, "app", "", "only this application (id or name)")
	cmd.Flags().StringVar(&target, "target", "", "only this app target id")
	cmd.Flags().StringVar(&state, "state", "", "only deployments in this state")
	return cmd
}

func writeDeployments(w io.Writer, page wire.Page[wire.Deployment]) error {
	rows := make([][]string, len(page.Items))
	for i, d := range page.Items {
		rows[i] = []string{
			string(d.ID), d.Kind, d.State, orDash(string(d.StateReason)), shortCommit(d.CommitSHA),
			knownGoodMark(d.KnownGood), formatTime(d.CreatedAt),
		}
	}
	if err := table(w, []string{"ID", "KIND", "STATE", "REASON", "COMMIT", "KNOWN GOOD", "CREATED"}, rows); err != nil {
		return err
	}
	moreHint(w, page.NextCursor)
	return nil
}

func shortCommit(sha string) string {
	if len(sha) > shortCommitLen {
		return sha[:shortCommitLen]
	}
	return sha
}

func knownGoodMark(good bool) string {
	if good {
		return "yes"
	}
	return "-"
}

func newDeploymentsGetCmd(env []string) *cobra.Command {
	var follow bool
	var interval time.Duration
	cmd := &cobra.Command{
		Use:   "get <deployment-id>",
		Short: "Show a deployment and its step timeline",
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
			d, err := api.GetDeployment(cmd.Context(), id)
			if err != nil {
				return err
			}
			if !follow {
				return emit(cmd, d, func(w io.Writer) error { return writeTimeline(w, d) })
			}
			return followDeployment(cmd, api, d, interval)
		},
	}
	cmd.Flags().BoolVar(&follow, "follow", false, "print the timeline whenever it changes, until the deployment settles")
	cmd.Flags().DurationVar(&interval, "interval", defaultWatchInterval, "with --follow: how often to poll")
	return cmd
}

// followDeployment streams the timeline until the deployment is terminal and
// reports a deployment that did not succeed as the command's failure.
func followDeployment(cmd *cobra.Command, api *client.Client, d wire.Deployment, interval time.Duration) error {
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() { _ = api.HoldPresence(ctx) }()
	final, err := pollUntilTerminal(ctx, api, d, interval, func(d wire.Deployment) error {
		return emit(cmd, d, func(w io.Writer) error {
			if err := writeTimeline(w, d); err != nil {
				return err
			}
			_, err := fmt.Fprintln(w)
			return err
		})
	})
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	return outcomeError(final)
}

func newDeploymentsCancelCmd(env []string) *cobra.Command {
	return &cobra.Command{
		Use:   "cancel <deployment-id>",
		Short: "Cancel a deployment that has not started changing services",
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
			d, err := api.CancelDeployment(cmd.Context(), id)
			if err != nil {
				return err
			}
			return emit(cmd, d, func(w io.Writer) error {
				_, err := fmt.Fprintf(w, "deployment %s is now %s\n", d.ID, d.State)
				return err
			})
		},
	}
}

// writeTimeline renders a deployment as its summary followed by its steps.
func writeTimeline(w io.Writer, d wire.Deployment) error {
	pairs := [][2]string{
		{"id", string(d.ID)},
		{"kind", d.Kind},
		{"state", d.State},
		{"reason", orDash(reasonWithCause(d))},
		{"commit", d.CommitSHA},
		{"plan hash", orDash(derefString(d.PlanHash))},
		{"compose hash", orDash(derefString(d.ComposeHash))},
		{"known good", knownGoodMark(d.KnownGood)},
		{"created", formatTime(d.CreatedAt)},
		{"finished", formatTimePtr(d.FinishedAt)},
	}
	if err := fields(w, pairs); err != nil {
		return err
	}
	if err := writeImages(w, d.Images); err != nil {
		return err
	}
	return writeSteps(w, d.Steps)
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func writeSteps(w io.Writer, steps []wire.DeploymentStep) error {
	if len(steps) == 0 {
		return nil
	}
	rows := make([][]string, len(steps))
	for i, s := range steps {
		rows[i] = []string{
			fmt.Sprint(s.Ordinal), s.Name, s.State, fmt.Sprint(s.Attempt),
			formatTimePtr(s.StartedAt), formatTimePtr(s.FinishedAt), stepOutcome(s),
		}
	}
	_, _ = fmt.Fprintln(w, "\nsteps:")
	return table(w, []string{"#", "STEP", "STATE", "ATTEMPT", "STARTED", "FINISHED", "ERROR"}, rows)
}

func stepOutcome(s wire.DeploymentStep) string {
	if s.Error == nil {
		return "-"
	}
	var b bytes.Buffer
	b.WriteString(string(s.Error.Code))
	if s.Error.Reason != "" {
		b.WriteString("/" + string(s.Error.Reason))
	}
	if s.Error.Cause != "" {
		b.WriteString(" (" + s.Error.Cause + ")")
	}
	return b.String()
}
