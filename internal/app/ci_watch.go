package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/providers/github"
)

const (
	defaultCIPollInitial = 15 * time.Second
	defaultCIPollMax     = 2 * time.Minute
	defaultCITimeout     = 2 * time.Hour
	defaultCIWatchTick   = 5 * time.Second

	ciNudgeBuffer   = 64
	ciMaxPerPass    = 100
	ciVerifyTimeout = time.Minute
)

// CIPolling is github.ci_poll_initial, ci_poll_max and ci_timeout (spec §18).
// Local mode polls from Initial, doubling up to Max. Server mode is driven by
// webhooks and polls only as a backstop, every Max. A deployment still not
// green Timeout after it was requested fails.
type CIPolling struct {
	Initial, Max, Timeout time.Duration
	Server                bool
}

func (p CIPolling) withDefaults() CIPolling {
	if p.Initial <= 0 {
		p.Initial = defaultCIPollInitial
	}
	if p.Max <= 0 {
		p.Max = defaultCIPollMax
	}
	if p.Timeout <= 0 {
		p.Timeout = defaultCITimeout
	}
	p.Max = max(p.Max, p.Initial)
	return p
}

// nextInterval is how long to wait after a check that found CI pending, given
// the interval that preceded it.
func (p CIPolling) nextInterval(previous time.Duration) time.Duration {
	if p.Server {
		return p.Max
	}
	return min(max(2*previous, p.Initial), p.Max)
}

// Finalizer turns a deployment whose CI passed (or that has no CI gate) into a
// final plan and a job (spec §20.2 step 2; ADR-0011), moving it out of created
// or waiting_ci. check is the evidence of the passed required checks, nil
// without a gate. A deployment that is itself unacceptable (Compose rejected,
// digest unbound, policy denied) is failed by the Finalizer and returns nil; a
// returned error is an infrastructure fault and the watcher will try again.
type Finalizer interface {
	Finalize(ctx context.Context, id domain.ID, checks []github.CheckEvidence) error
}

// CIWatcherOptions tune the CI watcher.
type CIWatcherOptions struct {
	// Tick is how often due deployments are looked for; default 5s.
	Tick    time.Duration
	OnError func(error) // default: ignored
}

// NewCIWatcher validates cfg. Polling comes from github.ci_* and the mode.
func NewCIWatcher(cfg Config, clients GitHubClients, finalizer Finalizer, poll CIPolling, o CIWatcherOptions) (CIWatcher, error) {
	return newCIWatcher(cfg, clients, finalizer, poll, o)
}

func newCIWatcher(cfg Config, clients GitHubClients, finalizer Finalizer, poll CIPolling, o CIWatcherOptions) (*ciWatcher, error) {
	c, err := newCore(cfg)
	if err != nil {
		return nil, err
	}
	if clients == nil || finalizer == nil {
		return nil, errors.New("app: the CI watcher needs the GitHub clients and a finalizer")
	}
	w := &ciWatcher{
		core: c, clients: clients, finalizer: finalizer, poll: poll.withDefaults(),
		tick: o.Tick, onError: o.OnError, nudges: make(chan ciNudge, ciNudgeBuffer),
	}
	if w.tick <= 0 {
		w.tick = defaultCIWatchTick
	}
	if w.onError == nil {
		w.onError = func(error) {}
	}
	return w, nil
}

type ciNudge struct {
	repositoryID int64
	sha          string
}

type ciWatcher struct {
	core
	clients   GitHubClients
	finalizer Finalizer
	poll      CIPolling
	tick      time.Duration
	onError   func(error)
	nudges    chan ciNudge
}

var _ CIWatcher = (*ciWatcher)(nil)

// Nudge asks for one re-evaluation of the deployments waiting on sha in the
// GitHub repository. It never blocks: when the queue is full the nudge is
// dropped, and the backstop poll covers it.
func (w *ciWatcher) Nudge(repositoryID int64, sha string) {
	select {
	case w.nudges <- ciNudge{repositoryID: repositoryID, sha: sha}:
	default:
	}
}

// Run evaluates due deployments, and nudged ones as they arrive, until ctx ends.
func (w *ciWatcher) Run(ctx context.Context) error {
	ticker := time.NewTicker(w.tick)
	defer ticker.Stop()
	for {
		w.report(ctx, w.pollDue(ctx))
		select {
		case <-ctx.Done():
			return nil
		case n := <-w.nudges:
			w.report(ctx, w.handleNudge(ctx, n))
		case <-ticker.C:
		}
	}
}

func (w *ciWatcher) report(ctx context.Context, err error) {
	if err != nil && ctx.Err() == nil {
		w.onError(err)
	}
}

// pendingPolicy says what an evaluation does with CI still running.
type pendingPolicy int

const (
	rescheduleWhenPending   pendingPolicy = iota // a poll: back off and look again later
	keepScheduleWhenPending                      // a nudge: the poll schedule is untouched
)

// pollDue evaluates every waiting_ci deployment whose check is due and
// finalizes the deployments that have no CI gate.
func (w *ciWatcher) pollDue(ctx context.Context) error {
	q := w.cfg.DB.Reader()
	due, err := database.ListDueCIChecks(ctx, q, w.cfg.Clock.Now(), ciMaxPerPass)
	if err != nil {
		return fmt.Errorf("list due CI checks: %w", err)
	}
	ungated, err := database.ListDeployments(ctx, q, database.DeploymentFilter{State: deployments.StateCreated}, ciMaxPerPass)
	if err != nil {
		return fmt.Errorf("list ungated deployments: %w", err)
	}
	var errs []error
	for _, dep := range due {
		errs = append(errs, w.evaluate(ctx, dep.ID, rescheduleWhenPending))
	}
	for _, dep := range ungated {
		errs = append(errs, w.finalizer.Finalize(ctx, dep.ID, nil))
	}
	return errors.Join(errs...)
}

// handleNudge evaluates, once, the deployments waiting on the nudged commit of
// the nudged repository.
func (w *ciWatcher) handleNudge(ctx context.Context, n ciNudge) error {
	q := w.cfg.DB.Reader()
	waiting, err := database.ListDeployments(ctx, q, database.DeploymentFilter{State: deployments.StateWaitingCI}, maxDeploymentsPage)
	if err != nil {
		return fmt.Errorf("list waiting deployments: %w", err)
	}
	var errs []error
	for _, dep := range waiting {
		if dep.CommitSha != n.sha {
			continue
		}
		scope, err := loadDeploymentScope(ctx, q, dep.AppTargetID)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if scope.repo != nil && scope.repo.GithubRepositoryID == n.repositoryID {
			errs = append(errs, w.evaluate(ctx, dep.ID, keepScheduleWhenPending))
		}
	}
	return errors.Join(errs...)
}

// evaluate asks GitHub whether the commit of a waiting_ci deployment passed
// CI and acts on the answer: finalize, fail, or wait. The network call runs
// outside any transaction; the outcome is applied only if the deployment is
// still waiting.
func (w *ciWatcher) evaluate(ctx context.Context, id domain.ID, onPending pendingPolicy) error {
	q := w.cfg.DB.Reader()
	dep, err := database.GetDeployment(ctx, q, id)
	if err != nil || dep.State != deployments.StateWaitingCI {
		return err
	}
	scope, err := loadDeploymentScope(ctx, q, dep.AppTargetID)
	if err != nil {
		return err
	}
	report, verifyErr := w.verify(ctx, scope, dep.CommitSha)
	expired := dep.CIDeadlineAt != nil && !w.cfg.Clock.Now().Before(*dep.CIDeadlineAt)
	switch {
	case verifyErr != nil:
		return errors.Join(fmt.Errorf("check CI of deployment %s: %w", id, verifyErr),
			w.waitOrTimeOut(ctx, dep, expired, smerr.ReasonCITimeout, onPending))
	case report.Verdict == github.VerdictPassed:
		return w.finalizer.Finalize(ctx, id, report.Evidence)
	case report.Verdict == github.VerdictFailed && smerr.Reason(report.Reason) == smerr.ReasonCheckFailed:
		return w.failCI(ctx, dep, smerr.ReasonCheckFailed)
	}
	// Pending, or a required check that has not shown up yet: a commit just
	// pushed has no check runs for a while, so both wait for the deadline.
	timeout := smerr.ReasonCITimeout
	if report.Verdict == github.VerdictFailed {
		timeout = smerr.Reason(report.Reason)
	}
	return w.waitOrTimeOut(ctx, dep, expired, timeout, onPending)
}

func (w *ciWatcher) verify(ctx context.Context, scope deploymentScope, sha string) (github.CheckReport, error) {
	if !scope.gated() {
		return github.CheckReport{}, errors.New("the app has no CI gate any more")
	}
	client, err := w.clients.For(ctx, scope.repo.ProviderID)
	if err != nil {
		return github.CheckReport{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, ciVerifyTimeout)
	defer cancel()
	repo := github.Repo{
		ID: scope.repo.GithubRepositoryID, OwnerID: scope.repo.GithubOwnerID, Owner: scope.repo.Owner,
		Name: scope.repo.Name, URL: scope.repo.URL, DefaultBranch: scope.repo.DefaultBranch,
	}
	return github.VerifyChecks(ctx, client, repo, sha, githubCIPolicy(*scope.spec.CI))
}

// waitOrTimeOut fails a deployment whose CI wait is over (spec §18: after
// ci_timeout, CI_NOT_PASSED) and otherwise schedules its next look.
func (w *ciWatcher) waitOrTimeOut(ctx context.Context, dep database.Deployment, expired bool, timeout smerr.Reason, onPending pendingPolicy) error {
	switch {
	case expired:
		return w.failCI(ctx, dep, timeout)
	case onPending == keepScheduleWhenPending:
		return nil
	}
	return w.reschedule(ctx, dep.ID)
}

func (w *ciWatcher) failCI(ctx context.Context, dep database.Deployment, reason smerr.Reason) error {
	return w.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		return w.failProvisional(ctx, tx, dep.ID, reason, map[string]any{"commit_sha": dep.CommitSha})
	})
}

// reschedule backs off from the interval the deployment was last scheduled
// with, which is the distance between its last update and its next check.
func (w *ciWatcher) reschedule(ctx context.Context, id domain.ID) error {
	return w.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		current, err := database.GetDeployment(ctx, tx, id)
		if err != nil || current.State != deployments.StateWaitingCI {
			return err
		}
		var previous time.Duration
		if current.NextCICheck != nil {
			previous = current.NextCICheck.Sub(current.UpdatedAt)
		}
		now := w.cfg.Clock.Now()
		return database.ScheduleCICheck(ctx, tx, id, now.Add(w.poll.nextInterval(previous)), now)
	})
}
