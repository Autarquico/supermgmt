package app

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// Services submits service actions (start, stop, restart) as jobs.
type Services struct {
	core
	plans *Plans
}

// NewServices validates cfg.
func NewServices(cfg Config, store *jobs.Store) (*Services, error) {
	c, err := newCore(cfg)
	if err != nil {
		return nil, err
	}
	plans, err := NewPlans(cfg, store)
	if err != nil {
		return nil, err
	}
	return &Services{core: c, plans: plans}, nil
}

// Act plans and submits verb on a service in one step (the convenience
// endpoint of spec §23). The job is non_retryable and, in a production
// environment, waits in Approvals. The node must have completed node.setup,
// and setup must have granted the verb on this unit (ADR-0009 g).
func (s *Services) Act(ctx context.Context, by Caller, id domain.ID, verb domain.ServiceVerb) (Submission, error) {
	return commit(ctx, s.core, by, func(ctx context.Context, tx *database.Tx) (Submission, error) {
		if !verb.Valid() {
			return Submission{}, smerr.New(smerr.CodeInvalidArgument, "", "unknown service verb")
		}
		actor, err := s.beginRequest(ctx, tx, by)
		if err != nil {
			return Submission{}, err
		}
		b, err := build(ctx, tx, verb.Action(), by.ID, domain.ResourceRef{Type: domain.ResourceService, ID: id}, nil)
		if err != nil {
			return Submission{}, err
		}
		if err := s.plans.requireMayPlan(ctx, tx, actor, b.target); err != nil {
			return Submission{}, err
		}
		res, err := s.evaluate(ctx, tx, actor, b)
		if err != nil {
			return Submission{}, err
		}
		if err := s.requireGrant(ctx, tx, id, verb); err != nil {
			return Submission{}, err
		}
		return s.plans.planAndSubmit(ctx, tx, by, actor, b, res)
	})
}

// requireGrant refuses a verb that node.setup did not grant on this service.
func (s *Services) requireGrant(ctx context.Context, q database.Querier, id domain.ID, verb domain.ServiceVerb) error {
	svc, err := database.GetService(ctx, q, id)
	if err != nil {
		return err
	}
	setup, err := loadSetup(ctx, q, svc.NodeID)
	if err != nil {
		return err
	}
	return grantError(svc, setup, verb)
}

func grantError(svc domain.Service, setup *runtimes.SetupMeta, verb domain.ServiceVerb) error {
	switch {
	case setup == nil:
		return smerr.New(smerr.CodeCapabilityUnavailable, "", "the node has not completed node.setup")
	case !slicesContainsVerb(actionsFor(svc, setup), verb):
		return smerr.FromReason(smerr.ReasonUnitNotEligible, fmt.Sprintf("node.setup did not grant %s on %s", verb, svc.Name))
	}
	return nil
}

func slicesContainsVerb(verbs []domain.ServiceVerb, v domain.ServiceVerb) bool {
	for _, candidate := range verbs {
		if candidate == v {
			return true
		}
	}
	return false
}

// ---- the job ------------------------------------------------------------------

// Settle bounds how long a handler waits for the platform to finish an action
// whose command already returned (systemd may still have a job queued).
type Settle struct {
	Window   time.Duration // default 30s
	Interval time.Duration // default 1s
	// Sleep waits for d or until ctx ends; default is a real timer. Tests
	// replace it to drive a fake clock.
	Sleep func(ctx context.Context, d time.Duration)
}

func (s Settle) withDefaults() Settle {
	if s.Window <= 0 {
		s.Window = 30 * time.Second
	}
	if s.Interval <= 0 {
		s.Interval = time.Second
	}
	if s.Sleep == nil {
		s.Sleep = sleepFor
	}
	return s
}

func sleepFor(ctx context.Context, d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

// actionHandler executes service.start|stop|restart. The remote command runs
// only after the intent is durable and marked dispatched; its outcome is
// established from evidence, never from the command's exit alone (spec §20.4).
type actionHandler struct {
	core
	store    *jobs.Store
	conn     Connector
	adapters Adapters
	settle   Settle
}

// dispatch is one action about to be sent.
type dispatch struct {
	svc     domain.Service
	node    domain.Node
	verb    domain.ServiceVerb
	ref     runtimes.ServiceRef
	adapter runtimes.Adapter
}

func (h actionHandler) Run(ctx context.Context, lease jobs.Lease) error {
	job, err := h.store.Get(ctx, h.cfg.DB.Reader(), lease.JobID)
	if err != nil {
		return err
	}
	d, setup, err := h.prepare(ctx, job)
	if err != nil {
		return err
	}
	ex, err := h.conn.Automated(d.node, &setup)
	if err != nil {
		return err
	}
	if err := d.adapter.Preflight(ctx, ex, d.ref); err != nil {
		return err
	}
	pre, err := d.adapter.PreState(ctx, ex, d.ref)
	if err != nil {
		return err
	}
	marker := h.cfg.IDs.NewID().String()
	cmd, err := d.adapter.Mutate(d.ref, d.verb, marker, setup)
	if err != nil {
		return err
	}
	intent, err := h.store.RecordIntent(ctx, lease, jobs.NewIntent{
		Step: "dispatch", Operation: job.Type, TargetType: string(domain.ResourceService), TargetID: d.svc.ID.String(),
		Marker: marker, PreState: pre, DeadlineAt: h.cfg.Clock.Now().Add(cmd.Deadline),
	})
	if err != nil {
		return err
	}
	if err := h.store.MarkDispatched(ctx, lease, intent.ID); err != nil {
		return err
	}
	dispatchedAt, err := h.dispatchedAt(ctx, job.ID, intent.ID)
	if err != nil {
		return err
	}
	res, runErr := ex.Run(ctx, cmd)
	window := h.settle.Window
	if runErr != nil {
		window += cmd.Deadline + templates.KillAfter // the command may still be running on the node
	}
	ev, observeErr := h.observe(ctx, d, ex, marker, pre, dispatchedAt, window)
	return h.conclude(ctx, lease, intent.ID, d, sent{exit: res.ExitStatus, runErr: runErr, evidence: ev, observeErr: observeErr, pre: pre})
}

// prepare loads what the action acts on. A node without setup, or setup that
// did not grant the verb, is CAPABILITY_UNAVAILABLE: the grant may have been
// removed since the plan was approved.
func (h actionHandler) prepare(ctx context.Context, job jobs.Job) (dispatch, runtimes.SetupMeta, error) {
	q := h.cfg.DB.Reader()
	verb, err := domain.ParseServiceVerb(strings.TrimPrefix(job.Type, "service."))
	if err != nil {
		return dispatch{}, runtimes.SetupMeta{}, err
	}
	svc, err := database.GetService(ctx, q, job.Resource.ID)
	if err != nil {
		return dispatch{}, runtimes.SetupMeta{}, err
	}
	node, err := database.GetNode(ctx, q, svc.NodeID)
	if err != nil {
		return dispatch{}, runtimes.SetupMeta{}, err
	}
	setup, err := loadSetup(ctx, q, node.ID)
	if err != nil {
		return dispatch{}, runtimes.SetupMeta{}, err
	}
	if err := grantError(svc, setup, verb); err != nil {
		return dispatch{}, runtimes.SetupMeta{}, err
	}
	adapter, err := h.adapters.For(domain.ServiceKind(svc.Kind))
	if err != nil {
		return dispatch{}, runtimes.SetupMeta{}, err
	}
	return dispatch{svc: svc, node: node, verb: verb, ref: serviceRef(svc), adapter: adapter}, *setup, nil
}

func (h actionHandler) dispatchedAt(ctx context.Context, job, intent domain.ID) (time.Time, error) {
	intents, err := h.store.Intents(ctx, h.cfg.DB.Reader(), job)
	if err != nil {
		return time.Time{}, err
	}
	for _, in := range intents {
		if in.ID == intent && in.DispatchedAt != nil {
			return *in.DispatchedAt, nil
		}
	}
	return time.Time{}, smerr.New(smerr.CodeInternal, "", "the dispatched intent was not found")
}

// observe asks the adapter for evidence until it has some or the window ends.
func (h actionHandler) observe(ctx context.Context, d dispatch, ex transport.Executor, marker string, pre json.RawMessage,
	dispatchedAt time.Time, window time.Duration,
) (jobs.Evidence, error) {
	until := h.cfg.Clock.Now().Add(window)
	for {
		ev, err := d.adapter.Observe(ctx, ex, d.ref, d.verb, marker, pre, dispatchedAt)
		if err == nil {
			return ev, nil
		}
		if ctx.Err() != nil || !h.cfg.Clock.Now().Before(until) {
			return jobs.Evidence{}, err
		}
		h.settle.Sleep(ctx, h.settle.Interval)
	}
}

// sent is what happened when the command was sent and afterwards observed.
type sent struct {
	exit       int
	runErr     error
	evidence   jobs.Evidence
	observeErr error
	pre        json.RawMessage
}

// conclude closes the intent with what was established and ends the job. A
// command that exited non-zero failed; one whose outcome cannot be observed is
// reported as unknown, never as success.
func (h actionHandler) conclude(ctx context.Context, lease jobs.Lease, intent domain.ID, d dispatch, r sent) error {
	switch {
	case r.runErr == nil && r.exit != 0:
		failed := jobs.Evidence{
			Done: true, ExitStatus: r.exit, Proof: jobs.ProofDoneFile, Classification: jobs.ClassUnknown,
			Fingerprint: json.RawMessage(fmt.Sprintf(`{"exit_status":%d}`, r.exit)), Pre: r.pre,
		}
		return h.fail(ctx, lease, intent, failed, smerr.New(smerr.CodeInternal, "",
			fmt.Sprintf("%s %s failed (exit status %d)", d.verb, d.svc.Name, r.exit)))
	case r.observeErr != nil:
		if err := h.store.CompleteIntent(ctx, lease, intent, jobs.OutcomeFailed, nil); err != nil {
			return err
		}
		return outcomeUnknown(d, r.runErr, r.observeErr)
	case r.evidence.Classification != jobs.ClassComplete:
		return h.fail(ctx, lease, intent, r.evidence, notDone(d, r.evidence.Classification))
	}
	evidence, err := json.Marshal(r.evidence)
	if err != nil {
		return fmt.Errorf("encode evidence: %w", err)
	}
	return h.store.CompleteIntent(ctx, lease, intent, jobs.OutcomeSucceeded, evidence)
}

func (h actionHandler) fail(ctx context.Context, lease jobs.Lease, intent domain.ID, ev jobs.Evidence, cause error) error {
	evidence, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("encode evidence: %w", err)
	}
	if err := h.store.CompleteIntent(ctx, lease, intent, jobs.OutcomeFailed, evidence); err != nil {
		return err
	}
	return cause
}

func outcomeUnknown(d dispatch, runErr, observeErr error) error {
	cause := observeErr
	if runErr != nil {
		cause = runErr
	}
	return smerr.Wrap(cause, smerr.CodeNodeUnreachable, "", fmt.Sprintf(
		"%s %s was dispatched but its outcome could not be established; check the service before retrying", d.verb, d.svc.Name))
}

func notDone(d dispatch, class jobs.Classification) error {
	if class == jobs.ClassUnknown || class == jobs.ClassPartialStable {
		return smerr.New(smerr.CodeInternal, "", fmt.Sprintf("%s %s ended in a state that could not be confirmed", d.verb, d.svc.Name))
	}
	return smerr.New(smerr.CodeInternal, "", fmt.Sprintf("%s %s did not take effect", d.verb, d.svc.Name))
}
