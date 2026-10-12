package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/providers/proxmox"
)

// powerDeadline is how long a power task may run before the handler gives up
// waiting (ADR-0025). The PVE-side shutdown timeout is below it.
func powerDeadline(verb string) (time.Duration, error) {
	switch verb {
	case "start":
		return proxmox.DeadlineStart, nil
	case "shutdown":
		return proxmox.DeadlineShutdown, nil
	case "reboot":
		return proxmox.DeadlineReboot, nil
	case "stop":
		return proxmox.DeadlineStop, nil
	}
	return 0, smerr.New(smerr.CodeInvalidArgument, "", fmt.Sprintf("%q is not a power verb", verb))
}

// proxmoxPowerHandler executes proxmox.vm.power (ADR-0025). The POST is sent
// once, only after the intent is durable and marked dispatched; the UPID is
// persisted before the task is first polled; and only a stopped task (or a
// definite refusal) settles the intent. Any other ending leaves it recorded
// and returns jobs.ErrOutcomeUnknown: Proxmox calls carry no node-side marker,
// so the reconciler decides from task correlation and never re-dispatches.
type proxmoxPowerHandler struct {
	core
	store       *jobs.Store
	sync        *ProxmoxSync
	settle      Settle
	httpTimeout time.Duration
}

// powerTarget is the guest a power job acts on, as discovery last saw it.
type powerTarget struct {
	node         domain.Node
	guest        proxmox.GuestRef
	verb         string
	tokenUser    string
	client       proxmox.Client
	pre          powerPreState
	clusterNodes []string // members that are online, where a task of the guest can be listed
	dispatchedAt time.Time
}

func (h *proxmoxPowerHandler) Run(ctx context.Context, lease jobs.Lease) error {
	job, err := h.store.Get(ctx, h.cfg.DB.Reader(), lease.JobID)
	if err != nil {
		return err
	}
	t, err := h.target(ctx, job)
	if err != nil {
		return err
	}
	deadline, err := powerDeadline(t.verb)
	if err != nil {
		return err
	}
	if err := h.recheckPermission(ctx, t); err != nil {
		return err
	}
	if err := h.verifyGuest(ctx, &t); err != nil {
		return err
	}
	if t.pre.Baseline, err = h.baselineOf(ctx, t); err != nil {
		return err
	}
	pre, err := json.Marshal(t.pre)
	if err != nil {
		return fmt.Errorf("encode pre-state: %w", err)
	}
	intent, err := h.store.RecordIntent(ctx, lease, jobs.NewIntent{
		Step: "dispatch", Operation: powerOperation(t.verb), TargetType: string(domain.ResourceNode), TargetID: t.node.ID.String(),
		PreState: pre, DeadlineAt: h.cfg.Clock.Now().Add(deadline),
	})
	if err != nil {
		return err
	}
	if err := h.store.MarkDispatched(ctx, lease, intent.ID); err != nil {
		return err
	}
	t.dispatchedAt = h.cfg.Clock.Now()
	upid, outcome, postErr := t.client.Power(ctx, t.guest, t.verb)
	switch outcome {
	case proxmox.PowerAccepted:
		return h.await(ctx, lease, t, intent, upid)
	case proxmox.PowerRejected:
		return h.refused(ctx, lease, t, intent.ID, pre, postErr)
	case proxmox.PowerUncertain:
	}
	return powerUnknown(t, postErr)
}

// target resolves the guest, its provider's client and the token user.
func (h *proxmoxPowerHandler) target(ctx context.Context, job jobs.Job) (powerTarget, error) {
	q := h.cfg.DB.Reader()
	node, err := database.GetNode(ctx, q, job.Resource.ID)
	if err != nil {
		return powerTarget{}, err
	}
	guest, err := guestOf(node)
	if err != nil {
		return powerTarget{}, err
	}
	verb, err := verbOf(job.Payload)
	if err != nil {
		return powerTarget{}, err
	}
	provider, err := database.GetProvider(ctx, q, node.ProviderID)
	if err != nil {
		return powerTarget{}, err
	}
	if provider.Status == ProviderStatusRemoved {
		return powerTarget{}, smerr.New(smerr.CodeCapabilityUnavailable, "", fmt.Sprintf("provider %q was removed from the configuration file", provider.Name))
	}
	client, err := h.sync.clientFor(ctx, provider)
	if err != nil {
		return powerTarget{}, smerr.Wrap(err, smerr.CodeProviderError, "", "the Proxmox client is unavailable")
	}
	user, err := h.sync.tokenUserOf(ctx, provider)
	if err != nil {
		return powerTarget{}, smerr.Wrap(err, smerr.CodeProviderError, "", "the Proxmox token is unavailable")
	}
	return powerTarget{
		node: node, guest: guest, verb: verb, tokenUser: user, client: client,
		pre: powerPreState{
			Type: string(guest.Type), VMID: guest.VMID, PVENode: guest.Node, TokenUser: user, Status: h.statusOf(ctx, node.ID),
			Incarnation: incarnationOfNode(node),
		},
	}, nil
}

func incarnationOfNode(node domain.Node) string {
	id, _ := node.Metadata[metadataIncarnation].(string)
	return id
}

// guestOf reads the guest's address from the metadata discovery wrote.
func guestOf(node domain.Node) (proxmox.GuestRef, error) {
	typ, _ := node.Metadata["type"].(string)
	pveNode, _ := node.Metadata["pve_node"].(string)
	vmid, isNumber := node.Metadata["vmid"].(float64)
	guestType := proxmox.GuestType(typ)
	valid := (node.Kind == proxmox.KindQEMU && guestType == proxmox.GuestQEMU) || (node.Kind == proxmox.KindLXC && guestType == proxmox.GuestLXC)
	if !valid || pveNode == "" || !isNumber || vmid < 1 {
		return proxmox.GuestRef{}, smerr.New(smerr.CodeInvalidArgument, "", "the node is not a Proxmox guest that can be powered")
	}
	return proxmox.GuestRef{Node: pveNode, Type: guestType, VMID: int(vmid)}, nil
}

func verbOf(payload json.RawMessage) (string, error) {
	var params struct {
		Verb string `json:"verb"`
	}
	if err := json.Unmarshal(payload, &params); err != nil {
		return "", smerr.Wrap(err, smerr.CodeInternal, "", "proxmox.vm.power job has an unreadable payload")
	}
	return params.Verb, nil
}

// statusOf is the last power state discovery observed, empty if none.
func (h *proxmoxPowerHandler) statusOf(ctx context.Context, node domain.ID) string {
	o, err := database.LatestObservation(ctx, h.cfg.DB.Reader(), nodeRef(node), proxmox.ObservationStatus)
	if err != nil {
		return ""
	}
	var status ProxmoxStatus
	if decodeObservation(o, &status) != nil {
		return ""
	}
	return status.Status
}

// recheckPermission asks Proxmox now whether the token may still power the
// guest: the capability was advertised from an earlier read (ADR-0023).
func (h *proxmoxPowerHandler) recheckPermission(ctx context.Context, t powerTarget) error {
	privs, err := t.client.PathPermissions(ctx, guestACLPath(t.guest.VMID))
	if err != nil {
		return smerr.Wrap(err, smerr.CodeProviderError, "", "the token's Proxmox permissions could not be read")
	}
	if !privs.Has(privPowerMgmt) {
		return smerr.New(smerr.CodeCapabilityUnavailable, "", "the Proxmox token no longer holds "+privPowerMgmt+" on this guest")
	}
	return nil
}

// verifyGuest reads the cluster now and requires the guest at this type and
// VMID to be the one the job was planned for: the plan names a node row, and
// a VMID that was freed can be given to another guest. The guest is then
// addressed where it is now, which also follows a migration.
func (h *proxmoxPowerHandler) verifyGuest(ctx context.Context, t *powerTarget) error {
	inventory, err := t.client.Resources(ctx)
	if err != nil {
		return smerr.Wrap(err, smerr.CodeProviderError, "", "the Proxmox cluster could not be read")
	}
	i := slices.IndexFunc(inventory.Guests, func(g proxmox.Guest) bool {
		return g.Ref.Type == t.guest.Type && g.Ref.VMID == t.guest.VMID
	})
	if i < 0 || guestSpec(inventory.Guests[i]).name != t.node.Name || inventory.Guests[i].Template {
		return smerr.New(smerr.CodeConflict, "", fmt.Sprintf("%s is no longer the guest this job was planned for; refresh the provider and plan again", t.node.Name))
	}
	t.guest = inventory.Guests[i].Ref
	t.pre.PVENode = t.guest.Node
	for _, n := range inventory.Nodes {
		if n.Status == "online" {
			t.clusterNodes = append(t.clusterNodes, n.Name)
		}
	}
	return nil
}

// baselineOf lists the tasks of this guest, type and user that already exist,
// on every online member, so that correlation after a crash can tell them
// from the one this dispatch starts. It never returns nil.
func (h *proxmoxPowerHandler) baselineOf(ctx context.Context, t powerTarget) ([]string, error) {
	taskType, err := proxmox.TaskType(t.guest.Type, t.verb)
	if err != nil {
		return nil, err
	}
	since, _ := proxmox.CorrelationWindow(h.cfg.Clock.Now(), h.httpTimeout)
	filter := proxmox.TaskFilter{VMID: t.guest.VMID, TypeName: taskType, User: t.tokenUser, Since: since}
	baseline := []string{}
	for _, name := range t.clusterNodes {
		tasks, err := t.client.Tasks(ctx, name, filter)
		if err != nil {
			return nil, smerr.Wrap(err, smerr.CodeProviderError, "", fmt.Sprintf("the tasks of Proxmox node %s could not be listed", name))
		}
		for _, task := range tasks {
			baseline = append(baseline, task.UPID.Raw)
		}
	}
	return baseline, nil
}

// refused settles an intent whose POST was definitely rejected: nothing was
// accepted, so the job fails.
func (h *proxmoxPowerHandler) refused(ctx context.Context, lease jobs.Lease, t powerTarget, intent domain.ID, pre json.RawMessage, cause error) error {
	ev, err := rejectionEvidence(cause, pre)
	if err != nil {
		return err
	}
	if err := h.complete(ctx, lease, intent, ev, jobs.OutcomeFailed); err != nil {
		return err
	}
	return smerr.Wrap(cause, smerr.CodeProviderError, "", fmt.Sprintf("Proxmox refused to %s %s: %s", t.verb, t.node.Name, reasonOf(cause)))
}

func reasonOf(err error) string {
	var api *proxmox.APIError
	if errors.As(err, &api) && api.Message != "" {
		return limitText(api.Message, pveRejectionMax)
	}
	return "the request was not accepted"
}

// await persists the UPID, then polls its task, on the node the UPID names,
// until it stops or the deadline passes.
func (h *proxmoxPowerHandler) await(ctx context.Context, lease jobs.Lease, t powerTarget, intent jobs.Intent, upid proxmox.UPID) error {
	if !h.startedInWindow(t, upid) {
		return powerUnknown(t, fmt.Errorf("the task id %s started outside the dispatch window", upid.Raw))
	}
	if err := h.store.RecordExternalRef(ctx, lease, intent.ID, upid.Raw); err != nil {
		if errors.Is(err, jobs.ErrLeaseLost) {
			return err
		}
		return powerUnknown(t, fmt.Errorf("record the task id %s: %w", upid.Raw, err))
	}
	for {
		task, err := t.client.Task(ctx, upid)
		if err == nil && task.Stopped() {
			return h.stopped(ctx, lease, t, intent, task)
		}
		if ctx.Err() != nil || !h.cfg.Clock.Now().Before(intent.DeadlineAt) {
			return powerUnknown(t, errors.Join(errTaskRunning, err))
		}
		h.settle.Sleep(ctx, h.settle.Interval)
	}
}

// startedInWindow: a task that began long before or after the dispatch cannot
// be the one this dispatch started (the UPID's own start time is PVE's clock).
func (h *proxmoxPowerHandler) startedInWindow(t powerTarget, upid proxmox.UPID) bool {
	from, until := proxmox.CorrelationWindow(t.dispatchedAt, h.httpTimeout)
	return !upid.StartTime.Before(from) && !upid.StartTime.After(until)
}

// stopped settles the intent from the task the handler saw end.
func (h *proxmoxPowerHandler) stopped(ctx context.Context, lease jobs.Lease, t powerTarget, intent jobs.Intent, task proxmox.TaskStatus) error {
	ev, err := taskEvidence(task, intent.PreState)
	if err != nil {
		return err
	}
	if ev.Classification == jobs.ClassComplete {
		return h.complete(ctx, lease, intent.ID, ev, jobs.OutcomeSucceeded)
	}
	if err := h.complete(ctx, lease, intent.ID, ev, jobs.OutcomeFailed); err != nil {
		return err
	}
	return smerr.New(smerr.CodeProviderError, "", fmt.Sprintf("%s %s failed: %s", t.verb, t.node.Name, limitText(task.ExitStatus, pveRejectionMax)))
}

func (h *proxmoxPowerHandler) complete(ctx context.Context, lease jobs.Lease, intent domain.ID, ev jobs.Evidence, outcome string) error {
	raw, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("encode evidence: %w", err)
	}
	return h.store.CompleteIntent(ctx, lease, intent, outcome, raw)
}

// powerUnknown ends the handler without a verdict: the dispatch may have been
// accepted, so the job is interrupted, keeps its locks, and is never retried.
func powerUnknown(t powerTarget, cause error) error {
	detail := fmt.Sprintf("%s %s was dispatched but its outcome could not be established; check the guest and resolve the job", t.verb, t.node.Name)
	return smerr.Wrap(fmt.Errorf("%w: %w", jobs.ErrOutcomeUnknown, cause), smerr.CodeProviderError, "", detail)
}
