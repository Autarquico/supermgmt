package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
	"github.com/autarquico/supermgmt/internal/providers/proxmox"
)

// defaultProxmoxHTTPTimeout mirrors the proxmox client's default request
// timeout, which the correlation window is computed from.
const defaultProxmoxHTTPTimeout = 30 * time.Second

const (
	pveExitOK        = "OK"
	pveStatusStopped = "stopped"
	pveRejected      = "rejected" // fingerprint status of a refusal that produced no task
	pveRejectionMax  = 200
)

var errTaskRunning = errors.New("the Proxmox task is still running")

// powerOperation is the operation name of a power intent (ADR-0025).
func powerOperation(verb string) string { return policy.ActionProxmoxVMPower + "." + verb }

// powerVerbOf extracts the verb from a power operation name.
func powerVerbOf(operation string) (string, error) {
	verb, ok := strings.CutPrefix(operation, policy.ActionProxmoxVMPower+".")
	if !ok || verb == "" {
		return "", fmt.Errorf("operation %q is not a Proxmox power operation", operation)
	}
	return verb, nil
}

// powerPreState is the intent's pre_state: what the dispatch acted on.
type powerPreState struct {
	Type        string `json:"type"`
	VMID        int    `json:"vmid"`
	PVENode     string `json:"pve_node"`
	TokenUser   string `json:"token_user"`
	Status      string `json:"status"`
	Incarnation string `json:"incarnation,omitempty"`
	// Baseline are the tasks of this guest, type and user that existed when the
	// dispatch was about to be sent: none of them is its task. A nil baseline
	// (an intent from before baselines) cannot rule anything out.
	Baseline []string `json:"baseline"`
}

// taskFingerprint is the frozen fingerprint of task-stop evidence (ADR-0025):
// two samples pair only if all three fields are identical.
type taskFingerprint struct {
	UPID       string `json:"upid"`
	Status     string `json:"status"`
	ExitStatus string `json:"exitstatus"`
}

// taskEvidence encodes a task observation. A running task is no evidence yet.
// A stopped task is definite: complete when it ended OK, not_started (which
// the reconciler maps to failed) otherwise.
func taskEvidence(t proxmox.TaskStatus, pre json.RawMessage) (jobs.Evidence, error) {
	if !t.Stopped() {
		return jobs.Evidence{}, errTaskRunning
	}
	class := jobs.ClassNotStarted
	if t.ExitStatus == pveExitOK {
		class = jobs.ClassComplete
	}
	return stoppedEvidence(taskFingerprint{UPID: t.UPID.Raw, Status: pveStatusStopped, ExitStatus: t.ExitStatus}, class, pre)
}

// rejectionEvidence encodes a definite refusal received before any task: the
// operation was never accepted.
func rejectionEvidence(cause error, pre json.RawMessage) (jobs.Evidence, error) {
	reason := limitText(strings.Join(strings.Fields(cause.Error()), " "), pveRejectionMax)
	return stoppedEvidence(taskFingerprint{Status: pveRejected, ExitStatus: reason}, jobs.ClassNotStarted, pre)
}

func stoppedEvidence(fp taskFingerprint, class jobs.Classification, pre json.RawMessage) (jobs.Evidence, error) {
	raw, err := json.Marshal(fp)
	if err != nil {
		return jobs.Evidence{}, fmt.Errorf("encode task fingerprint: %w", err)
	}
	return jobs.Evidence{
		Done: true, ExitStatus: 0, Proof: jobs.ProofPVETask, Classification: class, Fingerprint: raw, Pre: pre,
	}, nil
}

// ProxmoxEvidence implements jobs.EvidenceSource for the dispatched intents of
// Proxmox operations (ADR-0025). It finds the task an intent started (the
// recorded UPID, else the one task of any cluster node that matches the
// dispatch exactly) and reports it only once it has stopped. Everything else
// is an error, which the reconciler reads as "no evidence yet": zero or
// several candidates are never resolved by guessing.
type ProxmoxEvidence struct {
	core
	sync        *ProxmoxSync
	httpTimeout time.Duration
}

var _ jobs.EvidenceSource = (*ProxmoxEvidence)(nil)

// NewProxmoxEvidence validates cfg. httpTimeout must equal the
// proxmox.WithHTTPTimeout of sync's clients; zero means their default (30s).
func NewProxmoxEvidence(cfg Config, sync *ProxmoxSync, httpTimeout time.Duration) (*ProxmoxEvidence, error) {
	c, err := newCore(cfg)
	if err != nil {
		return nil, err
	}
	if sync == nil {
		return nil, errors.New("app: a proxmox sync is required")
	}
	return &ProxmoxEvidence{core: c, sync: sync, httpTimeout: orDefaultDuration(httpTimeout, defaultProxmoxHTTPTimeout)}, nil
}

// Collect observes the task behind one dispatched intent.
func (e *ProxmoxEvidence) Collect(ctx context.Context, intent jobs.Intent) (jobs.Evidence, error) {
	if intent.DispatchedAt == nil {
		return jobs.Evidence{}, fmt.Errorf("intent %s was never dispatched", intent.ID)
	}
	var pre powerPreState
	if err := json.Unmarshal(intent.PreState, &pre); err != nil {
		return jobs.Evidence{}, fmt.Errorf("intent %s has an unreadable pre-state: %w", intent.ID, err)
	}
	client, err := e.clientOf(ctx, intent)
	if err != nil {
		return jobs.Evidence{}, err
	}
	upid, err := e.taskOf(ctx, client, intent, pre)
	if err != nil {
		return jobs.Evidence{}, err
	}
	task, err := client.Task(ctx, upid)
	if err != nil {
		return jobs.Evidence{}, fmt.Errorf("read task %s: %w", upid.Raw, err)
	}
	return taskEvidence(task, intent.PreState)
}

func (e *ProxmoxEvidence) clientOf(ctx context.Context, intent jobs.Intent) (proxmox.Client, error) {
	q := e.cfg.DB.Reader()
	node, err := database.GetNode(ctx, q, domain.ID(intent.TargetID))
	if err != nil {
		return nil, err
	}
	provider, err := database.GetProvider(ctx, q, node.ProviderID)
	if err != nil {
		return nil, err
	}
	return e.sync.clientFor(ctx, provider)
}

// taskOf is the recorded UPID, or the one the dispatch can be correlated to.
func (e *ProxmoxEvidence) taskOf(ctx context.Context, client proxmox.Client, intent jobs.Intent, pre powerPreState) (proxmox.UPID, error) {
	if intent.ExternalRef != "" {
		return proxmox.ParseUPID(intent.ExternalRef)
	}
	return e.correlate(ctx, client, intent, pre)
}

// correlate looks for the task of a dispatch whose UPID was never recorded, on
// every node of the cluster (the guest may have migrated since), all pages.
func (e *ProxmoxEvidence) correlate(ctx context.Context, client proxmox.Client, intent jobs.Intent, pre powerPreState) (proxmox.UPID, error) {
	verb, err := powerVerbOf(intent.Operation)
	if err != nil {
		return proxmox.UPID{}, err
	}
	taskType, err := proxmox.TaskType(proxmox.GuestType(pre.Type), verb)
	if err != nil {
		return proxmox.UPID{}, err
	}
	from, until := proxmox.CorrelationWindow(*intent.DispatchedAt, e.httpTimeout)
	cluster, err := client.Resources(ctx)
	if err != nil {
		return proxmox.UPID{}, fmt.Errorf("list the cluster nodes: %w", err)
	}
	if pre.Baseline == nil {
		return proxmox.UPID{}, fmt.Errorf("intent %s recorded no baseline of earlier %s tasks on guest %d: one of them cannot be ruled out", intent.ID, taskType, pre.VMID)
	}
	filter := proxmox.TaskFilter{VMID: pre.VMID, TypeName: taskType, User: pre.TokenUser, Since: from, Until: until}
	var candidates []proxmox.TaskStatus
	for _, n := range cluster.Nodes {
		tasks, err := client.Tasks(ctx, n.Name, filter)
		if err != nil {
			return proxmox.UPID{}, fmt.Errorf("list the tasks of node %s: %w", n.Name, err) // that node may hold the task
		}
		candidates = append(candidates, tasks...)
	}
	want := proxmox.Want{Type: taskType, VMID: pre.VMID, User: pre.TokenUser, From: from, Until: until, Known: pre.Baseline}
	upid, found := proxmox.Correlate(candidates, want)
	switch found {
	case proxmox.CorrelatedOne:
		return upid, nil
	case proxmox.CorrelatedNone:
	case proxmox.CorrelatedMany:
		return proxmox.UPID{}, fmt.Errorf("several %s tasks of %s on guest %d match the dispatch", taskType, pre.TokenUser, pre.VMID)
	}
	return proxmox.UPID{}, fmt.Errorf("no %s task of %s on guest %d matches the dispatch", taskType, pre.TokenUser, pre.VMID)
}

// tokenUserOf is the user a task started with the provider's token carries in
// its UPID: the part of "<user>@<realm>!<tokenid>=<secret>" before the "=".
func (s *ProxmoxSync) tokenUserOf(ctx context.Context, p domain.Provider) (string, error) {
	token, err := s.opts.Token(ctx, p.CredentialRef)
	if err != nil {
		return "", fmt.Errorf("the API token is unavailable: %w", err)
	}
	user, _, ok := strings.Cut(token.Reveal(), "=")
	if !ok || user == "" {
		return "", errors.New("the API token has no user")
	}
	return user, nil
}
