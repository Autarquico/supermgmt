package app

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare"
	sshnode "github.com/autarquico/supermgmt/internal/providers/ssh"
	"github.com/autarquico/supermgmt/internal/runtimes/systemd"
	"github.com/autarquico/supermgmt/internal/secrets"
	"github.com/autarquico/supermgmt/internal/textsafe"
)

// Audit events of the tunnel jobs. Each Cloudflare mutation is one event with
// the object ID; none carries a credential.
const (
	eventTunnelEnabled     = "node.tunnel.enabled"
	eventTunnelConflict    = "node.tunnel.conflict"
	eventTunnelFailed      = "node.tunnel.failed"
	eventTunnelAbandoned   = "node.tunnel.enable_abandoned"
	eventTunnelCreated     = "cloudflare.tunnel.created"
	eventTunnelAdopted     = "cloudflare.tunnel.adopted"
	eventIngressSet        = "cloudflare.tunnel.ingress_set"
	eventAccessAppCreated  = "cloudflare.access_app.created"
	eventAccessAppAdopted  = "cloudflare.access_app.adopted"
	eventDNSCreated        = "cloudflare.dns_record.created"
	eventDNSAdopted        = "cloudflare.dns_record.adopted"
	eventServiceTokenNew   = "cloudflare.service_token.created" //nolint:gosec // an audit action name, not a credential
	eventServiceTokenGone  = "cloudflare.service_token.deleted" //nolint:gosec // an audit action name, not a credential
	eventPolicyCreated     = "cloudflare.access_policy.created"
	eventPolicyAdopted     = "cloudflare.access_policy.adopted"
	eventPolicyUpdated     = "cloudflare.access_policy.updated"
	maxRecordedErrorLength = 300
)

// phaseOrder is the order the state machines walk; a phase is a step that
// completed. Enable and disable share only the first phase, so one list orders
// both.
var phaseOrder = []database.TunnelPhase{
	database.PhaseStarted, database.PhaseTokenReady, database.PhaseTunnelCreated, database.PhaseIngressSet,
	database.PhaseAccessReady, database.PhaseDNSCreated, database.PhaseInstalled, database.PhaseVerified,
	database.PhaseCommitted,
	database.PhaseDirectVerified, database.PhaseSwitched, database.PhaseServiceRemoved, database.PhaseRouteClosed,
	database.PhaseAccessRemoved, database.PhaseTunnelDeleted, database.PhaseDone,
}

func phaseIndex(p database.TunnelPhase) int { return slices.Index(phaseOrder, p) }

// placeholderTunnelToken has the shape of a tunnel token. It lets the setup
// parameters be validated, with the pin check, before anything is created.
var placeholderTunnelToken = audit.Secret(strings.Repeat("A", 32))

// tunnelEngine runs the tunnel jobs of one instance.
type tunnelEngine struct {
	core
	opts TunnelOptions
}

func newTunnelEngine(c core, opts *TunnelOptions) (*tunnelEngine, error) {
	if opts == nil {
		return nil, nil
	}
	if opts.Secrets == nil {
		return nil, errors.New("app: tunnel options need a secret store")
	}
	if _, err := secretName(opts.Config.AccessTokenRef); err != nil {
		return nil, err
	}
	if _, err := secretName(opts.Config.APITokenRef); err != nil {
		return nil, err
	}
	return &tunnelEngine{core: c, opts: *opts}, nil
}

// tunnelRun is one enable attempt of one node.
type tunnelRun struct {
	*tunnelEngine
	api        CloudflareAPI
	lease      jobs.Lease
	job        jobs.Job
	node       domain.Node
	instanceID string
	zoneID     string
	hostname   string
	op         database.TunnelOperation
	// lastEnabled merges the objects the node's finished enables (committed or
	// abandoned) left behind since its newest finished disable, newest ID
	// first: a rerun or a disable uses them instead of treating them as
	// foreign. Zero when there are none.
	lastEnabled database.TunnelOperation
	disabling   bool // names the failing step as a disable's
}

// requireTunnelAllowed is the refusal of tunnel=true: the feature needs the
// cloudflare: block and an ssh node. It runs when the plan is created and again
// when the job runs.
func requireTunnelAllowed(configured bool, node domain.Node) error {
	switch {
	case !configured:
		return smerr.New(smerr.CodeInvalidArgument, "", "tunnel needs a cloudflare: block in the configuration; the Cloudflare connection is not configured")
	case node.Kind != sshnode.NodeKind:
		return smerr.New(smerr.CodeInvalidArgument, "", "tunnel is only available for ssh nodes")
	}
	return nil
}

// tunnelHostnameOf is the public hostname of the node, or an INVALID_ARGUMENT
// that says what to change when the node name does not make a DNS name.
func tunnelHostnameOf(nodeName, zone string) (string, error) {
	hostname, err := cloudflare.TunnelHostname(nodeName, zone)
	if err != nil {
		return "", smerr.New(smerr.CodeInvalidArgument, "", fmt.Sprintf(
			"the node name %q cannot be used with a tunnel: its hostname ssh-<node-name>.%s must be a valid DNS name. A node cannot be renamed: remove it with `sm nodes remove %s` and add it again with `sm nodes add --name <new-name> ...`, using lowercase letters, digits and hyphens, without dots, so that \"ssh-<new-name>\" stays within 63 characters",
			nodeName, zone, nodeName))
	}
	return hostname, nil
}

// begin validates everything that can be validated without a mutation, builds
// the client and finds or starts the enable operation record.
func (e *tunnelEngine) begin(ctx context.Context, lease jobs.Lease, job jobs.Job, node domain.Node, req setupRequest, id secrets.Identity) (*tunnelRun, error) {
	if err := requireTunnelAllowed(true, node); err != nil {
		return nil, err
	}
	if err := (systemd.SetupParams{
		User: node.Endpoint.User, InstanceID: "validate", AuthorizedKey: id.AuthorizedKey, Grants: req.Grants,
		LogsMode: req.LogsMode, DockerAccess: req.DockerAccess, Tunnel: &systemd.TunnelParams{Token: placeholderTunnelToken},
	}).Validate(); err != nil {
		return nil, err
	}
	hostname, err := tunnelHostnameOf(node.Name, e.opts.Config.Zone)
	if err != nil {
		return nil, err
	}
	r, err := e.newRun(ctx, lease, job, node, hostname)
	if err != nil {
		return nil, err
	}
	if err := r.openOperation(ctx, database.TunnelEnable); err != nil {
		return nil, err
	}
	return r, r.findLastEnabled(ctx)
}

// newRun builds the provisioning client from the stored API token and looks
// the zone up. It reads Cloudflare but changes nothing.
func (e *tunnelEngine) newRun(ctx context.Context, lease jobs.Lease, job jobs.Job, node domain.Node, hostname string) (*tunnelRun, error) {
	r, err := e.newInstanceRun(ctx, lease, job)
	if err != nil {
		return nil, err
	}
	r.node, r.hostname = node, hostname
	zone, err := r.api.ZoneByName(ctx, e.opts.Config.Zone)
	if err != nil {
		return nil, r.step("zone lookup", err)
	}
	r.zoneID = zone.ID
	return r, nil
}

// newInstanceRun is a run that is not about one node: service-token rotation.
func (e *tunnelEngine) newInstanceRun(ctx context.Context, lease jobs.Lease, job jobs.Job) (*tunnelRun, error) {
	instance, err := database.GetInstance(ctx, e.cfg.DB.Reader())
	if err != nil {
		return nil, err
	}
	name, _ := secretName(e.opts.Config.APITokenRef)
	token, err := e.opts.Secrets.Get(ctx, secrets.Ref{Name: name})
	if err != nil {
		return nil, tunnelCredentialError(err)
	}
	api, err := e.opts.api(token)
	if err != nil {
		return nil, smerr.New(smerr.CodeInvalidArgument, "", "the Cloudflare API token is unusable: check cloudflare.api_token_ref")
	}
	return &tunnelRun{tunnelEngine: e, api: gateOnRestoreHold(api, e.cfg.DB.Reader()), lease: lease, job: job, instanceID: instance.ID.String()}, nil
}

func tunnelCredentialError(err error) error {
	if smerr.CodeOf(err) == smerr.CodeNotFound {
		return smerr.New(smerr.CodeCapabilityUnavailable, "", "the Cloudflare API token is not in the secret store: store it at cloudflare.api_token_ref")
	}
	return err
}

// openOperation resumes the node's unfinished operation or starts one of kind.
func (r *tunnelRun) openOperation(ctx context.Context, kind database.TunnelOperationKind) error {
	found, err := r.resumeActive(ctx, kind)
	if err != nil || found {
		return err
	}
	return r.createOperation(ctx, kind)
}

// resumeActive picks up the node's unfinished operation, if it has one.
func (r *tunnelRun) resumeActive(ctx context.Context, kind database.TunnelOperationKind) (bool, error) {
	op, err := database.ActiveTunnelOperation(ctx, r.cfg.DB.Reader(), r.node.ID)
	switch {
	case err == nil:
		return true, r.resume(ctx, op, kind)
	case smerr.CodeOf(err) != smerr.CodeNotFound:
		return false, err
	}
	return false, nil
}

func (r *tunnelRun) createOperation(ctx context.Context, kind database.TunnelOperationKind) error {
	return r.insertOperation(ctx, kind, nil)
}

// insertOperation writes a new record of kind, after before (when set) in the
// same fenced transaction.
func (r *tunnelRun) insertOperation(ctx context.Context, kind database.TunnelOperationKind, before func(context.Context, *database.Tx) error) error {
	var created database.TunnelOperation
	err := r.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		if err := r.lease.Fence(ctx, tx); err != nil {
			return err
		}
		if before != nil {
			if err := before(ctx, tx); err != nil {
				return err
			}
		}
		var err error
		created, err = database.CreateTunnelOperation(ctx, tx, database.TunnelOperation{
			ID: r.cfg.IDs.NewID(), NodeID: r.node.ID, Kind: kind, AccountID: r.opts.Config.AccountID,
			Zone: r.opts.Config.Zone, InstanceID: r.instanceID, Hostname: r.hostname, CreatedAt: r.cfg.Clock.Now(),
		})
		return err
	})
	if err == nil {
		r.op = created
	}
	return err
}

// replaceOperation abandons the unfinished enable and opens the next record in
// one transaction, so a crash never leaves the node between the two.
func (r *tunnelRun) replaceOperation(ctx context.Context, enable database.TunnelOperation, kind database.TunnelOperationKind) error {
	return r.insertOperation(ctx, kind, func(ctx context.Context, tx *database.Tx) error {
		return r.abandonEnableIn(ctx, tx, enable)
	})
}

// findLastEnabled gathers what the node's earlier enables left behind,
// ignoring the operation this run is working on: the objects of its finished
// enables, newest ID first. The newest finished disable ends the search, since
// it took its objects down. A rerun or a disable uses these objects instead of
// treating them as foreign.
func (r *tunnelRun) findLastEnabled(ctx context.Context) error {
	previous, err := database.ListTunnelOperations(ctx, r.cfg.DB.Reader(), r.node.ID)
	if err != nil {
		return err
	}
	r.lastEnabled = database.TunnelOperation{}
	for _, op := range previous {
		if op.ID == r.op.ID {
			continue
		}
		if op.Kind != database.TunnelEnable || !op.Phase.Finished() {
			return nil
		}
		r.lastEnabled = inheritObjects(r.lastEnabled, op)
	}
	return nil
}

// inheritObjects is newer, with the IDs it lacks taken from older.
func inheritObjects(newer, older database.TunnelOperation) database.TunnelOperation {
	if newer.ID == "" {
		return older
	}
	o := &newer.Objects
	o.TunnelID = cmp.Or(o.TunnelID, older.Objects.TunnelID)
	o.DNSRecordID = cmp.Or(o.DNSRecordID, older.Objects.DNSRecordID)
	o.AccessAppID = cmp.Or(o.AccessAppID, older.Objects.AccessAppID)
	return newer
}

func (r *tunnelRun) resume(ctx context.Context, op database.TunnelOperation, kind database.TunnelOperationKind) error {
	switch {
	case op.Kind != kind:
		return smerr.New(smerr.CodeConflict, "", fmt.Sprintf("a tunnel %s is unfinished on this node; finish it first", op.Kind))
	case op.AccountID != r.opts.Config.AccountID || op.Zone != r.opts.Config.Zone || op.Hostname != r.hostname:
		return smerr.New(smerr.CodeConflict, "", "an unfinished tunnel operation was started for another Cloudflare account, zone or hostname")
	case op.Phase == database.PhaseFailed && r.job.Attempts > 1:
		// As with a conflict, an automatic retry must not undo the halt.
		return &recordGone{inner: smerr.New(smerr.CodeConflict, "", fmt.Sprintf(
			"the tunnel operation of this node failed (%s); run setup again to repair it, or `sm nodes tunnel disable %s` to abandon the tunnel",
			op.LastError, r.node.Name))}
	case op.Phase == database.PhaseFailed:
		// A new job closes the failed enable and starts a generation that
		// inherits what it recorded: the IDs of a record never change.
		return r.replaceOperation(ctx, op, kind)
	case op.Phase == database.PhaseConflict && r.job.Attempts > 1:
		// An automatic retry must not undo the halt; a new job (an operator who
		// resolved the object in Cloudflare) resumes it.
		return &ownershipConflict{inner: smerr.New(smerr.CodeConflict, "",
			"the tunnel operation of this node stopped on a Cloudflare object it does not own; resolve it in Cloudflare and run setup again")}
	case op.Phase == database.PhaseConflict:
		var resumed database.TunnelOperation
		err := r.write(ctx, func(ctx context.Context, tx *database.Tx) error {
			if err := r.lease.Fence(ctx, tx); err != nil {
				return err
			}
			var err error
			resumed, err = database.ResumeHaltedTunnelOperation(ctx, tx, op.ID, op.Generation, database.PhaseConflict, r.cfg.Clock.Now())
			return err
		})
		op = resumed
		if err != nil {
			return err
		}
	}
	r.op = op
	return nil
}

// mayMutate is the lease check that precedes every Cloudflare mutation: a
// worker that lost its lease stops instead of mutating.
func (r *tunnelRun) mayMutate(ctx context.Context) error {
	return r.lease.Fence(ctx, r.cfg.DB.Reader())
}

// step names the step that failed without hiding the cause's code.
func (r *tunnelRun) step(name string, err error) error {
	if err == nil {
		return nil
	}
	if r.disabling {
		return fmt.Errorf("tunnel disable failed at %s: %w", name, err)
	}
	return fmt.Errorf("tunnel setup failed at %s: %w", name, err)
}

// fail halts the operation record when err ends it: an ownership conflict
// (the node stays held until an operator resolves it in Cloudflare) or a
// recorded object that cannot be repaired in place (failed). It returns err.
func (r *tunnelRun) fail(ctx context.Context, err error) error {
	var (
		conflict *ownershipConflict
		gone     *recordGone
		halt     database.TunnelPhase
		event    string
	)
	switch {
	case errors.As(err, &conflict):
		halt, event = database.PhaseConflict, eventTunnelConflict
	case errors.As(err, &gone):
		halt, event = database.PhaseFailed, eventTunnelFailed
	default:
		return err
	}
	if r.op.Phase.Halted() {
		return err
	}
	message := textsafe.Line(audit.ScrubString(err.Error()))
	if utf8.RuneCountInString(message) > maxRecordedErrorLength {
		message = string([]rune(message)[:maxRecordedErrorLength])
	}
	_ = r.write(context.WithoutCancel(ctx), func(ctx context.Context, tx *database.Tx) error {
		if err := r.lease.Fence(ctx, tx); err != nil {
			return err
		}
		if _, err := database.HaltTunnelOperation(ctx, tx, r.op.ID, r.op.Generation, r.op.Phase, halt, message, r.cfg.Clock.Now()); err != nil {
			return err
		}
		return r.emitFor(ctx, tx, event, domain.ResultFailed, map[string]any{"phase": string(r.op.Phase)})
	})
	return err
}

// abandonEnableIn closes an enable that will not finish. The schema lets an
// enable end only as committed, so the record ends there (the endpoint does
// not move; the audit event says it was abandoned), which releases the node
// and keeps the IDs for the next enable to repair or for a disable to take
// down.
func (r *tunnelRun) abandonEnableIn(ctx context.Context, tx *database.Tx, op database.TunnelOperation) error {
	phase := op.Phase
	if op.Phase.Halted() {
		phase = op.HaltedPhase
	}
	if _, err := database.AdvanceTunnelPhase(ctx, tx, op.ID, op.Generation, op.Phase, database.PhaseCommitted,
		database.TunnelObjects{}, r.cfg.Clock.Now()); err != nil {
		return err
	}
	r.op = op
	return r.emitFor(ctx, tx, eventTunnelAbandoned, domain.ResultSucceeded, map[string]any{"phase": string(phase)})
}

// emitFor emits an event on the node as the job's actor.
func (r *tunnelRun) emitFor(ctx context.Context, tx *database.Tx, action string, result domain.Result, data map[string]any) error {
	actor, err := loadActor(ctx, tx, r.job.ActorID, credentialOf(r.job))
	if err != nil {
		return err
	}
	data["job_id"], data["operation_id"], data["node_id"] = r.job.ID.String(), r.op.ID.String(), r.node.ID.String()
	return r.emit(ctx, tx, actor, action, nodeRef(r.node.ID), result, data)
}

// advance records that a step completed: the next phase, the object IDs and
// the audit event commit together under the lease fence. A phase already
// reached is not recorded again.
func (r *tunnelRun) advance(ctx context.Context, next database.TunnelPhase, objects database.TunnelObjects, action string, data map[string]any) error {
	return r.advanceWith(ctx, next, objects, action, data, nil)
}

// advanceWith is advance plus a change that must commit with the phase: the
// switch of the endpoint, the capability.
func (r *tunnelRun) advanceWith(ctx context.Context, next database.TunnelPhase, objects database.TunnelObjects, action string, data map[string]any, with func(context.Context, *database.Tx) error) error {
	if phaseIndex(r.op.Phase) >= phaseIndex(next) {
		return nil
	}
	var advanced database.TunnelOperation
	err := r.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		if err := r.lease.Fence(ctx, tx); err != nil {
			return err
		}
		if with != nil {
			if err := with(ctx, tx); err != nil {
				return err
			}
		}
		var err error
		advanced, err = database.AdvanceTunnelPhase(ctx, tx, r.op.ID, r.op.Generation, r.op.Phase, next, objects, r.cfg.Clock.Now())
		if err != nil || action == "" {
			return err
		}
		return r.emitFor(ctx, tx, action, domain.ResultSucceeded, data)
	})
	if err == nil {
		r.op = advanced
	}
	return err
}
