package app

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/plan"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
	sshnode "github.com/autarquico/supermgmt/internal/providers/ssh"
	"github.com/autarquico/supermgmt/internal/secrets"
	"github.com/autarquico/supermgmt/internal/transport/ssh"
)

// A node that is reachable only through Cloudflare Tunnel (ADR-0039) is added by an enrollment: a
// tunnel_enrollments row that exists before the node, advanced by short control_plane.apply jobs of the
// action node.add with tunnel=true. This file is the service the API calls (start, read, token, confirm,
// cancel); tunnel_enroll_run.go is what the jobs do and tunnel_enroll_schedule.go what re-arms them.

const (
	defaultEnrollmentExpiry = time.Hour
	maxEnrollmentExpiry     = 24 * time.Hour

	// enrollmentSSHPort is the node's SSH port behind the tunnel (the ingress points at it).
	enrollmentSSHPort = 22

	// enrollmentTokenPrefix names the connector token's secret: cloudflare/enroll/<enrollment id>.
	enrollmentTokenPrefix = "cloudflare/enroll/" //nolint:gosec // the prefix of a secret name, not a credential

	joinScriptURL = "https://raw.githubusercontent.com/autarquico/supermgmt/main/scripts/join.sh"

	// tunnelParamKey is the plan parameter that tells an enrollment from the insertion of a node.
	tunnelParamKey = "tunnel"

	reasonCancelled = "cancelled"
	reasonExpired   = "expired"
	reasonRefused   = "host key refused"
)

// Audit events of an enrollment. None carries the connector token. The subject is the node ID allocated
// when the enrollment started, the same one the Cloudflare objects embed, with the enrollment ID (the same
// value) in the payload: there is no node row before the commit, and audit rows do not reference nodes.
const (
	eventEnrollmentStarted   = "node.tunnel.enrollment_started"
	eventEnrollmentScanned   = "node.tunnel.enrollment_scanned"
	eventEnrollmentConfirmed = "node.tunnel.enrollment_confirmed"
	eventEnrollmentMismatch  = "node.tunnel.enrollment_mismatch"
	eventEnrollmentCancelled = "node.tunnel.enrollment_cancel_requested"
	eventEnrollmentHalted    = "node.tunnel.enrollment_halted"
	eventEnrollmentToken     = "node.tunnel.enrollment_token_shown" //nolint:gosec // an audit action name, not a credential
)

// HostKeyScanner reads the host key a target presents over its own transport (production: (*ssh.Pool).ScanHostKey).
type HostKeyScanner func(ctx context.Context, t ssh.Target) (ssh.HostKey, error)

// TunnelEnrollmentOptions are the collaborators of TunnelEnrollments.
type TunnelEnrollmentOptions struct {
	// Tunnel is the Cloudflare connection; nil (no cloudflare: block) refuses every start.
	Tunnel *TunnelOptions
	// Identity is the instance SSH identity, snapshotted when an enrollment starts.
	Identity SSHIdentity
	// Connector reaches the node through the tunnel for the proof.
	Connector Connector
	// Scan reads the host key over the tunnel; it never dials the node's address.
	Scan HostKeyScanner
	// Prober probes the node once it is committed (best effort); optional.
	Prober *Prober
	// Channel is the release channel of the node line; "" or "stable" adds nothing to it.
	Channel string
}

// TunnelEnrollments is the enrollment service of nodes reached only through the tunnel (ADR-0039).
type TunnelEnrollments struct {
	core
	plans  *Plans
	store  *jobs.Store
	engine *tunnelEngine // nil: no cloudflare: block
	opts   TunnelEnrollmentOptions
}

// NewTunnelEnrollments validates the collaborators. Without options.Tunnel the service still exists and
// refuses a start with the message that names the settings.
func NewTunnelEnrollments(cfg Config, plans *Plans, store *jobs.Store, o TunnelEnrollmentOptions) (*TunnelEnrollments, error) {
	c, err := newCore(cfg)
	if err != nil {
		return nil, err
	}
	if plans == nil || store == nil || o.Identity == nil || o.Scan == nil {
		return nil, fmt.Errorf("app: tunnel enrollments need plans, the job store, the instance identity and a host key scanner")
	}
	engine, err := newTunnelEngine(c, o.Tunnel)
	if err != nil {
		return nil, err
	}
	return &TunnelEnrollments{core: c, plans: plans, store: store, engine: engine, opts: o}, nil
}

// StartTunnelEnrollment is the request of `sm nodes add --name <name> --tunnel`.
type StartTunnelEnrollment struct {
	Name        string
	Environment string
	Tags        []string
	ExpiresIn   time.Duration // zero: one hour; at most 24 hours
}

// TunnelEnrollmentView is what the API shows of an enrollment. The connector token is never in it.
type TunnelEnrollmentView struct {
	ID                 domain.ID // the enrollment, which is also the ID of the node it becomes
	NodeID             domain.ID
	Name               string
	Environment        string
	Tags               []string
	Hostname           string
	Phase              string
	ExpiresAt          time.Time
	JoinLine           string
	HostPublicKey      string // the key scanned over the tunnel, once scanned
	HostKeyFingerprint string
	Error              string
}

// ---- start ---------------------------------------------------------------------------

// Start begins an enrollment (action node.add with tunnel=true). Everything that can be refused without
// touching Cloudflare is refused first. Policy may park the request for approval: the plan then carries
// the enrollment, its job creates the row when approved, and Pending is set instead of Applied.
func (s *TunnelEnrollments) Start(ctx context.Context, by Caller, r StartTunnelEnrollment) (DirectResult[TunnelEnrollmentView], error) {
	p, err := s.startParams(r)
	if err != nil {
		return DirectResult[TunnelEnrollmentView]{}, err
	}
	identity, err := s.opts.Identity(ctx) // before the transaction: the first call may write the secret store
	if err != nil {
		return DirectResult[TunnelEnrollmentView]{}, fmt.Errorf("load instance identity: %w", err)
	}
	return commit(ctx, s.core, by, func(ctx context.Context, tx *database.Tx) (DirectResult[TunnelEnrollmentView], error) {
		actor, err := s.beginRequest(ctx, tx, by)
		if err != nil {
			return DirectResult[TunnelEnrollmentView]{}, err
		}
		if err := requireNameFree(ctx, tx, p.Name, ""); err != nil {
			return DirectResult[TunnelEnrollmentView]{}, err
		}
		params, err := toParams(p)
		if err != nil {
			return DirectResult[TunnelEnrollmentView]{}, err
		}
		b, err := build(ctx, tx, actionNodeAdd, by.ID, nodeRef(p.NodeID), params)
		if err != nil {
			return DirectResult[TunnelEnrollmentView]{}, err
		}
		res, err := s.evaluate(ctx, tx, actor, b)
		if err != nil {
			return DirectResult[TunnelEnrollmentView]{}, err
		}
		var row database.TunnelEnrollment
		if !res.ApprovalRequired {
			if row, err = s.createRow(ctx, tx, actor, p, identity); err != nil {
				return DirectResult[TunnelEnrollmentView]{}, err
			}
		}
		submission, err := s.plans.planAndSubmit(ctx, tx, by, actor, b, res)
		if err != nil {
			return DirectResult[TunnelEnrollmentView]{}, err
		}
		if res.ApprovalRequired {
			return DirectResult[TunnelEnrollmentView]{Pending: &submission}, nil
		}
		view, err := s.view(ctx, tx, row)
		return DirectResult[TunnelEnrollmentView]{Applied: &view}, err
	})
}

// startParams validates a request without touching the database or Cloudflare and allocates the node ID.
func (s *TunnelEnrollments) startParams(r StartTunnelEnrollment) (nodeAddParams, error) {
	if s.engine == nil {
		return nodeAddParams{}, requireTunnelAllowed(false, domain.Node{})
	}
	if err := sshnode.ValidateName(r.Name); err != nil {
		return nodeAddParams{}, err
	}
	if _, err := tunnelHostnameOf(r.Name, s.engine.opts.Config.Zone); err != nil {
		return nodeAddParams{}, err
	}
	tags, err := normalizeTags(r.Tags)
	if err != nil {
		return nodeAddParams{}, err
	}
	expiry := r.ExpiresIn
	if expiry == 0 {
		expiry = defaultEnrollmentExpiry
	}
	if expiry < time.Second || expiry > maxEnrollmentExpiry {
		return nodeAddParams{}, smerr.New(smerr.CodeInvalidArgument, "", "expires_in must be between 1 second and 24 hours")
	}
	return nodeAddParams{
		NodeID: s.cfg.IDs.NewID(), ProviderID: s.cfg.IDs.NewID(), Name: r.Name, Environment: r.Environment, Tags: tags,
		Tunnel: true, ExpiresIn: int(expiry / time.Second),
	}, nil
}

// createRow reserves the name and records the enrollment as started by actor (the caller of an immediate
// start, the requester of an approved plan), with the instance's SSH identity as it is now.
// The name is checked here, in the transaction that inserts the row.
func (s *TunnelEnrollments) createRow(ctx context.Context, q database.Querier, actor domain.Actor, p nodeAddParams, identity secrets.Identity) (database.TunnelEnrollment, error) {
	if err := requireNameFree(ctx, q, p.Name, ""); err != nil {
		return database.TunnelEnrollment{}, err
	}
	instance, err := database.GetInstance(ctx, q)
	if err != nil {
		return database.TunnelEnrollment{}, err
	}
	zone := s.engine.opts.Config
	hostname, err := tunnelHostnameOf(p.Name, zone.Zone)
	if err != nil {
		return database.TunnelEnrollment{}, err
	}
	var environment domain.ID
	if p.Environment != "" {
		env, err := environmentNamed(ctx, q, p.Environment)
		if err != nil {
			return database.TunnelEnrollment{}, err
		}
		environment = env.ID
	}
	now := s.cfg.Clock.Now()
	row, err := database.CreateTunnelEnrollment(ctx, q, database.TunnelEnrollment{
		ID: p.NodeID, Name: p.Name, EnvironmentID: environment, Tags: p.Tags,
		AccountID: zone.AccountID, Zone: zone.Zone, InstanceID: instance.ID.String(), Hostname: hostname,
		ExpiresAt: now.Add(time.Duration(p.ExpiresIn) * time.Second), StartedBy: actor.ID,
		Identity: database.EnrollmentIdentity{
			PublicKey: identity.AuthorizedKey, Fingerprint: identity.FingerprintSHA256, CredentialRef: pinnedIdentityRef(identity),
		},
		TokenRef: "secret://" + enrollmentTokenPrefix + p.NodeID.String(), CreatedAt: now,
	})
	if err != nil {
		return database.TunnelEnrollment{}, err
	}
	return row, s.emit(ctx, q, actor, eventEnrollmentStarted, nodeRef(row.ID), domain.ResultSucceeded, map[string]any{
		"enrollment_id": row.ID.String(), "name": row.Name, "hostname": row.Hostname, "environment": p.Environment,
		"tags": row.Tags, "expires_at": row.ExpiresAt, "identity_fingerprint": row.Identity.Fingerprint,
	})
}

// directPolicyParams are the parameters policy sees for a direct action: none, except that a node.add of an
// enrollment says tunnel=true, so that rules and the risk of the action can tell it from the insertion of a
// node by address.
func directPolicyParams(spec policy.ActionSpec, pl plan.Plan) map[string]any {
	if spec.Name == actionNodeAdd && pl.Parameters[tunnelParamKey] == true {
		return map[string]any{policy.ParamTunnel: "true"}
	}
	return nil
}

// enrollmentInstanceLock is the instance-wide Cloudflare lock a node.add job of an enrollment takes while it
// can still initialise the service token and policies (ADR-0037): before the Cloudflare side is built. The
// later steps, which wait, scan, prove, commit and tear down, take only the node's own lock, so an
// enrollment never holds the instance for the hours it waits.
func enrollmentInstanceLock(ctx context.Context, q database.Querier, job jobs.Job, p plan.Plan) ([]domain.LockSpec, error) {
	if job.Type != JobControlPlaneApply || p.Action != actionNodeAdd || p.Parameters[tunnelParamKey] != true {
		return nil, nil
	}
	row, err := database.GetTunnelEnrollment(ctx, q, job.Resource.ID)
	switch {
	case smerr.CodeOf(err) == smerr.CodeNotFound:
		return []domain.LockSpec{cloudflareInstanceLock}, nil // this job creates the row and builds the Cloudflare side
	case err != nil:
		return nil, err
	case provisioningPhase(row.Phase):
		return []domain.LockSpec{cloudflareInstanceLock}, nil
	}
	return nil, nil
}

// provisioningPhase reports whether the Cloudflare side is still being built.
func provisioningPhase(p database.TunnelPhase) bool {
	return slices.Contains([]database.TunnelPhase{
		database.PhaseStarted, database.PhaseTokenReady, database.PhaseTunnelCreated, database.PhaseIngressSet, database.PhaseAccessReady,
	}, p)
}

// ---- reads ---------------------------------------------------------------------------

// List returns the enrollments that have not finished, oldest first, those the caller may read.
func (s *TunnelEnrollments) List(ctx context.Context, by Caller) ([]TunnelEnrollmentView, error) {
	q := s.cfg.DB.Reader()
	actor, err := s.beginRequest(ctx, q, by)
	if err != nil {
		return nil, err
	}
	rows, err := database.ListOpenTunnelEnrollments(ctx, q)
	if err != nil {
		return nil, err
	}
	views := make([]TunnelEnrollmentView, 0, len(rows))
	for _, row := range rows {
		target, err := s.target(ctx, q, row)
		if err != nil {
			return nil, err
		}
		if s.authorize(policy.Request{Actor: actor, Action: "node.read", Targets: []policy.Target{target}}).Decision != policy.DecisionAllow {
			continue
		}
		view, err := s.view(ctx, q, row)
		if err != nil {
			return nil, err
		}
		views = append(views, view)
	}
	return views, nil
}

// Get returns the newest enrollment of the name, finished ones included, so a client that waited for the
// commit sees it.
func (s *TunnelEnrollments) Get(ctx context.Context, by Caller, name string) (TunnelEnrollmentView, error) {
	row, _, err := s.authorized(ctx, by, name, "node.read")
	if err != nil {
		return TunnelEnrollmentView{}, err
	}
	return s.view(ctx, s.cfg.DB.Reader(), row)
}

// authorized checks the caller may do action on the enrollment of the name, then returns the newest one.
// Policy answers before the name is resolved, so a caller who may not act learns nothing about which
// enrollments exist. A refusal of an existing enrollment is audited.
func (s *TunnelEnrollments) authorized(ctx context.Context, by Caller, name, action string) (database.TunnelEnrollment, domain.Actor, error) {
	q := s.cfg.DB.Reader()
	actor, err := s.beginRequest(ctx, q, by)
	if err != nil {
		return database.TunnelEnrollment{}, domain.Actor{}, err
	}
	row, err := database.GetLatestTunnelEnrollmentByName(ctx, q, name)
	if err != nil && smerr.CodeOf(err) != smerr.CodeNotFound {
		return database.TunnelEnrollment{}, domain.Actor{}, err
	}
	found := err == nil
	target := policy.Target{Ref: nodeRef(row.ID), Attrs: policy.Attributes{Node: name, Provider: name}}
	if found {
		if target, err = s.target(ctx, q, row); err != nil {
			return database.TunnelEnrollment{}, domain.Actor{}, err
		}
	}
	if res := s.authorize(policy.Request{Actor: actor, Action: action, Targets: []policy.Target{target}}); res.Decision != policy.DecisionAllow {
		return database.TunnelEnrollment{}, actor, s.refuse(ctx, actor, action, target.Ref, res, found)
	}
	if !found {
		return database.TunnelEnrollment{}, actor, smerr.New(smerr.CodeNotFound, "", "tunnel enrollment not found")
	}
	return row, actor, nil
}

// requireStarter limits the steps that decide what the node will be (reading the connector token, confirming
// or refusing the key) to the identity that started the enrollment: another holder of node.add, or one
// whose own node.add needs approval, could otherwise pin a host of their choosing without that approval.
func (s *TunnelEnrollments) requireStarter(ctx context.Context, actor domain.Actor, row database.TunnelEnrollment) error {
	if actor.ID == row.StartedBy {
		return nil
	}
	res := policy.Result{Decision: policy.DecisionDeny, Reason: smerr.ReasonDefaultDeny}
	return s.refuse(ctx, actor, actionNodeAdd, nodeRef(row.ID), res, true)
}

// refuse answers a refused request with its typed error, auditing it when it is about an enrollment that exists.
func (s *TunnelEnrollments) refuse(ctx context.Context, actor domain.Actor, action string, ref domain.ResourceRef, res policy.Result, audited bool) error {
	return s.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		if audited {
			if err := s.auditDecision(ctx, tx, actor, action, ref, res); err != nil {
				return err
			}
		}
		return reject(decisionError(res))
	})
}

// refuseTokenToMCP denies the connector token to an mcp actor whatever its grant: it is a credential, and an
// mcp bearer never gets one (mcpgate.go). The refusal is audited like any other.
func (s *TunnelEnrollments) refuseTokenToMCP(ctx context.Context, actor domain.Actor, row database.TunnelEnrollment) error {
	res := policy.Result{Decision: policy.DecisionDeny, Reason: smerr.ReasonMCPActionForbidden}
	return s.refuse(ctx, actor, actionNodeAdd, nodeRef(row.ID), res, true)
}

// target is the policy view of the node an enrollment will become: its tags and environment.
func (s *TunnelEnrollments) target(ctx context.Context, q database.Querier, row database.TunnelEnrollment) (policy.Target, error) {
	target := policy.Target{Ref: nodeRef(row.ID), Attrs: policy.Attributes{Tags: row.Tags, Node: row.Name, Provider: row.Name}}
	if row.EnvironmentID == "" {
		return target, nil
	}
	env, err := environmentOf(ctx, q, row.EnvironmentID)
	if err != nil {
		return policy.Target{}, err
	}
	target.Attrs.Environment, target.Attrs.EnvironmentRisk, target.Attrs.ApprovalsRequired = env.Name, env.RiskLevel, env.ApprovalsRequired
	return target, nil
}

func environmentOf(ctx context.Context, q database.Querier, id domain.ID) (domain.Environment, error) {
	all, err := database.ListEnvironments(ctx, q)
	if err != nil {
		return domain.Environment{}, err
	}
	for _, env := range all {
		if env.ID == id {
			return env, nil
		}
	}
	return domain.Environment{}, smerr.New(smerr.CodeNotFound, "", "environment not found")
}

func (s *TunnelEnrollments) view(ctx context.Context, q database.Querier, row database.TunnelEnrollment) (TunnelEnrollmentView, error) {
	instance, err := database.GetInstance(ctx, q)
	if err != nil {
		return TunnelEnrollmentView{}, err
	}
	v := TunnelEnrollmentView{
		ID: row.ID, NodeID: row.ID, Name: row.Name, Tags: row.Tags, Hostname: row.Hostname, Phase: string(row.Phase),
		ExpiresAt: row.ExpiresAt, JoinLine: s.joinLine(instance.ID, row.Identity.PublicKey), HostPublicKey: row.ScannedHostKey,
		Error: enrollmentError(row),
	}
	if row.EnvironmentID != "" {
		env, err := environmentOf(ctx, q, row.EnvironmentID)
		if err != nil {
			return TunnelEnrollmentView{}, err
		}
		v.Environment = env.Name
	}
	if row.ScannedHostKey != "" {
		v.HostKeyFingerprint, _ = sshnode.Fingerprint(row.ScannedHostKey)
	}
	return v, nil
}

// enrollmentError is what the operator reads: the sanitized failure of a halted enrollment, or why a
// finished one ended, or what the node is still waited for.
func enrollmentError(row database.TunnelEnrollment) string {
	if row.LastError != "" {
		return row.LastError
	}
	if row.Phase != database.PhaseCommitted {
		return row.TerminalReason
	}
	return ""
}

// joinLine is the one line the operator runs on the node. It carries no secret: the instance ID and the
// authorized key are public, and the connector token is typed at the node's prompt.
func (s *TunnelEnrollments) joinLine(instance domain.ID, authorizedKey string) string {
	channel := ""
	if c := strings.TrimSpace(s.opts.Channel); c != "" && c != "stable" {
		channel = "SUPERMGMT_CHANNEL=" + c + " "
	}
	return fmt.Sprintf("curl -fsSL %s | sudo %ssh -s -- --tunnel --instance %s --authorized-key '%s'",
		joinScriptURL, channel, instance, authorizedKey)
}

// ---- the connector token ---------------------------------------------------------------

// Token returns the connector token to whoever started the enrollment while it is open (action node.add on
// the enrollment). It
// is stored in the secret store, shown here and nowhere else, and deleted when the node is proven, the
// enrollment ends or is cancelled.
func (s *TunnelEnrollments) Token(ctx context.Context, by Caller, name string) (audit.Secret, error) {
	row, actor, err := s.authorized(ctx, by, name, actionNodeAdd)
	if err != nil {
		return "", err
	}
	if actor.Type == domain.ActorMCP {
		return "", s.refuseTokenToMCP(ctx, actor, row)
	}
	if err := s.requireStarter(ctx, actor, row); err != nil {
		return "", err
	}
	if err := s.tokenAvailability(row); err != nil {
		return "", err
	}
	secretRef, err := secretName(row.TokenRef)
	if err != nil {
		return "", err
	}
	token, err := s.engine.opts.Secrets.Get(ctx, secrets.Ref{Name: secretRef})
	switch {
	case smerr.CodeOf(err) == smerr.CodeNotFound:
		return "", smerr.New(smerr.CodeConflict, "", "the Cloudflare side of the enrollment is still being built: ask again in a moment")
	case err != nil:
		return "", err
	}
	err = s.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		return s.emit(ctx, tx, actor, eventEnrollmentToken, nodeRef(row.ID), domain.ResultSucceeded,
			map[string]any{"enrollment_id": row.ID.String(), "name": row.Name})
	})
	return token, err
}

// tokenAvailability says why the token cannot be read now, nil while the node may still need it: the
// Cloudflare side is built and the enrollment waits for the node or for its confirmation.
func (s *TunnelEnrollments) tokenAvailability(row database.TunnelEnrollment) error {
	switch {
	case row.Phase.Halted():
		return smerr.New(smerr.CodeConflict, "", "the enrollment is halted: "+row.LastError)
	case provisioningPhase(row.Phase):
		return smerr.New(smerr.CodeConflict, "", "the Cloudflare side of the enrollment is still being built: ask again in a moment")
	case row.Phase == database.PhaseDNSCreated || row.Phase == database.PhaseScanned:
		if row.TerminalReason == "" && s.cfg.Clock.Now().Before(row.ExpiresAt) {
			return nil
		}
	}
	return smerr.New(smerr.CodeConflict, "", "the enrollment is not waiting for its node: the connector token is no longer available")
}

// ---- confirm, refuse, cancel ---------------------------------------------------------------

// Confirm binds the operator's decision to the enrollment and the exact key it was shown: it holds only
// while the enrollment is scanned and its scanned key is hostKey. A different key ends the enrollment with
// SSH_HOST_KEY_MISMATCH and its Cloudflare objects are cleaned up; a cancelled or expired enrollment, or
// one that is not yet scanned, is a CONFLICT.
func (s *TunnelEnrollments) Confirm(ctx context.Context, by Caller, name, hostKey string) (TunnelEnrollmentView, error) {
	hostKey = strings.TrimSpace(hostKey)
	if _, err := sshnode.ParseHostKey(hostKey); err != nil {
		return TunnelEnrollmentView{}, err
	}
	row, actor, err := s.authorized(ctx, by, name, actionNodeAdd)
	if err == nil {
		err = s.requireStarter(ctx, actor, row)
	}
	if err != nil {
		return TunnelEnrollmentView{}, err
	}
	return commit(ctx, s.core, by, func(ctx context.Context, tx *database.Tx) (TunnelEnrollmentView, error) {
		current, err := database.GetTunnelEnrollment(ctx, tx, row.ID)
		if err != nil {
			return TunnelEnrollmentView{}, err
		}
		now := s.cfg.Clock.Now()
		switch {
		case current.Phase == database.PhaseConfirmed && current.ConfirmedHostKey == hostKey:
			return s.view(ctx, tx, current) // a repeat of the same confirmation
		case !s.open(current, now) || current.Phase != database.PhaseScanned:
			return TunnelEnrollmentView{}, enrollmentNotConfirmable(current, now)
		case current.ScannedHostKey != hostKey:
			return s.refuseKey(ctx, tx, actor, current, "the key differs from the one scanned")
		}
		confirmed, err := database.ConfirmTunnelEnrollment(ctx, tx, current.ID, hostKey, now)
		if err != nil {
			return TunnelEnrollmentView{}, err
		}
		fingerprint, _ := sshnode.Fingerprint(hostKey)
		err = s.emit(ctx, tx, actor, eventEnrollmentConfirmed, nodeRef(current.ID), domain.ResultSucceeded,
			map[string]any{"enrollment_id": current.ID.String(), "host_key_fingerprint": fingerprint})
		if err != nil {
			return TunnelEnrollmentView{}, err
		}
		return s.view(ctx, tx, confirmed)
	})
}

// Refuse records that the operator did not accept the scanned key: the enrollment ends with
// SSH_HOST_KEY_MISMATCH and is cleaned up.
func (s *TunnelEnrollments) Refuse(ctx context.Context, by Caller, name string) (TunnelEnrollmentView, error) {
	row, actor, err := s.authorized(ctx, by, name, actionNodeAdd)
	if err == nil {
		err = s.requireStarter(ctx, actor, row)
	}
	if err != nil {
		return TunnelEnrollmentView{}, err
	}
	return commit(ctx, s.core, by, func(ctx context.Context, tx *database.Tx) (TunnelEnrollmentView, error) {
		current, err := database.GetTunnelEnrollment(ctx, tx, row.ID)
		if err != nil {
			return TunnelEnrollmentView{}, err
		}
		if !s.open(current, s.cfg.Clock.Now()) || current.Phase != database.PhaseScanned {
			return TunnelEnrollmentView{}, enrollmentNotConfirmable(current, s.cfg.Clock.Now())
		}
		return s.refuseKey(ctx, tx, actor, current, reasonRefused)
	})
}

// refuseKey moves a scanned enrollment to mismatch, which the next job cleans up, and answers the caller
// with SSH_HOST_KEY_MISMATCH. The transition commits with the rejection.
func (s *TunnelEnrollments) refuseKey(ctx context.Context, tx *database.Tx, actor domain.Actor, current database.TunnelEnrollment, why string) (TunnelEnrollmentView, error) {
	if _, err := database.AdvanceTunnelEnrollment(ctx, tx, current.ID, database.PhaseScanned, database.PhaseMismatch, database.TunnelObjects{}, s.cfg.Clock.Now()); err != nil {
		return TunnelEnrollmentView{}, err
	}
	err := s.emit(ctx, tx, actor, eventEnrollmentMismatch, nodeRef(current.ID), domain.ResultDenied,
		map[string]any{"enrollment_id": current.ID.String(), "reason": why})
	if err != nil {
		return TunnelEnrollmentView{}, err
	}
	return TunnelEnrollmentView{}, reject(smerr.New(smerr.CodeSSHHostKeyMismatch, "", "the host key was not accepted: the enrollment is ended and its Cloudflare objects are removed"))
}

// open reports whether the enrollment can still move toward a node: not finished, not being removed, not
// cancelled, not expired.
func (s *TunnelEnrollments) open(row database.TunnelEnrollment, now time.Time) bool {
	return !database.EnrollmentFinished(row.Phase) && !removalStarted(row.Phase) && row.Phase != database.PhaseMismatch &&
		row.TerminalReason == "" && now.Before(row.ExpiresAt)
}

func enrollmentNotConfirmable(row database.TunnelEnrollment, now time.Time) error {
	switch {
	case row.Phase == database.PhaseCommitted:
		return smerr.New(smerr.CodeConflict, "", "the enrollment is already committed")
	case database.EnrollmentFinished(row.Phase) || removalStarted(row.Phase) || row.Phase == database.PhaseMismatch || row.TerminalReason != "":
		return smerr.New(smerr.CodeConflict, "", "the enrollment was cancelled or ended")
	case !now.Before(row.ExpiresAt):
		return smerr.New(smerr.CodeConflict, "", "the enrollment expired")
	}
	return smerr.New(smerr.CodeConflict, "", "the enrollment has not scanned the node's host key yet: it is "+string(row.Phase))
}

// Cancel asks for the enrollment to be taken down (action node.add on the enrollment). The phase does not
// change here: the job that tears it down reconciles whatever an interrupted step left unrecorded before
// it starts the removal, and a confirmation or a commit that comes after this reads the reason and loses.
// Cancelling an enrollment that is ending or ended is a no-op; a committed one is a CONFLICT.
func (s *TunnelEnrollments) Cancel(ctx context.Context, by Caller, name string) (TunnelEnrollmentView, error) {
	row, actor, err := s.authorized(ctx, by, name, actionNodeAdd)
	if err != nil {
		return TunnelEnrollmentView{}, err
	}
	return commit(ctx, s.core, by, func(ctx context.Context, tx *database.Tx) (TunnelEnrollmentView, error) {
		current, err := database.GetTunnelEnrollment(ctx, tx, row.ID)
		if err != nil {
			return TunnelEnrollmentView{}, err
		}
		switch {
		case current.Phase == database.PhaseCommitted:
			return TunnelEnrollmentView{}, smerr.New(smerr.CodeConflict, "", "the enrollment is already committed: remove the node with `sm nodes remove`")
		case database.EnrollmentFinished(current.Phase) || removalStarted(current.Phase) || current.Phase == database.PhaseMismatch || current.TerminalReason != "":
			return s.view(ctx, tx, current)
		}
		ending, err := database.RequestTunnelEnrollmentEnd(ctx, tx, current.ID, reasonCancelled, s.cfg.Clock.Now())
		if err != nil {
			return TunnelEnrollmentView{}, err
		}
		err = s.emit(ctx, tx, actor, eventEnrollmentCancelled, nodeRef(current.ID), domain.ResultSucceeded,
			map[string]any{"enrollment_id": current.ID.String(), "phase": string(current.Phase)})
		if err != nil {
			return TunnelEnrollmentView{}, err
		}
		return s.view(ctx, tx, ending)
	})
}
