package app

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/discovery"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	sshnode "github.com/autarquico/supermgmt/internal/providers/ssh"
	"github.com/autarquico/supermgmt/internal/secrets"
	"github.com/autarquico/supermgmt/internal/textsafe"
	"github.com/autarquico/supermgmt/internal/transport/ssh"
)

// What the node.add jobs of an enrollment do. Every job is short: it looks at the enrollment's phase and
// does what that phase asks, then returns; the scheduler (tunnel_enroll_schedule.go) submits the next one.
//
//	started .. access_ready   provision the Cloudflare side (ADR-0037 order), keep the connector token
//	dns_created               one scan of the host key over the tunnel; the node may not be there yet
//	scanned                   nothing: waits for the operator's confirmation
//	confirmed                 prove the node with the confirmed key, then commit it in one transaction
//	mismatch, removing, ...   take the Cloudflare objects down, then end as expired or cancelled
//
// A cancel and an expiry make the cleanup due from whatever phase the enrollment is in.

const (
	// maxEnrollmentSteps bounds the phases one job walks.
	maxEnrollmentSteps = 8
)

// runJob runs the job when it carries an enrollment and reports whether it did. It is safe on a nil service.
func (s *TunnelEnrollments) runJob(ctx context.Context, lease jobs.Lease) (bool, error) {
	if s == nil {
		return false, nil
	}
	job, err := s.store.Get(ctx, s.cfg.DB.Reader(), lease.JobID)
	if err != nil {
		return true, err
	}
	if job.Type != JobControlPlaneApply || !payloadHasKey(job, tunnelParamKey) {
		return false, nil
	}
	p, err := payloadOf[nodeAddParams](job)
	if err != nil {
		return true, err
	}
	if !p.Tunnel {
		return false, nil
	}
	return true, s.advance(ctx, lease, job, p)
}

// advance walks the enrollment of the job as far as this job should: through the Cloudflare side and a first
// scan, or through the proof and the commit, or through the cleanup.
func (s *TunnelEnrollments) advance(ctx context.Context, lease jobs.Lease, job jobs.Job, p nodeAddParams) error {
	if s.engine == nil {
		return requireTunnelAllowed(false, domain.Node{})
	}
	row, err := s.openRow(ctx, lease, job, p)
	if err != nil {
		return err
	}
	for range maxEnrollmentSteps {
		again, err := s.step(ctx, lease, job, row)
		if err != nil {
			return s.haltIfExhausted(ctx, lease, job, row.ID, err)
		}
		if !again {
			return nil
		}
		if row, err = database.GetTunnelEnrollment(ctx, s.cfg.DB.Reader(), row.ID); err != nil {
			return err
		}
	}
	return nil
}

// openRow is the enrollment of the job. The job of an approved plan finds none and creates it, with the
// instance's SSH identity as it is now; the jobs after it always find the row.
func (s *TunnelEnrollments) openRow(ctx context.Context, lease jobs.Lease, job jobs.Job, p nodeAddParams) (database.TunnelEnrollment, error) {
	row, err := database.GetTunnelEnrollment(ctx, s.cfg.DB.Reader(), p.NodeID)
	if smerr.CodeOf(err) != smerr.CodeNotFound || err == nil {
		return row, err
	}
	identity, err := s.opts.Identity(ctx)
	if err != nil {
		return database.TunnelEnrollment{}, fmt.Errorf("load instance identity: %w", err)
	}
	err = s.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		if err := lease.Fence(ctx, tx); err != nil {
			return err
		}
		actor, err := loadActor(ctx, tx, job.ActorID, credentialOf(job))
		if err != nil {
			return err
		}
		row, err = s.createRow(ctx, tx, actor, p, identity)
		return err
	})
	return row, err
}

// endDue reports whether the enrollment has to be taken down now: it is being removed, its key was refused,
// it was cancelled, or it expired. It is checked before anything else, so a halted enrollment is cleaned up
// too.
func (s *TunnelEnrollments) endDue(row database.TunnelEnrollment, now time.Time) bool {
	if database.EnrollmentFinished(row.Phase) {
		return false
	}
	return removalStarted(row.Phase) || row.Phase == database.PhaseMismatch || row.TerminalReason != "" || !now.Before(row.ExpiresAt)
}

// step does what the phase of row asks. again says the enrollment moved on and the next phase may be worked
// in the same job.
func (s *TunnelEnrollments) step(ctx context.Context, lease jobs.Lease, job jobs.Job, row database.TunnelEnrollment) (bool, error) {
	switch {
	case database.EnrollmentFinished(row.Phase):
		return false, nil
	case s.endDue(row, s.cfg.Clock.Now()):
		return false, s.cleanup(ctx, lease, job, row)
	case row.Phase.Halted():
		return false, nil // waits for an operator: cancel it, or let it expire
	case provisioningPhase(row.Phase):
		return true, s.provision(ctx, lease, job, row)
	case row.Phase == database.PhaseDNSCreated:
		return false, s.scan(ctx, lease, job, row)
	case row.Phase == database.PhaseConfirmed:
		return s.proveAndCommit(ctx, lease, job, row)
	}
	return false, nil // scanned: the operator decides
}

// newRun is the provisioning run over the enrollment's row: the same code ADR-0037 gives a node, over the
// enrollment as its record.
func (s *TunnelEnrollments) newRun(ctx context.Context, lease jobs.Lease, job jobs.Job, row database.TunnelEnrollment) (*tunnelRun, *enrollmentRecord, error) {
	cf := s.engine.opts.Config
	if row.AccountID != cf.AccountID || row.Zone != cf.Zone {
		return nil, nil, smerr.New(smerr.CodeConflict, "", "the enrollment was started for another Cloudflare account or zone than the configured one")
	}
	r, err := s.engine.newRun(ctx, lease, job, domain.Node{ID: row.ID, Name: row.Name}, row.Hostname)
	if err != nil {
		return nil, nil, err
	}
	rec := newEnrollmentRecord(row, lease, r.write, s.cfg.Clock.Now)
	r.rec = rec
	return r, rec, nil
}

// ---- provisioning -------------------------------------------------------------------

func (s *TunnelEnrollments) provision(ctx context.Context, lease jobs.Lease, job jobs.Job, row database.TunnelEnrollment) error {
	r, rec, err := s.newRun(ctx, lease, job, row)
	if err != nil {
		return err
	}
	token, err := r.provisionCloudflare(ctx)
	if err != nil {
		return err
	}
	return s.storeToken(ctx, rec.Enrollment(), token)
}

// storeToken keeps the connector token in the secret store under the enrollment, unless it is there.
func (s *TunnelEnrollments) storeToken(ctx context.Context, row database.TunnelEnrollment, token audit.Secret) error {
	name, err := secretName(row.TokenRef)
	if err != nil {
		return err
	}
	if stored, err := s.engine.opts.Secrets.Get(ctx, secrets.Ref{Name: name}); err == nil && stored == token {
		return nil
	}
	_, err = s.engine.opts.Secrets.Put(ctx, name, token, map[string]any{"purpose": "cloudflare tunnel connector token of a node enrollment"})
	return err
}

// ensureToken restores the connector token when the worker died between recording the last Cloudflare
// object and storing it: it is read again from the tunnel, which every provisioning pass does too.
func (s *TunnelEnrollments) ensureToken(ctx context.Context, lease jobs.Lease, job jobs.Job, row database.TunnelEnrollment) error {
	name, err := secretName(row.TokenRef)
	if err != nil {
		return err
	}
	_, err = s.engine.opts.Secrets.Get(ctx, secrets.Ref{Name: name})
	if smerr.CodeOf(err) != smerr.CodeNotFound || err == nil {
		return err
	}
	r, rec, err := s.newRun(ctx, lease, job, row)
	if err != nil {
		return err
	}
	token, err := r.api.TunnelToken(ctx, rec.Objects().TunnelID)
	if err != nil {
		return r.step("tunnel token", err)
	}
	return s.storeToken(ctx, row, token)
}

// retireToken makes the stored connector token unreadable. The store keeps every version and has no delete,
// so the latest one is overwritten with a value that is no credential, as the service-token rotation does.
func (s *TunnelEnrollments) retireToken(ctx context.Context, row database.TunnelEnrollment) error {
	name, err := secretName(row.TokenRef)
	if err != nil {
		return err
	}
	stored, err := s.engine.opts.Secrets.Get(ctx, secrets.Ref{Name: name})
	if smerr.CodeOf(err) == smerr.CodeNotFound || (err == nil && stored == retiredCredential) {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = s.engine.opts.Secrets.Put(ctx, name, retiredCredential, map[string]any{"purpose": "cloudflare tunnel connector token of a node enrollment (retired)"})
	return err
}

// ---- scan ---------------------------------------------------------------------------

// scanTarget is the node as the tunnel reaches it: the hostname for both the host and the tunnel hostname.
// Nothing here is an address of the node.
func scanTarget(row database.TunnelEnrollment) ssh.Target {
	return ssh.Target{
		Host: row.Hostname, Port: enrollmentSSHPort, Transport: domain.TransportCloudflare, TunnelHostname: row.Hostname,
	}
}

// scan reads the host key once. A node that is not there yet is the normal case, not a failure: the reason
// is noted on the enrollment and the scheduler tries again with backoff until the expiry.
func (s *TunnelEnrollments) scan(ctx context.Context, lease jobs.Lease, job jobs.Job, row database.TunnelEnrollment) error {
	if err := s.ensureToken(ctx, lease, job, row); err != nil {
		return err
	}
	key, err := s.opts.Scan(ctx, scanTarget(row))
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return s.note(ctx, lease, row, "waiting for the node: "+sanitizedError(err))
	}
	return s.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		if err := lease.Fence(ctx, tx); err != nil {
			return err
		}
		current, err := database.GetTunnelEnrollment(ctx, tx, row.ID)
		if err != nil {
			return err
		}
		if current.Phase != database.PhaseDNSCreated || current.TerminalReason != "" {
			return nil // cancelled or moved on while scanning: the next step decides
		}
		scanned, err := database.RecordScannedHostKey(ctx, tx, row.ID, key.Authorized, s.cfg.Clock.Now())
		if err != nil {
			return err
		}
		if err := database.NoteTunnelEnrollment(ctx, tx, row.ID, database.PhaseScanned, "", s.cfg.Clock.Now()); err != nil {
			return err
		}
		return s.emitAs(ctx, tx, job, eventEnrollmentScanned, row.ID, domain.ResultSucceeded,
			map[string]any{"enrollment_id": row.ID.String(), "host_key_fingerprint": key.FingerprintSHA256, "host_key_type": key.Type, "phase": string(scanned.Phase)})
	})
}

// note records, fenced, what the enrollment is waiting for, without changing its phase.
func (s *TunnelEnrollments) note(ctx context.Context, lease jobs.Lease, row database.TunnelEnrollment, text string) error {
	return s.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		if err := lease.Fence(ctx, tx); err != nil {
			return err
		}
		return database.NoteTunnelEnrollment(ctx, tx, row.ID, row.Phase, text, s.cfg.Clock.Now())
	})
}

func sanitizedError(err error) string {
	message := textsafe.Line(audit.ScrubString(err.Error()))
	if runes := []rune(message); len(runes) > maxRecordedErrorLength {
		message = string(runes[:maxRecordedErrorLength])
	}
	return message
}

// ---- proof and commit ------------------------------------------------------------------------

// proofNode is the node the enrollment will become, in memory: the allocated ID, the dedicated user, the
// confirmed key pinned with exact bytes and the transport of the tunnel. The credential is the identity
// snapshot's, whatever the instance's identity is by now.
func proofNode(row database.TunnelEnrollment) domain.Node {
	return domain.Node{
		ID: row.ID, Name: row.Name, NativeID: row.Name, Kind: sshnode.NodeKind, CredentialRef: row.Identity.CredentialRef,
		Endpoint: domain.NodeEndpoint{
			Host: row.Hostname, Port: enrollmentSSHPort, User: config.DefaultSSHUser, HostPublicKey: row.ConfirmedHostKey,
			Transport: domain.TransportCloudflare, TunnelHostname: row.Hostname,
		},
	}
}

// proveAndCommit proves the node with the key the operator confirmed and, if it answers, commits it. It
// never uses Prober.Probe, which loads a node row that does not exist yet. A different key ends the
// enrollment as a mismatch; a node that does not answer yet is noted and tried again later. again is true
// when the cleanup of the enrollment is the next thing to do.
func (s *TunnelEnrollments) proveAndCommit(ctx context.Context, lease jobs.Lease, job jobs.Job, row database.TunnelEnrollment) (bool, error) {
	node := proofNode(row)
	ex, err := s.opts.Connector.Dedicated(node, row.Identity.CredentialRef)
	if err == nil {
		_, err = discovery.Probe(ctx, ex)
	}
	switch {
	case err == nil:
	case smerr.CodeOf(err) == smerr.CodeSSHHostKeyMismatch:
		return true, s.mismatch(ctx, lease, job, row)
	case ctx.Err() != nil:
		return false, ctx.Err()
	default:
		return false, s.note(ctx, lease, row, "waiting for the node: "+sanitizedError(err))
	}
	// The node answered through the tunnel, so its connector runs and the token has done its work.
	if err := s.retireToken(ctx, row); err != nil {
		return false, err
	}
	committed, err := s.commitNode(ctx, lease, job, row)
	switch {
	case err != nil:
		return false, err
	case !committed:
		return true, nil // cancelled, expired or re-keyed while the node was proven: the cleanup is next
	}
	if s.opts.Prober != nil {
		_ = s.opts.Prober.Probe(ctx, row.ID, ProbeFull, nil) // best effort: the refresher repeats it
	}
	return false, nil
}

// mismatch ends an enrollment whose node presented another key than the confirmed one.
func (s *TunnelEnrollments) mismatch(ctx context.Context, lease jobs.Lease, job jobs.Job, row database.TunnelEnrollment) error {
	return s.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		if err := lease.Fence(ctx, tx); err != nil {
			return err
		}
		if _, err := database.AdvanceTunnelEnrollment(ctx, tx, row.ID, database.PhaseConfirmed, database.PhaseMismatch, database.TunnelObjects{}, s.cfg.Clock.Now()); err != nil {
			return err
		}
		return s.emitAs(ctx, tx, job, eventEnrollmentMismatch, row.ID, domain.ResultDenied,
			map[string]any{"enrollment_id": row.ID.String(), "reason": "the node presented another host key than the confirmed one"})
	})
}

// commitNode writes the node in one fenced transaction: provider and node rows, the tunnel-only provenance,
// the committed tunnel operation that carries the Cloudflare object IDs, the enrollment marked committed and
// the audit event. Under the same transaction it checks again that nobody cancelled, expired or re-keyed the
// enrollment and that the name is still free. committed is false when it lost such a race; the caller then
// cleans the enrollment up.
func (s *TunnelEnrollments) commitNode(ctx context.Context, lease jobs.Lease, job jobs.Job, row database.TunnelEnrollment) (bool, error) {
	committed := true
	err := s.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		if err := lease.Fence(ctx, tx); err != nil {
			return err
		}
		current, err := database.GetTunnelEnrollment(ctx, tx, row.ID)
		if err != nil {
			return err
		}
		now := s.cfg.Clock.Now()
		if current.Phase != database.PhaseConfirmed || current.TerminalReason != "" || !now.Before(current.ExpiresAt) ||
			current.ConfirmedHostKey != row.ConfirmedHostKey {
			committed = false
			return nil
		}
		if err := requireNameFree(ctx, tx, current.Name, current.ID); err != nil {
			return err
		}
		actor, err := loadActor(ctx, tx, job.ActorID, credentialOf(job))
		if err != nil {
			return err
		}
		node, err := s.insertNode(ctx, tx, current, now)
		if err != nil {
			return err
		}
		if _, err := database.ImportCommittedTunnelOperation(ctx, tx, database.TunnelOperation{
			ID: s.cfg.IDs.NewID(), NodeID: node.ID, AccountID: current.AccountID, Zone: current.Zone,
			InstanceID: current.InstanceID, Hostname: current.Hostname, Objects: current.Objects, CreatedAt: now,
		}); err != nil {
			return err
		}
		if _, err := database.EndTunnelEnrollment(ctx, tx, current.ID, database.PhaseConfirmed, database.PhaseCommitted, now); err != nil {
			return err
		}
		fingerprint, _ := sshnode.Fingerprint(current.ConfirmedHostKey)
		return s.emit(ctx, tx, actor, actionNodeAdd, nodeRef(node.ID), domain.ResultSucceeded, map[string]any{
			"name": node.Name, "host": current.Hostname, "port": enrollmentSSHPort, "user": config.DefaultSSHUser,
			"transport": string(domain.TransportCloudflare), "host_key_fingerprint": fingerprint, "enrollment_id": current.ID.String(),
			"environment": row.EnvironmentID.String(), "job_id": job.ID.String(),
		})
	})
	return committed && err == nil, err
}

// insertNode writes the provider and the node of a committed enrollment: SSH, the tunnel transport with the
// hostname as the endpoint host, the confirmed key pinned, no admin_user, and the identity snapshot's
// versioned credential.
func (s *TunnelEnrollments) insertNode(ctx context.Context, tx *database.Tx, e database.TunnelEnrollment, now time.Time) (domain.Node, error) {
	provider, err := database.CreateProvider(ctx, tx, domain.Provider{
		ID: s.cfg.IDs.NewID(), Type: sshnode.ProviderType, Name: e.Name, Origin: domain.ProviderAPI,
		Endpoint: net.JoinHostPort(e.Hostname, strconv.Itoa(enrollmentSSHPort)), CredentialRef: e.Identity.CredentialRef,
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		return domain.Node{}, err
	}
	var environment *domain.ID
	if e.EnvironmentID != "" {
		environment = &e.EnvironmentID
	}
	node := proofNode(e)
	node.ProviderID, node.EnvironmentID = provider.ID, environment
	node.ManagementState, node.Reachability = domain.ManagementManaged, domain.ReachabilityUnknown
	node.Tags, node.Metadata = e.Tags, withTunnelOnly(nil)
	node.CreatedAt, node.UpdatedAt = now, now
	return database.CreateNode(ctx, tx, node)
}

// ---- cleanup --------------------------------------------------------------------------

// endingOf is why and how the enrollment ends: the reason recorded by a cancel or by the removal that
// already started, else the refusal of a key, else the expiry.
func endingOf(row database.TunnelEnrollment) (string, database.TunnelPhase) {
	reason := row.TerminalReason
	switch {
	case reason != "":
	case row.Phase == database.PhaseMismatch:
		reason = string(smerr.CodeSSHHostKeyMismatch)
	default:
		reason = reasonExpired
	}
	if reason == reasonExpired {
		return reason, database.PhaseExpired
	}
	return reason, database.PhaseCancelled
}

// cleanup takes the Cloudflare objects down (the teardown of ADR-0039) and releases the name. The token is
// retired first: once the enrollment is ending nobody should be shown it.
func (s *TunnelEnrollments) cleanup(ctx context.Context, lease jobs.Lease, job jobs.Job, row database.TunnelEnrollment) error {
	if err := s.retireToken(ctx, row); err != nil {
		return err
	}
	r, rec, err := s.newRun(ctx, lease, job, row)
	if err != nil {
		return err
	}
	reason, end := endingOf(row)
	return r.removeEnrollment(ctx, rec, reason, end)
}

// ---- halting --------------------------------------------------------------------------

// haltIfExhausted leaves the enrollment halted, with the sanitized cause, when the job that failed had no
// attempt left: the engine then fails the job for good, and an enrollment that waited for it would sit in a
// running phase that nothing advances. The cleanup is exempt: a removal that failed is tried again by the
// scheduler until nothing is left. It returns cause.
func (s *TunnelEnrollments) haltIfExhausted(ctx context.Context, lease jobs.Lease, job jobs.Job, id domain.ID, cause error) error {
	if job.Attempts < job.MaxAttempts || errors.Is(cause, jobs.ErrLeaseLost) || ctx.Err() != nil {
		return cause
	}
	ctx = context.WithoutCancel(ctx)
	row, err := database.GetTunnelEnrollment(ctx, s.cfg.DB.Reader(), id)
	if err != nil || row.Phase.Halted() || database.EnrollmentFinished(row.Phase) || s.endDue(row, s.cfg.Clock.Now()) {
		return cause
	}
	rec := newEnrollmentRecord(row, lease, s.write, s.cfg.Clock.Now)
	_ = rec.Halt(ctx, database.PhaseFailed, sanitizedError(cause), func(ctx context.Context, tx *database.Tx) error {
		return s.emitAs(ctx, tx, job, eventEnrollmentHalted, id, domain.ResultFailed,
			map[string]any{"enrollment_id": id.String(), "phase": string(cmp.Or(row.HaltedPhase, row.Phase))})
	})
	return cause
}

// emitAs emits an event about the enrollment as the actor of the job.
func (s *TunnelEnrollments) emitAs(ctx context.Context, q database.Querier, job jobs.Job, action string, id domain.ID, result domain.Result, data map[string]any) error {
	actor, err := loadActor(ctx, q, job.ActorID, credentialOf(job))
	if err != nil {
		return err
	}
	data["job_id"] = job.ID.String()
	return s.emit(ctx, q, actor, action, nodeRef(id), result, data)
}
