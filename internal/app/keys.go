package app

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
	"github.com/autarquico/supermgmt/internal/secrets"
)

const (
	actionSecretWrite = "secret.write"

	eventMasterKeyRotated = "secret.master_key.rotated"
	eventMasterKeyRetired = "secret.master_key.retired"
	eventMasterKeyExport  = "secret.master_key.exported"
	eventSecretImported   = "secret.imported"
	eventSSHKeyRotated    = "ssh_identity.rotated"

	// MaxImportedSecretBytes bounds one imported value; private keys and
	// tokens are far below it.
	MaxImportedSecretBytes = 64 << 10

	// exportIntentTTL is how long after its approval an export request can
	// still be executed (spec §11.2, as for mcp_client.issue_token).
	exportIntentTTL = 24 * time.Hour
)

// The operations of secret.write. Each is a plan and a control_plane.apply job
// when policy requires approval, which for a high-risk action is always.
const (
	opRotateMasterKey = "rotate_master_key"
	opRetireKey       = "retire_key"
	opExportKey       = "export_key"
	opImportSecret    = "import_secret"
	opRotateSSHKey    = "rotate_ssh_key"
)

var eventOfOperation = map[string]string{
	opRotateMasterKey: eventMasterKeyRotated,
	opRetireKey:       eventMasterKeyRetired,
	opExportKey:       eventMasterKeyExport,
	opImportSecret:    eventSecretImported,
	opRotateSSHKey:    eventSSHKeyRotated,
}

// secretWriteParams is what a secret.write plan and job carry. It never holds
// a secret value or a passphrase: an import names its staged, already sealed
// version and the SHA-256 of that version's ciphertext.
type secretWriteParams struct {
	Operation              string    `json:"operation"`
	KEKID                  domain.ID `json:"kek_id,omitempty"`
	ExternalBackupsHandled bool      `json:"external_backups_handled,omitempty"`
	Name                   string    `json:"name,omitempty"`
	StagedID               domain.ID `json:"staged_id,omitempty"`
	StagedCiphertextSHA256 string    `json:"staged_ciphertext_sha256,omitempty"`
}

// validate checks that the parameters are those of a submittable plan.
func (p secretWriteParams) validate() error {
	switch p.Operation {
	case opRotateMasterKey, opRotateSSHKey:
		return nil
	case opExportKey:
		return p.requireKEK()
	case opRetireKey:
		if !p.ExternalBackupsHandled {
			return smerr.New(smerr.CodeInvalidArgument, "", "retiring a key requires external_backups_handled: backups copied elsewhere may still need it")
		}
		return p.requireKEK()
	case opImportSecret:
		if p.Name == "" || p.StagedID == "" || p.StagedCiphertextSHA256 == "" {
			return smerr.New(smerr.CodeInvalidArgument, "", "an import plan names the secret, its staged version and the digest of the staged ciphertext")
		}
		return nil
	}
	return smerr.New(smerr.CodeInvalidArgument, "", "unknown secret.write operation "+p.Operation)
}

func (p secretWriteParams) requireKEK() error {
	_, err := domain.ParseID(p.KEKID.String())
	return err
}

// KeyManager implements Keys (spec §10, ADR-0021). Every operation is
// authorized for secret.write. Because that action is high risk, policy
// requires approval: the request becomes a plan and a control_plane.apply job,
// and the operation runs against the secrets package (which owns its
// transactions and the keyOps lock) when the job runs. Operations are audited
// with identifiers and fingerprints only, never key material, passphrases or
// secret values.
type KeyManager struct {
	core
	plans *Plans
	jobs  *jobs.Store
	admin *secrets.KeyAdmin
	store *secrets.Store
	mode  config.Mode
}

var _ Keys = (*KeyManager)(nil)

// NewKeyManager validates cfg and the collaborators. The job store is the one
// built with this package's Revalidator and LockPlanner. mode decides whether
// ExportKey may be served at all.
func NewKeyManager(cfg Config, jobStore *jobs.Store, admin *secrets.KeyAdmin, store *secrets.Store, mode config.Mode) (*KeyManager, error) {
	plans, err := NewPlans(cfg, jobStore)
	if err != nil {
		return nil, err
	}
	if admin == nil || store == nil {
		return nil, fmt.Errorf("app: key manager needs the key administrator and the secret store")
	}
	return &KeyManager{core: plans.core, plans: plans, jobs: jobStore, admin: admin, store: store, mode: mode}, nil
}

// ---- requests -------------------------------------------------------------------

// RotateMasterKey makes a new KEK active and rewraps every data key under it.
func (k *KeyManager) RotateMasterKey(ctx context.Context, by Caller) (DirectResult[wire.MasterKeyRotated], error) {
	req := k.request(secretWriteParams{Operation: opRotateMasterKey})
	return submitOrApply(ctx, k, by, req, func(ctx context.Context, actor domain.Actor) (wire.MasterKeyRotated, error) {
		return audited(ctx, k, k.write, actor, req.event(), func() (wire.MasterKeyRotated, map[string]any, error) {
			return k.rotateMasterKey(ctx)
		})
	})
}

func (k *KeyManager) rotateMasterKey(ctx context.Context) (wire.MasterKeyRotated, map[string]any, error) {
	r, err := k.admin.Rotate(ctx)
	if err != nil {
		return wire.MasterKeyRotated{}, nil, err
	}
	return wire.MasterKeyRotated{ActiveKEKID: r.Active, PreviousKEKID: r.Previous, Rewrapped: r.Rewrapped},
		map[string]any{"active_kek_id": r.Active, "previous_kek_id": r.Previous, "rewrapped": r.Rewrapped}, nil
}

// RetireKey deletes a KEK nothing references. The caller must acknowledge that
// backups kept outside backup.directory are handled (spec §10); the
// acknowledgement is part of the audit event.
func (k *KeyManager) RetireKey(ctx context.Context, by Caller, r wire.RetireKeyRequest) (DirectResult[struct{}], error) {
	req := k.request(secretWriteParams{Operation: opRetireKey, KEKID: r.KEKID, ExternalBackupsHandled: r.ExternalBackupsHandled})
	req.validate = req.params.validate
	return submitOrApply(ctx, k, by, req, func(ctx context.Context, actor domain.Actor) (struct{}, error) {
		return audited(ctx, k, k.write, actor, req.event(), func() (struct{}, map[string]any, error) {
			return k.retireKey(ctx, r.KEKID)
		})
	})
}

func (k *KeyManager) retireKey(ctx context.Context, id domain.ID) (struct{}, map[string]any, error) {
	return struct{}{}, map[string]any{"kek_id": id, "external_backups_handled": true}, k.admin.Retire(ctx, id)
}

// ImportSecret stores a new version of a named secret. ssh/default is reserved
// for the instance identity: it has its own rotation and metadata. Awaiting
// approval, the value waits sealed as a staged version that nothing can read.
func (k *KeyManager) ImportSecret(ctx context.Context, by Caller, r wire.ImportSecretRequest) (DirectResult[wire.SecretVersion], error) {
	req := k.request(secretWriteParams{Operation: opImportSecret, Name: r.Name})
	req.validate = func() error { return validateImport(r) }
	req.stage = func(ctx context.Context) (secretWriteParams, func(), error) {
		staged, err := k.store.Stage(ctx, r.Name, audit.Secret(r.Value), map[string]any{"source": "import"})
		if err != nil {
			return secretWriteParams{}, nil, err
		}
		discard := func() { _ = k.store.Discard(context.WithoutCancel(ctx), staged.ID) }
		return secretWriteParams{Operation: opImportSecret, Name: staged.Name, StagedID: staged.ID, StagedCiphertextSHA256: staged.CiphertextSHA256}, discard, nil
	}
	return submitOrApply(ctx, k, by, req, func(ctx context.Context, actor domain.Actor) (wire.SecretVersion, error) {
		return audited(ctx, k, k.write, actor, req.event(), func() (wire.SecretVersion, map[string]any, error) {
			ref, err := k.store.Put(ctx, r.Name, audit.Secret(r.Value), map[string]any{"source": "import"})
			return wire.SecretVersion{Name: ref.Name, Version: ref.Version}, map[string]any{"name": ref.Name, "version": ref.Version}, err
		})
	})
}

func validateImport(r wire.ImportSecretRequest) error {
	switch {
	case r.Name == secrets.SSHIdentityName:
		return smerr.New(smerr.CodeInvalidArgument, "", "secret "+secrets.SSHIdentityName+" is the instance SSH identity; use ssh-key rotate")
	case r.Value == "":
		return smerr.New(smerr.CodeInvalidArgument, "", "secret value is empty")
	case len(r.Value) > MaxImportedSecretBytes:
		return smerr.New(smerr.CodeInvalidArgument, "", fmt.Sprintf("secret value exceeds %d bytes", MaxImportedSecretBytes))
	}
	return nil
}

func (k *KeyManager) activateImport(ctx context.Context, p secretWriteParams) (wire.SecretVersion, map[string]any, error) {
	ref, err := k.store.Activate(ctx, secrets.Staged{ID: p.StagedID, Name: p.Name, CiphertextSHA256: p.StagedCiphertextSHA256})
	return wire.SecretVersion{Name: ref.Name, Version: ref.Version}, map[string]any{"name": ref.Name, "version": ref.Version}, err
}

// RotateSSHIdentity stores a new version of the instance SSH identity. Nodes
// keep signing with the version their setup pinned until node.setup re-runs.
func (k *KeyManager) RotateSSHIdentity(ctx context.Context, by Caller) (DirectResult[wire.SSHKey], error) {
	req := k.request(secretWriteParams{Operation: opRotateSSHKey})
	return submitOrApply(ctx, k, by, req, func(ctx context.Context, actor domain.Actor) (wire.SSHKey, error) {
		return audited(ctx, k, k.write, actor, req.event(), func() (wire.SSHKey, map[string]any, error) {
			return k.rotateSSHKey(ctx)
		})
	})
}

func (k *KeyManager) rotateSSHKey(ctx context.Context) (wire.SSHKey, map[string]any, error) {
	id, err := secrets.RotateSSHIdentity(ctx, k.store)
	if err != nil {
		return wire.SSHKey{}, nil, err
	}
	return wire.SSHKey{
			Ref: "secret://" + id.Ref.Name, Version: id.Ref.Version,
			AuthorizedKey: id.AuthorizedKey, FingerprintSHA256: id.FingerprintSHA256,
		},
		map[string]any{"name": id.Ref.Name, "version": id.Ref.Version, "fingerprint": id.FingerprintSHA256}, nil
}

// ---- the request protocol ---------------------------------------------------------

// secretRequest is one secret.write request before it is decided.
type secretRequest struct {
	params secretWriteParams
	ref    domain.ResourceRef
	// rule is a transport restriction applied before policy.
	rule func(Caller) error
	// validate checks the request once the caller is known to be allowed.
	validate func() error
	// stage prepares what the plan will reference, outside any transaction, and
	// returns the final parameters with the undo for a request that fails.
	stage func(ctx context.Context) (secretWriteParams, func(), error)
}

func (k *KeyManager) request(p secretWriteParams) secretRequest {
	return secretRequest{params: p, ref: domain.ResourceRef{Type: domain.ResourceSecret, ID: k.cfg.IDs.NewID()}}
}

func (r secretRequest) event() string { return eventOfOperation[r.params.Operation] }

// submitOrApply runs the request. Policy decides in a first transaction; an
// action that needs approval then becomes a plan and a job (committed with the
// request's Idempotency-Key), and one that does not is applied by direct.
func submitOrApply[T any](ctx context.Context, k *KeyManager, by Caller, req secretRequest, direct func(ctx context.Context, actor domain.Actor) (T, error)) (DirectResult[T], error) {
	actor, approvalRequired, err := k.preflight(ctx, by, req)
	if err != nil {
		return DirectResult[T]{}, err
	}
	if !approvalRequired {
		out, err := direct(ctx, actor)
		if err != nil {
			return DirectResult[T]{}, err
		}
		return DirectResult[T]{Applied: &out}, nil
	}
	params, discard := req.params, func() {}
	if req.stage != nil {
		if params, discard, err = req.stage(ctx); err != nil {
			return DirectResult[T]{}, err
		}
	}
	submission, err := k.submit(ctx, by, req, params)
	if err != nil {
		discard()
		return DirectResult[T]{}, err
	}
	return DirectResult[T]{Pending: &submission}, nil
}

// preflight identifies the caller and evaluates secret.write. A denial is
// audited and returned.
func (k *KeyManager) preflight(ctx context.Context, by Caller, req secretRequest) (domain.Actor, bool, error) {
	var (
		actor    domain.Actor
		approval bool
	)
	err := k.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		var err error
		if actor, err = k.beginRequest(ctx, tx, by); err != nil {
			return err
		}
		if req.rule != nil {
			if err := req.rule(by); err != nil {
				return k.denied(ctx, tx, actor, req.event(), err)
			}
		}
		res := k.authorize(policy.Request{Actor: actor, Action: actionSecretWrite, Targets: []policy.Target{{Ref: req.ref}}})
		if err := k.auditDecision(ctx, tx, actor, actionSecretWrite, req.ref, res); err != nil {
			return err
		}
		if err := decisionError(res); err != nil {
			return reject(err)
		}
		approval = res.ApprovalRequired
		if req.validate != nil {
			if err := req.validate(); err != nil {
				return reject(err)
			}
		}
		return nil
	})
	return actor, approval, err
}

// submit creates the plan and the control_plane.apply job of the request.
func (k *KeyManager) submit(ctx context.Context, by Caller, req secretRequest, params secretWriteParams) (Submission, error) {
	return commit(ctx, k.core, by, func(ctx context.Context, tx *database.Tx) (Submission, error) {
		actor, err := k.beginRequest(ctx, tx, by)
		if err != nil {
			return Submission{}, err
		}
		if req.rule != nil {
			if err := req.rule(by); err != nil {
				return Submission{}, k.denied(ctx, tx, actor, req.event(), err)
			}
		}
		planParams, err := toParams(params)
		if err != nil {
			return Submission{}, err
		}
		b, err := build(ctx, tx, actionSecretWrite, by.ID, req.ref, planParams)
		if err != nil {
			return Submission{}, err
		}
		res, err := k.evaluate(ctx, tx, actor, b)
		if err != nil {
			return Submission{}, err
		}
		if !res.ApprovalRequired {
			return Submission{}, reject(smerr.New(smerr.CodeConflict, "", "policy changed while the request was being made; repeat it"))
		}
		return k.plans.planAndSubmit(ctx, tx, by, actor, b, res)
	})
}

// ---- the approved job ---------------------------------------------------------------

// runApproved executes the operation an approved control_plane.apply job
// carries. The lease is fenced before the operation and before its audit event.
func (k *KeyManager) runApproved(ctx context.Context, lease jobs.Lease) error {
	fenced := func(ctx context.Context, fn func(context.Context, *database.Tx) error) error {
		return k.write(ctx, func(ctx context.Context, tx *database.Tx) error {
			if err := lease.Fence(ctx, tx); err != nil {
				return err
			}
			return fn(ctx, tx)
		})
	}
	var (
		job   jobs.Job
		actor domain.Actor
	)
	err := fenced(ctx, func(ctx context.Context, tx *database.Tx) error {
		var err error
		if job, err = k.jobs.Get(ctx, tx, lease.JobID); err != nil {
			return err
		}
		actor, err = loadActor(ctx, tx, job.ActorID, credentialOf(job))
		return err
	})
	if err != nil {
		return err
	}
	p, err := payloadOf[secretWriteParams](job)
	if err != nil {
		return err
	}
	if p.Operation == opExportKey {
		return nil // the approval is the whole effect: the requester executes the export itself
	}
	_, err = audited(ctx, k, fenced, actor, eventOfOperation[p.Operation], func() (struct{}, map[string]any, error) {
		data, err := k.perform(ctx, p)
		if data != nil {
			data["job_id"] = job.ID.String()
		}
		return struct{}{}, data, err
	})
	return err
}

func (k *KeyManager) perform(ctx context.Context, p secretWriteParams) (map[string]any, error) {
	var (
		data map[string]any
		err  error
	)
	switch p.Operation {
	case opRotateMasterKey:
		_, data, err = k.rotateMasterKey(ctx)
	case opRetireKey:
		_, data, err = k.retireKey(ctx, p.KEKID)
	case opRotateSSHKey:
		_, data, err = k.rotateSSHKey(ctx)
	case opImportSecret:
		_, data, err = k.activateImport(ctx, p)
	default:
		err = smerr.New(smerr.CodeInternal, "", "secret.write job with unsupported operation "+p.Operation)
	}
	return data, err
}

// ---- master key export ----------------------------------------------------------------

// ExportKey wraps a KEK under the caller's passphrase. It is served only to a
// local-socket caller of a local-mode instance: the response carries a wrapped
// master key and must never cross HTTPS or the server-mode admin socket.
//
// The export is two steps because a plan must never hold a passphrase. Without
// a passphrase the call requests the export: policy parks it as an
// approval-gated job that exports nothing. With a passphrase, the identity that
// made an approved request executes it, once, within 24h of the approval; a
// second execution or a late one is CONFLICT, another identity's is
// POLICY_DENIED. When policy needs no approval the passphrase exports directly.
func (k *KeyManager) ExportKey(ctx context.Context, by Caller, r wire.ExportKeyRequest) (DirectResult[wire.ExportedKey], error) {
	if _, err := domain.ParseID(r.KEKID.String()); err != nil {
		return DirectResult[wire.ExportedKey]{}, err
	}
	req := k.request(secretWriteParams{Operation: opExportKey, KEKID: r.KEKID})
	req.rule = k.requireLocalSocket
	req.validate = func() error { return k.requireLoaded(r.KEKID) }
	if r.Passphrase == "" {
		return submitOrApply(ctx, k, by, req, func(context.Context, domain.Actor) (wire.ExportedKey, error) {
			return wire.ExportedKey{}, smerr.New(smerr.CodeInvalidArgument, "", "a passphrase is required: this export needs no approval")
		})
	}
	actor, approvalRequired, err := k.preflight(ctx, by, req)
	if err != nil {
		return DirectResult[wire.ExportedKey]{}, err
	}
	var out wire.ExportedKey
	if approvalRequired {
		out, err = k.executeApprovedExport(ctx, by, actor, r)
	} else {
		out, err = audited(ctx, k, k.write, actor, eventMasterKeyExport, func() (wire.ExportedKey, map[string]any, error) {
			return k.export(ctx, r)
		})
	}
	if err != nil {
		return DirectResult[wire.ExportedKey]{}, err
	}
	return DirectResult[wire.ExportedKey]{Applied: &out}, nil
}

func (k *KeyManager) requireLoaded(id domain.ID) error {
	if !k.admin.Loaded(id) {
		return smerr.New(smerr.CodeNotFound, "", "no such key is loaded: "+id.String())
	}
	return nil
}

func (k *KeyManager) export(ctx context.Context, r wire.ExportKeyRequest) (wire.ExportedKey, map[string]any, error) {
	export, err := k.admin.Export(ctx, r.KEKID, r.Passphrase)
	return wire.ExportedKey{KEKID: r.KEKID, Export: export}, map[string]any{"kek_id": r.KEKID}, err
}

// executeApprovedExport spends the caller's approved export request. The
// request is checked first so a stranger costs no key derivation, and is
// claimed after the export exists, in the transaction that records the use:
// a failed export leaves the request intact, and two executions cannot both win.
func (k *KeyManager) executeApprovedExport(ctx context.Context, by Caller, actor domain.Actor, r wire.ExportKeyRequest) (wire.ExportedKey, error) {
	if err := k.claimExport(ctx, by, actor, r.KEKID, false); err != nil {
		return wire.ExportedKey{}, err
	}
	out, _, err := k.export(ctx, r)
	if err != nil {
		return wire.ExportedKey{}, err
	}
	if err := k.claimExport(ctx, by, actor, r.KEKID, true); err != nil {
		return wire.ExportedKey{}, err
	}
	return out, nil
}

// claimExport finds the caller's usable export request for kek and, when
// consume is set, records its use. A refusal is audited.
func (k *KeyManager) claimExport(ctx context.Context, by Caller, actor domain.Actor, kek domain.ID, consume bool) error {
	return k.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		intents, err := exportIntents(ctx, tx, kek)
		if err != nil {
			return err
		}
		intent, err := chooseIntent(intents, by.ID, k.cfg.Clock.Now())
		if err != nil {
			return k.refused(ctx, tx, actor, err)
		}
		if !consume {
			return nil
		}
		return k.emit(ctx, tx, actor, eventMasterKeyExport, domain.ResourceRef{Type: domain.ResourceSecret, ID: intent.target},
			domain.ResultSucceeded, map[string]any{"kek_id": kek, "job_id": intent.jobID.String()})
	})
}

// refused audits a refused execution and rejects with err.
func (k *KeyManager) refused(ctx context.Context, tx *database.Tx, actor domain.Actor, err error) error {
	result := domain.ResultFailed
	if smerr.CodeOf(err) == smerr.CodePolicyDenied {
		result = domain.ResultDenied
	}
	if emitErr := k.emit(ctx, tx, actor, eventMasterKeyExport, secretTarget, result, map[string]any{"code": string(smerr.CodeOf(err))}); emitErr != nil {
		return emitErr
	}
	return reject(err)
}

// exportIntent is an approved export request: a succeeded job.
type exportIntent struct {
	jobID      domain.ID
	target     domain.ID // the job's resource: unique per request, it names the use
	actor      domain.ID
	approvedAt time.Time
	used       bool
}

func (i exportIntent) usable(now time.Time) bool {
	return !i.used && now.Before(i.approvedAt.Add(exportIntentTTL))
}

// exportIntents lists the approved export requests for kek, newest first.
func exportIntents(ctx context.Context, q database.Querier, kek domain.ID) ([]exportIntent, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT j.id, j.resource_id, j.actor_id, j.finished_at,
		       EXISTS (SELECT 1 FROM events e WHERE e.action = ? AND e.resource_type = 'secret'
		               AND e.resource_id = j.resource_id AND e.result = 'succeeded')
		FROM jobs j
		WHERE j.type = ? AND j.resource_type = 'secret' AND j.state = 'succeeded'
		  AND json_extract(j.payload_json, '$.operation') = ? AND json_extract(j.payload_json, '$.kek_id') = ?
		ORDER BY j.finished_at DESC`,
		eventMasterKeyExport, JobControlPlaneApply, opExportKey, kek)
	if err != nil {
		return nil, fmt.Errorf("list export requests: %w", err)
	}
	defer rows.Close()
	var out []exportIntent
	for rows.Next() {
		var (
			i      exportIntent
			finish int64
		)
		if err := rows.Scan(&i.jobID, &i.target, &i.actor, &finish, &i.used); err != nil {
			return nil, fmt.Errorf("scan export request: %w", err)
		}
		i.approvedAt = domain.FromUnixMillis(finish)
		out = append(out, i)
	}
	return out, rows.Err()
}

// chooseIntent picks the request caller may execute now, or says why none.
func chooseIntent(intents []exportIntent, caller domain.ID, now time.Time) (exportIntent, error) {
	mine := slices.DeleteFunc(slices.Clone(intents), func(i exportIntent) bool { return i.actor != caller })
	if len(mine) == 0 {
		if slices.ContainsFunc(intents, func(i exportIntent) bool { return i.usable(now) }) {
			return exportIntent{}, smerr.FromReason(smerr.ReasonNotPlanActor, "the approved export request belongs to another identity")
		}
		return exportIntent{}, smerr.New(smerr.CodeApprovalRequired, "", "no approved export request: request the export without a passphrase and wait for its approval")
	}
	for _, i := range mine {
		if i.usable(now) {
			return i, nil
		}
	}
	return exportIntent{}, smerr.New(smerr.CodeConflict, "", "the approved export request was already used or has expired; request the export again")
}

// ---- authorization and audit ---------------------------------------------------

var secretTarget = domain.ResourceRef{Type: domain.ResourceSecret}

func (k *KeyManager) requireLocalSocket(by Caller) error {
	if k.mode != config.ModeLocal || by.Credential.Kind != domain.CredentialLocalSocket {
		return smerr.New(smerr.CodePolicyDenied, smerr.ReasonDefaultDeny,
			"exporting a master key is served only on the local-mode Unix socket; in server mode use `sm secrets export-key --offline`")
	}
	return nil
}

func (k *KeyManager) denied(ctx context.Context, tx *database.Tx, actor domain.Actor, event string, cause error) error {
	if err := k.emit(ctx, tx, actor, event, secretTarget, domain.ResultDenied, map[string]any{"reason": string(smerr.ReasonDefaultDeny)}); err != nil {
		return err
	}
	return reject(cause)
}

// transact runs fn in one write transaction; the approved job fences its lease
// there.
type transact func(ctx context.Context, fn func(ctx context.Context, tx *database.Tx) error) error

// audited runs op and records its outcome with write. A failed operation is
// recorded with its error code only. When the operation succeeded but its event
// could not be stored, the caller gets an INTERNAL error that says so: the
// change happened.
func audited[T any](ctx context.Context, k *KeyManager, write transact, actor domain.Actor, event string, op func() (T, map[string]any, error)) (T, error) {
	out, data, opErr := op()
	result := domain.ResultSucceeded
	if opErr != nil {
		result = domain.ResultFailed
		data = map[string]any{"code": string(smerr.CodeOf(opErr))}
	}
	if err := write(ctx, func(ctx context.Context, tx *database.Tx) error {
		return k.emit(ctx, tx, actor, event, secretTarget, result, data)
	}); err != nil && opErr == nil {
		var zero T
		return zero, smerr.Wrap(err, smerr.CodeInternal, "", event+" completed but its audit event could not be recorded")
	}
	if opErr != nil {
		var zero T
		return zero, opErr
	}
	return out, nil
}

// ---- SQL implementation of the transactional key primitive ------------------------

// SecretsKeyRepo extends SecretsRepo with the one primitive key rotation and
// retirement need (secrets.KeyRepo).
type SecretsKeyRepo struct {
	*SecretsRepo
}

var _ secrets.KeyRepo = (*SecretsKeyRepo)(nil)

// NewSecretsKeyRepo builds the adapter over the same database as NewSecretsRepo.
func NewSecretsKeyRepo(db *database.DB, clock domain.Clock) *SecretsKeyRepo {
	return &SecretsKeyRepo{SecretsRepo: NewSecretsRepo(db, clock)}
}

// UpdateKeys runs change over every secrets row and commits what it returns in
// one write transaction (spec §10: rewrap, kek_id and active_kek_id together).
func (r *SecretsKeyRepo) UpdateKeys(ctx context.Context, change func(rows []secrets.Record) (secrets.KeyChange, error)) error {
	return r.db.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		rows, err := allSecretRows(ctx, tx)
		if err != nil {
			return err
		}
		result, err := change(rows)
		if err != nil {
			return err
		}
		now := r.clock.Now()
		for _, moved := range result.Rewrapped {
			res, err := tx.ExecContext(ctx, `UPDATE secrets SET kek_id = ?, wrapped_dek = ?, rotated_at = ? WHERE id = ?`,
				moved.KEKID, moved.WrappedDEK, now.UnixMilli(), moved.ID)
			if err != nil {
				return fmt.Errorf("rewrap secret %s: %w", moved.Name, err)
			}
			if n, _ := res.RowsAffected(); n != 1 {
				return fmt.Errorf("rewrap secret %s: %d rows updated, want 1", moved.Name, n)
			}
		}
		for _, key := range slices.Sorted(mapsKeys(result.Settings)) {
			err := database.PutSetting(ctx, tx, database.Setting{Key: key, Value: []byte(result.Settings[key]), UpdatedAt: now})
			if err != nil {
				return err
			}
		}
		for _, key := range result.DeleteSettings {
			if _, err := tx.ExecContext(ctx, `DELETE FROM settings WHERE key = ?`, key); err != nil {
				return fmt.Errorf("delete setting %s: %w", key, err)
			}
		}
		return nil
	})
}

func mapsKeys(m map[string]string) func(yield func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

func allSecretRows(ctx context.Context, q database.Querier) ([]secrets.Record, error) {
	rows, err := q.QueryContext(ctx, `SELECT id, name, version, envelope_version, kek_id, wrapped_dek, ciphertext FROM secrets ORDER BY name, version`)
	if err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
	}
	defer rows.Close()
	var out []secrets.Record
	for rows.Next() {
		var rec secrets.Record
		if err := rows.Scan(&rec.ID, &rec.Name, &rec.Version, &rec.EnvelopeVersion, &rec.KEKID, &rec.WrappedDEK, &rec.Ciphertext); err != nil {
			return nil, fmt.Errorf("scan secret: %w", err)
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}
