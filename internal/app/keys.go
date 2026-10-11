package app

import (
	"context"
	"fmt"
	"slices"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
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
)

// KeyManager implements Keys (spec §10, ADR-0021). Each operation is
// authorized for secret.write in its own transaction, runs against the secrets
// package (which owns its transactions and the keyOps lock), and is audited
// afterwards with identifiers and fingerprints only, never key material,
// passphrases or secret values.
type KeyManager struct {
	core
	admin *secrets.KeyAdmin
	store *secrets.Store
	mode  config.Mode
}

var _ Keys = (*KeyManager)(nil)

// NewKeyManager validates cfg and the collaborators. mode decides whether
// ExportKey may be served at all.
func NewKeyManager(cfg Config, admin *secrets.KeyAdmin, store *secrets.Store, mode config.Mode) (*KeyManager, error) {
	c, err := newCore(cfg)
	if err != nil {
		return nil, err
	}
	if admin == nil || store == nil {
		return nil, fmt.Errorf("app: key manager needs the key administrator and the secret store")
	}
	return &KeyManager{core: c, admin: admin, store: store, mode: mode}, nil
}

// RotateMasterKey makes a new KEK active and rewraps every data key under it.
func (k *KeyManager) RotateMasterKey(ctx context.Context, by Caller) (wire.MasterKeyRotated, error) {
	actor, err := k.authorizeSecretWrite(ctx, by, eventMasterKeyRotated)
	if err != nil {
		return wire.MasterKeyRotated{}, err
	}
	return audited(ctx, k, actor, eventMasterKeyRotated, func() (wire.MasterKeyRotated, map[string]any, error) {
		r, err := k.admin.Rotate(ctx)
		if err != nil {
			return wire.MasterKeyRotated{}, nil, err
		}
		return wire.MasterKeyRotated{ActiveKEKID: r.Active, PreviousKEKID: r.Previous, Rewrapped: r.Rewrapped},
			map[string]any{"active_kek_id": r.Active, "previous_kek_id": r.Previous, "rewrapped": r.Rewrapped}, nil
	})
}

// RetireKey deletes a KEK nothing references. The caller must acknowledge that
// backups kept outside backup.directory are handled (spec §10); the
// acknowledgement is part of the audit event.
func (k *KeyManager) RetireKey(ctx context.Context, by Caller, r wire.RetireKeyRequest) error {
	actor, err := k.authorizeSecretWrite(ctx, by, eventMasterKeyRetired)
	if err != nil {
		return err
	}
	if _, err := domain.ParseID(r.KEKID.String()); err != nil {
		return err
	}
	if !r.ExternalBackupsHandled {
		return smerr.New(smerr.CodeInvalidArgument, "", "retiring a key requires external_backups_handled: backups copied elsewhere may still need it")
	}
	_, err = audited(ctx, k, actor, eventMasterKeyRetired, func() (struct{}, map[string]any, error) {
		return struct{}{}, map[string]any{"kek_id": r.KEKID, "external_backups_handled": true}, k.admin.Retire(ctx, r.KEKID)
	})
	return err
}

// ExportKey wraps a KEK under the caller's passphrase. It is served only to a
// local-socket caller of a local-mode instance: the response carries a wrapped
// master key and must never cross HTTPS or the server-mode admin socket.
func (k *KeyManager) ExportKey(ctx context.Context, by Caller, r wire.ExportKeyRequest) (wire.ExportedKey, error) {
	actor, err := k.authorizeExport(ctx, by)
	if err != nil {
		return wire.ExportedKey{}, err
	}
	if _, err := domain.ParseID(r.KEKID.String()); err != nil {
		return wire.ExportedKey{}, err
	}
	return audited(ctx, k, actor, eventMasterKeyExport, func() (wire.ExportedKey, map[string]any, error) {
		export, err := k.admin.Export(ctx, r.KEKID, r.Passphrase)
		return wire.ExportedKey{KEKID: r.KEKID, Export: export}, map[string]any{"kek_id": r.KEKID}, err
	})
}

// ImportSecret stores a new version of a named secret. ssh/default is reserved
// for the instance identity: it has its own rotation and metadata.
func (k *KeyManager) ImportSecret(ctx context.Context, by Caller, r wire.ImportSecretRequest) (wire.SecretVersion, error) {
	actor, err := k.authorizeSecretWrite(ctx, by, eventSecretImported)
	if err != nil {
		return wire.SecretVersion{}, err
	}
	if err := validateImport(r); err != nil {
		return wire.SecretVersion{}, err
	}
	return audited(ctx, k, actor, eventSecretImported, func() (wire.SecretVersion, map[string]any, error) {
		ref, err := k.store.Put(ctx, r.Name, audit.Secret(r.Value), map[string]any{"source": "import"})
		return wire.SecretVersion{Name: ref.Name, Version: ref.Version}, map[string]any{"name": ref.Name, "version": ref.Version}, err
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

// RotateSSHIdentity stores a new version of the instance SSH identity. Nodes
// keep signing with the version their setup pinned until node.setup re-runs.
func (k *KeyManager) RotateSSHIdentity(ctx context.Context, by Caller) (wire.SSHKey, error) {
	actor, err := k.authorizeSecretWrite(ctx, by, eventSSHKeyRotated)
	if err != nil {
		return wire.SSHKey{}, err
	}
	return audited(ctx, k, actor, eventSSHKeyRotated, func() (wire.SSHKey, map[string]any, error) {
		id, err := secrets.RotateSSHIdentity(ctx, k.store)
		if err != nil {
			return wire.SSHKey{}, nil, err
		}
		return wire.SSHKey{
				Ref: "secret://" + id.Ref.Name, Version: id.Ref.Version,
				AuthorizedKey: id.AuthorizedKey, FingerprintSHA256: id.FingerprintSHA256,
			},
			map[string]any{"name": id.Ref.Name, "version": id.Ref.Version, "fingerprint": id.FingerprintSHA256}, nil
	})
}

// ---- authorization and audit ---------------------------------------------------

var secretTarget = domain.ResourceRef{Type: domain.ResourceSecret}

// authorizeSecretWrite identifies the caller and evaluates secret.write. A
// denial is audited and returned; approval is refused because the operations
// touch files and cannot be parked as a job.
func (k *KeyManager) authorizeSecretWrite(ctx context.Context, by Caller, event string) (domain.Actor, error) {
	return k.authorizeWith(ctx, by, event, nil)
}

// authorizeExport is authorizeSecretWrite plus the transport rule of spec §10.
func (k *KeyManager) authorizeExport(ctx context.Context, by Caller) (domain.Actor, error) {
	return k.authorizeWith(ctx, by, eventMasterKeyExport, k.requireLocalSocket)
}

func (k *KeyManager) requireLocalSocket(by Caller) error {
	if k.mode != config.ModeLocal || by.Credential.Kind != domain.CredentialLocalSocket {
		return smerr.New(smerr.CodePolicyDenied, smerr.ReasonDefaultDeny,
			"exporting a master key is served only on the local-mode Unix socket; in server mode use `sm secrets export-key --offline`")
	}
	return nil
}

func (k *KeyManager) authorizeWith(ctx context.Context, by Caller, event string, transportRule func(Caller) error) (domain.Actor, error) {
	var actor domain.Actor
	err := k.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		var err error
		if actor, err = k.beginRequest(ctx, tx, by); err != nil {
			return err
		}
		if transportRule != nil {
			if err := transportRule(by); err != nil {
				return k.denied(ctx, tx, actor, event, err)
			}
		}
		res := k.authorize(policy.Request{Actor: actor, Action: actionSecretWrite, Targets: []policy.Target{{Ref: secretTarget}}})
		if err := k.auditDecision(ctx, tx, actor, actionSecretWrite, secretTarget, res); err != nil {
			return err
		}
		if err := decisionError(res); err != nil {
			return reject(err)
		}
		if res.ApprovalRequired {
			return reject(smerr.FromReason(smerr.ReasonApprovalNotSupported, "key and secret operations cannot wait for approval"))
		}
		return nil
	})
	return actor, err
}

func (k *KeyManager) denied(ctx context.Context, tx *database.Tx, actor domain.Actor, event string, cause error) error {
	if err := k.emit(ctx, tx, actor, event, secretTarget, domain.ResultDenied, map[string]any{"reason": string(smerr.ReasonDefaultDeny)}); err != nil {
		return err
	}
	return reject(cause)
}

// audited runs op and records its outcome. A failed operation is recorded with
// its error code only. When the operation succeeded but its event could not be
// stored, the caller gets an INTERNAL error that says so: the change happened.
func audited[T any](ctx context.Context, k *KeyManager, actor domain.Actor, event string, op func() (T, map[string]any, error)) (T, error) {
	out, data, opErr := op()
	result := domain.ResultSucceeded
	if opErr != nil {
		result = domain.ResultFailed
		data = map[string]any{"code": string(smerr.CodeOf(opErr))}
	}
	if err := k.write(ctx, func(ctx context.Context, tx *database.Tx) error {
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
