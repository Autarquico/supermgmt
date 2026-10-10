package app

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/secrets"
)

// SecretsRepo adapts the database repositories to secrets.Repo (ADR-0016). It
// stores and returns ciphertext only; sealing belongs to internal/secrets.
type SecretsRepo struct {
	db    *database.DB
	clock domain.Clock
}

var _ secrets.Repo = (*SecretsRepo)(nil)

// NewSecretsRepo builds the adapter.
func NewSecretsRepo(db *database.DB, clock domain.Clock) *SecretsRepo {
	return &SecretsRepo{db: db, clock: clock}
}

// Put inserts the next version of a secret. The store numbers versions from
// what Get returned, so the record must be exactly one past the newest stored
// version; anything else, including a version that exists, is CONFLICT.
func (r *SecretsRepo) Put(ctx context.Context, rec secrets.Record) error {
	meta, err := metadataOf(rec.MetadataJSON)
	if err != nil {
		return err
	}
	return r.db.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		newest := 0
		switch latest, err := database.GetSecret(ctx, tx, rec.Name, 0); {
		case err == nil:
			newest = latest.Version
		case smerr.CodeOf(err) != smerr.CodeNotFound:
			return err
		}
		if rec.Version != newest+1 {
			return smerr.New(smerr.CodeConflict, "", fmt.Sprintf("secret %s version %d cannot be stored: the newest is %d", rec.Name, rec.Version, newest))
		}
		_, err := database.PutSecretVersion(ctx, tx, database.SecretRecord{
			ID: rec.ID, Name: rec.Name, EnvelopeVersion: rec.EnvelopeVersion, KEKID: rec.KEKID,
			WrappedDEK: rec.WrappedDEK, Ciphertext: rec.Ciphertext, Metadata: meta, CreatedAt: rec.CreatedAt,
		})
		return err
	})
}

func metadataOf(text string) (map[string]any, error) {
	if text == "" {
		return nil, nil
	}
	var meta map[string]any
	if err := json.Unmarshal([]byte(text), &meta); err != nil {
		return nil, smerr.Wrap(err, smerr.CodeInvalidArgument, "", "secret metadata is not a JSON object")
	}
	return meta, nil
}

// Get returns one version of a secret; version 0 means the newest.
func (r *SecretsRepo) Get(ctx context.Context, name string, version int) (secrets.Record, error) {
	stored, err := database.GetSecret(ctx, r.db.Reader(), name, version)
	if err != nil {
		return secrets.Record{}, err
	}
	meta, err := json.Marshal(stored.Metadata)
	if err != nil {
		return secrets.Record{}, fmt.Errorf("encode secret metadata: %w", err)
	}
	return secrets.Record{
		ID: stored.ID, Name: stored.Name, Version: stored.Version, EnvelopeVersion: stored.EnvelopeVersion,
		KEKID: stored.KEKID, WrappedDEK: stored.WrappedDEK, Ciphertext: stored.Ciphertext,
		MetadataJSON: string(meta), CreatedAt: stored.CreatedAt,
	}, nil
}

// ReferencedKEKs lists every KEK the database refers to, in secrets rows and
// in settings, so a missing key file fails the start (ADR-0016).
func (r *SecretsRepo) ReferencedKEKs(ctx context.Context) ([]domain.ID, error) {
	return database.ReferencedKEKIDs(ctx, r.db.Reader())
}

// Setting reads a settings value; found is false when the key is absent.
func (r *SecretsRepo) Setting(ctx context.Context, key string) (string, bool, error) {
	s, err := database.GetSetting(ctx, r.db.Reader(), key)
	if smerr.CodeOf(err) == smerr.CodeNotFound {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return string(s.Value), true, nil
}

// PutSetting inserts or replaces a setting.
func (r *SecretsRepo) PutSetting(ctx context.Context, key, valueJSON string) error {
	return r.db.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		return database.PutSetting(ctx, tx, database.Setting{Key: key, Value: json.RawMessage(valueJSON), UpdatedAt: r.clock.Now()})
	})
}
