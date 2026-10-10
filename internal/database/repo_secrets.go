package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
)

// SecretRecord is a stored secret version (spec §9, §10). It holds ciphertext
// only: sealing and opening belong to internal/secrets, never to this package.
type SecretRecord struct {
	ID              domain.ID
	Name            string
	Version         int
	EnvelopeVersion int
	KEKID           domain.ID
	WrappedDEK      []byte
	Ciphertext      []byte
	Metadata        map[string]any
	CreatedAt       time.Time
	RotatedAt       *time.Time
}

// PutSecretVersion stores r as the next version of r.Name (1 for a new name)
// and returns it with that version. r.Version is ignored. The version is
// computed in the same statement, so concurrent writers cannot collide.
func PutSecretVersion(ctx context.Context, q Querier, r SecretRecord) (SecretRecord, error) {
	metadata, err := encodeJSON(r.Metadata)
	if err != nil {
		return SecretRecord{}, err
	}
	err = q.QueryRowContext(ctx, `
		INSERT INTO secrets (id, name, version, envelope_version, kek_id, wrapped_dek, ciphertext,
		                     metadata_json, created_at, rotated_at)
		SELECT ?, ?, coalesce(max(version), 0) + 1, ?, ?, ?, ?, ?, ?, ? FROM secrets WHERE name = ?
		RETURNING version`,
		r.ID, r.Name, r.EnvelopeVersion, r.KEKID, r.WrappedDEK, r.Ciphertext, metadata,
		millis(r.CreatedAt), nullMillis(r.RotatedAt), r.Name).Scan(&r.Version)
	if err != nil {
		return SecretRecord{}, conflictIfDuplicate(err, "secret")
	}
	return r, nil
}

// GetSecret returns the given version of the named secret; a version below 1
// means the latest. NOT_FOUND when there is no such secret or version.
func GetSecret(ctx context.Context, q Querier, name string, version int) (SecretRecord, error) {
	query := `SELECT id, name, version, envelope_version, kek_id, wrapped_dek, ciphertext, metadata_json,
		created_at, rotated_at FROM secrets WHERE name = ?`
	args := []any{name}
	if version >= 1 {
		query += ` AND version = ?`
		args = append(args, version)
	} else {
		query += ` ORDER BY version DESC LIMIT 1`
	}
	var (
		r         SecretRecord
		metadata  string
		createdMs int64
		rotated   sql.NullInt64
	)
	err := q.QueryRowContext(ctx, query, args...).Scan(&r.ID, &r.Name, &r.Version, &r.EnvelopeVersion, &r.KEKID,
		&r.WrappedDEK, &r.Ciphertext, &metadata, &createdMs, &rotated)
	if err != nil {
		return SecretRecord{}, getErr(err, "secret")
	}
	if r.Metadata, err = decodeMap(metadata); err != nil {
		return SecretRecord{}, err
	}
	r.CreatedAt, r.RotatedAt = domain.FromUnixMillis(createdMs), timeOf(rotated)
	return r, nil
}

// ReferencedKEKIDs lists, sorted and without duplicates, every KEK id the
// database refers to: secret rows, settings.active_kek_id and the
// settings.kek_check.<id> records. Startup verifies that each one is loadable.
func ReferencedKEKIDs(ctx context.Context, q Querier) ([]domain.ID, error) {
	ids, err := list(ctx, q, "secret kek ids", `SELECT DISTINCT kek_id FROM secrets`,
		func(row scanner) (domain.ID, error) {
			var id domain.ID
			return id, row.Scan(&id)
		})
	if err != nil {
		return nil, err
	}
	settings, err := ListSettings(ctx, q, "")
	if err != nil {
		return nil, err
	}
	for _, s := range settings {
		id, ok, err := kekIDOfSetting(s)
		if err != nil {
			return nil, err
		}
		if ok {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	return slices.Compact(ids), nil
}

const (
	activeKEKSetting      = "active_kek_id"
	kekCheckSettingPrefix = "kek_check."
)

func kekIDOfSetting(s Setting) (domain.ID, bool, error) {
	switch {
	case s.Key == activeKEKSetting:
		var id domain.ID
		if err := json.Unmarshal(s.Value, &id); err != nil {
			return "", false, fmt.Errorf("decode setting %s: %w", s.Key, err)
		}
		return id, id != "", nil
	case strings.HasPrefix(s.Key, kekCheckSettingPrefix) && len(s.Key) > len(kekCheckSettingPrefix):
		return domain.ID(strings.TrimPrefix(s.Key, kekCheckSettingPrefix)), true, nil
	}
	return "", false, nil
}
