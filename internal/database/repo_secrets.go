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

// A staged secret version is sealed but not yet active (ADR-0021: an import
// waiting for approval). It is stored with a negative version, so it can never
// be mistaken for a current one and several can wait under the same name. The
// version it receives on activation is the next positive one.
const firstStagedVersion = -1

// PutSecretVersion stores r as the next version of r.Name (1 for a new name)
// and returns it with that version. r.Version is ignored. The version is
// computed in the same statement, so concurrent writers cannot collide.
func PutSecretVersion(ctx context.Context, q Querier, r SecretRecord) (SecretRecord, error) {
	return insertSecret(ctx, q, r, `max(coalesce(max(version), 0), 0) + 1`)
}

// StageSecret stores r as a staged (inactive) version of r.Name. Its version is
// negative and r.Version is ignored.
func StageSecret(ctx context.Context, q Querier, r SecretRecord) (SecretRecord, error) {
	return insertSecret(ctx, q, r, `min(coalesce(min(version), 0), 0) + `+fmt.Sprint(firstStagedVersion))
}

func insertSecret(ctx context.Context, q Querier, r SecretRecord, versionExpr string) (SecretRecord, error) {
	metadata, err := encodeJSON(r.Metadata)
	if err != nil {
		return SecretRecord{}, err
	}
	err = q.QueryRowContext(ctx, `
		INSERT INTO secrets (id, name, version, envelope_version, kek_id, wrapped_dek, ciphertext,
		                     metadata_json, created_at, rotated_at)
		SELECT ?, ?, `+versionExpr+`, ?, ?, ?, ?, ?, ?, ? FROM secrets WHERE name = ?
		RETURNING version`,
		r.ID, r.Name, r.EnvelopeVersion, r.KEKID, r.WrappedDEK, r.Ciphertext, metadata,
		millis(r.CreatedAt), nullMillis(r.RotatedAt), r.Name).Scan(&r.Version)
	if err != nil {
		return SecretRecord{}, conflictIfDuplicate(err, "secret")
	}
	return r, nil
}

// ActivateStagedSecret makes a staged version the next current one of its name
// and returns it. Activating a version that is already current returns it
// unchanged, so a retried job converges. NOT_FOUND when no such version exists
// (it was discarded).
func ActivateStagedSecret(ctx context.Context, q Querier, id domain.ID) (SecretRecord, error) {
	res, err := q.ExecContext(ctx, `
		UPDATE secrets SET version = (
			SELECT max(coalesce(max(other.version), 0), 0) + 1 FROM secrets AS other WHERE other.name = secrets.name)
		WHERE id = ? AND version < 0`, id)
	if err != nil {
		return SecretRecord{}, fmt.Errorf("activate staged secret: %w", err)
	}
	if n, _ := res.RowsAffected(); n > 1 {
		return SecretRecord{}, fmt.Errorf("activate staged secret: %d rows updated", n)
	}
	r, err := GetSecretByID(ctx, q, id)
	if err != nil {
		return SecretRecord{}, err
	}
	return r, nil
}

// DeleteStagedSecret removes a staged version and its ciphertext. A version
// that is current, or does not exist, is left alone.
func DeleteStagedSecret(ctx context.Context, q Querier, id domain.ID) error {
	if _, err := q.ExecContext(ctx, `DELETE FROM secrets WHERE id = ? AND version < 0`, id); err != nil {
		return fmt.Errorf("delete staged secret: %w", err)
	}
	return nil
}

// DeleteSecretsByName removes every version of the named secret, staged ones included.
func DeleteSecretsByName(ctx context.Context, q Querier, name string) error {
	if _, err := q.ExecContext(ctx, `DELETE FROM secrets WHERE name = ?`, name); err != nil {
		return fmt.Errorf("delete secret versions: %w", err)
	}
	return nil
}

// GetSecretByID returns a stored version, current or staged.
func GetSecretByID(ctx context.Context, q Querier, id domain.ID) (SecretRecord, error) {
	return scanSecret(q.QueryRowContext(ctx, secretColumns+` FROM secrets WHERE id = ?`, id))
}

// GetSecret returns the given version of the named secret; a version below 1
// means the latest. Staged versions are never returned. NOT_FOUND when there is no such secret or version.
func GetSecret(ctx context.Context, q Querier, name string, version int) (SecretRecord, error) {
	query := secretColumns + ` FROM secrets WHERE name = ? AND version >= 1`
	args := []any{name}
	if version >= 1 {
		query += ` AND version = ?`
		args = append(args, version)
	} else {
		query += ` ORDER BY version DESC LIMIT 1`
	}
	return scanSecret(q.QueryRowContext(ctx, query, args...))
}

//nolint:gosec // column names, not credentials
const secretColumns = `SELECT id, name, version, envelope_version, kek_id, wrapped_dek, ciphertext, metadata_json,
	created_at, rotated_at`

func scanSecret(row *sql.Row) (SecretRecord, error) {
	var (
		r         SecretRecord
		metadata  string
		createdMs int64
		rotated   sql.NullInt64
	)
	err := row.Scan(&r.ID, &r.Name, &r.Version, &r.EnvelopeVersion, &r.KEKID,
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
