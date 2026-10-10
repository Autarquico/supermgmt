package database

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"modernc.org/sqlite"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// SQLite extended result codes for the two ways a uniqueness rule fires.
const (
	sqliteConstraintPrimaryKey = 1555
	sqliteConstraintUnique     = 2067
)

func isUniqueViolation(err error) bool {
	var sqliteErr *sqlite.Error
	if !errors.As(err, &sqliteErr) {
		return false
	}
	code := sqliteErr.Code()
	return code == sqliteConstraintUnique || code == sqliteConstraintPrimaryKey
}

func notFound(what string) error {
	return smerr.New(smerr.CodeNotFound, "", what+" not found")
}

// conflictIfDuplicate turns a uniqueness violation into CONFLICT and wraps
// everything else with context.
func conflictIfDuplicate(err error, what string) error {
	if isUniqueViolation(err) {
		return smerr.Wrap(err, smerr.CodeConflict, "", what+" already exists")
	}
	return fmt.Errorf("insert %s: %w", what, err)
}

// scanner is satisfied by *sql.Row and *sql.Rows.
type scanner interface{ Scan(dest ...any) error }

func encodeJSON(v any) (string, error) {
	if v == nil {
		return "{}", nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("encode json: %w", err)
	}
	return string(b), nil
}

func decodeMap(s string) (map[string]any, error) {
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return nil, fmt.Errorf("decode json: %w", err)
	}
	return m, nil
}

func millis(t time.Time) int64 { return domain.UnixMillis(t) }

func nullMillis(t *time.Time) sql.NullInt64 {
	if t == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: millis(*t), Valid: true}
}

func timeOf(n sql.NullInt64) *time.Time {
	if !n.Valid {
		return nil
	}
	t := domain.FromUnixMillis(n.Int64)
	return &t
}

func nullID(id *domain.ID) sql.NullString {
	if id == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: id.String(), Valid: true}
}

func idOf(n sql.NullString) *domain.ID {
	if !n.Valid {
		return nil
	}
	id := domain.ID(n.String)
	return &id
}
