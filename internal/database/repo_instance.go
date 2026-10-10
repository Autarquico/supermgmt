package database

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// Instance is the single row identifying this SuperMgmt installation.
type Instance struct {
	ID        domain.ID
	Name      string
	CreatedAt time.Time
}

// CreateInstance stores i unless an instance row already exists, in which case
// it returns CONFLICT. The check and the insert are one statement.
func CreateInstance(ctx context.Context, q Querier, i Instance) error {
	res, err := q.ExecContext(ctx, `
		INSERT INTO instances (id, name, created_at)
		SELECT ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM instances)`,
		i.ID, i.Name, millis(i.CreatedAt))
	if err != nil {
		return fmt.Errorf("insert instance: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("insert instance: %w", err)
	}
	if n == 0 {
		return smerr.New(smerr.CodeConflict, "", "instance already exists")
	}
	return nil
}

// GetInstance returns the instance row, or NOT_FOUND before the first daemon start.
func GetInstance(ctx context.Context, q Querier) (Instance, error) {
	var (
		i         Instance
		createdMs int64
	)
	err := q.QueryRowContext(ctx, `SELECT id, name, created_at FROM instances`).Scan(&i.ID, &i.Name, &createdMs)
	if err != nil {
		return Instance{}, getErr(err, "instance")
	}
	i.CreatedAt = domain.FromUnixMillis(createdMs)
	return i, nil
}

// Setting is one key of the settings table; Value is JSON.
type Setting struct {
	Key       string
	Value     json.RawMessage
	UpdatedAt time.Time
}

// PutSetting upserts s. A non-JSON value is INVALID_ARGUMENT.
func PutSetting(ctx context.Context, q Querier, s Setting) error {
	if s.Key == "" || !json.Valid(s.Value) {
		return smerr.New(smerr.CodeInvalidArgument, "", "setting needs a key and a JSON value")
	}
	_, err := q.ExecContext(ctx, `
		INSERT INTO settings (key, value_json, updated_at) VALUES (?, ?, ?)
		ON CONFLICT (key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at`,
		s.Key, string(s.Value), millis(s.UpdatedAt))
	if err != nil {
		return fmt.Errorf("put setting: %w", err)
	}
	return nil
}

const settingColumns = `key, value_json, updated_at`

func scanSetting(row scanner) (Setting, error) {
	var (
		s         Setting
		value     string
		updatedMs int64
	)
	if err := row.Scan(&s.Key, &value, &updatedMs); err != nil {
		return Setting{}, err
	}
	s.Value, s.UpdatedAt = json.RawMessage(value), domain.FromUnixMillis(updatedMs)
	return s, nil
}

// GetSetting returns the setting or NOT_FOUND.
func GetSetting(ctx context.Context, q Querier, key string) (Setting, error) {
	s, err := scanSetting(q.QueryRowContext(ctx, `SELECT `+settingColumns+` FROM settings WHERE key = ?`, key))
	return s, getErr(err, "setting")
}

// ListSettings returns the settings whose key starts with prefix, ordered by key.
func ListSettings(ctx context.Context, q Querier, prefix string) ([]Setting, error) {
	return list(ctx, q, "settings",
		`SELECT `+settingColumns+` FROM settings WHERE substr(key, 1, ?) = ? ORDER BY key`,
		scanSetting, utf8.RuneCountInString(prefix), prefix)
}
