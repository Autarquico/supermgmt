package database

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// Keys of the M2 settings rows (ADR-0020).
const (
	SettingConfigSnapshot     = "config_snapshot"
	SettingRestoreHold        = "restore_hold"
	SettingBackupReservations = "backup.reservations"
)

// ConfigSnapshot is the configuration a daemon activated: the bytes backups
// archive instead of whatever is on disk now. Generation counts activations.
type ConfigSnapshot struct {
	Config     []byte `json:"config"`
	Policy     []byte `json:"policy"`
	Generation int64  `json:"generation"`
}

// GetConfigSnapshot returns the stored snapshot or NOT_FOUND.
func GetConfigSnapshot(ctx context.Context, q Querier) (ConfigSnapshot, error) {
	s, err := GetSetting(ctx, q, SettingConfigSnapshot)
	if err != nil {
		return ConfigSnapshot{}, err
	}
	var snap ConfigSnapshot
	if err := json.Unmarshal(s.Value, &snap); err != nil {
		return ConfigSnapshot{}, fmt.Errorf("decode config snapshot: %w", err)
	}
	return snap, nil
}

// PutConfigSnapshot stores config and policy bytes (policy may be nil) as the
// next generation and returns it. Call it inside the write transaction that
// activates the configuration, so both commit together.
func PutConfigSnapshot(ctx context.Context, q Querier, config, policy []byte, at time.Time) (ConfigSnapshot, error) {
	previous, err := GetConfigSnapshot(ctx, q)
	if err != nil && !isNotFound(err) {
		return ConfigSnapshot{}, err
	}
	next := ConfigSnapshot{Config: config, Policy: policy, Generation: previous.Generation + 1}
	value, err := json.Marshal(next)
	if err != nil {
		return ConfigSnapshot{}, fmt.Errorf("encode config snapshot: %w", err)
	}
	if err := PutSetting(ctx, q, Setting{Key: SettingConfigSnapshot, Value: value, UpdatedAt: at}); err != nil {
		return ConfigSnapshot{}, err
	}
	return next, nil
}

// GetRestoreHold reports whether a restore hold is in force. An absent row
// means no hold; a row that cannot be read as a boolean is an error, so the
// caller fails closed (ADR-0020).
func GetRestoreHold(ctx context.Context, q Querier) (bool, error) {
	s, err := GetSetting(ctx, q, SettingRestoreHold)
	if isNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var held bool
	if err := json.Unmarshal(s.Value, &held); err != nil {
		return false, fmt.Errorf("decode restore hold: %w", err)
	}
	return held, nil
}

// SetRestoreHold sets or clears the restore hold.
func SetRestoreHold(ctx context.Context, q Querier, held bool, at time.Time) error {
	value, err := json.Marshal(held)
	if err != nil {
		return fmt.Errorf("encode restore hold: %w", err)
	}
	return PutSetting(ctx, q, Setting{Key: SettingRestoreHold, Value: value, UpdatedAt: at})
}

func isNotFound(err error) bool {
	var e *smerr.Error
	return errors.As(err, &e) && e.Code == smerr.CodeNotFound
}
