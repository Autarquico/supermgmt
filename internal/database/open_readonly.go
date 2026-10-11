package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/secrets"
)

// ReadOnly is a database opened for reading only: no migrations, no writes and
// no -wal or -shm files created next to it, so a command run as root on a
// service-owned database leaves no root-owned files behind.
type ReadOnly struct{ pool *sql.DB }

// OpenReadOnly opens the existing database at path read-only and immutable.
// Immutable skips locking and the WAL index, which is sound only while nothing
// else writes: callers hold the database lock (AcquireDatabaseLock) with the
// service stopped. A database that still has a non-empty -wal file (the last
// writer crashed) is refused, because immutable mode would ignore its content.
func OpenReadOnly(ctx context.Context, path string) (*ReadOnly, error) {
	if path == "" {
		return nil, errors.New("database path is empty")
	}
	if err := requireNoPendingWAL(path); err != nil {
		return nil, err
	}
	pool, err := sql.Open("sqlite", dsn(path, url.Values{"mode": {"ro"}, "immutable": {"1"}}))
	if err != nil {
		return nil, fmt.Errorf("open database read-only: %w", err)
	}
	pool.SetMaxOpenConns(1)
	if err := pool.PingContext(ctx); err != nil {
		_ = pool.Close()
		return nil, fmt.Errorf("open database read-only: %w", err)
	}
	return &ReadOnly{pool: pool}, nil
}

func requireNoPendingWAL(path string) error {
	info, err := os.Stat(path + "-wal")
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat database wal: %w", err)
	}
	if info.Size() > 0 {
		return smerr.New(smerr.CodeConflict, "", "the database has unmerged write-ahead log content: start the service once so it recovers, then stop it")
	}
	return nil
}

// Querier reads from the database.
func (r *ReadOnly) Querier() Querier { return r.pool }

// HasSchema reports whether the database was ever migrated.
func (r *ReadOnly) HasSchema(ctx context.Context) (bool, error) {
	has, _, err := readSchemaVersion(ctx, r.pool)
	return has, err
}

// Close closes the database.
func (r *ReadOnly) Close() error { return r.pool.Close() }

// ReadOnlySecrets is a secrets.Repo that reads the key check records and the
// KEKs the secrets table references, and refuses every write. Offline key
// commands and the restore key check use it: neither may change the database.
type ReadOnlySecrets struct{ Q Querier }

var _ secrets.Repo = ReadOnlySecrets{}

var errReadOnlySecrets = errors.New("the secrets repository is read-only here")

// Setting reads settings.value_json; found is false when the key is absent.
func (s ReadOnlySecrets) Setting(ctx context.Context, key string) (string, bool, error) {
	setting, err := GetSetting(ctx, s.Q, key)
	if smerr.CodeOf(err) == smerr.CodeNotFound {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return string(setting.Value), true, nil
}

// ReferencedKEKs lists the KEKs the database needs.
func (s ReadOnlySecrets) ReferencedKEKs(ctx context.Context) ([]domain.ID, error) {
	return ReferencedKEKIDs(ctx, s.Q)
}

func (ReadOnlySecrets) Put(context.Context, secrets.Record) error { return errReadOnlySecrets }

func (ReadOnlySecrets) Get(context.Context, string, int) (secrets.Record, error) {
	return secrets.Record{}, errReadOnlySecrets
}

func (ReadOnlySecrets) PutStaged(context.Context, secrets.Record) error { return errReadOnlySecrets }

func (ReadOnlySecrets) GetByID(context.Context, domain.ID) (secrets.Record, error) {
	return secrets.Record{}, errReadOnlySecrets
}

func (ReadOnlySecrets) ActivateStaged(context.Context, domain.ID) (secrets.Record, error) {
	return secrets.Record{}, errReadOnlySecrets
}

func (ReadOnlySecrets) DeleteStaged(context.Context, domain.ID) error { return errReadOnlySecrets }

func (ReadOnlySecrets) PutSettings(context.Context, map[string]string) error {
	return errReadOnlySecrets
}
