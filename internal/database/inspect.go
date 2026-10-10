package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"

	"github.com/autarquico/supermgmt/migrations"
)

// LatestSchemaVersion is the highest schema version embedded in this binary.
func LatestSchemaVersion() (int, error) {
	all, err := loadMigrations(migrations.FS)
	if err != nil {
		return 0, err
	}
	return all[len(all)-1].version, nil
}

// Inspection is what a read-only look at a database file found.
type Inspection struct {
	// Exists is false when there is no file at the path.
	Exists bool
	// HasSchema is false for an empty file that was never migrated.
	HasSchema bool
	// SchemaVersion is the highest applied migration, 0 without a schema.
	SchemaVersion int
	// IntegrityFindings holds the rows PRAGMA integrity_check reported, other than "ok".
	IntegrityFindings []string
}

// Inspect reads path without creating, migrating or writing anything, so
// `sm doctor` can look at a database whose daemon is not running (or is).
func Inspect(ctx context.Context, path string) (Inspection, error) {
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		return Inspection{}, nil
	} else if err != nil {
		return Inspection{}, fmt.Errorf("stat database: %w", err)
	}
	pool, err := sql.Open("sqlite", readOnlyDSN(path))
	if err != nil {
		return Inspection{}, fmt.Errorf("open database read-only: %w", err)
	}
	defer pool.Close()
	pool.SetMaxOpenConns(1)

	found := Inspection{Exists: true}
	if found.HasSchema, found.SchemaVersion, err = readSchemaVersion(ctx, pool); err != nil {
		return Inspection{}, err
	}
	if found.IntegrityFindings, err = integrityFindings(ctx, pool); err != nil {
		return Inspection{}, err
	}
	return found, nil
}

func readOnlyDSN(path string) string {
	return dsn(path, url.Values{"mode": {"ro"}, "_pragma": {"busy_timeout(5000)"}})
}

func readSchemaVersion(ctx context.Context, q Querier) (hasSchema bool, version int, err error) {
	var tables int
	if err := q.QueryRowContext(ctx,
		`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'`).Scan(&tables); err != nil {
		return false, 0, fmt.Errorf("read schema: %w", err)
	}
	if tables == 0 {
		return false, 0, nil
	}
	if err := q.QueryRowContext(ctx, `SELECT coalesce(max(version), 0) FROM schema_migrations`).Scan(&version); err != nil {
		return false, 0, fmt.Errorf("read schema version: %w", err)
	}
	return true, version, nil
}

func integrityFindings(ctx context.Context, q Querier) ([]string, error) {
	rows, err := list(ctx, q, "integrity findings", `PRAGMA integrity_check`, func(row scanner) (string, error) {
		var line string
		return line, row.Scan(&line)
	})
	if err != nil {
		return nil, err
	}
	if len(rows) == 1 && rows[0] == "ok" {
		return nil, nil
	}
	return rows, nil
}
