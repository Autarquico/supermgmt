package database

import (
	"context"
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"strconv"

	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/migrations"
)

// SchemaTooNewError reports a database migrated by a newer binary (spec §29.3:
// rollback goes through a backup, never through down migrations).
type SchemaTooNewError struct {
	DatabaseVersion int
	BinaryVersion   int
}

func (e *SchemaTooNewError) Error() string {
	return fmt.Sprintf("database schema version %d is newer than this binary supports (%d)",
		e.DatabaseVersion, e.BinaryVersion)
}

type migration struct {
	version int
	name    string
	sql     string
}

var migrationFile = regexp.MustCompile(`^(\d{6})_[a-z0-9_]+\.up\.sql$`)

// Migrate applies every embedded migration newer than the database, each in
// its own write transaction, and records it in schema_migrations. Re-running
// is a no-op.
func (d *DB) Migrate(ctx context.Context) error {
	all, err := loadMigrations(migrations.FS)
	if err != nil {
		return err
	}
	current, err := d.schemaVersion(ctx)
	if err != nil {
		return err
	}
	if latest := all[len(all)-1].version; current > latest {
		return &SchemaTooNewError{DatabaseVersion: current, BinaryVersion: latest}
	}
	for _, m := range all {
		if m.version <= current {
			continue
		}
		if err := d.apply(ctx, m); err != nil {
			return fmt.Errorf("apply migration %s: %w", m.name, err)
		}
	}
	return nil
}

func (d *DB) apply(ctx context.Context, m migration) error {
	return d.WithWriteTx(ctx, func(ctx context.Context, tx *Tx) error {
		if _, err := tx.ExecContext(ctx, m.sql); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx,
			`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`,
			m.version, domain.UnixMillis(d.clock.Now()))
		return err
	})
}

// schemaVersion returns the highest applied version, or 0 for a fresh database.
func (d *DB) schemaVersion(ctx context.Context) (int, error) {
	var version int
	err := d.WithWriteTx(ctx, func(ctx context.Context, tx *Tx) error {
		var exists int
		if err := tx.QueryRowContext(ctx,
			`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'`,
		).Scan(&exists); err != nil || exists == 0 {
			return err
		}
		return tx.QueryRowContext(ctx, `SELECT coalesce(max(version), 0) FROM schema_migrations`).Scan(&version)
	})
	if err != nil {
		return 0, fmt.Errorf("read schema version: %w", err)
	}
	return version, nil
}

func loadMigrations(fsys fs.FS) ([]migration, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("read migrations: %w", err)
	}
	var all []migration
	for _, e := range entries {
		match := migrationFile.FindStringSubmatch(e.Name())
		if match == nil {
			continue
		}
		body, err := fs.ReadFile(fsys, e.Name())
		if err != nil {
			return nil, fmt.Errorf("read migration %s: %w", e.Name(), err)
		}
		version, _ := strconv.Atoi(match[1])
		all = append(all, migration{version: version, name: e.Name(), sql: string(body)})
	}
	if len(all) == 0 {
		return nil, fmt.Errorf("no migrations embedded")
	}
	slices.SortFunc(all, func(a, b migration) int { return a.version - b.version })
	return all, nil
}
