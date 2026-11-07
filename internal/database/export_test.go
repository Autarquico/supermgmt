package database

import (
	"context"

	"github.com/autarquico/supermgmt/migrations"
)

// MigrateUpTo applies the embedded migrations up to and including version (those already applied are skipped), for tests of a later migration's input.
func MigrateUpTo(ctx context.Context, db *DB, version int) error {
	all, err := loadMigrations(migrations.FS)
	if err != nil {
		return err
	}
	current, err := db.schemaVersion(ctx)
	if err != nil {
		return err
	}
	for _, m := range all {
		if m.version > current && m.version <= version {
			if err := db.apply(ctx, m); err != nil {
				return err
			}
		}
	}
	return nil
}
