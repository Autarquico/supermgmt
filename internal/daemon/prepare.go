package daemon

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/version"
)

// Prepared is what a control plane needs before anything is configured: a
// current database with the instance row, and the master keys. Close releases
// the database.
type Prepared struct {
	db  *database.DB
	kit keyKit
}

// Prepare is the first half of the startup of ADR-0020, shared by the daemon
// and `sm server init`: it finishes or discards an interrupted restore, opens
// and migrates the database, makes the instance row, records the version
// transition and the downgrades the installer authorized offline (ADR-0035),
// and opens the key files, creating the first master key only when the
// instance has none. It is idempotent: a second call finds everything in place and changes nothing.
//
// The caller holds the database lock.
func Prepare(ctx context.Context, o Options) (*Prepared, error) {
	o, err := o.withDefaults()
	if err != nil {
		return nil, err
	}
	if err := recoverRestore(o.Config); err != nil {
		return nil, err
	}
	db, err := openDatabase(ctx, o.Config, o.Clock)
	if err != nil {
		return nil, err
	}
	if err := ensureInstance(ctx, db, o.Config, o.Clock, o.IDs); err != nil {
		return nil, errors.Join(fmt.Errorf("create the instance row: %w", err), db.Close())
	}
	if err := recordInstanceAudit(ctx, db, o); err != nil {
		return nil, errors.Join(err, db.Close())
	}
	kit, err := openSecrets(ctx, o.Config, db, o.Clock, o.IDs)
	if err != nil {
		return nil, errors.Join(err, db.Close())
	}
	return &Prepared{db: db, kit: kit}, nil
}

func recordInstanceAudit(ctx context.Context, db *database.DB, o Options) error {
	dataDir, err := filepath.Abs(o.Config.Instance.DataDir)
	if err != nil {
		return fmt.Errorf("data_dir %q: %w", o.Config.Instance.DataDir, err)
	}
	audit := app.InstanceAudit{DB: db, Clock: o.Clock, IDs: o.IDs, DataDir: dataDir, Log: o.Log}
	return audit.Record(ctx, o.SMVersion, version.Info().Commit)
}

// ActiveKEK is the id of the master key that wraps new secrets.
func (p *Prepared) ActiveKEK() domain.ID {
	id, _ := p.kit.keys.Active()
	return id
}

// Close closes the database.
func (p *Prepared) Close() error { return p.db.Close() }
