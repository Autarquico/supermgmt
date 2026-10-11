package secrets

import (
	"context"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
)

// Record is one row of the secrets table (spec §9): ciphertext only.
type Record struct {
	ID              domain.ID
	Name            string
	Version         int
	EnvelopeVersion int
	KEKID           domain.ID
	WrappedDEK      []byte
	Ciphertext      []byte
	MetadataJSON    string
	CreatedAt       time.Time
}

// Repo is the persistence seam of the slice. The SQL implementation lives in
// internal/database; secretstest.MemRepo is the in-memory fake.
type Repo interface {
	// Put inserts a new version. A (name, version) pair that exists is a conflict.
	Put(ctx context.Context, r Record) error
	// Get returns one version of a secret; version 0 means the latest.
	// A missing secret is a NOT_FOUND error.
	Get(ctx context.Context, name string, version int) (Record, error)
	// ReferencedKEKs lists the distinct kek_id values of all secrets rows.
	ReferencedKEKs(ctx context.Context) ([]domain.ID, error)
	// Setting reads settings.value_json (spec §9); found is false when absent.
	Setting(ctx context.Context, key string) (valueJSON string, found bool, err error)
	// PutSettings inserts or replaces several settings in ONE transaction: all
	// are stored or none (first-KEK creation depends on it).
	PutSettings(ctx context.Context, values map[string]string) error
}

// KeyChange is what a key operation asks the repository to commit atomically.
type KeyChange struct {
	// Rewrapped replaces KEKID and WrappedDEK of the stored rows with the same ID.
	Rewrapped []Record
	// Settings are upserted; values are JSON.
	Settings map[string]string
	// DeleteSettings are removed.
	DeleteSettings []string
}

// KeyRepo adds the one transactional primitive key rotation and retirement
// need (spec §10, ADR-0021).
type KeyRepo interface {
	Repo
	// UpdateKeys runs change inside ONE write transaction: it receives every
	// secrets row and returns what to store. An error from change, or from the
	// database, stores nothing. change may run more than once, so it must have
	// no side effects.
	UpdateKeys(ctx context.Context, change func(rows []Record) (KeyChange, error)) error
}
