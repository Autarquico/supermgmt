// Package secretstest provides an in-memory secrets.Repo for tests of the
// secrets package and of code that depends on it.
package secretstest

import (
	"context"
	"slices"
	"sync"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/secrets"
)

// MemRepo is a goroutine-safe secrets.Repo held in memory.
type MemRepo struct {
	mu       sync.Mutex
	records  []secrets.Record
	settings map[string]string
}

// NewMemRepo returns an empty repository.
func NewMemRepo() *MemRepo { return &MemRepo{settings: map[string]string{}} }

var _ secrets.Repo = (*MemRepo)(nil)

func (m *MemRepo) Put(_ context.Context, r secrets.Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.records {
		if existing.Name == r.Name && existing.Version == r.Version {
			return smerr.New(smerr.CodeConflict, "", "secret version exists")
		}
	}
	m.records = append(m.records, cloneRecord(r))
	return nil
}

func (m *MemRepo) Get(_ context.Context, name string, version int) (secrets.Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var best *secrets.Record
	for i := range m.records {
		r := &m.records[i]
		if r.Name != name || (version != 0 && r.Version != version) {
			continue
		}
		if best == nil || r.Version > best.Version {
			best = r
		}
	}
	if best == nil {
		return secrets.Record{}, smerr.New(smerr.CodeNotFound, "", "secret not found")
	}
	return cloneRecord(*best), nil
}

func (m *MemRepo) ReferencedKEKs(context.Context) ([]domain.ID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var ids []domain.ID
	for _, r := range m.records {
		if !slices.Contains(ids, r.KEKID) {
			ids = append(ids, r.KEKID)
		}
	}
	return ids, nil
}

func (m *MemRepo) Setting(_ context.Context, key string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.settings[key]
	return v, ok, nil
}

func (m *MemRepo) PutSetting(_ context.Context, key, valueJSON string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.settings[key] = valueJSON
	return nil
}

// Update rewrites a stored record in place, for tamper and rewrap tests.
func (m *MemRepo) Update(name string, version int, edit func(*secrets.Record)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.records {
		if m.records[i].Name == name && m.records[i].Version == version {
			edit(&m.records[i])
		}
	}
}

// Dump returns every stored byte (rows and settings) for plaintext-leak scans.
func (m *MemRepo) Dump() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []byte
	for _, r := range m.records {
		out = append(out, r.Name...)
		out = append(out, r.WrappedDEK...)
		out = append(out, r.Ciphertext...)
		out = append(out, r.MetadataJSON...)
	}
	for k, v := range m.settings {
		out = append(out, k...)
		out = append(out, v...)
	}
	return out
}

func cloneRecord(r secrets.Record) secrets.Record {
	r.WrappedDEK = slices.Clone(r.WrappedDEK)
	r.Ciphertext = slices.Clone(r.Ciphertext)
	return r
}
